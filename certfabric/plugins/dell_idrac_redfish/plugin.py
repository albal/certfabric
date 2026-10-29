"""Dell iDRAC 7 / 8 / 9 / 10.

iDRAC 9 and 10: imports the certificate and key as a PKCS#12 bundle through Dell's Redfish
`DelliDRACCardService.ImportSSLCertificate` action (CertificateType `CustomCertificate`).

iDRAC 7 and 8 (12G / 13G servers) have no Redfish certificate import, so the key and chain
go up over the remote RACADM protocol instead: each is staged with `/cgi-bin/putfile`, then
`racadm sslkeyupload` / `racadm sslcertupload` installs it.

Either way the Device's DNS names (its hostname and SNI name, if not IP addresses) are then
added to iDRAC's `WebServer.ManualDNSEntry`: with HostHeaderCheck on, iDRAC answers 400 to a
name it does not know, so the new certificate would be unusable by name. Existing entries are
kept. Finally iDRAC is restarted so its web server serves the new certificate. Host power
state is not affected.

Credentials: username + password (an iDRAC user with Configure Manager privilege).
Options:
  manager_id       default `iDRAC.Embedded.1`
  reset            restart iDRAC after the import (default true; the cert is not served until then)
  verify_timeout   seconds to wait for iDRAC to come back serving it (default 300)
  allow_hostname   add the Device's DNS names to iDRAC's allowed host names (default true)
"""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import re
import struct
from collections.abc import Awaitable, Callable
from xml.sax.saxutils import escape

import httpx
from cryptography.hazmat.primitives import serialization

from certfabric.plugins.base import (
    BaseDevicePlugin,
    PluginError,
    PluginValidationResult,
    describe,
    device_tls_context,
)

TIMEOUT_SECONDS = 60
# Model is e.g. "13G Monolithic"; servers before 14G carry iDRAC 7 or 8.
FIRST_REDFISH_IMPORT_GENERATION = 14
# The upload slot remote racadm stages SSL keys and certificates in; commands refer to it as `sslcertfile`.
RACADM_SSL_FILE = b"RACSSLCERT1"
RACADM_MAX_FILE = 0x10000
MANUAL_DNS_ENTRY = "WebServer.1.ManualDNSEntry"
HOSTNAME = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$")


def _generation(model: str) -> int | None:
    match = re.match(r"(\d+)G\b", model)
    return int(match.group(1)) if match else None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _xml_field(body: str, tag: str) -> str | None:
    match = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.DOTALL)
    return html.unescape(match.group(1)) if match else None


def _traditional_pem(privkey_pem: str) -> bytes:
    """The key as `BEGIN RSA/EC PRIVATE KEY`, the form iDRAC 8's key upload was built around."""
    key = serialization.load_pem_private_key(privkey_pem.encode(), password=None)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )


class DellIdracRedfishPlugin(BaseDevicePlugin):
    plugin_id = "dell_idrac_redfish"
    plugin_name = "Dell iDRAC (Redfish)"
    target_category = "bmc"
    supported_models = ["iDRAC 7", "iDRAC 8", "iDRAC 9", "iDRAC 10"]

    @property
    def _manager(self) -> str:
        return str(self.options.get("manager_id", "iDRAC.Embedded.1"))

    def _client(self) -> httpx.AsyncClient:
        creds = self.credentials
        if not (creds.username and creds.password):
            raise PluginError("An iDRAC username and password are required")
        # iDRAC's current certificate is the one being replaced, so it cannot be trusted.
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}",
            auth=(creds.username, creds.password),
            verify=device_tls_context(),
            timeout=TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
        )

    @staticmethod
    def _check(response: httpx.Response, action: str) -> None:
        if response.status_code == 401:
            raise PluginError("iDRAC rejected the username or password")
        if response.status_code >= 400:
            try:
                messages = response.json()["error"]["@Message.ExtendedInfo"]
                detail = "; ".join(m.get("Message", "") for m in messages)
            except (ValueError, KeyError, TypeError):
                detail = response.text[:200]
            raise PluginError(f"{action} failed ({response.status_code}): {detail}")

    async def _read_manager(self, client: httpx.AsyncClient) -> dict:
        response = await client.get(f"/redfish/v1/Managers/{self._manager}")
        self._check(response, "Reading the iDRAC manager")
        return response.json()

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client:
                manager = await self._read_manager(client)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"iDRAC unreachable: {describe(exc)}")
        model = manager.get("Model", "iDRAC")
        firmware = manager.get("FirmwareVersion", "unknown")
        return PluginValidationResult(
            success=True, message=f"{model}, firmware {firmware}", details={"model": model, "firmware": firmware}
        )

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        try:
            async with self._client() as client:
                generation = _generation(str((await self._read_manager(client)).get("Model", "")))
                if generation is not None and generation < FIRST_REDFISH_IMPORT_GENERATION:
                    await self._import_with_racadm(client, privkey_pem, fullchain_pem)
                else:
                    await self._import_with_redfish(client, pfx_bundle, pfx_password)
                    await self._allow_hostnames_with_redfish(client)
                if self.options.get("reset", True):
                    self.log("Restarting iDRAC so its web server serves the new certificate")
                    response = await client.post(
                        f"/redfish/v1/Managers/{self._manager}/Actions/Manager.Reset",
                        json={"ResetType": "GracefulRestart"},
                    )
                    self._check(response, "iDRAC restart")
        except httpx.HTTPError as exc:
            raise PluginError(f"iDRAC unreachable: {describe(exc)}") from None
        return True

    async def _import_with_redfish(self, client: httpx.AsyncClient, pfx_bundle: bytes, pfx_password: str | None) -> None:
        service = f"/redfish/v1/Dell/Managers/{self._manager}/DelliDRACCardService"
        self.log("Importing the certificate into iDRAC")
        response = await client.post(
            f"{service}/Actions/DelliDRACCardService.ImportSSLCertificate",
            json={
                "CertificateType": "CustomCertificate",
                "SSLCertificateFile": base64.b64encode(pfx_bundle).decode(),
                "Passphrase": pfx_password or "",
            },
        )
        self._check(response, "Certificate import")

    async def _import_with_racadm(self, client: httpx.AsyncClient, privkey_pem: str, fullchain_pem: str) -> None:
        self.log("This iDRAC has no Redfish certificate import; using remote RACADM")
        creds = self.credentials
        response = await client.post(
            "/cgi-bin/login",
            content=(
                "<?xml version='1.0'?><LOGIN><REQ>"
                f"<USERNAME>{escape(creds.username or '')}</USERNAME><PASSWORD>{escape(creds.password or '')}</PASSWORD>"
                "</REQ></LOGIN>"
            ),
            auth=None,
        )
        self._check(response, "RACADM login")
        sid = _xml_field(response.text, "SID")
        if _xml_field(response.text, "RC") != "0x0" or not sid:
            raise PluginError("iDRAC rejected the username or password")
        try:
            self.log("Uploading the private key to iDRAC")
            await self._racadm_put(client, sid, _traditional_pem(privkey_pem), "Private key upload")
            await self._racadm_exec(client, sid, "racadm sslkeyupload -f sslcertfile -t 1", "Private key upload")
            self.log("Uploading the certificate chain to iDRAC")
            await self._racadm_put(client, sid, fullchain_pem.encode(), "Certificate upload")
            await self._racadm_exec(client, sid, "racadm sslcertupload -f sslcertfile -t 1", "Certificate upload")

            async def read() -> str:
                output = await self._racadm_exec(
                    client, sid, "racadm get iDRAC.WebServer.ManualDNSEntry", "Reading allowed host names"
                )
                match = re.search(r"^ManualDNSEntry=(.*)$", output, re.MULTILINE)
                return match.group(1).strip() if match else ""

            async def write(value: str) -> None:
                command = f'racadm set iDRAC.WebServer.ManualDNSEntry "{value}"'
                await self._racadm_exec(client, sid, command, "Setting allowed host names")

            await self._allow_hostnames(read, write)
        finally:
            await client.post("/cgi-bin/logout", headers={"Cookie": f"sid={sid}"}, auth=None)

    async def _racadm_put(self, client: httpx.AsyncClient, sid: str, data: bytes, action: str) -> None:
        """Stage a file: a 32-byte name, u32 length, a chunk flag (0 = whole file), 3 pad bytes, then the data."""
        if len(data) > RACADM_MAX_FILE:
            raise PluginError(f"{action} failed: the file is larger than iDRAC accepts")
        response = await client.post(
            "/cgi-bin/putfile",
            content=RACADM_SSL_FILE.ljust(32, b"\0") + struct.pack("<IB3x", len(data), 0) + data,
            headers={"Content-Type": "application/octet-stream", "Cookie": f"sid={sid}"},
            auth=None,
        )
        self._check(response, action)
        if len(response.content) < 4 or struct.unpack("<I", response.content[:4])[0] != 0:
            raise PluginError(f"{action} failed: iDRAC refused the file transfer")

    async def _racadm_exec(self, client: httpx.AsyncClient, sid: str, command: str, action: str) -> str:
        response = await client.post(
            "/cgi-bin/exec",
            content=(
                "<?xml version='1.0'?><EXEC><REQ>"
                f"<CMDINPUT>{escape(command)}</CMDINPUT><MAXOUTPUTLEN>0x0fff</MAXOUTPUTLEN>"
                "</REQ></EXEC>"
            ),
            headers={"Cookie": f"sid={sid}"},
            auth=None,
        )
        self._check(response, action)
        output = (_xml_field(response.text, "CMDOUTPUT") or "").strip()
        if _xml_field(response.text, "CMDRC") != "0x0":
            raise PluginError(f"{action} failed: {output or response.text[:200]}")
        return output

    async def _allow_hostnames_with_redfish(self, client: httpx.AsyncClient) -> None:
        attributes = f"/redfish/v1/Managers/{self._manager}/Attributes"

        async def read() -> str:
            response = await client.get(attributes)
            self._check(response, "Reading allowed host names")
            return str(response.json().get("Attributes", {}).get(MANUAL_DNS_ENTRY) or "")

        async def write(value: str) -> None:
            response = await client.patch(attributes, json={"Attributes": {MANUAL_DNS_ENTRY: value}})
            self._check(response, "Setting allowed host names")

        await self._allow_hostnames(read, write)

    def _hostnames(self) -> list[str]:
        names: list[str] = []
        for name in (self.host, self.sni):
            if name and HOSTNAME.match(name) and not _is_ip(name) and name.lower() not in map(str.lower, names):
                names.append(name)
        return names

    async def _allow_hostnames(
        self, read: Callable[[], Awaitable[str]], write: Callable[[str], Awaitable[None]]
    ) -> None:
        """Add the Device's DNS names to iDRAC's ManualDNSEntry; a failure here does not fail the Deployment."""
        names = self._hostnames()
        if not names or not self.options.get("allow_hostname", True):
            return
        try:
            entries = [entry.strip() for entry in (await read()).split(",") if entry.strip()]
            known = {entry.lower() for entry in entries}
            missing = [name for name in names if name.lower() not in known]
            if missing:
                self.log(f"Allowing {', '.join(missing)} through iDRAC's Host header check")
                await write(",".join(entries + missing))
        except (PluginError, httpx.HTTPError) as exc:
            self.log(f"Could not add {', '.join(names)} to iDRAC's allowed host names: {describe(exc)}")

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """iDRAC takes minutes to restart; poll until it serves the new certificate."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(self.options.get("verify_timeout", 300))
        while True:
            if await self.served_fingerprint() == expected_fingerprint:
                return True
            if loop.time() >= deadline:
                return False
            await asyncio.sleep(5 if deadline - loop.time() > 5 else 0.2)
