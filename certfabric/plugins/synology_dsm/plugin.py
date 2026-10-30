"""Synology DSM 6.2 / 7.x: import the certificate through DSM's web API.

Set the Device's port to DSM's HTTPS port (5001 unless changed in Control Panel > Login Portal).

The certificate replaces DSM's default certificate in place, then every service still on another
certificate is moved to it, since DSM's default does not by itself change which certificate a
service uses. Other certificates stay on the NAS. DSM restarts its web server if it needs to,
which briefly interrupts the web interface.

Credentials: username + password of a local administrator. DSM asks a 2-factor account for a
code at every login, so this needs a dedicated account without 2-factor authentication.
Options:
  description      the DSM certificate to replace, by its Description in Control Panel > Security >
                   Certificate. If none matches, a new one is added and made the default. Services
                   are only moved to a default certificate, so one that is not stays as it is.
  assign_services  move services to the default certificate (default true); set false to keep
                   services on purpose on other certificates
  verify_timeout   seconds to wait for DSM to serve the new certificate (default 60)
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx

from certfabric.plugins.base import (
    BaseDevicePlugin,
    PluginError,
    PluginValidationResult,
    describe,
    device_tls_context,
)
from certfabric.x509util import split_pem_chain

TIMEOUT_SECONDS = 60
ENTRY = "/webapi/entry.cgi"
# The Description given to a certificate this Plugin adds, when the `description` option is not set.
DEFAULT_DESCRIPTION = "CertFabric"
# DSM's nginx answers every path on ports 80 and 443 with a page naming the real ports.
REDIRECT_PAGE_HTTPS_PORT = re.compile(r'id="https"[^>]*value="(\d+)"')
TWO_FACTOR = "This account uses 2-factor authentication; use a dedicated administrator without it"
LOGIN_ERRORS = {
    400: "DSM rejected the username or password",
    401: "This DSM account is disabled",
    402: "This DSM account may not sign in to DSM",
    403: TWO_FACTOR,
    404: TWO_FACTOR,
    406: "DSM enforces 2-factor authentication for this account; use an administrator exempt from it",
    407: "DSM has blocked CertFabric's IP address after failed logins",
    408: "This DSM account's password has expired",
    409: "This DSM account's password has expired",
    410: "This DSM account's password must be changed",
}
API_ERRORS = {105: "This DSM account is not an administrator"}


@dataclass(frozen=True)
class _Session:
    auth_path: str
    auth_version: int
    sid: str
    token: str | None


def _data(response: httpx.Response, action: str, errors: dict[int, str] = API_ERRORS) -> dict[str, Any]:
    """DSM answers 200 to almost everything: the outcome is in the `success` field of the JSON body."""
    if response.status_code >= 400:
        raise PluginError(f"{action} returned {response.status_code}; is this Synology DSM?")
    try:
        body = response.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise PluginError(f"{action} did not return JSON; is this Synology DSM?")
    if not body.get("success"):
        code = (body.get("error") or {}).get("code")
        raise PluginError(errors.get(code, f"{action} failed with DSM error {code}"))
    return body.get("data") or {}


class SynologyDsmPlugin(BaseDevicePlugin):
    plugin_id = "synology_dsm"
    plugin_name = "Synology DSM"
    target_category = "generic"
    supported_models = ["DSM 6.2", "DSM 7.x"]

    def _client(self) -> httpx.AsyncClient:
        if not (self.credentials.username and self.credentials.password):
            raise PluginError("A DSM username and password are required")
        # DSM's current certificate is the one being replaced, so it cannot be trusted.
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}",
            verify=device_tls_context(),
            timeout=TIMEOUT_SECONDS,
        )

    @asynccontextmanager
    async def _session(self, client: httpx.AsyncClient) -> AsyncIterator[_Session]:
        session = await self._login(client)
        try:
            yield session
        finally:
            await self._logout(client, session)

    async def _login(self, client: httpx.AsyncClient) -> _Session:
        response = await client.get(
            "/webapi/query.cgi",
            params={"api": "SYNO.API.Info", "version": 1, "method": "query", "query": "SYNO.API.Auth"},
        )
        if redirect := REDIRECT_PAGE_HTTPS_PORT.search(response.text):
            raise PluginError(f"Port {self.port} is DSM's redirect page; set the Device's port to {redirect[1]}")
        api = _data(response, "The API query").get("SYNO.API.Auth")
        if not api:
            raise PluginError("DSM did not list its login API; is this Synology DSM?")
        # POST, so the password stays out of URLs and logs. acme.sh's POST login sends
        # enable_syno_token in both the URL and the body, so this does too.
        response = await client.post(
            f"/webapi/{api['path']}",
            params={"enable_syno_token": "yes"},
            data={
                "api": "SYNO.API.Auth",
                "version": api["maxVersion"],
                "method": "login",
                "format": "sid",
                "enable_syno_token": "yes",
                "account": self.credentials.username,
                "passwd": self.credentials.password,
            },
        )
        data = _data(response, "Login", LOGIN_ERRORS)
        token = data.get("synotoken")
        if token:
            # Without this header DSM answers every later call with error 119, invalid session.
            client.headers["X-SYNO-TOKEN"] = token
        return _Session(api["path"], api["maxVersion"], data["sid"], token)

    async def _logout(self, client: httpx.AsyncClient, session: _Session) -> None:
        """Best effort: the web server may be restarting, and DSM expires the session by itself."""
        try:
            await client.get(
                f"/webapi/{session.auth_path}",
                params={
                    "api": "SYNO.API.Auth",
                    "version": session.auth_version,
                    "method": "logout",
                    "_sid": session.sid,
                },
            )
        except httpx.HTTPError as exc:
            self.log(f"Could not log out of DSM: {describe(exc)}")

    async def _certificates(self, client: httpx.AsyncClient, session: _Session) -> list[dict[str, Any]]:
        response = await client.post(
            ENTRY, data={"api": "SYNO.Core.Certificate.CRT", "version": 1, "method": "list", "_sid": session.sid}
        )
        return _data(response, "Listing certificates").get("certificates", [])

    def _target(self, certificates: list[dict[str, Any]]) -> dict[str, Any] | None:
        """The DSM certificate to replace, or None to add a new one."""
        if description := self.options.get("description"):
            return next((c for c in certificates if c.get("desc") == str(description)), None)
        return next((c for c in certificates if c.get("is_default")), None)

    @staticmethod
    def _name(certificate: dict[str, Any]) -> str:
        """DSM's default certificate often has no Description, so fall back to the name it was issued for."""
        return certificate.get("desc") or (certificate.get("subject") or {}).get("common_name") or certificate["id"]

    def _new_description(self) -> str:
        return str(self.options.get("description") or DEFAULT_DESCRIPTION)

    def _services_to_move(self, certificates: list[dict[str, Any]], *target_ids: str) -> list[dict[str, Any]]:
        """Settings moving services off every other certificate. DSM 6 drops a service set to its own certificate."""
        if not self.options.get("assign_services", True):
            return []
        return [
            {"service": service, "old_id": certificate["id"]}
            for certificate in certificates
            if certificate["id"] not in target_ids
            for service in certificate.get("services") or []
            if service.get("user_setable", True)
        ]

    async def _assign_services(
        self, client: httpx.AsyncClient, session: _Session, moves: list[dict[str, Any]], certificate_id: str
    ) -> None:
        names = ", ".join(str(move["service"].get("display_name")) for move in moves)
        self.log(f"Moving DSM services to the new certificate: {names}")
        settings = [{**move, "id": certificate_id} for move in moves]
        response = await client.post(
            ENTRY,
            data={
                "api": "SYNO.Core.Certificate.Service",
                "version": 1,
                "method": "set",
                "_sid": session.sid,
                "settings": json.dumps(settings, separators=(",", ":")),
            },
        )
        _data(response, "Moving services")

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client, self._session(client) as session:
                certificates = await self._certificates(client, session)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"DSM unreachable: {describe(exc)}")
        target = self._target(certificates)
        if target is None:
            message = f"Signed in; will add a certificate named {self._new_description()!r}"
        else:
            message = f"Signed in; will replace the certificate named {self._name(target)!r}"
        if target is None or target.get("is_default"):
            if moves := self._services_to_move(certificates, target["id"] if target else ""):
                message += f" and move {len(moves)} services to it"
        return PluginValidationResult(success=True, message=message)

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        files = {
            "key": ("privkey.pem", privkey_pem.encode(), "application/octet-stream"),
            "cert": ("cert.pem", cert_pem.encode(), "application/octet-stream"),
        }
        if intermediates := split_pem_chain(fullchain_pem)[1:]:
            files["inter_cert"] = ("chain.pem", "".join(intermediates).encode(), "application/octet-stream")
        try:
            async with self._client() as client, self._session(client) as session:
                certificates = await self._certificates(client, session)
                target = self._target(certificates)
                if target is None:
                    fields = {"id": "", "desc": self._new_description(), "as_default": "true"}
                    self.log(f"Adding certificate {fields['desc']!r} to DSM as the default")
                else:
                    fields = {"id": target["id"], "desc": target.get("desc", "")}
                    if target.get("is_default"):
                        fields["as_default"] = "true"
                    self.log(f"Replacing DSM certificate {self._name(target)!r}")
                moves = self._services_to_move(certificates, fields["id"]) if "as_default" in fields else []
                params = {"api": "SYNO.Core.Certificate", "version": 1, "method": "import", "_sid": session.sid}
                if session.token:
                    params["SynoToken"] = session.token
                response = await client.post(ENTRY, params=params, data=fields, files=files)
                data = _data(response, "Certificate import")
                if data.get("restart_httpd"):
                    self.log("DSM is restarting its web server")
                # DSM may give a replaced certificate a new id, so take the one it reports.
                certificate_id = data.get("id") or fields["id"]
                moves = [move for move in moves if move["old_id"] != certificate_id]
                if moves:
                    if not certificate_id:
                        raise PluginError("DSM did not say which certificate it imported")
                    await self._assign_services(client, session, moves, certificate_id)
        except httpx.HTTPError as exc:
            raise PluginError(f"DSM unreachable: {describe(exc)}") from None
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """DSM's web server may restart after the import; poll until it serves the new certificate."""
        deadline = asyncio.get_running_loop().time() + float(self.options.get("verify_timeout", 60))
        while True:
            if await self.served_fingerprint() == expected_fingerprint:
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(1)
