"""Synology DSM 6.2 / 7.x: import the certificate through DSM's web API.

Set the Device's port to DSM's HTTPS port (5001 unless changed in Control Panel > Login Portal).

The certificate replaces DSM's default certificate in place, so the services bound to it keep
working and pick up the new one. DSM restarts its web server if it needs to, which briefly
interrupts the web interface. On a NAS with several certificates, use the `description` option
to replace a different one.

Credentials: username + password of a local administrator. DSM asks a 2-factor account for a
code at every login, so this needs a dedicated account without 2-factor authentication.
Options:
  description      the DSM certificate to replace, by its Description in Control Panel > Security >
                   Certificate. If none matches, a new one is added and made the default.
  verify_timeout   seconds to wait for DSM to serve the new certificate (default 60)
"""

from __future__ import annotations

import asyncio
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

    async def _target(self, client: httpx.AsyncClient, session: _Session) -> dict[str, Any] | None:
        """The DSM certificate to replace, or None to add a new one."""
        response = await client.post(
            ENTRY, data={"api": "SYNO.Core.Certificate.CRT", "version": 1, "method": "list", "_sid": session.sid}
        )
        certificates = _data(response, "Listing certificates").get("certificates", [])
        if description := self.options.get("description"):
            return next((c for c in certificates if c.get("desc") == str(description)), None)
        return next((c for c in certificates if c.get("is_default")), None)

    def _new_description(self) -> str:
        return str(self.options.get("description") or DEFAULT_DESCRIPTION)

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client, self._session(client) as session:
                target = await self._target(client, session)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"DSM unreachable: {describe(exc)}")
        if target is None:
            return PluginValidationResult(
                success=True, message=f"Signed in; will add a certificate named {self._new_description()!r}"
            )
        return PluginValidationResult(
            success=True, message=f"Signed in; will replace the certificate named {target.get('desc')!r}"
        )

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
                target = await self._target(client, session)
                if target is None:
                    fields = {"id": "", "desc": self._new_description(), "as_default": "true"}
                    self.log(f"Adding certificate {fields['desc']!r} to DSM as the default")
                else:
                    fields = {"id": target["id"], "desc": target.get("desc", "")}
                    if target.get("is_default"):
                        fields["as_default"] = "true"
                    self.log(f"Replacing DSM certificate {fields['desc']!r}")
                params = {"api": "SYNO.Core.Certificate", "version": 1, "method": "import", "_sid": session.sid}
                if session.token:
                    params["SynoToken"] = session.token
                response = await client.post(ENTRY, params=params, data=fields, files=files)
                data = _data(response, "Certificate import")
                if data.get("restart_httpd"):
                    self.log("DSM is restarting its web server")
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
