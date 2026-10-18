"""Proxmox VE 7.x / 8.x: upload a custom certificate through the PVE API, with SSH fallback.

The API call restarts pveproxy only; guest VMs are not touched.

Credentials (API, pick one):
  username + api_token     an API token, username as `user@realm!tokenid`
  username + password      a PVE user, e.g. `root@pam`
Credentials (SSH fallback, optional):
  extra["ssh_password"] or extra["ssh_private_key"]
Options:
  node             the node name; discovered when the cluster has exactly one node
  ssh_username     default `root`
  ssh_port         default 22
  ssh_host_key     pin the SSH server key ("ssh-ed25519 AAAA...")
  verify_timeout   seconds to wait for pveproxy to serve the new certificate (default 30)
"""

from __future__ import annotations

import asyncio
import secrets
import shlex
from typing import Any

import asyncssh
import httpx

from certfabric.plugins.base import (
    BaseDevicePlugin,
    PluginError,
    PluginValidationResult,
    describe,
    device_tls_context,
)

TIMEOUT_SECONDS = 30


class ProxmoxVePlugin(BaseDevicePlugin):
    plugin_id = "proxmox_ve"
    plugin_name = "Proxmox VE"
    target_category = "hypervisor"
    supported_models = ["Proxmox VE 7.x", "Proxmox VE 8.x"]

    # --- API -----------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        # The device's current certificate is the one being replaced, so it cannot be trusted.
        return httpx.AsyncClient(
            base_url=f"https://{self.host}:{self.port}/api2/json",
            verify=device_tls_context(),
            timeout=TIMEOUT_SECONDS,
        )

    async def _login(self, client: httpx.AsyncClient) -> None:
        creds = self.credentials
        if not creds.username:
            raise PluginError("A Proxmox username is required")
        if creds.api_token:
            client.headers["Authorization"] = f"PVEAPIToken={creds.username}={creds.api_token}"
            return
        if not creds.password:
            raise PluginError("A Proxmox password or API token is required")
        response = await client.post("/access/ticket", data={"username": creds.username, "password": creds.password})
        if response.status_code == 401:
            raise PluginError("Proxmox rejected the username or password")
        response.raise_for_status()
        data = response.json()["data"]
        client.cookies.set("PVEAuthCookie", data["ticket"])
        client.headers["CSRFPreventionToken"] = data["CSRFPreventionToken"]

    async def _get(self, client: httpx.AsyncClient, path: str) -> Any:
        response = await client.get(path)
        if response.status_code == 401:
            raise PluginError("Proxmox rejected the credentials")
        response.raise_for_status()
        return response.json()["data"]

    async def _node(self, client: httpx.AsyncClient) -> str:
        if node := self.options.get("node"):
            return str(node)
        nodes = [n["node"] for n in await self._get(client, "/nodes")]
        if len(nodes) != 1:
            raise PluginError(f"Set the `node` option; this cluster has nodes {', '.join(nodes)}")
        return nodes[0]

    async def test_connection(self) -> PluginValidationResult:
        try:
            async with self._client() as client:
                await self._login(client)
                version = (await self._get(client, "/version"))["version"]
                node = await self._node(client)
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        except httpx.HTTPError as exc:
            return PluginValidationResult(success=False, message=f"Proxmox API unreachable: {describe(exc)}")
        return PluginValidationResult(
            success=True, message=f"Proxmox VE {version}, node {node}", details={"version": version, "node": node}
        )

    async def _deploy_api(self, fullchain_pem: str, privkey_pem: str) -> None:
        async with self._client() as client:
            await self._login(client)
            node = await self._node(client)
            self.log(f"Uploading custom certificate to node {node} via the Proxmox API")
            response = await client.post(
                f"/nodes/{node}/certificates/custom",
                data={"certificates": fullchain_pem, "key": privkey_pem, "force": "1", "restart": "1"},
            )
            if response.status_code == 401:
                raise PluginError("Proxmox rejected the credentials")
            if response.status_code >= 400:
                raise PluginError(f"Proxmox API returned {response.status_code}: {response.text[:200]}")

    # --- SSH fallback --------------------------------------------------------

    def _ssh_configured(self) -> bool:
        return bool(self.credentials.extra.get("ssh_password") or self.credentials.extra.get("ssh_private_key"))

    async def _deploy_ssh(self, fullchain_pem: str, privkey_pem: str) -> None:
        extra = self.credentials.extra
        kwargs: dict[str, Any] = {
            "port": int(self.options.get("ssh_port", 22)),
            "username": self.options.get("ssh_username", "root"),
            "connect_timeout": TIMEOUT_SECONDS,
            "known_hosts": (
                asyncssh.import_known_hosts(f"* {self.options['ssh_host_key']}")
                if self.options.get("ssh_host_key")
                else None
            ),
        }
        if key := extra.get("ssh_private_key"):
            kwargs["client_keys"] = [asyncssh.import_private_key(key)]
        else:
            kwargs["password"] = extra["ssh_password"]
            kwargs["client_keys"] = None
        stem = f"/tmp/certfabric-{secrets.token_hex(8)}"
        try:
            async with asyncssh.connect(self.host, **kwargs) as conn:
                async with conn.start_sftp_client() as sftp:
                    for suffix, content in ((".pem", fullchain_pem), (".key", privkey_pem)):
                        async with sftp.open(stem + suffix, "w") as remote:
                            await remote.write(content)
                        await sftp.chmod(stem + suffix, 0o600)
                command = (
                    f"pvenode cert set {shlex.quote(stem + '.pem')} {shlex.quote(stem + '.key')} --force 1 --restart 1; "
                    f"status=$?; rm -f {shlex.quote(stem + '.pem')} {shlex.quote(stem + '.key')}; exit $status"
                )
                self.log("Installing the certificate with pvenode over SSH")
                result = await conn.run(command, check=False, timeout=TIMEOUT_SECONDS)
        except asyncssh.PermissionDenied:
            raise PluginError("SSH authentication failed") from None
        except (OSError, asyncssh.Error) as exc:
            raise PluginError(f"SSH fallback failed: {exc}") from None
        if result.exit_status != 0:
            raise PluginError(f"pvenode exited with status {result.exit_status}: {str(result.stderr).strip()[:200]}")

    # --- Contract ------------------------------------------------------------

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        try:
            await self._deploy_api(fullchain_pem, privkey_pem)
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            if not self._ssh_configured():
                raise PluginError(f"Proxmox API unreachable ({exc}) and no SSH fallback is configured") from None
            self.log(f"Proxmox API unreachable ({type(exc).__name__}); falling back to SSH")
            await self._deploy_ssh(fullchain_pem, privkey_pem)
        except httpx.HTTPError as exc:
            raise PluginError(f"Proxmox API error: {describe(exc)}") from None
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """pveproxy restarts after the upload; poll until it serves the new certificate."""
        deadline = asyncio.get_running_loop().time() + float(self.options.get("verify_timeout", 30))
        while True:
            if await self.served_fingerprint() == expected_fingerprint:
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(1)
