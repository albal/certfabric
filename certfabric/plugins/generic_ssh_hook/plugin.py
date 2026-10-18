"""Generic SSH hook: upload PEM files over SFTP, then run a reload command.

Options:
  cert_path, key_path, fullchain_path  remote paths to write (at least one)
  reload_command                       run after upload, e.g. `systemctl reload nginx`
  ssh_port                             default 22
  ssh_host_key                         the server's public key ("ssh-ed25519 AAAA...");
                                       when set, any other key is refused
Credentials: username, and password or extra["ssh_private_key"].
"""

from __future__ import annotations

import asyncssh

from certfabric.plugins.base import BaseDevicePlugin, PluginError, PluginValidationResult

TIMEOUT_SECONDS = 30


class GenericSshHookPlugin(BaseDevicePlugin):
    plugin_id = "generic_ssh_hook"
    plugin_name = "Generic SSH hook"
    target_category = "generic"
    supported_models = ["Linux servers", "Unraid", "TrueNAS Core"]

    def _connect_kwargs(self) -> dict:
        creds = self.credentials
        if not creds.username:
            raise PluginError("SSH username is required")
        kwargs: dict = {
            "port": int(self.options.get("ssh_port", 22)),
            "username": creds.username,
            "connect_timeout": TIMEOUT_SECONDS,
        }
        if key := creds.extra.get("ssh_private_key"):
            kwargs["client_keys"] = [asyncssh.import_private_key(key)]
        elif creds.password:
            kwargs["password"] = creds.password
            kwargs["client_keys"] = None
        else:
            raise PluginError("An SSH password or private key is required")
        if host_key := self.options.get("ssh_host_key"):
            known = asyncssh.import_known_hosts(f"* {host_key}")
            kwargs["known_hosts"] = known
        else:
            kwargs["known_hosts"] = None
        return kwargs

    async def _connect(self) -> asyncssh.SSHClientConnection:
        kwargs = self._connect_kwargs()
        try:
            conn = await asyncssh.connect(self.host, **kwargs)
        except asyncssh.PermissionDenied:
            raise PluginError("SSH authentication failed") from None
        except asyncssh.HostKeyNotVerifiable:
            raise PluginError("SSH host key does not match the pinned ssh_host_key") from None
        except (OSError, asyncssh.Error) as exc:
            raise PluginError(f"SSH connection failed: {exc}") from None
        if "ssh_host_key" not in self.options:
            server_key = conn.get_server_host_key()
            fingerprint = server_key.get_fingerprint() if server_key else "unknown"
            self.log(f"Warning: SSH host key not pinned (server presented {fingerprint})")
        return conn

    async def test_connection(self) -> PluginValidationResult:
        try:
            conn = await self._connect()
        except PluginError as exc:
            return PluginValidationResult(success=False, message=str(exc))
        async with conn:
            return PluginValidationResult(success=True, message=f"SSH login as {self.credentials.username} succeeded")

    async def deploy_certificate(
        self, cert_pem: str, privkey_pem: str, fullchain_pem: str, pfx_bundle: bytes, pfx_password: str | None
    ) -> bool:
        files = {
            "cert_path": (cert_pem, 0o644),
            "key_path": (privkey_pem, 0o600),
            "fullchain_path": (fullchain_pem, 0o644),
        }
        targets = {opt: self.options[opt] for opt in files if self.options.get(opt)}
        if not targets:
            raise PluginError("Set at least one of cert_path, key_path or fullchain_path")
        async with await self._connect() as conn, conn.start_sftp_client() as sftp:
            for option, remote_path in targets.items():
                content, mode = files[option]
                async with sftp.open(remote_path, "w") as remote:
                    await remote.write(content)
                await sftp.chmod(remote_path, mode)
                self.log(f"Uploaded {option.removesuffix('_path')} to {remote_path}")
            if command := self.options.get("reload_command"):
                self.log(f"Running reload command: {command}")
                result = await conn.run(command, check=False, timeout=TIMEOUT_SECONDS)
                for stream in (result.stdout, result.stderr):
                    if stream:
                        self.log(str(stream).rstrip())
                if result.exit_status != 0:
                    raise PluginError(f"Reload command exited with status {result.exit_status}")
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        return await self.served_fingerprint() == expected_fingerprint
