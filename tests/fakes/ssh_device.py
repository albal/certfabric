"""A simulated Linux server: SSH/SFTP into a temp directory, plus a TLS port.

Running the command `reload-tls` makes the TLS port serve whatever certificate and key
were uploaded to /etc/tls/cert.pem and /etc/tls/key.pem.
"""

from __future__ import annotations

from pathlib import Path

import asyncssh

from tests.fakes.tls_device import FakeTlsDevice

USERNAME = "deploy"
PASSWORD = "ssh-password-0123456789"
RELOAD_COMMAND = "reload-tls"


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == USERNAME and password == PASSWORD


class FakeSshDevice:
    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "etc" / "tls").mkdir(parents=True, exist_ok=True)
        self.tls = FakeTlsDevice("linux.factory")
        self.host = "127.0.0.1"
        self.ssh_port = 0
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.commands: list[str] = []
        self._server: asyncssh.SSHAcceptor | None = None

    @property
    def public_host_key(self) -> str:
        return self.host_key.export_public_key().decode().strip()

    async def start(self) -> FakeSshDevice:
        await self.tls.start()
        self._server = await asyncssh.create_server(
            _Server,
            self.host,
            0,
            server_host_keys=[self.host_key],
            sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(self.root).encode()),
            process_factory=self._handle_command,
        )
        self.ssh_port = self._server.sockets[0].getsockname()[1]
        return self

    async def _handle_command(self, process: asyncssh.SSHServerProcess) -> None:
        self.commands.append(process.command or "")
        if process.command == RELOAD_COMMAND:
            tls_dir = self.root / "etc" / "tls"
            self.tls.present((tls_dir / "cert.pem").read_text(), (tls_dir / "key.pem").read_text())
            process.stdout.write("tls reloaded\n")
            process.exit(0)
        else:
            process.stderr.write(f"{process.command}: command not found\n")
            process.exit(127)

    def options(self, **extra: object) -> dict:
        return {
            "ssh_port": self.ssh_port,
            "cert_path": "/etc/tls/cert.pem",
            "key_path": "/etc/tls/key.pem",
            "fullchain_path": "/etc/tls/fullchain.pem",
            "reload_command": RELOAD_COMMAND,
            **extra,
        }

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        await self.tls.stop()
