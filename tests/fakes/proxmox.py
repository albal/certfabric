"""A simulated Proxmox VE node: the PVE API on its TLS port, plus SSH with `pvenode cert set`."""

from __future__ import annotations

import re
import secrets
from pathlib import Path

from tests.fakes.https_device import FakeHttpsDevice, Request, Response
from tests.fakes.ssh_device import FakeSshDevice

USERNAME = "root@pam"
PASSWORD = "pve-root-password-123"
TOKEN_USER = "root@pam!certfabric"
TOKEN_SECRET = "0b6e2f3c-1111-2222-3333-444455556666"
NODE = "pve1"


class FakeProxmox:
    def __init__(self, root: Path) -> None:
        (root / "tmp").mkdir(parents=True, exist_ok=True)
        self.https = FakeHttpsDevice(self._handle, "pve1.factory")
        self.ssh = FakeSshDevice(root, tls=self.https, command_handler=self._command)
        self.api_down = False
        self.restarts = 0
        self._tickets: set[str] = set()

    @property
    def host(self) -> str:
        return self.https.host

    @property
    def port(self) -> int:
        return self.https.port

    async def start(self) -> FakeProxmox:
        await self.ssh.start()  # also starts the HTTPS port
        return self

    async def stop(self) -> None:
        await self.ssh.stop()

    def _authorised(self, request: Request) -> bool:
        if request.headers.get("authorization") == f"PVEAPIToken={TOKEN_USER}={TOKEN_SECRET}":
            return True
        ticket = request.cookies().get("PVEAuthCookie")
        if ticket not in self._tickets:
            return False
        return request.method == "GET" or request.headers.get("csrfpreventiontoken") == "csrf-" + ticket

    async def _handle(self, request: Request) -> Response:
        if self.api_down:
            return Response(503)
        if request.path == "/api2/json/access/ticket" and request.method == "POST":
            form = request.form()
            if (form.get("username"), form.get("password")) != (USERNAME, PASSWORD):
                return Response(401)
            ticket = f"PVE:{USERNAME}:{secrets.token_hex(8)}"
            self._tickets.add(ticket)
            return Response.json({"data": {"ticket": ticket, "CSRFPreventionToken": "csrf-" + ticket, "username": USERNAME}})
        if not self._authorised(request):
            return Response(401)
        if request.path == "/api2/json/version":
            return Response.json({"data": {"version": "8.2.4", "release": "8.2"}})
        if request.path == "/api2/json/nodes":
            return Response.json({"data": [{"node": NODE, "status": "online"}]})
        if request.path == f"/api2/json/nodes/{NODE}/certificates/custom" and request.method == "POST":
            form = request.form()
            self._install(form["certificates"], form["key"])
            return Response.json({"data": [{"filename": "pveproxy-ssl.pem"}]})
        return Response(404)

    def _install(self, chain_pem: str, key_pem: str) -> None:
        self.restarts += 1
        self.https.present(chain_pem, key_pem)

    def _command(self, command: str) -> tuple[int, str]:
        match = re.match(r"pvenode cert set (\S+) (\S+) --force 1 --restart 1; ", command)
        if not match:
            return 127, f"{command}: not found\n"
        chain, key = (self.ssh.root / p.strip("'").lstrip("/") for p in match.groups())
        self._install(chain.read_text(), key.read_text())
        chain.unlink()
        key.unlink()
        return 0, "pveproxy restarted\n"
