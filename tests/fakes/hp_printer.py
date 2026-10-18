"""A simulated HP LaserJet Pro EWS: session cookie + CSRF, rejects bundles carrying a chain."""

from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tests.fakes.https_device import FakeHttpsDevice, Request, Response

PASSWORD = "printer-admin-pass-42"


class FakeHpPrinter:
    def __init__(self, *, legacy_tls: bool = False) -> None:
        self.https = FakeHttpsDevice(self._handle, "HP-M283fdw", legacy_tls=legacy_tls)
        self._sessions: dict[str, str] = {}  # session id -> CSRF token
        self.uploads = 0

    @property
    def host(self) -> str:
        return self.https.host

    @property
    def port(self) -> int:
        return self.https.port

    async def start(self) -> FakeHpPrinter:
        await self.https.start()
        return self

    async def stop(self) -> None:
        await self.https.stop()

    async def _handle(self, request: Request) -> Response:
        expected = "Basic " + base64.b64encode(f"admin:{PASSWORD}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return Response(401, headers={"WWW-Authenticate": 'Basic realm="HP"'})
        if request.path == "/Security/Certificates" and request.method == "GET":
            session, token = secrets.token_hex(8), secrets.token_hex(12)
            self._sessions[session] = token
            html = f'<html><form><input type="hidden" name="CSRFToken" value="{token}"/></form></html>'
            return Response(200, html.encode(), {"Set-Cookie": f"sid={session}; Path=/; Secure", "Content-Type": "text/html"})
        if request.path == "/Security/Certificates/Import" and request.method == "POST":
            form = request.form()
            if self._sessions.get(request.cookies().get("sid", "")) != form.get("CSRFToken"):
                return Response(403, b"CSRF check failed")
            try:
                key, cert, chain = pkcs12.load_key_and_certificates(form["certificate"], form["password"].encode())
            except (ValueError, KeyError):
                return Response(400, b"Invalid certificate file or password")
            if chain:
                return Response(400, b"Certificate chains are not supported")
            self.uploads += 1
            key_pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode()
            self.https.present(cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem)
            return Response(200, b"<html>Certificate imported</html>")
        return Response(404)
