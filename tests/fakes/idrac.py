"""A simulated Dell iDRAC: Redfish with basic auth; an imported cert is served after a reset."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tests.fakes.https_device import FakeHttpsDevice, Request, Response

USERNAME = "root"
PASSWORD = "calvin-but-longer-123"
MANAGER = "/redfish/v1/Managers/iDRAC.Embedded.1"
IMPORT = (
    "/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DelliDRACCardService/Actions/"
    "DelliDRACCardService.ImportSSLCertificate"
)


def _error(status: int, message: str) -> Response:
    return Response.json({"error": {"@Message.ExtendedInfo": [{"Message": message}]}}, status)


class FakeIdrac:
    def __init__(self) -> None:
        self.https = FakeHttpsDevice(self._handle, "idrac.factory")
        self.pending: tuple[str, str] | None = None
        self.resets = 0

    @property
    def host(self) -> str:
        return self.https.host

    @property
    def port(self) -> int:
        return self.https.port

    async def start(self) -> FakeIdrac:
        await self.https.start()
        return self

    async def stop(self) -> None:
        await self.https.stop()

    async def _handle(self, request: Request) -> Response:
        expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return Response(401)
        if request.path == MANAGER and request.method == "GET":
            return Response.json({"Model": "14G Monolithic", "FirmwareVersion": "7.00.00.171"})
        if request.path == IMPORT and request.method == "POST":
            body = request.json()
            if body.get("CertificateType") != "CustomCertificate":
                return _error(400, "Unsupported CertificateType")
            try:
                key, cert, chain = pkcs12.load_key_and_certificates(
                    base64.b64decode(body["SSLCertificateFile"]), body["Passphrase"].encode()
                )
            except (ValueError, KeyError):
                return _error(400, "Unable to import the certificate: invalid file or passphrase")
            pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()  # noqa: E731
            key_pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode()
            self.pending = (pem(cert) + "".join(pem(c) for c in chain), key_pem)
            return Response.json({"@Message.ExtendedInfo": [{"Message": "Certificate imported; reset iDRAC"}]})
        if request.path == f"{MANAGER}/Actions/Manager.Reset" and request.method == "POST":
            if json.loads(request.body).get("ResetType") != "GracefulRestart":
                return _error(400, "Invalid ResetType")
            self.resets += 1
            if self.pending:
                self.https.present(*self.pending)
                self.pending = None
            return Response(204)
        return Response(404)
