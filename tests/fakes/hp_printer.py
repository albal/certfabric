"""A simulated HP LaserJet Pro EmWeb interface, modelled on a real M283fdw.

It follows the printer's certificate wizard (Configure > Import > upload to
/hp/device/Certificate.pfx), rejects uploads that skip the wizard, passphrases over 16
characters, wrong passphrases and bundles that carry a chain. With `admin_password` set
it demands HTTP basic auth; the real printer this was modelled on had none.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from tests.fakes.https_device import FakeHttpsDevice, Request, Response

PASSWORD = "printer-admin-pass-42"

CERTS_PAGE = """<html><head><title>HP Color LaserJet MFP M283fdw&nbsp;&nbsp;&nbsp;192.168.0.208</title></head>
<body><FORM method="post" ACTION="/hp/device/set_config_networkCerts.html/config">
<INPUT type="submit" name="ViewPrintCert" VALUE="View"><INPUT type="submit" name="ConfigurePrintCert" VALUE="Configure">
</FORM></body></html>"""
IMPORT_FORM = """<html><body><FORM method="post" enctype="multipart/form-data" ACTION="Certificate.pfx">
<INPUT type="file" name="FileName" id="FileName"><INPUT type="password" name="Password" maxlength="16">
<INPUT type="submit" name="Finish" id="Finish" value=""></FORM></body></html>"""


def _see_other(location: str) -> Response:
    return Response(303, b"", {"Location": location})


class FakeHpPrinter:
    def __init__(self, *, legacy_tls: bool = False, admin_password: str | None = PASSWORD) -> None:
        self.https = FakeHttpsDevice(self._handle, "HP-M283fdw", legacy_tls=legacy_tls)
        self.admin_password = admin_password
        self.step = "idle"  # idle -> configure -> import
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
        if self.admin_password:
            expected = "Basic " + base64.b64encode(f"admin:{self.admin_password}".encode()).decode()
            if request.headers.get("authorization") != expected:
                return Response(401, headers={"WWW-Authenticate": 'Basic realm="HP"'})
        route = (request.method, request.path)
        if route == ("GET", "/hp/device/set_config_networkCerts.html"):
            return Response(200, CERTS_PAGE.encode(), {"Content-Type": "text/html"})
        if route == ("POST", "/hp/device/set_config_networkCerts.html/config"):
            if request.form().get("ConfigurePrintCert") != "Configure":
                return Response(400)
            self.step = "configure"
            return _see_other("/hp/device/set_config_networkPrintCerts.html?tab=Networking&amp;menu=NetCertCreateCR")
        if route == ("POST", "/hp/device/set_config_networkPrintCerts.html/config"):
            form = request.form()
            if self.step != "configure" or form.get("ConfigOpt") != "ImptCert" or "Next" not in form:
                return Response(400)
            self.step = "import"
            return _see_other("/hp/device/set_config_networkCertsImport.html?tab=Networking&amp;menu=NetCertImport")
        if route == ("GET", "/hp/device/set_config_networkCertsImport.html"):
            return Response(200, IMPORT_FORM.encode(), {"Content-Type": "text/html"})
        if route == ("POST", "/hp/device/set_config_networkCertsImport.html/config"):
            self.step = "idle"
            return _see_other("/hp/device/set_config_networkCerts.html?tab=Networking&amp;menu=NetCerts")
        if route == ("POST", "/hp/device/Certificate.pfx"):
            return self._upload(request)
        return Response(404)

    def _upload(self, request: Request) -> Response:
        if self.step != "import":
            return Response(400, b"Certificate wizard not started")
        form = request.form()
        password = form.get("Password", "")
        if form.get("Finish") != "Finish" or not password or len(password) > 16:
            return Response(400, b"Invalid form")
        try:
            key, cert, chain = pkcs12.load_key_and_certificates(form["FileName"], password.encode())
        except (ValueError, KeyError):
            return Response(400, b"Invalid certificate file or password")
        if chain:
            return Response(400, b"Certificate chains are not supported")
        self.step = "idle"
        self.uploads += 1
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        self.https.present(cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem)
        return _see_other("/hp/device/set_config_networkCerts.html?tab=Networking&amp;menu=NetCerts")
