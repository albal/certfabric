"""A simulated Dell iDRAC: an imported cert is served after a reset.

A 14G+ iDRAC (9/10) imports a PKCS#12 bundle over Redfish. A 13G iDRAC 8 has no Redfish
certificate import and instead takes the key and chain over the remote RACADM protocol, as
observed on a T630 running 2.86.86.86.
"""

from __future__ import annotations

import base64
import html
import json
import re
import secrets
import struct

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


def _racadm(tag: str, **fields: str) -> Response:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return Response(200, f'<?xml version="1.0" encoding="UTF-8"?><{tag}><RESP>{inner}</RESP></{tag}>'.encode())


class FakeIdrac:
    def __init__(self, *, legacy_tls: bool = False, model: str = "14G Monolithic") -> None:
        self.https = FakeHttpsDevice(self._handle, "idrac.factory", legacy_tls=legacy_tls)
        self.model = model
        self.pending: tuple[str, str] | None = None
        self.resets = 0
        # remote RACADM state (iDRAC 8)
        self.sessions: set[str] = set()
        self.staged: bytes | None = None
        self.pending_key: str | None = None
        self.pending_chain: str | None = None
        # iDRAC.WebServer.ManualDNSEntry: extra names the Host header check accepts
        self.manual_dns_entry = ""
        self.refuse_settings = False

    @property
    def racadm(self) -> bool:
        return int(self.model.split("G")[0]) < 14

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
        if request.path.startswith("/cgi-bin/") and self.racadm:
            return self._handle_racadm(request)
        expected = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
        if request.headers.get("authorization") != expected:
            return Response(401)
        if request.path == MANAGER and request.method == "GET":
            firmware = "2.86.86.86" if self.racadm else "7.00.00.171"
            return Response.json({"Model": self.model, "FirmwareVersion": firmware})
        if request.path == f"{MANAGER}/Attributes" and not self.racadm:
            if request.method == "PATCH":
                self.manual_dns_entry = request.json()["Attributes"]["WebServer.1.ManualDNSEntry"]
                return Response(200)
            return Response.json({"Attributes": {"WebServer.1.ManualDNSEntry": self.manual_dns_entry}})
        if request.path == IMPORT and request.method == "POST":
            if self.racadm:
                return _error(405, "Unable to run the method because the requested HTTP method is not allowed.")
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
            if self.pending_key and self.pending_chain:
                self.pending = (self.pending_chain, self.pending_key)
                self.pending_key = self.pending_chain = None
            if self.pending:
                self.https.present(*self.pending)
                self.pending = None
            return Response(204)
        return Response(404)

    def _handle_racadm(self, request: Request) -> Response:
        body = request.body.decode(errors="replace")
        if request.path == "/cgi-bin/login":
            username = re.search(r"<USERNAME>(.*?)</USERNAME>", body)
            password = re.search(r"<PASSWORD>(.*?)</PASSWORD>", body)
            if not (username and password and (username[1], password[1]) == (USERNAME, PASSWORD)):
                return _racadm("LOGIN", RC="0x10", SID="", STATENAME="SESSION_INVALID")
            sid = secrets.token_urlsafe(12)
            self.sessions.add(sid)
            return _racadm("LOGIN", RC="0x0", SID=sid, STATENAME="OK")
        sid = request.cookies().get("sid")
        if request.path == "/cgi-bin/logout":
            self.sessions.discard(sid)
            return Response(200)
        if sid not in self.sessions:
            return Response(200, struct.pack("<I", 1))
        if request.path == "/cgi-bin/putfile":
            name, length, flag = struct.unpack("<32sIB3x", request.body[:40])
            if name.rstrip(b"\0") != b"RACSSLCERT1" or flag != 0 or len(request.body) != 40 + length:
                return Response(200, struct.pack("<I", 2))
            self.staged = request.body[40:]
            return Response(200, struct.pack("<I", 0))
        if request.path == "/cgi-bin/exec":
            command = html.unescape(re.search(r"<CMDINPUT>(.*?)</CMDINPUT>", body)[1])
            if command == "racadm get iDRAC.WebServer.ManualDNSEntry":
                output = f"[Key=iDRAC.Embedded.1#WebServer.1]\r\nManualDNSEntry={self.manual_dns_entry}"
                return _racadm("EXEC", RC="0x0", CMDRC="0x0", CMDOUTPUT=output)
            set_entry = re.fullmatch(r'racadm set iDRAC.WebServer.ManualDNSEntry "(.*)"', command)
            if set_entry and not self.refuse_settings:
                self.manual_dns_entry = set_entry[1]
                return _racadm("EXEC", RC="0x0", CMDRC="0x0", CMDOUTPUT="Object value modified successfully")
            staged, self.staged = (self.staged or b"").decode(), None
            if command == "racadm sslkeyupload -f sslcertfile -t 1" and "PRIVATE KEY-----" in staged:
                self.pending_key = staged
                return _racadm("EXEC", RC="0x0", CMDRC="0x0", CMDOUTPUT="SSL key successfully uploaded to the RAC.")
            if command == "racadm sslcertupload -f sslcertfile -t 1" and "BEGIN CERTIFICATE" in staged:
                self.pending_chain = staged
                return _racadm("EXEC", RC="0x0", CMDRC="0x0", CMDOUTPUT="Certificate successfully uploaded to the RAC.")
            return _racadm("EXEC", RC="0x0", CMDRC="0x2", CMDOUTPUT="ERROR: Unable to allocate memory for operation.")
        return Response(404)
