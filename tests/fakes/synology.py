"""A simulated Synology DSM: the web API on its TLS port, serving whichever certificate is the default."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from tests.fakes.https_device import FakeHttpsDevice, Request, Response

USERNAME = "certfabric"
PASSWORD = "dsm-admin-password-123"
TWO_FACTOR_USERNAME = "admin-2fa"
PLAIN_USERNAME = "not-an-admin"
FACTORY_ID = "FaCtOrY"
FACTORY_DESC = "synology.factory"


def error(code: int) -> Response:
    return Response.json({"success": False, "error": {"code": code}})


def ok(data: dict | None = None) -> Response:
    return Response.json({"success": True, "data": data or {}})


@dataclass
class StoredCertificate:
    id: str
    desc: str
    is_default: bool
    cert_pem: str
    key_pem: str
    inter_pem: str = ""


class FakeSynology:
    def __init__(self) -> None:
        self.https = FakeHttpsDevice(self._handle, FACTORY_DESC)
        self.certificates: list[StoredCertificate] = []
        self.logins = 0
        self.import_error: int | None = None
        self.not_dsm = False
        self.fail_logout = False
        self._sessions: dict[str, str] = {}  # sid -> SynoToken

    @property
    def host(self) -> str:
        return self.https.host

    @property
    def port(self) -> int:
        return self.https.port

    @property
    def open_sessions(self) -> int:
        return len(self._sessions)

    async def start(self) -> FakeSynology:
        await self.https.start()
        factory = StoredCertificate(FACTORY_ID, FACTORY_DESC, True, self.https.cert_pem, self.https.key_pem)
        self.certificates.append(factory)
        return self

    async def stop(self) -> None:
        await self.https.stop()

    def add_certificate(self, id: str, desc: str) -> None:
        self.certificates.append(StoredCertificate(id, desc, False, "", ""))

    def by_id(self, id: str) -> StoredCertificate:
        return next(c for c in self.certificates if c.id == id)

    async def _handle(self, request: Request) -> Response:
        if self.not_dsm:
            return Response(404)
        if request.path == "/webapi/query.cgi":
            return ok({"SYNO.API.Auth": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 7}})
        if request.path != "/webapi/entry.cgi":
            return Response(404)
        api = request.query.get("api") or request.form().get("api")
        if api == "SYNO.API.Auth":
            return self._auth(request)
        if api == "SYNO.Core.Certificate.CRT":
            return self._list(request)
        if api == "SYNO.Core.Certificate":
            return self._import(request)
        return error(102)

    def _auth(self, request: Request) -> Response:
        if request.query.get("method") == "logout":
            if self.fail_logout:
                raise ConnectionError("web server restarting")
            self._sessions.pop(request.query["_sid"], None)
            return ok()
        form = request.form()
        assert request.method == "POST" and "passwd" not in request.query
        self.logins += 1
        if form["account"] == TWO_FACTOR_USERNAME:
            return error(403)
        if form["account"] not in (USERNAME, PLAIN_USERNAME) or form["passwd"] != PASSWORD:
            return error(400)
        sid = secrets.token_hex(8)
        self._sessions[sid] = secrets.token_hex(8) if request.query.get("enable_syno_token") == "yes" else ""
        if form["account"] == PLAIN_USERNAME:
            self._sessions[sid] = "plain"
        return ok({"sid": sid, "synotoken": self._sessions[sid]})

    def _list(self, request: Request) -> Response:
        sid = request.form().get("_sid")
        if sid not in self._sessions:
            return error(119)
        if self._sessions[sid] == "plain":
            return error(105)
        return ok(
            {"certificates": [{"id": c.id, "desc": c.desc, "is_default": c.is_default} for c in self.certificates]}
        )

    def _import(self, request: Request) -> Response:
        token = self._sessions.get(request.query.get("_sid", ""))
        if not token or request.query.get("SynoToken") != token:
            return error(119)
        if self.import_error is not None:
            return error(self.import_error)
        form = request.form()
        if form["id"]:
            stored = self.by_id(form["id"])
            stored.desc = form["desc"]
        else:
            stored = StoredCertificate(secrets.token_hex(3), form["desc"], False, "", "")
            self.certificates.append(stored)
        stored.key_pem = form["key"].decode()
        stored.cert_pem = form["cert"].decode()
        stored.inter_pem = form.get("inter_cert", b"").decode()
        if form.get("as_default") == "true":
            for certificate in self.certificates:
                certificate.is_default = certificate is stored
        default = next(c for c in self.certificates if c.is_default)
        self.https.present(default.cert_pem + default.inter_pem, default.key_pem)
        return ok({"id": stored.id, "restart_httpd": True})
