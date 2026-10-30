"""A simulated Synology DSM: the web API on its TLS port, serving the certificate bound to the system service.

As on a real NAS, being the default certificate moves no services: they stay where they are bound.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field

from tests.fakes.https_device import FakeHttpsDevice, Request, Response

USERNAME = "certfabric"
PASSWORD = "dsm-admin-password-123"
TWO_FACTOR_USERNAME = "admin-2fa"
PLAIN_USERNAME = "not-an-admin"
FACTORY_ID = "FaCtOrY"
FACTORY_DESC = "synology.factory"


SYSTEM_SERVICE = {
    "display_name": "DSM Desktop Service",
    "display_name_i18n": "common:web_desktop",
    "isPkg": False,
    "multiple_cert": True,
    "owner": "root",
    "service": "default",
    "subscriber": "system",
    "user_setable": True,
}
FTPS_SERVICE = {**SYSTEM_SERVICE, "display_name": "FTPS", "service": "ftpd", "subscriber": "smbftpd"}
FIXED_SERVICE = {**SYSTEM_SERVICE, "display_name": "Fixed", "service": "fixed", "user_setable": False}

# What DSM's nginx serves on ports 80 and 443 for any path, whatever the request.
REDIRECT_PAGE = b"""<!DOCTYPE html>
<html>
    <body>
        <input type="hidden" id="http" name="http" value="5000">
        <input type="hidden" id="https" name="https" value="5001">
        <input type="hidden" id="prefer_https" name="prefer_https" value="true">
    </body>
</html>
"""


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
    services: list[dict] = field(default_factory=list)
    common_name: str = ""


class FakeSynology:
    def __init__(self) -> None:
        self.https = FakeHttpsDevice(self._handle, FACTORY_DESC)
        self.certificates: list[StoredCertificate] = []
        self.logins = 0
        self.import_error: int | None = None
        self.service_error: int | None = None
        self.service_sets = 0
        self.not_dsm = False
        self.redirect_only = False
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
        factory = StoredCertificate(
            FACTORY_ID, FACTORY_DESC, True, self.https.cert_pem, self.https.key_pem, services=[SYSTEM_SERVICE, FTPS_SERVICE]
        )
        self.certificates.append(factory)
        return self

    async def stop(self) -> None:
        await self.https.stop()

    def add_certificate(self, id: str, desc: str) -> None:
        self.certificates.append(StoredCertificate(id, desc, False, "", ""))

    def bind_services_elsewhere(self, id: str, desc: str, *extra_services: dict) -> None:
        """Move every service to a separate, non-default certificate, which keeps being served."""
        factory = self.by_id(FACTORY_ID)
        self.certificates.append(
            StoredCertificate(id, desc, False, factory.cert_pem, factory.key_pem, services=[*factory.services, *extra_services])
        )
        factory.services = []

    def by_id(self, id: str) -> StoredCertificate:
        return next(c for c in self.certificates if c.id == id)

    def service_names(self, id: str) -> list[str]:
        return [service["display_name"] for service in self.by_id(id).services]

    def _serve_system_certificate(self) -> None:
        bound = next(c for c in self.certificates if SYSTEM_SERVICE in c.services)
        self.https.present(bound.cert_pem + bound.inter_pem, bound.key_pem)

    async def _handle(self, request: Request) -> Response:
        if self.not_dsm:
            return Response(404)
        if self.redirect_only:
            return Response(200, REDIRECT_PAGE, {"Content-Type": "text/html"})
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
        if api == "SYNO.Core.Certificate.Service":
            return self._set_services(request)
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

    def _authenticated(self, request: Request, sid: str | None) -> bool:
        """DSM answers 119 unless a session's calls carry its SynoToken in this header."""
        token = self._sessions.get(sid or "")
        return bool(token) and request.headers.get("x-syno-token") == token

    def _list(self, request: Request) -> Response:
        sid = request.form().get("_sid")
        if not self._authenticated(request, sid):
            return error(119)
        if self._sessions[sid] == "plain":
            return error(105)
        return ok(
            {
                "certificates": [
                    {
                        "id": c.id,
                        "desc": c.desc,
                        "is_default": c.is_default,
                        "services": c.services,
                        "subject": {"common_name": c.common_name},
                    }
                    for c in self.certificates
                ]
            }
        )

    def _import(self, request: Request) -> Response:
        sid = request.query.get("_sid")
        if not self._authenticated(request, sid) or request.query.get("SynoToken") != self._sessions[sid]:
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
        self._serve_system_certificate()
        return ok({"id": stored.id, "restart_httpd": True})

    def _set_services(self, request: Request) -> Response:
        form = request.form()
        if not self._authenticated(request, form.get("_sid")):
            return error(119)
        if self.service_error is not None:
            return error(self.service_error)
        self.service_sets += 1
        for setting in json.loads(form["settings"]):
            old, new, service = self.by_id(setting["old_id"]), self.by_id(setting["id"]), setting["service"]
            # DSM 6 drops a service "moved" to the certificate it is already on.
            assert old is not new and service in old.services and service.get("user_setable", True)
            old.services.remove(service)
            new.services.append(service)
        self._serve_system_certificate()
        return ok({"restart_httpd": True})
