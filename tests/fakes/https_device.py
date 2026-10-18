"""A minimal HTTPS server on top of FakeTlsDevice, for simulating device web APIs.

Each test simulator supplies a handler; the TLS port can switch certificate at any time,
which is how simulators "install" what a Plugin uploads.
"""

from __future__ import annotations

import asyncio
import email.parser
import email.policy
import json
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from tests.fakes.tls_device import FakeTlsDevice


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    def form(self) -> dict[str, Any]:
        """urlencoded fields as str; multipart fields as str, or bytes for file parts."""
        content_type = self.headers.get("content-type", "")
        if content_type.startswith("multipart/form-data"):
            message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                f"Content-Type: {content_type}\r\n\r\n".encode() + self.body
            )
            fields: dict[str, Any] = {}
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                payload = part.get_payload(decode=True)
                fields[name] = payload if part.get_filename() else payload.decode()
            return fields
        return {k: v[0] for k, v in parse_qs(self.body.decode()).items()}

    def cookies(self) -> dict[str, str]:
        jar = {}
        for pair in self.headers.get("cookie", "").split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                jar[k] = v
        return jar


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(cls, data: Any, status: int = 200, **headers: str) -> Response:
        return cls(status, json.dumps(data).encode(), {"Content-Type": "application/json", **headers})


Handler = Callable[[Request], Awaitable[Response]]


class FakeHttpsDevice(FakeTlsDevice):
    def __init__(self, handler: Handler, common_name: str = "device.factory", *, legacy_tls: bool = False) -> None:
        super().__init__(common_name, legacy_tls=legacy_tls)
        self.handler = handler
        self.requests: list[Request] = []

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                request_line, *lines = head.decode("latin-1").split("\r\n")
                method, target, _ = request_line.split(" ", 2)
                headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines if ":" in l)}
                body = await reader.readexactly(int(headers.get("content-length", 0)))
                url = urlsplit(target)
                request = Request(method, url.path, {k: v[0] for k, v in parse_qs(url.query).items()}, headers, body)
                self.requests.append(request)
                response = await self.handler(request)
                reason = "OK" if response.status < 400 else "Error"
                out = [f"HTTP/1.1 {response.status} {reason}", f"Content-Length: {len(response.body)}"]
                out += [f"{k}: {v}" for k, v in response.headers.items()]
                writer.write(("\r\n".join(out) + "\r\n\r\n").encode() + response.body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
