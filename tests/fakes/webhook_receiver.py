"""A minimal HTTP server that records webhook POSTs."""

from __future__ import annotations

import asyncio
import json
from typing import Any


class WebhookReceiver:
    def __init__(self, status: int = 200, delay: float = 0.0) -> None:
        self.status = status
        self.delay = delay
        self.events: list[dict[str, Any]] = []
        self._server: asyncio.Server | None = None
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def of_type(self, event: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["event"] == event]

    async def start(self) -> WebhookReceiver:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            length = next(
                int(line.split(b":", 1)[1])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            self.events.append(json.loads(await reader.readexactly(length)))
            await asyncio.sleep(self.delay)
            writer.write(f"HTTP/1.1 {self.status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
