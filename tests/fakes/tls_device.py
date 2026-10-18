"""An in-process TLS server standing in for a Device. Tests change what it presents."""

from __future__ import annotations

import asyncio
import ssl
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from tests.fakes.certs import self_signed


class FakeTlsDevice:
    def __init__(self, common_name: str = "factory.local") -> None:
        self.host = "127.0.0.1"
        self.port = 0
        # Each certificate gets its own context, swapped in per handshake: loading a second
        # chain into one context keeps both (one per key type) and OpenSSL may pick the old one.
        self._current: ssl.SSLContext | None = None
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.sni_callback = self._select_context
        self._server: asyncio.Server | None = None
        self.cert_pem, self.key_pem = "", ""
        self.present(*self_signed(common_name, datetime.now(UTC)))

    def present(self, cert_pem: str, key_pem: str) -> None:
        """Serve this certificate to every new connection."""
        self.cert_pem, self.key_pem = cert_pem, key_pem
        with tempfile.TemporaryDirectory() as tmp:
            chain, key = Path(tmp, "chain.pem"), Path(tmp, "key.pem")
            chain.write_text(cert_pem)
            key.write_text(key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(chain, key)
            if self._current is None:
                self._context.load_cert_chain(chain, key)
            self._current = context

    def _select_context(self, ssl_object: ssl.SSLObject, _server_name: str | None, _context: ssl.SSLContext) -> None:
        ssl_object.context = self._current

    async def start(self) -> FakeTlsDevice:
        # A large backlog lets one fake stand in for hundreds of Devices probed at once.
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, ssl=self._context, backlog=1024
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        """Become unreachable. `start()` again brings the device back on the same port."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(1)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

