"""AcmeRunner: the only code that runs `acme.sh`.

Arguments are always passed as an array (never through a shell) and every domain is
validated first. Each run gets a throwaway `--home`, because `acme.sh` saves DNS
credentials in plaintext to its config; deleting it keeps secrets encrypted at rest only.
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

KeyType = Literal["RSA2048", "ECDSA_P256"]
KEY_LENGTH: dict[str, str] = {"RSA2048": "2048", "ECDSA_P256": "ec-256"}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"^(?:\*\.)?(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_DNS_TYPE = re.compile(r"^dns_[a-z0-9_]+$")
_SERVER = re.compile(r"^(letsencrypt|letsencrypt_test|zerossl|https://[A-Za-z0-9./:_-]+)$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ISSUE_TIMEOUT_SECONDS = 15 * 60


class AcmeError(Exception):
    """`acme.sh` was refused or failed; the message is safe to show the admin once redacted."""


def validate_domain(domain: str) -> str:
    normalised = domain.strip().lower().rstrip(".")
    if len(normalised) > 253 or not _DOMAIN.match(normalised):
        raise ValueError(f"{domain!r} is not a valid domain name")
    return normalised


@dataclass(frozen=True)
class IssuedFiles:
    cert_pem: str
    key_pem: str
    fullchain_pem: str


class AcmeRunner:
    def __init__(self, acme_sh: str) -> None:
        self._acme_sh = acme_sh

    async def issue(
        self,
        *,
        domains: list[str],
        dns_type: str,
        credentials: dict[str, str],
        key_type: KeyType,
        server: str,
        on_output: Callable[[str], None],
    ) -> IssuedFiles:
        domains = [validate_domain(d) for d in domains]
        if not domains:
            raise AcmeError("At least one domain is required")
        if not _DNS_TYPE.match(dns_type):
            raise AcmeError(f"{dns_type!r} is not a valid DNS type")
        if not _SERVER.match(server):
            raise AcmeError(f"{server!r} is not a valid ACME server")
        if any(not _ENV_NAME.match(k) for k in credentials):
            raise AcmeError("Invalid credential name")

        with tempfile.TemporaryDirectory(prefix="certfabric-acme-") as tmp:
            home = Path(tmp)
            out = {name: home / f"{name}.pem" for name in ("cert", "key", "fullchain")}
            args = [
                "--issue",
                "--dns", dns_type,
                *[arg for d in domains for arg in ("-d", d)],
                "--keylength", KEY_LENGTH[key_type],
                "--server", server,
                "--home", str(home),
                "--cert-file", str(out["cert"]),
                "--key-file", str(out["key"]),
                "--fullchain-file", str(out["fullchain"]),
                "--force",
            ]  # fmt: skip
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **credentials}
            await self._run(args, env, on_output)
            try:
                return IssuedFiles(*(out[name].read_text() for name in ("cert", "key", "fullchain")))
            except FileNotFoundError:
                raise AcmeError("acme.sh finished but did not write the certificate files") from None

    async def _run(self, args: list[str], env: dict[str, str], on_output: Callable[[str], None]) -> None:
        try:
            process = await asyncio.create_subprocess_exec(
                self._acme_sh, *args,
                env=env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )  # fmt: skip
        except FileNotFoundError:
            raise AcmeError(f"acme.sh not found at {self._acme_sh!r}") from None
        assert process.stdout is not None
        tail: list[str] = []

        async def pump() -> None:
            async for raw in process.stdout:  # type: ignore[union-attr]
                line = raw.decode(errors="replace").rstrip("\n")
                on_output(line)
                tail[:] = (tail + [line])[-5:]

        try:
            await asyncio.wait_for(asyncio.gather(pump(), process.wait()), ISSUE_TIMEOUT_SECONDS)
        except TimeoutError:
            process.kill()
            raise AcmeError("acme.sh timed out") from None
        if process.returncode != 0:
            raise AcmeError(f"acme.sh exited with code {process.returncode}: " + " | ".join(tail))
