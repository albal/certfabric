"""Masks secrets in log output before it is stored or streamed."""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL
)
_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_KEY_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_MIN_SECRET_LENGTH = 4


class Redactor:
    """Replaces every known secret, and any PEM private key block, with a marker."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        self._secrets: set[str] = set()
        self._in_key_block = False
        self.add(secrets)

    def add(self, secrets: Iterable[str]) -> None:
        self._secrets.update(s for s in secrets if s and len(s) >= _MIN_SECRET_LENGTH)

    def redact(self, text: str) -> str:
        text = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
        # Longest first, so a secret containing another is masked whole.
        for secret in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(secret, REDACTED)
        return text

    def redact_line(self, line: str) -> str | None:
        """Redact one line of streamed output. Lines inside a private key block are dropped."""
        if self._in_key_block:
            if _KEY_END.search(line):
                self._in_key_block = False
            return None
        if _KEY_BEGIN.search(line) and not _KEY_END.search(line):
            self._in_key_block = True
            return REDACTED
        return self.redact(line)
