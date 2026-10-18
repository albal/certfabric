"""Fernet encryption for every secret CertFabric stores (ADR-0001)."""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class VaultError(Exception):
    """Raised when a stored secret cannot be decrypted with the current key."""


class Vault:
    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise VaultError("Secret cannot be decrypted with the current key") from None

    def encrypt_json(self, value: Any) -> str:
        return self.encrypt(json.dumps(value))

    def decrypt_json(self, token: str) -> Any:
        return json.loads(self.decrypt(token))
