"""Re-encrypt every stored secret under a new secret key, all or nothing.

Run it with CertFabric stopped: the server holds the old key in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import create_engine, text

from certfabric.db import migrate
from certfabric.vault import Vault, VaultError

# (table, primary key, encrypted column)
ENCRYPTED_COLUMNS = (
    ("dns_providers", "id", "encrypted_credentials"),
    ("devices", "id", "encrypted_credentials"),
    ("certificates", "id", "privkey_pem_encrypted"),
)


class RotationError(Exception):
    pass


@dataclass(frozen=True)
class RotationResult:
    rows: int


def rotate(db_path: Path, old_key: bytes, new_key: bytes) -> RotationResult:
    if old_key == new_key:
        raise RotationError("The new key is the same as the current key")
    migrate(db_path)
    old, new = Vault(old_key), Vault(new_key)
    engine = create_engine(f"sqlite:///{db_path}")
    rows = 0
    try:
        # One transaction: either every secret moves to the new key or none does.
        with engine.begin() as conn:
            for table, pk, column in ENCRYPTED_COLUMNS:
                found = conn.execute(text(f"SELECT {pk}, {column} FROM {table} WHERE {column} IS NOT NULL")).all()
                for row_id, token in found:
                    try:
                        plaintext = old.decrypt(token)
                    except VaultError:
                        raise RotationError(
                            f"{table} {row_id} cannot be decrypted with the current key; nothing was changed"
                        ) from None
                    conn.execute(
                        text(f"UPDATE {table} SET {column} = :value WHERE {pk} = :id"),
                        {"value": new.encrypt(plaintext), "id": row_id},
                    )
                    rows += 1
    finally:
        engine.dispose()
    return RotationResult(rows)
