import os
import sqlite3

import pytest
from cryptography.fernet import Fernet

from certfabric.cli import main
from certfabric.config import ConfigError, load_settings
from certfabric.db import migrate
from certfabric.vault import Vault, VaultError


def test_refuses_to_start_without_secret_key():
    with pytest.raises(ConfigError, match="No secret key"):
        load_settings({})


def test_refuses_invalid_secret_key():
    with pytest.raises(ConfigError, match="not a valid"):
        load_settings({"CERTFABRIC_SECRET_KEY": "not-a-key"})


def test_cli_serve_exits_nonzero_without_key(monkeypatch, capsys):
    monkeypatch.delenv("CERTFABRIC_SECRET_KEY", raising=False)
    monkeypatch.delenv("CERTFABRIC_SECRET_KEY_FILE", raising=False)
    assert main(["serve"]) == 1
    assert "No secret key" in capsys.readouterr().err


def test_key_from_environment():
    key = Fernet.generate_key()
    assert load_settings({"CERTFABRIC_SECRET_KEY": key.decode()}).secret_key == key


def test_key_file_must_be_private(tmp_path):
    path = tmp_path / "key"
    path.write_bytes(Fernet.generate_key())
    os.chmod(path, 0o644)
    with pytest.raises(ConfigError, match="chmod 0400"):
        load_settings({"CERTFABRIC_SECRET_KEY_FILE": str(path)})


def test_key_file_with_0400(tmp_path):
    path = tmp_path / "key"
    key = Fernet.generate_key()
    path.write_bytes(key + b"\n")
    os.chmod(path, 0o400)
    assert load_settings({"CERTFABRIC_SECRET_KEY_FILE": str(path)}).secret_key == key


def test_vault_round_trip_and_wrong_key():
    vault = Vault(Fernet.generate_key())
    token = vault.encrypt_json({"token": "s3cret"})
    assert "s3cret" not in token
    assert vault.decrypt_json(token) == {"token": "s3cret"}
    with pytest.raises(VaultError):
        Vault(Fernet.generate_key()).decrypt(token)


def test_migrations_create_schema_in_wal_mode_and_are_idempotent(tmp_path):
    db_path = tmp_path / "cf.db"
    migrate(db_path)
    migrate(db_path)
    conn = sqlite3.connect(db_path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"admin_user", "sessions", "alembic_version"} <= tables
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
