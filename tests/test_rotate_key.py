import sqlite3

import pytest
from cryptography.fernet import Fernet

from certfabric.cli import main
from certfabric.keyrotation import ENCRYPTED_COLUMNS, RotationError, rotate
from certfabric.vault import Vault, VaultError
from tests.conftest import CF_TOKEN, DEVICE_PASSWORD, create_device, issue_certificate


def secrets_in(db_path):
    conn = sqlite3.connect(db_path)
    return [
        token
        for table, _, column in ENCRYPTED_COLUMNS
        for (token,) in conn.execute(f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL")
    ]


@pytest.fixture
async def populated(client, tls_device, settings):
    """A database holding every kind of secret: DNS credentials, Device credentials, a private key."""
    cert = await issue_certificate(client, ["printer.lan.example.com"])
    await create_device(client, tls_device, sni="printer.lan.example.com", certificate_id=cert["id"])
    assert len(secrets_in(settings.db_path)) == 3
    return settings


async def test_rotation_moves_every_secret_to_the_new_key(populated):
    settings = populated
    new_key = Fernet.generate_key()
    result = rotate(settings.db_path, settings.secret_key, new_key)
    assert result.rows == 3
    old, new = Vault(settings.secret_key), Vault(new_key)
    plaintexts = [new.decrypt(token) for token in secrets_in(settings.db_path)]
    assert any(CF_TOKEN in p for p in plaintexts)
    assert any(DEVICE_PASSWORD in p for p in plaintexts)
    assert any("PRIVATE KEY" in p for p in plaintexts)
    for token in secrets_in(settings.db_path):
        with pytest.raises(VaultError):
            old.decrypt(token)


async def test_rotation_is_all_or_nothing(populated):
    settings = populated
    # One secret that the current key cannot read, encountered after others were re-encrypted.
    stray = Vault(Fernet.generate_key()).encrypt("{}")
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE certificates SET privkey_pem_encrypted = ?", (stray,))
    conn.commit()
    before = secrets_in(settings.db_path)
    with pytest.raises(RotationError, match="nothing was changed"):
        rotate(settings.db_path, settings.secret_key, Fernet.generate_key())
    assert secrets_in(settings.db_path) == before
    old = Vault(settings.secret_key)
    old.decrypt(before[0])  # DNS credentials still readable with the old key


async def test_cli_with_new_key_file_then_server_starts_with_it(populated, monkeypatch, tmp_path, clock):
    import httpx

    from certfabric.app import create_app
    from tests.conftest import ADMIN_PASSWORD, BASE_URL

    settings = populated
    new_key = Fernet.generate_key()
    key_file = tmp_path / "new.key"
    key_file.write_bytes(new_key)
    monkeypatch.setenv("CERTFABRIC_SECRET_KEY", settings.secret_key.decode())
    monkeypatch.setenv("CERTFABRIC_DB_PATH", str(settings.db_path))
    assert main(["rotate-key", "--new-key-file", str(key_file)]) == 0

    from dataclasses import replace

    restarted = create_app(replace(settings, secret_key=new_key), clock)
    async with restarted.router.lifespan_context(restarted):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url=BASE_URL) as client:
            await client.post("/api/auth/login", json={"password": ADMIN_PASSWORD})
            providers = (await client.get("/api/dns-providers")).json()
            assert providers[0]["credentials"]["CF_Token"].endswith(CF_TOKEN[-4:])
            device = (await client.get("/api/devices")).json()[0]
            job = await client.post(f"/api/devices/{device['id']}/deploy")
            assert job.status_code == 202


async def test_cli_generate_prints_the_new_key(populated, monkeypatch, capsys):
    settings = populated
    monkeypatch.setenv("CERTFABRIC_SECRET_KEY", settings.secret_key.decode())
    monkeypatch.setenv("CERTFABRIC_DB_PATH", str(settings.db_path))
    assert main(["rotate-key", "--generate"]) == 0
    new_key = capsys.readouterr().out.strip().encode()
    Vault(new_key).decrypt(secrets_in(settings.db_path)[0])


async def test_cli_refuses_without_current_key_or_with_a_bad_new_key(populated, monkeypatch, tmp_path, capsys):
    settings = populated
    monkeypatch.delenv("CERTFABRIC_SECRET_KEY", raising=False)
    monkeypatch.delenv("CERTFABRIC_SECRET_KEY_FILE", raising=False)
    assert main(["rotate-key", "--generate"]) == 1
    bad = tmp_path / "bad.key"
    bad.write_text("not a key")
    monkeypatch.setenv("CERTFABRIC_SECRET_KEY", settings.secret_key.decode())
    monkeypatch.setenv("CERTFABRIC_DB_PATH", str(settings.db_path))
    assert main(["rotate-key", "--new-key-file", str(bad)]) == 1
    assert "not a valid" in capsys.readouterr().err
