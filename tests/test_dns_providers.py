import sqlite3

import pytest

CF = {"name": "Cloudflare", "acme_dns_type": "dns_cf", "credentials": {"CF_Token": "cf-token-0123456789abcd"}}


async def test_create_list_get_masks_credentials(client):
    created = (await client.post("/api/dns-providers", json=CF)).json()
    assert created["name"] == "Cloudflare"
    assert created["credentials"]["CF_Token"].endswith("abcd")
    assert "cf-token-0123456789" not in created["credentials"]["CF_Token"]

    listed = (await client.get("/api/dns-providers")).json()
    assert [p["id"] for p in listed] == [created["id"]]
    fetched = (await client.get(f"/api/dns-providers/{created['id']}")).json()
    assert fetched == created


async def test_credentials_are_saved_without_surrounding_whitespace(client, app):
    body = {**CF, "credentials": {" CF_Token ": "  cf-token-0123456789abcd  "}}
    created = (await client.post("/api/dns-providers", json=body)).json()
    assert list(created["credentials"]) == ["CF_Token"]
    assert created["credentials"]["CF_Token"].endswith("abcd")


async def test_credentials_are_encrypted_at_rest(client, settings):
    await client.post("/api/dns-providers", json=CF)
    row = sqlite3.connect(settings.db_path).execute("SELECT encrypted_credentials FROM dns_providers").fetchone()
    assert "cf-token" not in row[0]


async def test_short_secrets_reveal_nothing(client):
    body = {**CF, "credentials": {"CF_Token": "short"}}
    created = (await client.post("/api/dns-providers", json=body)).json()
    assert "short" not in created["credentials"]["CF_Token"]


async def test_update_rotates_credentials_and_renames(client):
    pid = (await client.post("/api/dns-providers", json=CF)).json()["id"]
    updated = await client.patch(
        f"/api/dns-providers/{pid}", json={"name": "CF prod", "credentials": {"CF_Token": "new-token-zzzzzzzz9999"}}
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "CF prod"
    assert updated.json()["credentials"]["CF_Token"].endswith("9999")
    assert updated.json()["acme_dns_type"] == "dns_cf"


async def test_delete_unused_provider(client):
    pid = (await client.post("/api/dns-providers", json=CF)).json()["id"]
    assert (await client.delete(f"/api/dns-providers/{pid}")).status_code == 204
    assert (await client.get(f"/api/dns-providers/{pid}")).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {**CF, "acme_dns_type": "dns_cf; rm -rf /"},
        {**CF, "acme_dns_type": "cf"},
        {**CF, "credentials": {}},
        {**CF, "credentials": {"PATH": "/tmp"}},
        {**CF, "credentials": {"LD_PRELOAD": "/tmp/x.so"}},
        {**CF, "credentials": {"not a name": "x"}},
    ],
)
async def test_rejects_unsafe_input(client, body):
    assert (await client.post("/api/dns-providers", json=body)).status_code == 422


async def test_unknown_provider_is_404(client):
    assert (await client.get("/api/dns-providers/nope")).status_code == 404
    assert (await client.delete("/api/dns-providers/nope")).status_code == 404
