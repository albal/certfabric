import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from certfabric.app import create_app
from certfabric.redaction import REDACTED
from certfabric.x509util import build_pkcs12, info_from_pem, split_pem_chain
from tests.conftest import ADMIN_PASSWORD, BASE_URL, CF_TOKEN, create_dns_provider, issue_certificate, wait_for_job


@pytest.mark.parametrize(
    "domains",
    [["*.lan.example.com"], ["nas.lan.example.com", "nas.example.com", "files.example.com"], ["idrac.lan.example.com"]],
)
async def test_issues_wildcard_san_and_single_host(client, domains):
    cert = await issue_certificate(client, domains)
    assert cert["domain_primary"] == domains[0]
    assert cert["sans"] == domains
    assert cert["status"] == "VALID"
    assert cert["key_type"] == "RSA2048"
    assert len(cert["fingerprint_sha256"]) == 64
    assert "privkey" not in str(cert).lower()


async def test_injects_dns_credentials_and_passes_safe_arguments(client, fake_acme):
    await issue_certificate(client, ["*.lan.example.com"])
    [call] = fake_acme.invocations
    assert call["env"]["CF_Token"] == CF_TOKEN
    assert call["args"]["dns"] == "dns_cf"
    assert call["args"]["domains"] == ["*.lan.example.com"]
    assert call["args"]["server"] == "letsencrypt"
    assert call["args"]["keylength"] == "2048"


async def test_ecdsa_key_type(client, fake_acme):
    cert = await issue_certificate(client, ["a.example.com"], key_type="ECDSA_P256")
    assert cert["key_type"] == "ECDSA_P256"
    assert fake_acme.invocations[-1]["args"]["keylength"] == "ec-256"


@pytest.mark.parametrize(
    ("settings_body", "server"),
    [
        ({"acme_ca": "letsencrypt", "acme_use_staging": True}, "letsencrypt_test"),
        ({"acme_ca": "zerossl"}, "zerossl"),
        ({"acme_ca": "https://ca.lan.example.com/acme/directory"}, "https://ca.lan.example.com/acme/directory"),
    ],
)
async def test_ca_setting_changes_the_server(client, fake_acme, settings_body, server):
    assert (await client.put("/api/settings", json=settings_body)).status_code == 200
    await issue_certificate(client, ["a.example.com"])
    assert fake_acme.invocations[-1]["args"]["server"] == server


async def test_settings_default_and_validation(client):
    assert (await client.get("/api/settings")).json() == {
        "acme_ca": "letsencrypt",
        "acme_use_staging": False,
        "renewal_threshold_days": 28,
    }
    bad = await client.put("/api/settings", json={"acme_ca": "zerossl", "acme_use_staging": True})
    assert bad.status_code == 422
    assert (await client.put("/api/settings", json={"acme_ca": "http://insecure"})).status_code == 422


@pytest.mark.parametrize(
    "domain",
    ["-d evil.com", "a.example.com; rm -rf /", "$(reboot).example.com", "--server=x", "*.*.example.com", "localhost", ""],
)
async def test_hostile_domains_never_reach_acme(client, fake_acme, domain):
    provider_id = await create_dns_provider(client)
    response = await client.post("/api/certificates", json={"domains": [domain], "dns_provider_id": provider_id})
    assert response.status_code == 422
    assert fake_acme.invocations == []


async def test_private_key_encrypted_and_artifacts_valid(client, settings):
    cert = await issue_certificate(client, ["a.example.com"])
    row = sqlite3.connect(settings.db_path).execute(
        "SELECT cert_pem, fullchain_pem, privkey_pem_encrypted FROM certificates WHERE id = ?", (cert["id"],)
    ).fetchone()
    cert_pem, fullchain_pem, encrypted_key = row
    assert "PRIVATE KEY" not in encrypted_key
    assert len(split_pem_chain(fullchain_pem)) == 2
    assert info_from_pem(cert_pem).fingerprint_sha256 == cert["fingerprint_sha256"]


async def test_pkcs12_bundle_can_be_built_with_and_without_chain(client, app):
    from cryptography.hazmat.primitives.serialization import pkcs12

    from certfabric.models import Certificate

    cert = await issue_certificate(client, ["a.example.com"])
    async with app.state.db.session() as db:
        row = await db.get(Certificate, cert["id"])
    key_pem = app.state.vault.decrypt(row.privkey_pem_encrypted)
    chain = split_pem_chain(row.fullchain_pem)[1:]
    leaf_only = pkcs12.load_pkcs12(build_pkcs12(row.cert_pem, key_pem, "pass-phrase"), b"pass-phrase")
    assert leaf_only.additional_certs == []
    with_chain = pkcs12.load_pkcs12(build_pkcs12(row.cert_pem, key_pem, "pp", chain), b"pp")
    assert len(with_chain.additional_certs) == 1


async def test_failed_issuance_stores_nothing_and_reports_why(client, fake_acme):
    fake_acme.configure(fail=True)
    provider_id = await create_dns_provider(client)
    response = await client.post("/api/certificates", json={"domains": ["a.example.com"], "dns_provider_id": provider_id})
    job = await wait_for_job(client, response.json()["job_id"])
    assert job["state"] == "failed"
    assert "NXDOMAIN" in job["error"]
    assert (await client.get("/api/certificates")).json() == []


async def test_output_is_redacted(client, fake_acme):
    fake_acme.configure(echo_env=["CF_Token"], print_key=True)
    provider_id = await create_dns_provider(client)
    response = await client.post("/api/certificates", json={"domains": ["a.example.com"], "dns_provider_id": provider_id})
    job = await wait_for_job(client, response.json()["job_id"])
    assert job["state"] == "succeeded"
    assert CF_TOKEN not in job["output"]
    assert "PRIVATE KEY" not in job["output"]
    assert REDACTED in job["output"]


async def test_unknown_dns_provider_is_rejected(client):
    response = await client.post("/api/certificates", json={"domains": ["a.example.com"], "dns_provider_id": "nope"})
    assert response.status_code == 422


async def test_dns_provider_in_use_cannot_be_deleted(client):
    cert = await issue_certificate(client, ["a.example.com"])
    response = await client.delete(f"/api/dns-providers/{cert['dns_provider_id']}")
    assert response.status_code == 409
    assert (await client.get(f"/api/dns-providers/{cert['dns_provider_id']}")).status_code == 200


async def test_status_becomes_expiring_then_expired(client, clock):
    cert = await issue_certificate(client, ["a.example.com"])
    clock.advance(timedelta(days=63))
    assert (await client.get(f"/api/certificates/{cert['id']}")).json()["status"] == "EXPIRING"
    clock.advance(timedelta(days=30))
    assert (await client.get(f"/api/certificates/{cert['id']}")).json()["status"] == "EXPIRED"


def test_issuance_output_streams_over_websocket(settings, clock, fake_acme):
    fake_acme.configure(echo_env=["CF_Token"])
    with TestClient(create_app(settings, clock), base_url=BASE_URL) as tc:
        tc.post("/api/auth/setup", json={"password": ADMIN_PASSWORD})
        body = {"name": "CF", "acme_dns_type": "dns_cf", "credentials": {"CF_Token": CF_TOKEN}}
        provider_id = tc.post("/api/dns-providers", json=body).json()["id"]
        job_id = tc.post(
            "/api/certificates", json={"domains": ["a.example.com"], "dns_provider_id": provider_id}
        ).json()["job_id"]
        cookie = f"certfabric_session={tc.cookies.get('certfabric_session')}"
        messages = []
        with tc.websocket_connect(f"/ws/jobs/{job_id}", headers={"cookie": cookie}) as ws:
            while (message := ws.receive_json())["type"] != "end":
                messages.append(message["text"])
        assert message["state"] == "succeeded"
        assert any("Cert success" in m for m in messages)
        assert not any(CF_TOKEN in m for m in messages)
