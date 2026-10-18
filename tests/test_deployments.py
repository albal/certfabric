import asyncio

import pytest

from tests.conftest import (
    DEVICE_PASSWORD,
    create_device,
    deploy,
    issue_certificate,
    managed_device,
    wait_for_job,
)
from tests.fakes import fake_device_control
from tests.fakes.certs import fingerprint


async def test_plugins_are_listed(client):
    plugins = {p["plugin_id"]: p for p in (await client.get("/api/plugins")).json()}
    assert {"generic_ssh_hook", "fake_device"} <= plugins.keys()
    assert plugins["generic_ssh_hook"]["target_category"] == "generic"
    assert plugins["generic_ssh_hook"]["supported_models"]


@pytest.mark.parametrize(
    ("sans", "name", "ok"),
    [
        (["*.lan.example.com"], "printer.lan.example.com", True),
        (["*.lan.example.com"], "a.b.lan.example.com", False),
        (["*.lan.example.com"], "lan.example.com", False),
        (["nas.example.com", "files.example.com"], "files.example.com", True),
        (["nas.example.com"], "printer.example.com", False),
    ],
)
async def test_assignment_requires_san_coverage(client, tls_device, sans, name, ok):
    cert = await issue_certificate(client, sans)
    device = await create_device(client, tls_device, sni=name)
    response = await client.put(f"/api/devices/{device['id']}/certificate", json={"certificate_id": cert["id"]})
    assert (response.status_code == 200) is ok, response.text
    if ok:
        assert response.json()["assigned_certificate_id"] == cert["id"]
        assert response.json()["state"] == "UNKNOWN"


async def test_ip_only_device_cannot_be_assigned(client, tls_device):
    cert = await issue_certificate(client, ["*.lan.example.com"])
    device = await create_device(client, tls_device)
    response = await client.put(f"/api/devices/{device['id']}/certificate", json={"certificate_id": cert["id"]})
    assert response.status_code == 422
    assert "sni" in response.json()["detail"]


async def test_renaming_a_device_out_of_coverage_is_rejected(client, tls_device):
    device, _ = await managed_device(client, tls_device)
    response = await client.patch(f"/api/devices/{device['id']}", json={"sni": "printer.other.com"})
    assert response.status_code == 422


async def test_unassign_returns_to_monitor_only(client, tls_device):
    device, _ = await managed_device(client, tls_device)
    response = await client.put(f"/api/devices/{device['id']}/certificate", json={"certificate_id": None})
    assert response.json()["state"] == "MONITOR_ONLY"


async def test_redeploy_now_installs_and_verifies(client, tls_device):
    device, cert = await managed_device(client, tls_device)
    job = await deploy(client, device["id"])
    assert job["state"] == "succeeded", job
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]
    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["state"] == "IN_SYNC"
    assert after["presented_certificate"]["fingerprint_sha256"] == cert["fingerprint_sha256"]

    [log] = (await client.get(f"/api/devices/{device['id']}/deployments")).json()
    assert log["success"] is True
    assert log["trigger_source"] == "MANUAL"
    assert log["certificate_id"] == cert["id"]
    assert log["execution_time_ms"] >= 0


@pytest.mark.parametrize(("mode", "reason"), [("fail", "reported"), ("raise", "rejected the upload"), ("no_effect", "Verification failed")])
async def test_failed_deployment_is_reported_and_logged(client, tls_device, mode, reason):
    device, _ = await managed_device(client, tls_device)
    fake_device_control.CONTROLS[tls_device.port].mode = mode
    job = await deploy(client, device["id"])
    assert job["state"] == "failed"
    assert reason in job["error"]
    [log] = (await client.get(f"/api/devices/{device['id']}/deployments")).json()
    assert log["success"] is False
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "UNKNOWN"


async def test_deployment_output_is_redacted(client, tls_device):
    device, _ = await managed_device(client, tls_device)
    job = await deploy(client, device["id"])
    assert DEVICE_PASSWORD not in job["output"]
    assert "pfx=[REDACTED]" in job["output"]
    [log] = (await client.get(f"/api/devices/{device['id']}/deployments")).json()
    assert DEVICE_PASSWORD not in log["log_output"]


async def test_fixed_pfx_passphrase_is_used_and_redacted(client, tls_device):
    device, _ = await managed_device(
        client, tls_device, credentials={"username": "admin", "password": DEVICE_PASSWORD, "pfx_passphrase": "fixed-pfx-pass"}
    )
    job = await deploy(client, device["id"])
    assert "fixed-pfx-pass" not in job["output"]


async def test_only_one_deployment_per_device_at_a_time(client, tls_device):
    device, _ = await managed_device(client, tls_device)
    fake_device_control.CONTROLS[tls_device.port].delay = 0.2
    first = await client.post(f"/api/devices/{device['id']}/deploy")
    second = await client.post(f"/api/devices/{device['id']}/deploy")
    assert first.status_code == 202
    assert second.status_code == 409
    await wait_for_job(client, first.json()["job_id"])
    assert fake_device_control.CONTROLS[tls_device.port].deploys == 1
    assert (await client.post(f"/api/devices/{device['id']}/deploy")).status_code == 202


async def test_monitor_only_device_cannot_be_deployed(client, tls_device):
    device = await create_device(client, tls_device)
    assert (await client.post(f"/api/devices/{device['id']}/deploy")).status_code == 422
    assert (await client.post("/api/devices/nope/deploy")).status_code == 404


def test_deployment_output_streams_over_websocket(settings, clock, tmp_path):
    from fastapi.testclient import TestClient

    from certfabric.app import create_app
    from tests.conftest import ADMIN_PASSWORD, BASE_URL, CF_TOKEN
    from tests.fakes.tls_device import FakeTlsDevice

    with TestClient(create_app(settings, clock), base_url=BASE_URL) as tc:
        fake = tc.portal.call(FakeTlsDevice().start)
        fake_device_control.register(fake)
        tc.post("/api/auth/setup", json={"password": ADMIN_PASSWORD})
        provider = tc.post("/api/dns-providers", json={"name": "CF", "acme_dns_type": "dns_cf", "credentials": {"CF_Token": CF_TOKEN}}).json()
        job_id = tc.post("/api/certificates", json={"domains": ["p.lan.example.com"], "dns_provider_id": provider["id"]}).json()["job_id"]
        while tc.get(f"/api/jobs/{job_id}").json()["state"] == "running":
            tc.portal.call(asyncio.sleep, 0.01)
        cert_id = tc.get(f"/api/jobs/{job_id}").json()["result"]["certificate_id"]
        device = tc.post("/api/devices", json={
            "name": "p", "hostname": fake.host, "port": fake.port, "sni": "p.lan.example.com",
            "plugin_id": "fake_device", "certificate_id": cert_id,
            "credentials": {"username": "admin", "password": DEVICE_PASSWORD},
        }).json()
        job_id = tc.post(f"/api/devices/{device['id']}/deploy").json()["job_id"]
        cookie = f"certfabric_session={tc.cookies.get('certfabric_session')}"
        lines = []
        with tc.websocket_connect(f"/ws/jobs/{job_id}", headers={"cookie": cookie}) as ws:
            while (message := ws.receive_json())["type"] != "end":
                lines.append(message["text"])
        tc.portal.call(fake.stop)
    assert message["state"] == "succeeded"
    assert any("verified" in line for line in lines)
    assert not any(DEVICE_PASSWORD in line for line in lines)
