from tests.conftest import deploy, issue_certificate, managed_device, settle
from tests.fakes import fake_device_control
from tests.fakes.certs import fingerprint, self_signed


async def probe(client, device_id):
    response = await client.post(f"/api/devices/{device_id}/probe")
    assert response.status_code == 200
    return response.json()


async def history(client, device_id):
    return [d["trigger_source"] for d in (await client.get(f"/api/devices/{device_id}/deployments")).json()]


async def test_in_sync_device_is_left_alone(client, app, tls_device, webhooks):
    device, _ = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    assert (await probe(client, device["id"]))["state"] == "IN_SYNC"
    await settle(app)
    assert await history(client, device["id"]) == ["MANUAL"]
    assert webhooks.events == []


async def test_first_probe_of_a_new_device_deploys_without_an_alarm(client, app, tls_device, webhooks):
    device, cert = await managed_device(client, tls_device)
    assert (await probe(client, device["id"]))["state"] == "UNKNOWN"
    await settle(app)
    assert await history(client, device["id"]) == ["INITIAL_SETUP"]
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]
    assert webhooks.events == []


async def test_outdated_device_is_redeployed_quietly(client, app, tls_device, webhooks):
    device, old = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    new = await issue_certificate(client, ["printer.lan.example.com"])
    await client.put(f"/api/devices/{device['id']}/certificate", json={"certificate_id": new["id"]})

    assert (await probe(client, device["id"]))["state"] == "OUTDATED"
    await settle(app)
    assert await history(client, device["id"]) == ["OUTDATED_HEAL", "MANUAL"]
    assert fingerprint(tls_device.cert_pem) == new["fingerprint_sha256"] != old["fingerprint_sha256"]
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "IN_SYNC"
    assert webhooks.events == []
    assert (await client.get("/api/events")).json() == []


async def test_drift_is_alarmed_and_healed(client, app, clock, tls_device, webhooks):
    device, cert = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    tls_device.present(*self_signed("HP-Factory", clock.now()))  # firmware update reverted it

    assert (await probe(client, device["id"]))["state"] == "DRIFT_DETECTED"
    await settle(app)
    assert await history(client, device["id"]) == ["DRIFT_HEAL", "MANUAL"]
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "IN_SYNC"

    [event] = webhooks.of_type("drift_detected")
    assert event["device"]["id"] == device["id"]
    assert event["level"] == "warning"
    [feed] = (await client.get("/api/events")).json()
    assert feed["event"] == "drift_detected"
    assert feed["level"] == "warning"
    assert feed["device_id"] == device["id"]


async def test_unhealed_drift_alarms_once(client, app, clock, tls_device, webhooks):
    device, _ = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    tls_device.present(*self_signed("HP-Factory", clock.now()))
    fake_device_control.CONTROLS[tls_device.port].mode = "fail"

    for _ in range(3):
        assert (await probe(client, device["id"]))["state"] == "DRIFT_DETECTED"
        await settle(app)
    assert len(webhooks.of_type("drift_detected")) == 1


async def test_monitor_only_devices_are_never_classified_or_deployed(client, app, clock, tls_device, webhooks):
    from tests.conftest import create_device

    device = await create_device(client, tls_device)
    tls_device.present(*self_signed("whatever", clock.now()))
    assert (await probe(client, device["id"]))["state"] == "MONITOR_ONLY"
    await settle(app)
    assert await history(client, device["id"]) == []
    assert fake_device_control.CONTROLS[tls_device.port].deploys == 0
    assert webhooks.events == []


async def test_scheduled_sweep_heals_drift(client, app, clock, scheduler, tls_device):
    from datetime import timedelta

    device, cert = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    await scheduler.advance(timedelta(minutes=1))
    tls_device.present(*self_signed("HP-Factory", clock.now()))
    await scheduler.advance(timedelta(hours=6))
    await settle(app)
    assert "DRIFT_HEAL" in await history(client, device["id"])
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]
