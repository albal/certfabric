from tests.conftest import create_device, deploy, managed_device, settle
from tests.fakes.certs import fingerprint, self_signed


async def probe(client, device_id):
    return (await client.post(f"/api/devices/{device_id}/probe")).json()


async def test_unreachable_after_three_failed_probes_then_recovery(client, app, tls_device, webhooks):
    device, _ = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    await tls_device.stop()

    assert (await probe(client, device["id"]))["state"] == "IN_SYNC"
    assert (await probe(client, device["id"]))["state"] == "IN_SYNC"
    third = await probe(client, device["id"])
    assert third["state"] == "UNREACHABLE"
    assert third["consecutive_probe_failures"] == 3
    await settle(app)
    [down] = webhooks.of_type("device_unreachable")
    assert down["device"]["id"] == device["id"]
    assert down["level"] == "error"

    assert (await probe(client, device["id"]))["state"] == "UNREACHABLE"
    await settle(app)
    assert len(webhooks.of_type("device_unreachable")) == 1

    await tls_device.start()
    recovered = await probe(client, device["id"])
    assert recovered["state"] == "IN_SYNC"
    assert recovered["consecutive_probe_failures"] == 0
    await settle(app)
    assert len(webhooks.of_type("device_recovered")) == 1
    assert {e["event"] for e in (await client.get("/api/events")).json()} == {"device_unreachable", "device_recovered"}


async def test_device_returning_with_a_factory_cert_is_drift(client, app, clock, tls_device, webhooks):
    device, cert = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    await tls_device.stop()
    for _ in range(3):
        await probe(client, device["id"])
    tls_device.present(*self_signed("factory-reset", clock.now()))
    await tls_device.start()

    assert (await probe(client, device["id"]))["state"] == "DRIFT_DETECTED"
    await settle(app)
    assert [e["event"] for e in webhooks.events] == ["device_unreachable", "device_recovered", "drift_detected"]
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]


async def test_monitor_only_device_can_be_unreachable(client, app, tls_device, webhooks):
    device = await create_device(client, tls_device)
    await tls_device.stop()
    for _ in range(3):
        result = await probe(client, device["id"])
    assert result["state"] == "UNREACHABLE"
    await tls_device.start()
    assert (await probe(client, device["id"]))["state"] == "MONITOR_ONLY"
    await settle(app)
    assert [e["event"] for e in webhooks.events] == ["device_unreachable", "device_recovered"]
