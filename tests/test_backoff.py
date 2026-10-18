from datetime import datetime, timedelta

from tests.conftest import DEVICE_PASSWORD, deploy, managed_device, settle
from tests.fakes import fake_device_control
from tests.fakes.certs import fingerprint, self_signed


async def history(client, device_id):
    rows = (await client.get(f"/api/devices/{device_id}/deployments")).json()
    return [(r["trigger_source"], r["success"]) for r in reversed(rows)]


async def drifted_failing_device(client, app, clock, tls_device):
    device, cert = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    control = fake_device_control.CONTROLS[tls_device.port]
    control.mode = "fail"
    tls_device.present(*self_signed("factory", clock.now()))
    await client.post(f"/api/devices/{device['id']}/probe")  # Drift -> first heal fails
    await settle(app)
    return device, cert, control


async def test_retries_back_off_then_deploy_failed(client, app, clock, scheduler, tls_device, webhooks):
    device, _, control = await drifted_failing_device(client, app, clock, tls_device)
    first_failure = clock.now()
    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["consecutive_deploy_failures"] == 1
    assert datetime.fromisoformat(after["next_retry_at"]) == first_failure + timedelta(hours=1)

    # Nothing happens before the first backoff elapses.
    await scheduler.advance(timedelta(minutes=59))
    await settle(app)
    assert control.deploys == 2
    await scheduler.advance(timedelta(minutes=2))
    await settle(app)
    assert control.deploys == 3  # retry 1, after 1h
    await scheduler.advance(timedelta(hours=5, minutes=50))
    await settle(app)
    assert control.deploys == 3
    await scheduler.advance(timedelta(minutes=20))
    await settle(app)
    assert control.deploys == 4  # retry 2, after 6h -> third consecutive failure

    final = (await client.get(f"/api/devices/{device['id']}")).json()
    assert final["state"] == "DEPLOY_FAILED"
    assert final["next_retry_at"] is None
    [event] = webhooks.of_type("deploy_failed")
    assert event["device"]["id"] == device["id"]
    assert event["level"] == "error"

    # No automatic retries while Deploy Failed, even across many Probe intervals.
    await scheduler.advance(timedelta(days=3))
    await settle(app)
    assert control.deploys == 4
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "DEPLOY_FAILED"
    assert [t for t, _ in await history(client, device["id"])] == ["MANUAL", "DRIFT_HEAL", "RETRY", "RETRY"]


async def deploy_failed_device(client, app, clock, scheduler, tls_device):
    device, cert, control = await drifted_failing_device(client, app, clock, tls_device)
    await scheduler.advance(timedelta(hours=8))
    await settle(app)
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "DEPLOY_FAILED"
    return device, cert, control


async def test_manual_redeploy_resets_and_heals(client, app, clock, scheduler, tls_device):
    device, cert, control = await deploy_failed_device(client, app, clock, scheduler, tls_device)
    control.mode = "succeed"
    job = await deploy(client, device["id"])
    assert job["state"] == "succeeded"
    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["state"] == "IN_SYNC"
    assert after["consecutive_deploy_failures"] == 0
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]


async def test_failed_manual_redeploy_restarts_the_backoff(client, app, clock, scheduler, tls_device):
    device, _, control = await deploy_failed_device(client, app, clock, scheduler, tls_device)
    job = await deploy(client, device["id"])
    assert job["state"] == "failed"
    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["consecutive_deploy_failures"] == 1
    assert after["next_retry_at"] is not None
    await scheduler.advance(timedelta(hours=1, minutes=1))
    await settle(app)
    assert [t for t, _ in await history(client, device["id"])][-1] == "RETRY"


async def test_credentials_change_resets_and_healing_resumes(client, app, clock, scheduler, tls_device):
    device, cert, control = await deploy_failed_device(client, app, clock, scheduler, tls_device)
    control.mode = "succeed"
    updated = await client.patch(
        f"/api/devices/{device['id']}", json={"credentials": {"username": "admin", "password": DEVICE_PASSWORD + "!"}}
    )
    assert updated.json()["consecutive_deploy_failures"] == 0
    assert updated.json()["state"] == "UNKNOWN"
    await client.post(f"/api/devices/{device['id']}/probe")
    await settle(app)
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]
    assert (await client.get(f"/api/devices/{device['id']}")).json()["state"] == "IN_SYNC"
