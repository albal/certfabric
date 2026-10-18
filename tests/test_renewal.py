from datetime import timedelta

from tests.conftest import create_device, deploy, issue_certificate, managed_device, settle
from tests.fakes import fake_device_control
from tests.fakes.certs import fingerprint
from tests.fakes.tls_device import FakeTlsDevice


async def jump(clock, scheduler, app, delta):
    """Jump the clock, then let one round of scheduled jobs run."""
    clock.advance(delta)
    await scheduler.advance(timedelta(hours=1))
    await settle(app)


async def certs(client):
    return {c["id"]: c for c in (await client.get("/api/certificates")).json()}


async def test_renews_inside_the_threshold_and_deploys(client, app, clock, scheduler, fake_acme, tls_device):
    device, old = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    issuances = len(fake_acme.invocations)

    await jump(clock, scheduler, app, timedelta(days=60))  # 30 days left: not yet
    assert len(fake_acme.invocations) == issuances
    await jump(clock, scheduler, app, timedelta(days=2))  # 27 days left
    assert len(fake_acme.invocations) == issuances + 1

    all_certs = await certs(client)
    [new] = [c for c in all_certs.values() if c["id"] != old["id"]]
    assert all_certs[old["id"]]["status"] == "SUPERSEDED"
    assert all_certs[old["id"]]["superseded_by"] == new["id"]
    assert new["status"] == "VALID"
    assert new["sans"] == old["sans"]
    assert new["dns_provider_id"] == old["dns_provider_id"]

    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["assigned_certificate_id"] == new["id"]
    assert after["state"] == "IN_SYNC"
    assert fingerprint(tls_device.cert_pem) == new["fingerprint_sha256"]
    triggers = [d["trigger_source"] for d in (await client.get(f"/api/devices/{device['id']}/deployments")).json()]
    assert triggers[0] == "RENEWAL"


async def test_shared_certificate_is_renewed_exactly_once(client, app, clock, scheduler, fake_acme):
    cert = await issue_certificate(client, ["*.lan.example.com"])
    fakes = [await FakeTlsDevice().start() for _ in range(3)]
    try:
        for i, fake in enumerate(fakes):
            fake_device_control.register(fake)
            await create_device(client, fake, name=f"d{i}", sni=f"d{i}.lan.example.com", certificate_id=cert["id"])
        before = len(fake_acme.invocations)
        await jump(clock, scheduler, app, timedelta(days=63))
        await jump(clock, scheduler, app, timedelta(hours=3))
        assert len(fake_acme.invocations) == before + 1
        new_id = next(c["id"] for c in (await certs(client)).values() if c["status"] == "VALID")
        for fake in fakes:
            assert fingerprint(fake.cert_pem) == (await certs(client))[new_id]["fingerprint_sha256"]
    finally:
        for fake in fakes:
            await fake.stop()


async def test_renewal_proceeds_while_devices_are_unreachable(client, app, clock, scheduler, fake_acme, tls_device):
    device, old = await managed_device(client, tls_device)
    await deploy(client, device["id"])
    await tls_device.stop()
    await jump(clock, scheduler, app, timedelta(days=63))
    new = next(c for c in (await certs(client)).values() if c["status"] == "VALID")
    assert new["id"] != old["id"]
    after = (await client.get(f"/api/devices/{device['id']}")).json()
    assert after["assigned_certificate_id"] == new["id"]
    assert after["consecutive_deploy_failures"] == 1  # the RENEWAL Deployment could not reach it

    await tls_device.start()
    await jump(clock, scheduler, app, timedelta(hours=1))  # backoff elapses, retry succeeds
    assert fingerprint(tls_device.cert_pem) == new["fingerprint_sha256"]


async def test_superseded_private_key_is_deleted_after_30_days(client, app, clock, scheduler):
    old = await issue_certificate(client, ["a.example.com"])
    await jump(clock, scheduler, app, timedelta(days=63))
    assert (await certs(client))[old["id"]]["has_private_key"] is True
    await jump(clock, scheduler, app, timedelta(days=29))
    assert (await certs(client))[old["id"]]["has_private_key"] is True
    await jump(clock, scheduler, app, timedelta(days=2))
    kept = (await certs(client))[old["id"]]
    assert kept["has_private_key"] is False
    assert kept["fingerprint_sha256"] == old["fingerprint_sha256"]
    assert kept["status"] == "SUPERSEDED"


async def test_failed_renewal_alerts_and_retries_after_six_hours(client, app, clock, scheduler, fake_acme, webhooks):
    old = await issue_certificate(client, ["a.example.com"])
    fake_acme.configure(fail=True)
    before = len(fake_acme.invocations)
    await jump(clock, scheduler, app, timedelta(days=63))
    assert len(fake_acme.invocations) == before + 1
    [event] = webhooks.of_type("renewal_failed")
    assert event["certificate"]["id"] == old["id"]
    shown = (await certs(client))[old["id"]]
    assert "NXDOMAIN" in shown["renewal_error"]
    assert shown["status"] == "EXPIRING"

    await jump(clock, scheduler, app, timedelta(hours=4))
    assert len(fake_acme.invocations) == before + 1  # not hammering the CA
    fake_acme.configure(fail=False)
    await jump(clock, scheduler, app, timedelta(hours=2))
    assert len(fake_acme.invocations) == before + 2
    assert (await certs(client))[old["id"]]["status"] == "SUPERSEDED"


async def test_threshold_is_a_setting(client, app, clock, scheduler, fake_acme):
    await client.put("/api/settings", json={"acme_ca": "letsencrypt", "renewal_threshold_days": 10})
    await issue_certificate(client, ["a.example.com"])
    before = len(fake_acme.invocations)
    await jump(clock, scheduler, app, timedelta(days=63))
    assert len(fake_acme.invocations) == before
    await jump(clock, scheduler, app, timedelta(days=18))
    assert len(fake_acme.invocations) == before + 1
