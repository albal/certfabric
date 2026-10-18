import json
import time

from tests.conftest import CF_TOKEN, DEVICE_PASSWORD, create_device, issue_certificate
from tests.fakes.webhook_receiver import WebhookReceiver


async def test_create_list_delete(client):
    created = await client.post("/api/webhooks", json={"url": "https://hooks.example.com/certfabric"})
    assert created.status_code == 201
    assert [h["url"] for h in (await client.get("/api/webhooks")).json()] == ["https://hooks.example.com/certfabric"]
    assert (await client.delete(f"/api/webhooks/{created.json()['id']}")).status_code == 204
    assert (await client.get("/api/webhooks")).json() == []


async def test_rejects_non_http_urls(client):
    for url in ["ftp://x.example.com", "file:///etc/passwd", "not a url"]:
        assert (await client.post("/api/webhooks", json={"url": url})).status_code == 422


async def test_event_is_delivered_to_every_webhook(client, app, webhooks):
    second = await WebhookReceiver().start()
    await client.post("/api/webhooks", json={"url": second.url})
    assert (await client.post("/api/webhooks/test")).status_code == 202
    await app.state.notifier.drain()
    await second.stop()
    for receiver in (webhooks, second):
        [event] = receiver.events
        assert event["event"] == "test"
        assert event["message"]
        assert event["timestamp"]


async def test_payload_carries_no_secrets(client, app, webhooks, tls_device):
    from certfabric.models import Certificate, Device

    cert = await issue_certificate(client, ["printer.lan.example.com"])
    device = await create_device(client, tls_device, sni="printer.lan.example.com", certificate_id=cert["id"])
    async with app.state.db.session() as db:
        device_row = await db.get(Device, device["id"])
        cert_row = await db.get(Certificate, cert["id"])
    await app.state.notifier.emit("drift_detected", "Drift", device=device_row, certificate=cert_row)
    await app.state.notifier.drain()
    raw = json.dumps(webhooks.events)
    assert webhooks.events[0]["device"]["id"] == device["id"]
    assert webhooks.events[0]["certificate"]["fingerprint_sha256"] == cert["fingerprint_sha256"]
    for secret in [DEVICE_PASSWORD, CF_TOKEN, "PRIVATE KEY", "encrypted"]:
        assert secret not in raw


async def test_failing_or_slow_receiver_does_not_block_the_sender(client, app):
    broken = await WebhookReceiver(status=500).start()
    slow = await WebhookReceiver(delay=2).start()
    await client.post("/api/webhooks", json={"url": broken.url})
    await client.post("/api/webhooks", json={"url": slow.url})
    await client.post("/api/webhooks", json={"url": "http://127.0.0.1:1/unreachable"})
    started = time.monotonic()
    assert (await client.post("/api/webhooks/test")).status_code == 202
    assert time.monotonic() - started < 1
    await app.state.notifier.drain()
    assert len(broken.events) == 1 and len(slow.events) == 1
    await broken.stop()
    await slow.stop()
