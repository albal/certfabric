import sqlite3
import time
from datetime import timedelta

import pytest

from certfabric.plugins.base import DeviceCredentials
from certfabric.plugins.generic_ssh_hook.plugin import GenericSshHookPlugin
from tests.conftest import create_device
from tests.fakes.certs import fingerprint, self_signed
from tests.fakes.tls_device import FakeTlsDevice

CREDS = {"username": "admin", "password": "printer-password-123", "api_token": "tok-abcdefghijklmnop"}


async def test_options_and_extra_secrets_are_saved_without_surrounding_whitespace(client, tls_device):
    device = await create_device(
        client,
        tls_device,
        plugin_options={" key_path ": "/etc/ssl/device.key   ", "verify_timeout": 30, "reset": False},
    )
    assert device["plugin_options"] == {"key_path": "/etc/ssl/device.key", "verify_timeout": 30, "reset": False}

    updated = await client.patch(f"/api/devices/{device['id']}", json={"plugin_options": {"key_path": "\t/new.key\n"}})
    assert updated.json()["plugin_options"] == {"key_path": "/new.key"}


def test_extra_secrets_are_trimmed_even_when_read_back_from_storage():
    credentials = DeviceCredentials(**{"extra": {" ssh_password ": "  secret-value  "}})
    assert credentials.extra == {"ssh_password": "secret-value"}


def test_plugins_receive_stored_options_without_surrounding_whitespace():
    plugin = GenericSshHookPlugin(
        "host", 22, DeviceCredentials(), options={"key_path": "/etc/ssl/device.key   ", " ssh_port ": 2222, "off": False}
    )
    assert plugin.options == {"key_path": "/etc/ssl/device.key", "ssh_port": 2222, "off": False}


async def test_create_list_update_delete(client, tls_device):
    device = await create_device(client, tls_device, credentials=CREDS, plugin_options={"reload": "nginx"})
    assert device["state"] == "MONITOR_ONLY"
    assert device["credentials"]["username"] == "admin"
    assert "printer-password" not in str(device["credentials"])
    assert device["polling_interval_minutes"] == 360
    assert [d["id"] for d in (await client.get("/api/devices")).json()] == [device["id"]]

    updated = await client.patch(f"/api/devices/{device['id']}", json={"name": "HP M283", "polling_interval_minutes": 60})
    assert updated.json()["name"] == "HP M283"
    assert updated.json()["polling_interval_minutes"] == 60
    assert updated.json()["credentials"]["username"] == "admin"

    assert (await client.delete(f"/api/devices/{device['id']}")).status_code == 204
    assert (await client.get(f"/api/devices/{device['id']}")).status_code == 404


async def test_credentials_encrypted_at_rest(client, tls_device, settings):
    await create_device(client, tls_device, credentials=CREDS)
    stored = sqlite3.connect(settings.db_path).execute("SELECT encrypted_credentials FROM devices").fetchone()[0]
    assert "printer-password" not in stored


@pytest.mark.parametrize(
    "body",
    [
        {"hostname": "bad host"},
        {"hostname": "printer; reboot"},
        {"sni": "10.0.0.5"},
        {"port": 0},
        {"plugin_id": "../../etc"},
        {"polling_interval_minutes": 1},
    ],
)
async def test_rejects_invalid_device(client, tls_device, body):
    base = {"name": "x", "hostname": "printer.lan", "plugin_id": "generic_ssh_hook"}
    assert (await client.post("/api/devices", json={**base, **body})).status_code == 422


async def test_ip_device_with_sni(client, tls_device):
    device = await create_device(client, tls_device, sni="printer.lan.example.com")
    assert device["hostname"] == "127.0.0.1"
    assert device["sni"] == "printer.lan.example.com"


async def test_probe_records_presented_certificate(client, tls_device):
    device = await create_device(client, tls_device)
    probed = (await client.post(f"/api/devices/{device['id']}/probe")).json()
    presented = probed["presented_certificate"]
    assert presented["fingerprint_sha256"] == fingerprint(tls_device.cert_pem)
    assert presented["common_name"] == "factory.local"
    assert presented["sans"] == ["factory.local"]
    assert "factory.local" in presented["issuer"]
    assert presented["serial_number"]
    assert presented["expires_at"]
    assert probed["state"] == "MONITOR_ONLY"
    assert probed["last_scanned_at"]


async def test_failed_probe_is_recorded(client, tls_device):
    device = await create_device(client, tls_device)
    await tls_device.stop()
    probed = (await client.post(f"/api/devices/{device['id']}/probe")).json()
    assert probed["consecutive_probe_failures"] == 1
    assert probed["last_probe_error"]
    assert probed["presented_certificate"] is None


async def test_test_connection_before_saving(client, tls_device):
    body = {"name": "x", "hostname": tls_device.host, "port": tls_device.port, "plugin_id": "fake_device"}
    ok = (await client.post("/api/devices/test-connection", json=body)).json()
    assert ok["success"] is True
    assert ok["presented_certificate"]["fingerprint_sha256"] == fingerprint(tls_device.cert_pem)
    await tls_device.stop()
    failed = (await client.post("/api/devices/test-connection", json=body)).json()
    assert failed["success"] is False
    assert (await client.get("/api/devices")).json() == []


async def test_test_connection_runs_the_plugin_check(client, tls_device):
    from tests.fakes import fake_device_control

    device = await create_device(client, tls_device)
    assert (await client.post(f"/api/devices/{device['id']}/test-connection")).json()["success"] is True
    fake_device_control.CONTROLS[tls_device.port].bad_credentials = True
    result = (await client.post(f"/api/devices/{device['id']}/test-connection")).json()
    assert result == {**result, "success": False, "message": "Login rejected"}


async def test_unknown_plugin_is_rejected(client, tls_device):
    body = {"name": "x", "hostname": "printer.lan", "plugin_id": "not_installed"}
    assert (await client.post("/api/devices", json=body)).status_code == 422


async def test_sweep_honours_each_devices_interval(client, tls_device, scheduler, clock):
    fast = await create_device(client, tls_device, name="fast", polling_interval_minutes=60)
    slow = await create_device(client, tls_device, name="slow")  # default 6 hours
    await scheduler.advance(timedelta(minutes=1))
    first = {d["name"]: d["last_scanned_at"] for d in (await client.get("/api/devices")).json()}
    assert first["fast"] and first["slow"]

    tls_device.present(*self_signed("changed.local", clock.now()))
    await scheduler.advance(timedelta(minutes=61))
    fast_now = (await client.get(f"/api/devices/{fast['id']}")).json()
    slow_now = (await client.get(f"/api/devices/{slow['id']}")).json()
    assert fast_now["presented_certificate"]["common_name"] == "changed.local"
    assert slow_now["presented_certificate"]["common_name"] == "factory.local"

    await scheduler.advance(timedelta(hours=5))
    slow_now = (await client.get(f"/api/devices/{slow['id']}")).json()
    assert slow_now["presented_certificate"]["common_name"] == "changed.local"


async def test_probe_never_sends_application_data(client):
    received = []

    class RecordingDevice(FakeTlsDevice):
        async def _handle(self, reader, writer):
            received.append(await reader.read(1024))
            writer.close()

    device = await RecordingDevice().start()
    try:
        created = await create_device(client, device)
        await client.post(f"/api/devices/{created['id']}/probe")
    finally:
        await device.stop()
    assert received == [b""]


async def test_250_devices_probed_in_under_15_seconds(app, client):
    from certfabric import devices

    # Several servers, because one listener's accept backlog (128 on macOS) can't take 250 at once.
    fakes = [await FakeTlsDevice().start() for _ in range(5)]
    try:
        for i in range(250):
            await create_device(client, fakes[i % len(fakes)], name=f"device-{i:03}")
        started = time.monotonic()
        await devices.sweep(app.state)
        elapsed = time.monotonic() - started
    finally:
        for fake in fakes:
            await fake.stop()
    listed = (await client.get("/api/devices")).json()
    assert all(d["presented_certificate"] for d in listed)
    assert elapsed < 15, f"sweep took {elapsed:.1f}s"
