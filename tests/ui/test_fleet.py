import re
from datetime import timedelta

from playwright.async_api import expect

from tests.conftest import ADMIN_PASSWORD, create_device, deploy, managed_device, settle
from tests.fakes import fake_device_control
from tests.fakes.certs import self_signed
from tests.fakes.tls_device import FakeTlsDevice
from tests.ui.conftest import sign_in


async def test_first_run_sets_the_password(anon, page):
    await page.goto("/")
    await expect(page).to_have_url("/login")
    await page.get_by_label("New admin password").fill("short")
    await page.get_by_label("Confirm password").fill("short")
    await page.get_by_role("button", name="Set password").click()
    await expect(page.get_by_role("alert")).to_contain_text("12 characters")

    await page.get_by_label("New admin password").fill(ADMIN_PASSWORD)
    await page.get_by_label("Confirm password").fill(ADMIN_PASSWORD)
    await page.get_by_role("button", name="Set password").click()
    await expect(page.get_by_test_id("fleet-table")).to_contain_text("No Devices yet")
    await expect(page.get_by_test_id("metric-devices")).to_have_text("0")


async def test_login_and_logout(client, page):
    await page.goto("/")
    await page.get_by_label("Admin password").fill("not the password")
    await page.get_by_role("button", name="Sign in").click()
    await expect(page.get_by_role("alert")).to_have_text("Wrong password")
    await page.get_by_label("Admin password").fill(ADMIN_PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await expect(page.get_by_test_id("fleet-table")).to_be_visible()

    await page.get_by_role("button", name="Sign out").click()
    await expect(page).to_have_url("/login")
    await page.goto("/")
    await expect(page).to_have_url("/login")


async def test_fleet_shows_every_state_and_the_ribbon(client, app, clock, page, tls_device):
    in_sync, cert = await managed_device(client, tls_device, name="iDRAC R740")
    await deploy(client, in_sync["id"])

    drift_fake = await FakeTlsDevice().start()
    control = fake_device_control.register(drift_fake)
    drifted, _ = await managed_device(client, drift_fake, domain="printer2.lan.example.com", name="HP M283fdw")
    await deploy(client, drifted["id"])
    drift_fake.present(*self_signed("HP-Factory", clock.now()))
    control.mode = "fail"
    await client.post(f"/api/devices/{drifted['id']}/probe")
    await settle(app)

    expiring_fake = await FakeTlsDevice().start()
    expiring_fake.present(*self_signed("old.lan", clock.now(), days=10))
    expiring = await create_device(client, expiring_fake, name="Old switch")
    await client.post(f"/api/devices/{expiring['id']}/probe")

    down_fake = await FakeTlsDevice().start()
    down = await create_device(client, down_fake, name="Lab NAS")
    await down_fake.stop()
    for _ in range(3):
        await client.post(f"/api/devices/{down['id']}/probe")

    try:
        await sign_in(page)
        rows = page.get_by_test_id("device-row")
        await expect(rows).to_have_count(4)

        def row(device):
            return page.locator(f'[data-device-id="{device["id"]}"]')

        await expect(row(in_sync).get_by_test_id("state-badge")).to_have_attribute("data-state", "IN_SYNC")
        await expect(row(in_sync)).to_contain_text("printer.lan.example.com")
        await expect(row(in_sync)).to_contain_text("Fake device")
        await expect(row(in_sync)).to_contain_text(f"{tls_device.host}:{tls_device.port}")
        await expect(row(drifted).get_by_test_id("state-badge")).to_have_text("Drift Detected: Reverted")
        await expect(row(expiring).get_by_test_id("state-badge")).to_have_attribute("data-state", "MONITOR_ONLY")
        await expect(row(expiring).get_by_test_id("expiring-badge")).to_contain_text("Expiring")
        await expect(row(down).get_by_test_id("state-badge")).to_have_text("Unreachable")

        await expect(page.get_by_test_id("metric-devices")).to_have_text("4")
        await expect(page.get_by_test_id("metric-certificates")).to_have_text("2")
        drift_metric = page.get_by_test_id("metric-drift")
        await expect(drift_metric).to_have_text("1")
        await expect(drift_metric).to_have_class(re.compile(r"\banimate-pulse\b"))
    finally:
        await drift_fake.stop()
        await expiring_fake.stop()


async def test_expired_session_returns_to_login(client, clock, page):
    await sign_in(page)
    clock.advance(timedelta(days=8))
    await page.reload()
    await expect(page).to_have_url("/login")


async def test_fleet_sorts_by_clicking_headers(client, page, tls_device):
    second = await FakeTlsDevice().start()
    try:
        await create_device(client, tls_device, name="Bravo")
        await create_device(client, second, name="alpha")
        await create_device(client, tls_device, name="Charlie")

        await sign_in(page)
        names = page.get_by_test_id("device-row").locator("td:first-child")
        header = page.get_by_role("columnheader", name="Device")
        await expect(names).to_have_text(["alpha", "Bravo", "Charlie"])
        await expect(header).to_have_attribute("aria-sort", "ascending")

        await header.get_by_role("button").click()
        await expect(names).to_have_text(["Charlie", "Bravo", "alpha"])
        await expect(header).to_have_attribute("aria-sort", "descending")

        await header.get_by_role("button").click()
        await expect(names).to_have_text(["alpha", "Bravo", "Charlie"])

        await page.get_by_role("columnheader", name="Target").get_by_role("button").click()
        await expect(header).to_have_attribute("aria-sort", "none")
    finally:
        await second.stop()
