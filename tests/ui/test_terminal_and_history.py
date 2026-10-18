from datetime import timedelta

from playwright.async_api import expect

from tests.conftest import DEVICE_PASSWORD, deploy, managed_device, settle
from tests.fakes import fake_device_control
from tests.fakes.certs import fingerprint, self_signed
from tests.ui.conftest import sign_in


async def drifted(client, app, clock, tls_device, *, fail: bool):
    device, cert = await managed_device(client, tls_device, name="HP M283fdw")
    await deploy(client, device["id"])
    tls_device.present(*self_signed("HP-Factory", clock.now()))
    control = fake_device_control.CONTROLS[tls_device.port]
    control.mode = "fail" if fail else "succeed"
    if fail:
        await client.post(f"/api/devices/{device['id']}/probe")
        await settle(app)
    return device, cert, control


async def test_redeploy_now_streams_into_the_terminal(client, app, clock, page, tls_device):
    device, cert, control = await drifted(client, app, clock, tls_device, fail=True)
    control.mode = "succeed"
    await sign_in(page)
    row = page.locator(f'[data-device-id="{device["id"]}"]')
    await expect(row.get_by_test_id("state-badge")).to_have_attribute("data-state", "DRIFT_DETECTED")

    await row.get_by_role("button", name="Redeploy Now").click()
    terminal = page.get_by_test_id("terminal")
    await expect(terminal).to_have_attribute("aria-hidden", "false")
    await expect(page.get_by_test_id("terminal-status")).to_have_text("Succeeded")
    output = page.get_by_test_id("terminal-output")
    await expect(output).to_contain_text("Deployment verified")
    await expect(output.locator("span.text-green-400", has_text="upload complete")).to_be_visible()  # ANSI colour
    await expect(output).not_to_contain_text(DEVICE_PASSWORD)
    await expect(row.get_by_test_id("state-badge")).to_have_attribute("data-state", "IN_SYNC")
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]

    await page.get_by_role("button", name="Close").click()
    await expect(terminal).to_have_attribute("aria-hidden", "true")


async def test_failed_redeploy_shows_the_reason(client, app, clock, page, tls_device):
    device, _, _ = await drifted(client, app, clock, tls_device, fail=True)
    await sign_in(page)
    await page.locator(f'[data-device-id="{device["id"]}"]').get_by_role("button", name="Redeploy Now").click()
    await expect(page.get_by_test_id("terminal-status")).to_contain_text("Failed: Plugin reported the Deployment failed")


async def test_device_page_shows_history_and_resets_deploy_failed(client, app, clock, scheduler, page, tls_device):
    device, cert, control = await drifted(client, app, clock, tls_device, fail=True)
    await scheduler.advance(timedelta(hours=8))  # two retries fail -> Deploy Failed
    await settle(app)

    await sign_in(page)
    await page.get_by_role("link", name="HP M283fdw").click()
    await expect(page).to_have_url(f"/devices/{device['id']}")
    await expect(page.get_by_role("heading", name="HP M283fdw")).to_be_visible()
    await expect(page.get_by_test_id("state-badge")).to_have_text("Deploy Failed")
    await expect(page.get_by_test_id("deploy-failures")).to_have_text("3")

    history = page.get_by_test_id("deployment")
    await expect(history).to_have_count(4)
    await expect(history.first).to_contain_text("Retry")
    await expect(history.first).to_contain_text("Failed")
    await expect(history.last).to_contain_text("Manual")
    await expect(history.last).to_contain_text("Succeeded")
    await history.last.locator("summary").click()
    await expect(history.last).to_contain_text("login admin:[REDACTED]")

    control.mode = "succeed"
    await page.get_by_role("button", name="Redeploy Now").click()
    await expect(page.get_by_test_id("terminal-status")).to_have_text("Succeeded")
    await page.get_by_role("button", name="Close").click()
    await expect(page.get_by_test_id("state-badge")).to_have_text("In Sync")
    await expect(page.get_by_test_id("deploy-failures")).to_have_text("0")
    await expect(page.get_by_test_id("presented-fingerprint")).to_have_text(cert["fingerprint_sha256"])
    await expect(history).to_have_count(5)
