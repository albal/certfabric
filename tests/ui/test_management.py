from playwright.async_api import expect

from tests.conftest import CF_TOKEN, DEVICE_PASSWORD, issue_certificate, settle
from tests.fakes.certs import fingerprint
from tests.fakes.webhook_receiver import WebhookReceiver
from tests.ui.conftest import sign_in


async def nav(page, name):
    await page.get_by_role("navigation").get_by_role("link", name=name).click()


async def test_dns_providers_are_managed_and_secrets_masked(client, page):
    await sign_in(page)
    await nav(page, "DNS Providers")
    await page.get_by_role("button", name="Add DNS Provider").click()
    form = page.get_by_role("form", name="New DNS Provider")
    await form.get_by_label("Name", exact=True).fill("Cloudflare")
    await form.get_by_label("Credentials value 1").fill(CF_TOKEN)
    await form.get_by_role("button", name="Add DNS Provider").click()

    row = page.get_by_test_id("dns-provider")
    await expect(row).to_contain_text("Cloudflare")
    await expect(row.get_by_test_id("masked-credentials")).to_contain_text("CF_Token=")
    await expect(page.get_by_test_id("dns-providers")).not_to_contain_text(CF_TOKEN)

    await row.get_by_role("button", name="Edit").click()
    await page.get_by_role("form", name="Edit Cloudflare").get_by_label("Name", exact=True).fill("CF prod")
    await page.get_by_role("button", name="Save").click()
    await expect(row).to_contain_text("CF prod")
    assert (await client.get("/api/dns-providers")).json()[0]["credentials"]["CF_Token"].endswith(CF_TOKEN[-4:])


async def test_in_use_dns_provider_cannot_be_deleted(client, page):
    await issue_certificate(client, ["a.lan.example.com"])
    await sign_in(page)
    await nav(page, "DNS Providers")
    await page.get_by_test_id("dns-provider").get_by_role("button", name="Delete").click()
    await expect(page.get_by_role("alert")).to_contain_text("used by a Certificate")


async def test_request_a_certificate(client, app, page):
    await client.post("/api/dns-providers", json={"name": "CF", "acme_dns_type": "dns_cf", "credentials": {"CF_Token": CF_TOKEN}})
    await sign_in(page)
    await nav(page, "Certificates")
    await expect(page.get_by_test_id("renewal-info")).to_contain_text("28 days")
    await page.get_by_role("button", name="Request Certificate").click()
    form = page.get_by_role("form", name="Request a Certificate")
    await form.get_by_label("Domains").fill("*.lan.example.com\nlan.example.com")
    await form.get_by_label("Key type").select_option("ECDSA_P256")
    await form.get_by_role("button", name="Request Certificate").click()
    await expect(page.get_by_test_id("terminal-status")).to_have_text("Succeeded")
    await expect(page.get_by_test_id("terminal-output")).not_to_contain_text(CF_TOKEN)
    await page.get_by_role("button", name="Close").click()
    row = page.get_by_test_id("certificate-row")
    await expect(row).to_contain_text("*.lan.example.com")
    await expect(row).to_contain_text("ECDSA_P256")
    await expect(row).to_contain_text("VALID")


async def test_add_test_and_assign_a_device(client, app, page, tls_device):
    other = await issue_certificate(client, ["nas.other.example.com"])
    cert = await issue_certificate(client, ["*.lan.example.com"])
    await sign_in(page)
    await page.get_by_role("link", name="Add Device").click()
    await page.get_by_label("Name", exact=True).fill("Office printer")
    await page.get_by_label("Plugin").select_option("fake_device")
    await expect(page.get_by_test_id("plugin-models")).to_contain_text("FakeTlsDevice")
    await page.get_by_label("Hostname or IP").fill(tls_device.host)
    await page.get_by_label("Port").fill(str(tls_device.port))
    await page.get_by_label("TLS name (SNI)").fill("printer.lan.example.com")
    await page.get_by_label("Username").fill("admin")
    await page.get_by_label("Password", exact=True).fill(DEVICE_PASSWORD)

    await page.get_by_role("button", name="Test connection").click()
    await expect(page.get_by_test_id("test-result")).to_have_text("✓ Fake login ok")

    await page.get_by_label("Assign a Certificate").select_option(cert["id"])
    await page.get_by_role("button", name="Add Device").click()
    await expect(page.get_by_role("heading", name="Office printer")).to_be_visible()
    devices = (await client.get("/api/devices")).json()
    assert devices[0]["assigned_certificate_id"] == cert["id"]
    assert devices[0]["credentials"]["password"] != DEVICE_PASSWORD

    # Assigning a Certificate that does not cover the Device is refused with the reason.
    await page.get_by_label("Managed Certificate").select_option(other["id"])
    await page.get_by_role("button", name="Assign").click()
    await expect(page.get_by_role("alert")).to_contain_text("does not cover printer.lan.example.com")

    await page.get_by_role("button", name="Redeploy Now").click()
    await expect(page.get_by_test_id("terminal-status")).to_have_text("Succeeded")
    assert fingerprint(tls_device.cert_pem) == cert["fingerprint_sha256"]


async def test_edit_a_device_keeps_secrets_unless_changed(client, page, tls_device):
    from tests.conftest import create_device

    device = await create_device(client, tls_device, name="Switch")
    await sign_in(page)
    await page.goto(f"/devices/{device['id']}/edit")
    await expect(page.get_by_label("Password", exact=True)).to_have_value("")
    await page.get_by_label("Name", exact=True).fill("Core switch")
    await page.get_by_label("Probe interval (minutes)").fill("60")
    await page.get_by_role("button", name="Save Device").click()
    await expect(page.get_by_role("heading", name="Core switch")).to_be_visible()
    saved = (await client.get(f"/api/devices/{device['id']}")).json()
    assert saved["polling_interval_minutes"] == 60
    assert saved["credentials"]["password"] is not None  # untouched


async def test_webhooks_are_managed_and_tested(client, app, page):
    receiver = await WebhookReceiver().start()
    try:
        await sign_in(page)
        await nav(page, "Webhooks")
        await page.get_by_label("URL").fill("ftp://nope")
        await page.get_by_role("button", name="Add", exact=True).click()
        await expect(page.get_by_role("alert")).to_be_visible()
        await page.get_by_label("URL").fill(receiver.url)
        await page.get_by_role("button", name="Add", exact=True).click()
        await expect(page.get_by_test_id("webhook")).to_contain_text(receiver.url)
        await page.get_by_role("button", name="Send test event").click()
        await expect(page.get_by_role("status")).to_contain_text("Test event sent")
        await settle(app)
        assert [e["event"] for e in receiver.events] == ["test"]
        await page.get_by_test_id("webhook").get_by_role("button", name="Delete").click()
        await expect(page.get_by_test_id("webhook")).to_have_count(0)
    finally:
        await receiver.stop()


async def test_settings_and_schedule(client, page):
    await sign_in(page)
    await nav(page, "Settings")
    await expect(page.get_by_test_id("next-renewal-check")).not_to_have_text("—")
    await page.get_by_label("Use the staging CA").check()
    await page.get_by_label("Renew this many days before expiry").fill("21")
    await page.get_by_role("button", name="Save settings").click()
    await expect(page.get_by_role("status")).to_have_text("Saved.")
    assert (await client.get("/api/settings")).json() == {
        "acme_ca": "letsencrypt",
        "acme_use_staging": True,
        "renewal_threshold_days": 21,
    }
    await page.get_by_label("ACME CA").select_option("custom")
    await page.get_by_label("ACME directory URL").fill("http://insecure")
    await page.get_by_role("button", name="Save settings").click()
    await expect(page.get_by_role("alert")).to_be_visible()
