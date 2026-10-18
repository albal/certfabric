import pytest

from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.plugins.contract import PluginContract, make_certificate
from certfabric.plugins.hp_pro_ews.plugin import HpProEwsPlugin
from certfabric.probe import probe
from certfabric.x509util import build_pkcs12, split_pem_chain
from tests.fakes import hp_printer
from tests.fakes.certs import fingerprint
from tests.fakes.hp_printer import FakeHpPrinter


@pytest.fixture
async def simulator():
    device = await FakeHpPrinter().start()
    yield device
    await device.stop()


@pytest.fixture
def make_plugin(simulator):
    def make(credentials, log, **options):
        return HpProEwsPlugin(
            simulator.host,
            simulator.port,
            credentials,
            options={"cycle_wait": 0, "verify_timeout": 0.3, **options},
            log=log,
        )

    return make


@pytest.fixture
def good_credentials():
    return DeviceCredentials(password=hp_printer.PASSWORD)


@pytest.fixture
def bad_credentials():
    return DeviceCredentials(password="12345678")


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return fingerprint(simulator.https.cert_pem)

    return served


class TestHpContract(PluginContract):
    pass


def test_asks_the_engine_for_a_leaf_only_bundle():
    assert HpProEwsPlugin.pfx_include_chain is False


def test_asks_the_engine_for_a_short_passphrase():
    assert HpProEwsPlugin.pfx_passphrase_max_length == 16


async def test_walks_the_emweb_certificate_wizard(simulator, make_plugin, good_credentials):
    cert = make_certificate("printer.lan.example.com")
    plugin = make_plugin(good_credentials, print)
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("one-time"), "one-time")
    assert simulator.uploads == 1
    assert [(r.method, r.path) for r in simulator.https.requests] == [
        ("GET", "/hp/device/set_config_networkCerts.html"),
        ("POST", "/hp/device/set_config_networkCerts.html/config"),
        ("POST", "/hp/device/set_config_networkPrintCerts.html/config"),
        ("GET", "/hp/device/set_config_networkCertsImport.html"),
        ("POST", "/hp/device/Certificate.pfx"),
    ]
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)


async def test_printer_without_an_admin_password(good_credentials):
    from certfabric.plugins.base import DeviceCredentials

    printer = await FakeHpPrinter(admin_password=None).start()
    try:
        plugin = HpProEwsPlugin(printer.host, printer.port, DeviceCredentials(), options={"cycle_wait": 0}, log=print)
        result = await plugin.test_connection()
        assert result.success, result.message
        assert "M283fdw" in result.message
        cert = make_certificate()
        assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
        assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    finally:
        await printer.stop()


async def test_not_an_emweb_printer(simulator, make_plugin, good_credentials):
    from tests.fakes.https_device import Response

    async def other(_request):
        return Response(404)

    simulator.https.handler = other
    result = await make_plugin(good_credentials, print).test_connection()
    assert not result.success
    assert "404" in result.message


async def test_printer_rejects_a_bundle_with_a_chain(make_plugin, good_credentials):
    cert = make_certificate()
    with_chain = build_pkcs12(cert.cert_pem, cert.key_pem, "pw", split_pem_chain(cert.fullchain_pem)[1:])
    with pytest.raises(PluginError, match="refused"):
        await make_plugin(good_credentials, print).deploy_certificate(
            cert.cert_pem, cert.key_pem, cert.fullchain_pem, with_chain, "pw"
        )


async def test_waits_for_the_daemon_to_cycle(make_plugin, good_credentials):
    import time

    cert = make_certificate()
    plugin = make_plugin(good_credentials, print, cycle_wait=0.3)
    await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
    started = time.monotonic()
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert time.monotonic() - started >= 0.3


async def test_end_to_end_through_the_engine(client, simulator):
    """The engine builds a leaf-only bundle with a fresh passphrase, which the printer accepts."""
    from tests.conftest import deploy, issue_certificate

    cert = await issue_certificate(client, ["printer.lan.example.com"])
    device = await client.post(
        "/api/devices",
        json={
            "name": "HP M283fdw",
            "hostname": simulator.host,
            "port": simulator.port,
            "sni": "printer.lan.example.com",
            "plugin_id": "hp_pro_ews",
            "plugin_options": {"cycle_wait": 0, "verify_timeout": 1},
            "credentials": {"password": hp_printer.PASSWORD},
            "certificate_id": cert["id"],
        },
    )
    job = await deploy(client, device.json()["id"])
    assert job["state"] == "succeeded", job
    assert fingerprint(simulator.https.cert_pem) == cert["fingerprint_sha256"]
    assert hp_printer.PASSWORD not in job["output"]


async def test_engine_refuses_a_fixed_passphrase_the_printer_cannot_take(client, simulator):
    from tests.conftest import deploy, issue_certificate

    cert = await issue_certificate(client, ["printer.lan.example.com"])
    device = await client.post(
        "/api/devices",
        json={
            "name": "HP",
            "hostname": simulator.host,
            "port": simulator.port,
            "sni": "printer.lan.example.com",
            "plugin_id": "hp_pro_ews",
            "credentials": {"password": hp_printer.PASSWORD, "pfx_passphrase": "x" * 17},
            "certificate_id": cert["id"],
        },
    )
    job = await deploy(client, device.json()["id"])
    assert job["state"] == "failed"
    assert "16 characters" in job["error"]
    assert simulator.uploads == 0


async def test_works_with_firmware_that_only_speaks_legacy_tls(make_plugin, good_credentials):
    """Regression: the M283fdw offers only TLS 1.2 RSA/SHA-1 suites, which Python's defaults refuse."""
    printer = await FakeHpPrinter(legacy_tls=True).start()
    try:
        plugin = HpProEwsPlugin(
            printer.host, printer.port, good_credentials, options={"cycle_wait": 0, "verify_timeout": 1}, log=print
        )
        result = await plugin.test_connection()
        assert result.success, result.message
        assert (await probe(printer.host, printer.port)).ok  # the Probe already coped
        cert = make_certificate("printer.lan.example.com")
        assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
        assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    finally:
        await printer.stop()
