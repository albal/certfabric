import pytest

from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.plugins.contract import PluginContract, make_certificate
from certfabric.plugins.dell_idrac_redfish.plugin import DellIdracRedfishPlugin
from tests.fakes import idrac
from tests.fakes.certs import fingerprint
from tests.fakes.idrac import FakeIdrac


@pytest.fixture
async def simulator():
    device = await FakeIdrac().start()
    yield device
    await device.stop()


@pytest.fixture
def make_plugin(simulator):
    def make(credentials, log, **options):
        return DellIdracRedfishPlugin(
            simulator.host, simulator.port, credentials, options={"verify_timeout": 0.5, **options}, log=log
        )

    return make


@pytest.fixture
def good_credentials():
    return DeviceCredentials(username=idrac.USERNAME, password=idrac.PASSWORD)


@pytest.fixture
def bad_credentials():
    return DeviceCredentials(username=idrac.USERNAME, password="calvin")


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return fingerprint(simulator.https.cert_pem)

    return served


class TestIdracContract(PluginContract):
    pass


async def test_reports_model_and_firmware(make_plugin, good_credentials):
    result = await make_plugin(good_credentials, print).test_connection()
    assert result.details == {"model": "14G Monolithic", "firmware": "7.00.00.171"}


async def test_imports_pkcs12_with_chain_then_resets(simulator, make_plugin, good_credentials):
    cert = make_certificate("idrac.lan.example.com")
    plugin = make_plugin(good_credentials, print)
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw-123"), "pw-123")
    assert simulator.resets == 1
    assert fingerprint(simulator.https.cert_pem) == cert.fingerprint_sha256


async def test_without_reset_the_cert_is_not_served_yet(simulator, make_plugin, good_credentials):
    cert = make_certificate()
    plugin = make_plugin(good_credentials, print, reset=False)
    await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
    assert simulator.resets == 0
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256) is False


async def test_import_errors_are_reported(make_plugin, good_credentials):
    cert = make_certificate()
    plugin = make_plugin(good_credentials, print)
    with pytest.raises(PluginError, match="invalid file or passphrase"):
        await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("right"), "wrong")


async def test_works_with_older_idrac_tls(good_credentials):
    """iDRAC 8 firmware may offer only TLS 1.2 RSA/SHA-1 suites, which Python's defaults refuse."""
    device = await FakeIdrac(legacy_tls=True).start()
    try:
        plugin = DellIdracRedfishPlugin(device.host, device.port, good_credentials, options={"verify_timeout": 1}, log=print)
        assert (await plugin.test_connection()).success
        cert = make_certificate()
        assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
        assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    finally:
        await device.stop()


@pytest.fixture
async def idrac8():
    device = await FakeIdrac(model="13G Monolithic").start()
    yield device
    await device.stop()


def idrac8_plugin(device, credentials, **options):
    return DellIdracRedfishPlugin(
        device.host, device.port, credentials, options={"verify_timeout": 0.5, **options}, log=print
    )


async def test_idrac8_uploads_key_and_chain_over_racadm_then_resets(idrac8, good_credentials):
    """iDRAC 8 answers the Redfish import with 405, so the plugin must not use it."""
    cert = make_certificate("idrac.lan.example.com")
    plugin = idrac8_plugin(idrac8, good_credentials)
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, cert.pkcs12("pw"), "pw")
    assert idrac8.resets == 1
    assert idrac8.sessions == set()
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert "BEGIN RSA PRIVATE KEY" in idrac8.https.key_pem


async def test_idrac8_command_errors_are_reported(idrac8, good_credentials):
    cert = make_certificate()
    plugin = idrac8_plugin(idrac8, good_credentials)
    with pytest.raises(PluginError, match="Certificate upload failed: ERROR: Unable to allocate memory"):
        await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, "not a certificate", cert.pkcs12("pw"), "pw")
    assert idrac8.resets == 0
    assert idrac8.sessions == set()
