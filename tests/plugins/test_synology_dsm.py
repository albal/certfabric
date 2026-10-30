import pytest

from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.plugins.contract import PluginContract, make_certificate
from certfabric.plugins.synology_dsm.plugin import SynologyDsmPlugin
from tests.fakes import synology
from tests.fakes.certs import fingerprint
from tests.fakes.synology import FakeSynology

GOOD = DeviceCredentials(username=synology.USERNAME, password=synology.PASSWORD)


@pytest.fixture
async def simulator():
    device = await FakeSynology().start()
    yield device
    await device.stop()


@pytest.fixture
def make_plugin(simulator):
    def make(credentials, log, **options):
        return SynologyDsmPlugin(
            simulator.host, simulator.port, credentials, options={"verify_timeout": 0.5, **options}, log=log
        )

    return make


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return fingerprint(simulator.https.cert_pem)

    return served


class TestSynologyDsm(PluginContract):
    @pytest.fixture
    def good_credentials(self):
        return GOOD

    @pytest.fixture
    def bad_credentials(self):
        return DeviceCredentials(username=synology.USERNAME, password="wrong-password")


async def deploy(plugin):
    cert = make_certificate("nas.lan.example.com")
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
    return cert


async def test_replaces_the_default_certificate_in_place(simulator, make_plugin):
    lines = []
    plugin = make_plugin(GOOD, lines.append)
    cert = await deploy(plugin)
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert [c.id for c in simulator.certificates] == [synology.FACTORY_ID]
    stored = simulator.by_id(synology.FACTORY_ID)
    assert stored.is_default and stored.desc == synology.FACTORY_DESC
    assert any("restarting its web server" in line for line in lines)


async def test_sends_the_leaf_and_intermediates_separately(simulator, make_plugin):
    cert = await deploy(make_plugin(GOOD, print))
    stored = simulator.by_id(synology.FACTORY_ID)
    assert stored.cert_pem == cert.cert_pem
    assert stored.inter_pem.strip() == cert.fullchain_pem.removeprefix(cert.cert_pem).strip()


async def test_description_selects_a_certificate_and_leaves_the_default_alone(simulator, make_plugin):
    simulator.add_certificate("other", "Reverse proxy")
    await deploy(make_plugin(GOOD, print, description="Reverse proxy"))
    assert simulator.by_id("other").cert_pem
    assert not simulator.by_id("other").is_default
    assert simulator.by_id(synology.FACTORY_ID).is_default


async def test_unknown_description_adds_a_new_default(simulator, make_plugin):
    plugin = make_plugin(GOOD, print, description="Fresh")
    assert "will add" in (await plugin.test_connection()).message
    cert = await deploy(plugin)
    assert [c.desc for c in simulator.certificates if c.is_default] == ["Fresh"]
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)


async def test_adds_a_default_when_dsm_has_none(simulator, make_plugin):
    simulator.by_id(synology.FACTORY_ID).is_default = False
    await deploy(make_plugin(GOOD, print))
    assert [c.desc for c in simulator.certificates if c.is_default] == ["CertFabric"]


async def test_connection_names_the_certificate_it_will_replace(make_plugin):
    result = await make_plugin(GOOD, print).test_connection()
    assert result.success and synology.FACTORY_DESC in result.message


@pytest.mark.parametrize(
    ("username", "message"),
    [
        (synology.TWO_FACTOR_USERNAME, "2-factor"),
        (synology.PLAIN_USERNAME, "not an administrator"),
        ("nobody", "username or password"),
    ],
)
async def test_explains_why_an_account_cannot_be_used(make_plugin, username, message):
    result = await make_plugin(DeviceCredentials(username=username, password=synology.PASSWORD), print).test_connection()
    assert not result.success and message in result.message


async def test_reports_a_device_that_is_not_dsm(simulator, make_plugin):
    simulator.not_dsm = True
    result = await make_plugin(GOOD, print).test_connection()
    assert not result.success and "Synology DSM" in result.message


async def test_points_at_the_https_port_when_given_the_redirect_port(simulator, make_plugin):
    simulator.redirect_only = True
    result = await make_plugin(GOOD, print).test_connection()
    assert not result.success
    assert result.message == f"Port {simulator.port} is DSM's redirect page; set the Device's port to 5001"


async def test_import_failure_fails_the_deployment_and_logs_out(simulator, make_plugin):
    simulator.import_error = 5536
    with pytest.raises(PluginError, match="5536"):
        await deploy(make_plugin(GOOD, print))
    assert simulator.open_sessions == 0


async def test_logs_out_after_a_deployment(simulator, make_plugin):
    await deploy(make_plugin(GOOD, print))
    assert simulator.logins == 1 and simulator.open_sessions == 0


async def test_a_failed_logout_does_not_fail_the_deployment(simulator, make_plugin):
    simulator.fail_logout = True
    lines = []
    plugin = make_plugin(GOOD, lines.append)
    cert = await deploy(plugin)
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert any("Could not log out" in line for line in lines)
