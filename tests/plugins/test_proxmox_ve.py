import pytest

from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.plugins.contract import PluginContract, make_certificate
from certfabric.plugins.proxmox_ve.plugin import ProxmoxVePlugin
from tests.fakes import proxmox, ssh_device
from tests.fakes.certs import fingerprint
from tests.fakes.proxmox import FakeProxmox


@pytest.fixture
async def simulator(tmp_path):
    device = await FakeProxmox(tmp_path / "pve").start()
    yield device
    await device.stop()


@pytest.fixture
def make_plugin(simulator):
    def make(credentials, log, **options):
        return ProxmoxVePlugin(
            simulator.host,
            simulator.port,
            credentials,
            options={"ssh_port": simulator.ssh.ssh_port, "ssh_username": ssh_device.USERNAME, "verify_timeout": 0.5, **options},
            log=log,
        )

    return make


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return fingerprint(simulator.https.cert_pem)

    return served


@pytest.fixture
def bad_credentials():
    return DeviceCredentials(username=proxmox.USERNAME, password="wrong-password")


class TestProxmoxWithPassword(PluginContract):
    @pytest.fixture
    def good_credentials(self):
        return DeviceCredentials(username=proxmox.USERNAME, password=proxmox.PASSWORD)


class TestProxmoxWithApiToken(PluginContract):
    @pytest.fixture
    def good_credentials(self):
        return DeviceCredentials(username=proxmox.TOKEN_USER, api_token=proxmox.TOKEN_SECRET)


async def deploy(plugin):
    cert = make_certificate("pve1.lan.example.com")
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
    return cert


async def test_uses_the_api_and_discovers_the_node(simulator, make_plugin):
    plugin = make_plugin(DeviceCredentials(username=proxmox.TOKEN_USER, api_token=proxmox.TOKEN_SECRET), print)
    result = await plugin.test_connection()
    assert result.details == {"version": "8.2.4", "node": "pve1"}
    cert = await deploy(plugin)
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert simulator.ssh.commands == []
    assert any(r.path.endswith("/certificates/custom") for r in simulator.https.requests)


async def test_falls_back_to_ssh_when_the_api_is_unreachable(simulator, make_plugin):
    await simulator.https.stop()
    creds = DeviceCredentials(
        username=proxmox.TOKEN_USER, api_token=proxmox.TOKEN_SECRET, extra={"ssh_password": ssh_device.PASSWORD}
    )
    lines = []
    plugin = make_plugin(creds, lines.append)
    cert = make_certificate()
    assert await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
    assert any("falling back to SSH" in line for line in lines)
    assert simulator.ssh.commands and simulator.ssh.commands[0].startswith("pvenode cert set")
    await simulator.https.start()
    assert await plugin.post_deployment_verify(cert.fingerprint_sha256)
    assert list((simulator.ssh.root / "tmp").glob("certfabric-*")) == []  # temp files cleaned up


async def test_no_fallback_without_ssh_credentials(simulator, make_plugin):
    await simulator.https.stop()
    plugin = make_plugin(DeviceCredentials(username=proxmox.USERNAME, password=proxmox.PASSWORD), print)
    cert = make_certificate()
    with pytest.raises(PluginError, match="no SSH fallback"):
        await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
