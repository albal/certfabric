import stat

import pytest

from certfabric.plugins.base import DeviceCredentials, PluginError
from certfabric.plugins.contract import PluginContract, make_certificate
from certfabric.plugins.generic_ssh_hook.plugin import GenericSshHookPlugin
from tests.fakes import ssh_device
from tests.fakes.certs import fingerprint
from tests.fakes.ssh_device import FakeSshDevice


@pytest.fixture
async def simulator(tmp_path):
    device = await FakeSshDevice(tmp_path / "server").start()
    yield device
    await device.stop()


@pytest.fixture
def good_credentials():
    return DeviceCredentials(username=ssh_device.USERNAME, password=ssh_device.PASSWORD)


@pytest.fixture
def bad_credentials():
    return DeviceCredentials(username=ssh_device.USERNAME, password="wrong-password-xyz")


@pytest.fixture
def make_plugin(simulator):
    def make(credentials, log, **options):
        return GenericSshHookPlugin(
            simulator.tls.host,
            simulator.tls.port,
            credentials,
            options=simulator.options(**options),
            log=log,
        )

    return make


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return fingerprint(simulator.tls.cert_pem)

    return served


class TestGenericSshHookContract(PluginContract):
    pass


async def test_private_key_is_written_with_0600(simulator, make_plugin, good_credentials):
    cert = make_certificate()
    await make_plugin(good_credentials, print).deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
    mode = (simulator.root / "etc" / "tls" / "key.pem").stat().st_mode
    assert stat.S_IMODE(mode) == 0o600
    assert (simulator.root / "etc" / "tls" / "fullchain.pem").read_text() == cert.fullchain_pem


async def test_failing_reload_command_fails_the_deployment(simulator, make_plugin, good_credentials):
    from certfabric.plugins.base import PluginError

    cert = make_certificate()
    plugin = make_plugin(good_credentials, print, reload_command="systemctl reload nginx")
    with pytest.raises(PluginError, match="status 127"):
        await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)


async def test_unwritable_path_names_the_file_and_user(simulator, make_plugin, good_credentials):
    locked = simulator.root / "etc" / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    plugin = make_plugin(good_credentials, print, key_path="/etc/locked/device.key")
    cert = make_certificate()
    with pytest.raises(PluginError, match=f"/etc/locked/device.key as {ssh_device.USERNAME}"):
        await plugin.deploy_certificate(cert.cert_pem, cert.key_pem, cert.fullchain_pem, b"", None)
    locked.chmod(0o755)


async def test_pinned_host_key_is_enforced(simulator, make_plugin, good_credentials):
    import asyncssh

    pinned = make_plugin(good_credentials, print, ssh_host_key=simulator.public_host_key)
    assert (await pinned.test_connection()).success
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    wrong = make_plugin(good_credentials, print, ssh_host_key=other)
    result = await wrong.test_connection()
    assert not result.success
    assert "host key" in result.message


async def test_unpinned_host_key_is_logged(simulator, make_plugin, good_credentials):
    lines = []
    await make_plugin(good_credentials, lines.append).test_connection()
    assert any("not pinned" in line for line in lines)
