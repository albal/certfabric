# Writing a Plugin

A Plugin teaches CertFabric how to install a Certificate on one kind of Device. It is one Python file.

> **Trust boundary.** A Plugin runs in-process with CertFabric and receives decrypted credentials and the private key. CertFabric loads Plugins only from directories on local disk and does not sandbox them. Users should install only Plugins they have read, so keep yours short and readable.

## Where Plugins live

CertFabric loads every `<directory>/<plugin_id>/plugin.py` from its built-in Plugins and from each directory in `CERTFABRIC_PLUGINS_DIR` (`/app/plugins` in the Docker image, `/opt/certfabric-plugins` in the LXC install). Restart CertFabric after adding one.

## The contract

Subclass `BaseDevicePlugin` and implement three methods:

```python
from certfabric.plugins.base import BaseDevicePlugin, PluginError, PluginValidationResult


class AcmeSwitchPlugin(BaseDevicePlugin):
    """Shown to the admin in the Add Device form: document credentials and options here."""

    plugin_id = "acme_switch"            # lowercase letters, digits, underscores; unique
    plugin_name = "Acme managed switch"
    target_category = "network"          # printer, bmc, hypervisor, network or generic
    supported_models = ["Acme SW-24"]
    pfx_include_chain = True             # False if the device rejects chains in PKCS#12

    async def test_connection(self) -> PluginValidationResult:
        """Check reachability, credentials and compatibility. Never raise; report."""

    async def deploy_certificate(self, cert_pem, privkey_pem, fullchain_pem, pfx_bundle, pfx_password) -> bool:
        """Upload and activate. Return False or raise PluginError on failure."""

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """Return True once the device serves the new certificate."""
        return await self.served_fingerprint() == expected_fingerprint
```

Available on `self`:

| Attribute | Meaning |
| --- | --- |
| `host`, `port`, `sni` | Where the Device is and the name it serves |
| `credentials` | `username`, `password`, `api_token`, `pfx_passphrase`, and `extra` (a dict of further secrets) |
| `options` | Non-secret settings the admin entered (dict) |
| `log(line)` | Write to the Deployment log; known secrets are redacted, but avoid logging them anyway |
| `served_fingerprint()` | Probe the Device's TLS port and return the SHA-256 it serves |

Guidelines:

- The Device's current certificate is the one you are replacing, so its TLS cannot be verified: connect with verification off.
- Devices often restart their web server after an upload; poll in `post_deployment_verify` with a timeout taken from `options`.
- Raise `PluginError("message for the admin")` for expected failures. Anything else is reported as a Plugin crash.
- `pfx_bundle` is protected by `pfx_password`, a fresh passphrase for each Deployment unless the Device has a fixed one.

## Testing with the contract suite

`certfabric.plugins.contract.PluginContract` checks the behaviour every Plugin must have: metadata, connection checks with good and bad credentials, deploy plus verify, rejecting the wrong fingerprint, failing cleanly, and never logging secrets. Point it at a simulator of your device:

```python
import pytest

from certfabric.plugins.base import DeviceCredentials
from certfabric.plugins.contract import PluginContract
from acme_switch.plugin import AcmeSwitchPlugin


@pytest.fixture
async def simulator():
    ...  # start a fake device; it must start serving what it receives


@pytest.fixture
def make_plugin(simulator):
    return lambda credentials, log: AcmeSwitchPlugin(simulator.host, simulator.port, credentials, log=log)


@pytest.fixture
def good_credentials():
    return DeviceCredentials(username="admin", password="right")


@pytest.fixture
def bad_credentials():
    return DeviceCredentials(username="admin", password="wrong")


@pytest.fixture
def served_fingerprint(simulator):
    async def served():
        return simulator.current_fingerprint()
    return served


class TestAcmeSwitch(PluginContract):
    pass
```

Run it with `pytest` and `pytest-asyncio` (`asyncio_mode = "auto"`). The built-in Plugins' tests in `tests/plugins/` are worked examples, with simulators in `tests/fakes/`.
