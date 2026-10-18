"""Test Plugin: deploys to a FakeTlsDevice in-process, behaving as fake_device_control says."""

from __future__ import annotations

import asyncio

from certfabric.plugins.base import BaseDevicePlugin, PluginError, PluginValidationResult
from tests.fakes.fake_device_control import CONTROLS


class FakeDevicePlugin(BaseDevicePlugin):
    plugin_id = "fake_device"
    plugin_name = "Fake device"
    target_category = "generic"
    supported_models = ["FakeTlsDevice"]

    async def test_connection(self) -> PluginValidationResult:
        control = CONTROLS[self.port]
        if control.bad_credentials:
            return PluginValidationResult(success=False, message="Login rejected")
        return PluginValidationResult(success=True, message="Fake login ok")

    async def deploy_certificate(self, cert_pem, privkey_pem, fullchain_pem, pfx_bundle, pfx_password) -> bool:
        control = CONTROLS[self.port]
        control.deploys += 1
        # Deliberately noisy, so tests can prove the engine redacts what Plugins log.
        self.log(f"login {self.credentials.username}:{self.credentials.password} pfx={pfx_password}")
        if control.delay:
            await asyncio.sleep(control.delay)
        if control.mode == "fail":
            return False
        if control.mode == "raise":
            raise PluginError("Device rejected the upload")
        if control.mode == "succeed":
            control.device.present(cert_pem, privkey_pem)
            self.log("\x1b[32mupload complete\x1b[0m")
        return True

    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        return await self.served_fingerprint() == expected_fingerprint
