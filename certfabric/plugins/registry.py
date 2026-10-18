"""Discovers Plugins from `<dir>/<plugin_name>/plugin.py` on local disk. Nothing is loaded remotely."""

from __future__ import annotations

import importlib.util
import inspect
import logging
import re
import sys
from pathlib import Path

from certfabric.plugins.base import TARGET_CATEGORIES, BaseDevicePlugin

log = logging.getLogger(__name__)

BUILTIN_DIR = Path(__file__).parent
_PLUGIN_ID = re.compile(r"^[a-z0-9_]+$")


class PluginLoadError(Exception):
    pass


def _load_module(path: Path) -> object:
    name = f"certfabric_plugin_{path.parent.name}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _check(cls: type[BaseDevicePlugin], path: Path) -> None:
    for attr in ("plugin_id", "plugin_name", "target_category", "supported_models"):
        if not hasattr(cls, attr):
            raise PluginLoadError(f"{path}: {cls.__name__} is missing {attr}")
    if not _PLUGIN_ID.match(cls.plugin_id):
        raise PluginLoadError(f"{path}: plugin_id {cls.plugin_id!r} must match {_PLUGIN_ID.pattern}")
    if cls.target_category not in TARGET_CATEGORIES:
        raise PluginLoadError(f"{path}: target_category must be one of {TARGET_CATEGORIES}")


class PluginRegistry:
    def __init__(self, directories: list[Path]) -> None:
        self._plugins: dict[str, type[BaseDevicePlugin]] = {}
        for directory in directories:
            self._scan(directory)

    def _scan(self, directory: Path) -> None:
        for path in sorted(directory.glob("*/plugin.py")):
            module = _load_module(path)
            found = [
                cls
                for _, cls in inspect.getmembers(module, inspect.isclass)
                if issubclass(cls, BaseDevicePlugin)
                and cls is not BaseDevicePlugin
                and not inspect.isabstract(cls)
                and cls.__module__ == module.__name__  # type: ignore[attr-defined]
            ]
            for cls in found:
                _check(cls, path)
                if cls.plugin_id in self._plugins:
                    raise PluginLoadError(f"{path}: duplicate plugin_id {cls.plugin_id!r}")
                self._plugins[cls.plugin_id] = cls
                log.info("Loaded plugin %s from %s", cls.plugin_id, path)

    def get(self, plugin_id: str) -> type[BaseDevicePlugin] | None:
        return self._plugins.get(plugin_id)

    def all(self) -> list[type[BaseDevicePlugin]]:
        return sorted(self._plugins.values(), key=lambda cls: cls.plugin_id)
