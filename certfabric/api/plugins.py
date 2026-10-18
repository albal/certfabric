"""Installed Plugins."""

from __future__ import annotations

import sys

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/plugins", tags=["plugins"])


class PluginOut(BaseModel):
    plugin_id: str
    plugin_name: str
    target_category: str
    supported_models: list[str]
    description: str | None


@router.get("")
async def list_plugins(request: Request) -> list[PluginOut]:
    return [
        PluginOut(
            plugin_id=cls.plugin_id,
            plugin_name=cls.plugin_name,
            target_category=cls.target_category,
            supported_models=cls.supported_models,
            description=sys.modules[cls.__module__].__doc__,
        )
        for cls in request.app.state.plugins.all()
    ]
