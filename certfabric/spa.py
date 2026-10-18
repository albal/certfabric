"""Serves the built React dashboard. The page itself is public; everything it calls is not."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

PACKAGED_DIR = Path(__file__).parent / "static"
SOURCE_TREE_DIR = Path(__file__).parent.parent / "frontend" / "dist"
SPA_PATH = "/{path:path}"


def find_dist(configured: Path | None) -> Path | None:
    for candidate in (configured, PACKAGED_DIR, SOURCE_TREE_DIR):
        if candidate and (candidate / "index.html").is_file():
            return candidate
    return None


def mount(app: FastAPI, dist: Path) -> None:
    root = dist.resolve()

    @app.get(SPA_PATH, include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        if path.startswith(("api/", "ws/")):
            raise HTTPException(404)
        candidate = (root / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(root / "index.html")  # client-side routes
