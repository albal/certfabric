"""How stored secrets are shown back to the admin: never in full."""

from __future__ import annotations

MASK = "••••••••"


def mask(value: str) -> str:
    """Show only the last four characters of a long secret, nothing of a short one."""
    return MASK + value[-4:] if len(value) >= 12 else MASK


def mask_all(credentials: dict[str, str]) -> dict[str, str]:
    return {key: mask(value) for key, value in credentials.items()}
