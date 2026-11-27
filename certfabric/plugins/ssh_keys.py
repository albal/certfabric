"""Importing an SSH private key that a person pasted into the dashboard.

A single-line field drops the line breaks of a pasted key, leaving
`-----BEGIN OPENSSH PRIVATE KEY-----b3Bl...-----END OPENSSH PRIVATE KEY-----`,
which asyncssh rejects with "Missing PEM footer". Keys stored that way are
repaired here, so they work without being re-entered.
"""

from __future__ import annotations

import re
import textwrap

import asyncssh

from certfabric.plugins.base import PluginError

_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


def normalise_pem(text: str) -> str:
    """`text` with each PEM block's header, base64 body and footer on lines of their own."""
    match = _PEM_BLOCK.search(text)
    if not match or ":" in match.group(2):
        return text  # not PEM, or a legacy key with Proc-Type headers that cannot be rebuilt
    label, body = match.group(1), "".join(match.group(2).split())
    return f"-----BEGIN {label}-----\n" + "\n".join(textwrap.wrap(body, 64)) + f"\n-----END {label}-----\n"


def import_ssh_private_key(text: str) -> asyncssh.SSHKey:
    try:
        return asyncssh.import_private_key(normalise_pem(text))
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise PluginError(f"ssh_private_key is not a usable private key: {exc}") from None
