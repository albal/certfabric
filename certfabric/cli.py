"""Command-line entry point: `certfabric serve`, `generate-key`, `rotate-key`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from certfabric.config import ConfigError, load_settings, validate_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="certfabric")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the CertFabric server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    sub.add_parser("generate-key", help="Print a new secret key")
    rotate = sub.add_parser(
        "rotate-key",
        help="Re-encrypt every stored secret under a new key (stop the server first)",
        description="Reads the current key from CERTFABRIC_SECRET_KEY or CERTFABRIC_SECRET_KEY_FILE.",
    )
    new_key = rotate.add_mutually_exclusive_group(required=True)
    new_key.add_argument("--new-key-file", type=Path, help="File containing the new key")
    new_key.add_argument("--generate", action="store_true", help="Generate the new key and print it")
    args = parser.parse_args(argv)

    if args.command == "generate-key":
        print(Fernet.generate_key().decode())
        return 0
    if args.command == "rotate-key":
        return _rotate_key(args)

    try:
        load_settings()
    except ConfigError as exc:
        print(f"certfabric: {exc}", file=sys.stderr)
        return 1

    import uvicorn

    uvicorn.run("certfabric.app:create_app_from_env", factory=True, host=args.host, port=args.port)
    return 0


def _rotate_key(args: argparse.Namespace) -> int:
    from certfabric.keyrotation import RotationError, rotate

    try:
        settings = load_settings()
        new_key = Fernet.generate_key() if args.generate else args.new_key_file.read_bytes().strip()
        validate_key(new_key)
        result = rotate(settings.db_path, settings.secret_key, new_key)
    except (ConfigError, RotationError, OSError) as exc:
        print(f"certfabric: {exc}", file=sys.stderr)
        return 1
    print(f"Re-encrypted {result.rows} secrets in {settings.db_path}.", file=sys.stderr)
    if args.generate:
        print("New secret key (store it safely; the old key no longer works):", file=sys.stderr)
        print(new_key.decode())
    print("Update CERTFABRIC_SECRET_KEY or CERTFABRIC_SECRET_KEY_FILE before starting CertFabric.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
