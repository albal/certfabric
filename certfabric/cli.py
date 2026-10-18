"""Command-line entry point: `certfabric serve`, `certfabric generate-key`."""

from __future__ import annotations

import argparse
import sys

from cryptography.fernet import Fernet

from certfabric.config import ConfigError, load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="certfabric")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Run the CertFabric server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)
    sub.add_parser("generate-key", help="Print a new secret key")
    args = parser.parse_args(argv)

    if args.command == "generate-key":
        print(Fernet.generate_key().decode())
        return 0

    try:
        load_settings()
    except ConfigError as exc:
        print(f"certfabric: {exc}", file=sys.stderr)
        return 1

    import uvicorn

    uvicorn.run("certfabric.app:create_app_from_env", factory=True, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
