"""A stand-in for `acme.sh --issue`, driven by a JSON control file.

It parses the same arguments CertFabric passes, signs a leaf for the requested domains
with a throwaway CA, writes the files where asked, and records each invocation.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _parse(argv: list[str]) -> dict:
    parsed: dict = {"domains": []}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "-d":
            parsed["domains"].append(argv[i + 1])
            i += 2
        elif arg in ("--issue", "--force"):
            parsed[arg.lstrip("-")] = True
            i += 1
        else:
            parsed[arg.lstrip("-")] = argv[i + 1]
            i += 2
    return parsed


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def main() -> int:
    control = json.loads(Path(os.environ["FAKE_ACME_CONTROL"]).read_text())
    args = _parse(sys.argv[1:])
    with open(control["invocations"], "a") as log:
        env = {k: v for k, v in os.environ.items() if k not in ("FAKE_ACME_CONTROL",)}
        log.write(json.dumps({"argv": sys.argv[1:], "args": args, "env": env}) + "\n")

    print(f"[fake acme.sh] Using CA {args.get('server')}")
    for name in control.get("echo_env", []):
        print(f"[fake acme.sh] {name}='{os.environ.get(name, '')}'")
    if control.get("fail"):
        print("[fake acme.sh] Verify error: DNS problem: NXDOMAIN looking up TXT", flush=True)
        return 1

    now = datetime.fromisoformat(control["now"])
    if args["keylength"] == "ec-256":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=int(args["keylength"]))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake ACME Intermediate")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args["domains"][0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=control.get("validity_days", 90)))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in args["domains"]]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    if control.get("print_key"):
        print(key_pem)
    Path(args["cert-file"]).write_text(_pem(leaf))
    Path(args["key-file"]).write_text(key_pem)
    Path(args["fullchain-file"]).write_text(_pem(leaf) + _pem(ca))
    print(f"[fake acme.sh] Cert success for {', '.join(args['domains'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
