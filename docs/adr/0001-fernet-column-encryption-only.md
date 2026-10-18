# Encrypt secrets with Fernet at the column level, not SQLCipher

The PRD diagram showed "SQLite + SQLCipher" while its spec called for column-level Fernet. We chose Fernet only: SQLCipher needs a native build on Raspberry Pi and LXC, and the unencrypted metadata (hostnames, fingerprints) is already visible on the LAN. The key comes from `CERTFABRIC_SECRET_KEY`, and a `certfabric rotate-key` command re-encrypts everything under a new one.

## Consequences

- Losing the key makes every DNS token, Device password and private key unreadable; there is no escrow.
- The database file itself is not encrypted.
