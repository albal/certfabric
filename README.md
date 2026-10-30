# CertFabric

Self-hosted, agentless certificate lifecycle management for LAN and homelab devices that cannot do ACME themselves: printers, BMCs, hypervisors, NAS boxes, switches.

CertFabric issues certificates with [`acme.sh`](https://github.com/acmesh-official/acme.sh) using DNS-01, pushes them to each device through a hardware-specific **Plugin**, and keeps watching. A periodic **Probe** reads the certificate each device actually serves:

- serving the assigned Certificate: **In Sync**;
- serving an earlier CertFabric Certificate: **Outdated**, redeployed quietly;
- serving anything else (a factory certificate after a reset): **Drift**, redeployed and alarmed.

Certificates renew automatically 28 days before expiry (configurable) and are redeployed to every device that uses them. Failed Deployments are retried after 1 h, then 6 h, and stop after three failures in a row (**Deploy Failed**) until you intervene. Webhooks report Drift, Unreachable devices, Deploy Failed and failed renewals.

Vocabulary is defined in [`GLOSSARY.md`](GLOSSARY.md); how it fits together is in [`ARCHITECTURE.md`](ARCHITECTURE.md); design decisions are in [`docs/adr/`](docs/adr/) and [`PRD.md`](PRD.md).

## Built-in Plugins

| Plugin | Devices | How |
| --- | --- | --- |
| `generic_ssh_hook` | Linux servers, Unraid, TrueNAS Core | SFTP upload + reload command |
| `proxmox_ve` | Proxmox VE 7 / 8 | PVE API, SSH (`pvenode cert set`) fallback |
| `dell_idrac_redfish` | Dell iDRAC 7 / 8 / 9 / 10 | iDRAC 9+: Redfish `ImportSSLCertificate`; iDRAC 7/8: remote RACADM key + chain upload; then allows the Device's DNS name past the Host header check and restarts iDRAC |
| `hp_pro_ews` | HP Color LaserJet Pro M283fdw and similar | Embedded Web Server upload (reverse-engineered) |
| `synology_dsm` | Synology DSM 6.2 / 7.x | DSM web API (`SYNO.Core.Certificate`, undocumented): replaces the default certificate in place and moves all services to it |

Each Plugin documents its credentials and options in the dashboard's Add Device form. To write your own, see [`docs/plugins.md`](docs/plugins.md).

## Install

### Docker Compose

```sh
git clone https://github.com/albal/certfabric.git && cd certfabric
docker compose build
echo "CERTFABRIC_SECRET_KEY=$(docker run --rm certfabric certfabric generate-key)" > .env
docker compose up -d
```

Open `http://<host>:8080` and set the admin password. Data lives in the `certfabric-data` volume. The Compose file limits the container to 512 MB and one CPU; measured with 250 Devices probed in one sweep, CertFabric peaks at about 105 MiB (`scripts/measure_footprint.py`).

### Proxmox LXC

Create a Debian 12 container (512 MB, 1 core is enough), then run [`deploy/lxc/install.sh`](deploy/lxc/install.sh) inside it as root. The header of the script shows the `pct` commands. It installs CertFabric under `/opt/certfabric`, generates `/etc/certfabric/secret.key`, and runs it as the `certfabric` systemd service on port 8080. Re-run it to upgrade.

### From source

```sh
uv sync
(cd frontend && npm ci && npm run build)
export CERTFABRIC_SECRET_KEY=$(uv run certfabric generate-key)
uv run certfabric serve
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTFABRIC_SECRET_KEY` | — | Fernet key that encrypts every stored secret |
| `CERTFABRIC_SECRET_KEY_FILE` | — | Or: a file holding the key, readable only by its owner (`chmod 0400`) |
| `CERTFABRIC_DB_PATH` | `certfabric.db` | SQLite database |
| `CERTFABRIC_ACME_SH` | `acme.sh` | Path to the `acme.sh` script |
| `CERTFABRIC_PLUGINS_DIR` | — | Extra Plugin directories (`:`-separated), each holding `<plugin_id>/plugin.py` |
| `CERTFABRIC_FRONTEND_DIR` | found automatically | The built dashboard |

The CA (Let's Encrypt, its staging CA, ZeroSSL or a custom ACME directory) and the renewal threshold are set in the dashboard under **Settings**.

## Security

- **The secret key is everything.** DNS Provider credentials, Device credentials and private keys are encrypted with it (ADR-0001). **If you lose it, every stored secret is unreadable** and has to be re-entered; there is no escrow. Back it up somewhere other than the CertFabric host.
- **Rotating the key:** stop CertFabric, then run `certfabric rotate-key --new-key-file new.key` (or `--generate`), update the key setting and start it again. Rotation is all or nothing.
- **Plugins are trusted code.** A Plugin runs inside CertFabric and receives decrypted credentials and the private key. CertFabric only loads Plugins from local directories, never from the network, and does not sandbox them. **Only install Plugins you have read.**
- **One admin account.** The dashboard and API require a login; the password is set on first run.
- **Nothing leaves your network** except DNS-01 calls to your DNS provider and ACME calls to your CA. Logs and webhooks are scrubbed of secrets.
- `acme.sh` writes DNS credentials to its config in plaintext, so CertFabric runs it with a throwaway home directory for each issuance.

## Development

```sh
uv sync && (cd frontend && npm ci)
uv run pytest            # API, scheduler, Plugins and (with Chrome installed) UI tests
cd frontend && npm run dev   # dashboard on :5173, proxying to `certfabric serve` on :8080
```

Tests drive the real application with a fake clock, a fake `acme.sh` and simulated devices; see `tests/fakes/`.
