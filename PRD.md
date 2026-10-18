# Product Requirements Document (PRD)

## Project Name: CertFabric

**Document Version:** 1.1.0

**Status:** Approved for Implementation

**Revision 1.1.0:** Adopts the vocabulary in `GLOSSARY.md` and ADRs 0001–0003 (`docs/adr/`); adds authentication, CA/key-type configuration, retry/backoff, webhooks, and plugin trust boundary. "Active certificate" is now **Presented Certificate**; "managed certificate" is now **Certificate**.

**Target Environment:** Self-Hosted (Bare Metal, Docker, Proxmox LXC)

---

## 1. Executive Summary

CertFabric is a self-hosted, agentless Certificate Lifecycle Management (CLM) platform engineered specifically for local area networks and homelab environments. Unlike standard ACME automation tools that rely on local agents or modern REST APIs, CertFabric manages certificates across heterogeneous, closed, and legacy network hardware (such as HP printers, Dell iDRAC BMCs, managed switches, and Proxmox hypervisors).

CertFabric wraps `acme.sh` to obtain wildcard and SAN certificates using external DNS-01 challenges, stores certificates securely, and uses an extensible Python plugin architecture to push certificates directly into devices via proprietary protocols, web forms, and APIs. Additionally, an integrated background scanner continuously audits target endpoints over raw TLS sockets, automatically reissuing or redeploying certificates if a device purges its custom certificate or enters a 28-day expiration window.

---

## 2. Core Objectives & Key Metrics

* **Zero-Touch LAN Certificate Continuity:** Fully automate wildcard issuance, distribution, and renewal for devices lacking native ACME support.
* **Proactive State Reconciliation:** Detect device certificate purges (e.g., firmware updates or reboots that revert to self-signed defaults) within a configurable audit window (default: 6 hours) and automatically re-apply certificates.
* **Early Expiry Remediation:** Proactively renew each Certificate when its lifetime hits $\le 28$ days, then redeploy it to every assigned Device.
* **Modular Extensibility:** Allow third-party contributors to add support for any network appliance by implementing a single standardized Python class.
* **Lightweight Self-Hosting:** Run reliably on constrained hardware (e.g., Raspberry Pi 4, LXC containers) utilizing Python, SQLite, and a React SPA.

---

## 3. High-Level System Architecture

```text
                     ┌──────────────────────────────────────────────┐
                     │            External DNS Provider             │
                     │      (Cloudflare, Route53, Porkbun, etc.)    │
                     └──────────────────────▲───────────────────────┘
                                            │ DNS-01 API
┌───────────────────────────────────────────┼───────────────────────────────────────────┐
│ CertFabric Core Engine                    │                                           │
│                                           │                                           │
│  ┌──────────────────────┐      ┌──────────┴──────────┐      ┌──────────────────────┐  │
│  │   FastAPI Service    │◄────►│   acme.sh Wrapper   │      │   Device Polling     │  │
│  │  (REST / WebSocket)  │      │  (CLI Orchestrator) │      │   & Audit Engine     │  │
│  └──────────┬───────────┘      └──────────┬──────────┘      └──────────┬───────────┘  │
│             │                             │                            │              │
│  ┌──────────▼───────────┐                 │ Cert Artifacts             │ Raw TLS      │
│  │ SQLite Database (WAL)│                 │ Storage                    │ Probing      │
│  │   + Fernet columns   │                 ▼                            │              │
│  └──────────────────────┘      ┌─────────────────────┐                 │              │
│                                │   Plugin Registry   │                 │              │
│                                │  & Execution Engine │                 │              │
│                                └──────────┬──────────┘                 │              │
└───────────────────────────────────────────┼────────────────────────────┼──────────────┘
                                            │ Push Deployment            │ Verification
                                            ▼                            ▼
                     ┌─────────────────────────────────────────────────────────┐
                     │ Internal Network Devices                                │
                     │   - HP M283fdw / Printers (Reverse-Engineered HTTP POST) │
                     │   - Dell iDRAC (Redfish / RACADM)                       │
                     │   - Proxmox VE (PVE API / SSH)                          │
                     │   - Network Appliances (pfSense, UniFi, TrueNAS)        │
                     └─────────────────────────────────────────────────────────┘

```

---

## 4. Technical Specifications & Stack

### 4.1 Backend Engine

* **Runtime:** Python 3.11+
* **Application Framework:** FastAPI (Asynchronous REST API, OpenAPI docs, WebSockets for deployment logs).
* **Database & ORM:** SQLite 3 (WAL mode enabled) managed via SQLAlchemy 2.0 (asyncio) and Alembic for schema migrations.
* **Task Scheduler:** APScheduler (AsyncIOScheduler) executing audit sweeps and ACME check runs.
* **Cryptographic Storage:** `cryptography.fernet` (AES-128-CBC with HMAC-SHA256) for encrypting stored device passwords, API keys, and ACME account secrets at rest.
* **ACME Core:** Native integration with `acme.sh` installed as a local subprocess dependency. The CA is a per-install setting defaulting to Let's Encrypt production, with a "use staging CA" option for testing.
* **Authentication:** The API and SPA require login. v1 has a single admin account whose password is set at first run, with a session cookie. OIDC and multi-user are out of scope.
* **Secrets:** Column-level Fernet only; the database file is not encrypted (see ADR-0001).

### 4.2 Frontend Engine

* **Framework:** React 18+ with TypeScript.
* **Build Tool:** Vite.
* **Routing & State:** TanStack Router + TanStack Query (React Query) for server state caching.
* **Styling Framework:** Tailwind CSS with a strict corporate/industrial high-contrast palette.

---

## 5. Functional Requirements

### 5.1 ACME & Certificate Management Engine

* **FR-1.1: `acme.sh` Subprocess Wrapper:** The backend must interface with `acme.sh` via a secure Python wrapper (`AcmeRunner`), executing commands with JSON output parsing and streaming raw stdout/stderr to WebSocket channels.
* **FR-1.2: DNS-01 Credential Vault:** Securely store and inject environment variables (e.g., `CF_Token`, `AWS_ACCESS_KEY_ID`, `PORKBUN_API_KEY`) on a per-domain basis.
* **FR-1.3: Certificate Aggregation:** Support wildcards (`*.lan.example.com`), multi-domain SAN certificates, and distinct single-host certificates. A Certificate can only be assigned to a Device whose hostname its SANs cover; assignment is rejected otherwise.
* **FR-1.5: Key Type:** Chosen per Certificate. Default RSA 2048 (legacy firmware rejects ECDSA); ECDSA P-256 is opt-in.
* **FR-1.6: Renewal:** Driven per Certificate by its own `expires_at`: renew when ≤ 28 days remain, once per Certificate however many Devices share it (ADR-0003). A renewal marks the previous Certificate `SUPERSEDED` and triggers Deployment to every assigned Device. Superseded private keys are deleted after 30 days; metadata and fingerprints are kept.
* **FR-1.4: Artifact Generation:** Automatically parse, validate, and store the resulting artifacts:
* Leaf Certificate (`cert.pem`)
* Intermediate / Full Chain (`fullchain.pem`)
* Private Key (`privkey.pem`)
* PKCS#12 Bundle (`bundle.p12` / `bundle.pfx`) with a passphrase (required for printer and Windows deployments). By default a fresh passphrase is generated per Deployment, passed to the Plugin, and never stored; a user-specified passphrase is a per-Device setting kept in that Device's encrypted credentials.



### 5.2 Device Polling & Self-Healing Audit Engine

* **FR-2.1: Non-Invasive TLS Probing:** The scheduler must run a periodic socket connection (default every 6 hours, configurable per device) to the target host and port:
```python
# Logical probe flow
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with socket.create_connection((device.host, device.port), timeout=5) as sock:
    with context.wrap_socket(sock, server_hostname=device.sni or device.host) as ssock:
        der_cert = ssock.getpeercert(binary_form=True)

```


* **FR-2.2: Presented Certificate Parsing:** Extract Subject Alternative Names (SAN), Common Name (CN), Issuer, Serial Number, SHA256 Fingerprint, and `notAfter` timestamp directly from the peer certificate.
* **FR-2.3: Expiry Handling:** Probes never trigger issuance. If a Device's Presented Certificate expires in ≤ 28 days while its assigned Certificate is newer, the Device is treated as Outdated (FR-2.4). Issuance is owned by FR-1.6.
* **FR-2.4: Drift & Outdated Classification (ADR-0002):** Compare the Presented Certificate's SHA256 fingerprint to the Device's assigned Certificate and its successful Deployment history:
1. Matches the assigned Certificate → `IN_SYNC`.
2. Matches a Certificate previously deployed to this Device → `OUTDATED`. Redeploy the assigned Certificate quietly; no alarm.
3. Matches nothing CertFabric deployed (factory cert, purge, firmware reset) → `DRIFT_DETECTED`. Redeploy immediately and emit a warning to the dashboard and webhooks.
* **FR-2.5: Monitor-only Devices:** A Device with no assigned Certificate is Probed and its Presented Certificate shown, but never classified as Outdated or Drift and never deployed to.
* **FR-2.6: Unreachable:** A Device becomes `UNREACHABLE` after 3 consecutive failed Probes. Entering and leaving this state each send a webhook. A Device that returns serving a factory cert is then handled as Drift.
* **FR-2.7: Failure Backoff:** After a failed Deployment, retry with exponential backoff (1h, 6h, 24h, capped). After 3 consecutive failures set `DEPLOY_FAILED`, stop auto-retry, and send a webhook. A manual "Redeploy Now" or a credentials change resets the counter.
* **FR-2.8: Per-Device Lock:** Only one Deployment runs per Device at a time. A scheduled heal that finds one running skips; a second manual request is rejected or queued.
* **FR-2.9: Webhooks:** A configurable list of generic webhook URLs receives a JSON payload for: Drift, Unreachable and recovery, Deploy Failed, and Renewal failure. Payloads contain no secrets or key material. Chat-specific formats are out of scope.



### 5.3 Extensible Plugin Architecture

#### Plugin Specification

All device connectors must inherit from `BaseDevicePlugin` and reside in `/app/plugins/<plugin_name>/plugin.py`.

**Trust boundary:** Plugins run in-process and receive decrypted credentials and private keys, so a plugin is arbitrary code with access to everything. v1 does not sandbox plugins. They load only from the plugins directory on disk (no install-from-URL), and the docs must tell users to install only plugins they have read.

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel

class DeviceCredentials(BaseModel):
    username: Optional[str]
    password: Optional[str]
    api_token: Optional[str]
    extra_fields: Dict[str, Any] = {}

class PluginValidationResult(BaseModel):
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None

class BaseDevicePlugin(ABC):
    plugin_id: str
    plugin_name: str
    target_category: str  # "printer", "bmc", "hypervisor", "network", "generic"
    supported_models: list[str]

    def __init__(self, host: str, port: int, credentials: DeviceCredentials, use_tls: bool = True):
        self.host = host
        self.port = port
        self.credentials = credentials
        self.use_tls = use_tls

    @abstractmethod
    async def test_connection(self) -> PluginValidationResult:
        """Validate IP reachability, authentication credentials, and hardware compatibility."""
        pass

    @abstractmethod
    async def deploy_certificate(self, 
                                 cert_pem: str, 
                                 privkey_pem: str, 
                                 fullchain_pem: str, 
                                 pfx_bundle: bytes, 
                                 pfx_password: Optional[str]) -> bool:
        """Execute device-specific push, upload, and service reload logic."""
        pass

    @abstractmethod
    async def post_deployment_verify(self, expected_fingerprint: str) -> bool:
        """Probe the device post-install to verify the new certificate is being actively served."""
        pass

```

#### Core Plugins Delivered at Launch

| Plugin ID | Target Hardware | Mechanism / Protocol | Description |
| --- | --- | --- | --- |
| `hp_pro_ews` | HP Color LaserJet Pro (M283fdw & similar) | Reverse-engineered HTTPS Multipart Form Upload | Packages `.crt` & `.key` into a bare PKCS#12 bundle without root certs; handles session cookies, CSRF tokens, and uploads to `/Security/Certificates/Import`. |
| `dell_idrac_redfish` | Dell iDRAC 8 / 9 / 10 | Redfish REST API | Calls `POST /redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates` to import server cert and invokes automated web server daemon reload. |
| `proxmox_ve` | Proxmox VE 7.x / 8.x | Proxmox REST API / SSH fallback | Interacts with `/api2/json/nodes/{node}/certificates/custom` or runs `pvenode cert set` to reload `pveproxy` without disrupting guest VMs. |
| `generic_ssh_hook` | Linux Servers, Unraid, TrueNAS Core | SFTP / SCP + SSH Command Execution | Uploads `.pem` files to specified directories and runs an arbitrary reload command (e.g., `systemctl reload nginx`). |

---

## 6. Database Schema (SQLite)

SQLite is configured with `PRAGMA journal_mode = WAL;`, `PRAGMA synchronous = NORMAL;`, and `PRAGMA foreign_keys = ON;`.

```sql
CREATE TABLE dns_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    acme_dns_type TEXT NOT NULL, -- e.g., "dns_cf", "dns_aws"
    encrypted_credentials TEXT NOT NULL, -- JSON blob encrypted via Fernet
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    domain_primary TEXT NOT NULL,
    san_list TEXT NOT NULL, -- JSON array
    dns_provider_id TEXT REFERENCES dns_providers(id) ON DELETE RESTRICT,
    cert_pem TEXT NOT NULL,
    fullchain_pem TEXT NOT NULL,
    privkey_pem_encrypted TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    key_type TEXT NOT NULL DEFAULT 'RSA2048', -- 'RSA2048', 'ECDSA_P256'
    status TEXT NOT NULL -- "VALID", "EXPIRING", "EXPIRED", "REVOKED", "SUPERSEDED"
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    plugin_id TEXT NOT NULL,
    assigned_cert_id TEXT REFERENCES certificates(id) ON DELETE SET NULL,
    encrypted_credentials TEXT, -- JSON blob encrypted via Fernet
    polling_interval_minutes INTEGER DEFAULT 360,
    presented_fingerprint TEXT,
    presented_issuer TEXT,
    presented_expires_at DATETIME,
    drift_status TEXT DEFAULT 'IN_SYNC', -- 'IN_SYNC', 'OUTDATED', 'DRIFT_DETECTED', 'UNREACHABLE', 'DEPLOY_FAILED'
    consecutive_probe_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_deploy_failures INTEGER NOT NULL DEFAULT 0,
    next_retry_at DATETIME,
    last_scanned_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE deployment_logs (
    id TEXT PRIMARY KEY,
    device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
    cert_id TEXT REFERENCES certificates(id) ON DELETE CASCADE,
    trigger_source TEXT NOT NULL, -- "EXPIRY_POLL", "DRIFT_HEAL", "MANUAL", "INITIAL_SETUP"
    success BOOLEAN NOT NULL,
    execution_time_ms INTEGER NOT NULL,
    log_output TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webhooks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY, -- e.g. "acme_ca", "acme_use_staging"
    value TEXT NOT NULL
);

CREATE TABLE admin_user (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- single admin in v1
    password_hash TEXT NOT NULL
);

CREATE INDEX idx_devices_drift_status ON devices(drift_status);
CREATE INDEX idx_devices_presented_expires ON devices(presented_expires_at);
CREATE INDEX idx_certificates_expires ON certificates(expires_at);

```

---

## 7. Frontend Specification & UI/UX Design System

### 7.1 Visual Palette & Identity

The user interface adheres to a clean, authoritative industrial control dashboard using four core colors:

| Color Role | Tailwind Variable / Class | Hex Code | Purpose |
| --- | --- | --- | --- |
| **Canvas / Card White** | `bg-white`, `bg-slate-50` | `#FFFFFF`, `#F8FAFC` | Main application background, card fill, primary text contrast. |
| **Primary Executive Blue** | `bg-blue-600`, `text-blue-600` | `#1D4ED8` | Primary CTA buttons, brand badges, active tab markers, highlights. |
| **Deep Accent Blue** | `bg-slate-900`, `text-slate-900` | `#0F172A` | Sidebar, primary headers, data table header fill. |
| **Monochrome Black** | `bg-black`, `text-black` | `#000000` | Hard lines, high-contrast borders (`border-black`), deep typography. |
| **Alert / Warning Red** | `bg-red-600`, `text-red-600` | `#DC2626` | Drift alarms, purge alerts, $\le 28$-day expiry tags, failed deployments. |

### 7.2 Dashboard Layout

1. **Top Navigation & Global Health Ribbon:**
* Global summary metrics: Active Certificates, Devices Monitored, Purge/Drift Alerts (flashing red badge if $>0$), Next Automatic Sweep.


2. **Device Fleet Grid (Primary View):**
* Table displaying: Device Name, Target IP/Port, Hardware Plugin, Managed Certificate, Active Expiration Date, Dynamic Drift Indicator.
* **Drift Pill States:**
* `In Sync` (Solid slate-900 badge with blue indicator).
* `Outdated` (Slate-900 outline with blue indicator; redeploy in progress or queued).
* `Deploy Failed` (Solid red-600 badge; "Redeploy Now" button; auto-retry stopped).
* `Drift Detected: Reverted` (Solid red-600 badge with white text + immediate "Redeploy Now" button).
* `Expiring (<28d)` (Red outline with red warning icon).
* `Unreachable` (Muted gray badge with black border).




3. **Real-Time Deployment Terminal:**
* Slide-out drawer displaying ANSI-compatible real-time stdout/stderr logs from `acme.sh` issuance or plugin executions over WebSockets.



---

## 8. Detailed Execution Flows

### 8.1 Workflow: Automated Drift & Expiration Polling Loop

> **Superseded by FR-1.6 and FR-2.4–2.8.** The diagram below is the original 1.0.0 flow and is kept for history. In 1.1.0 the probe only classifies (`IN_SYNC` / `OUTDATED` / `DRIFT_DETECTED` / `UNREACHABLE`) and redeploys; renewal runs on a separate per-Certificate schedule.

```text
[Scheduler Event (Every N Hours)]
               │
               ▼
   [Query All Active Devices]
               │
               ▼
   [Perform TLS Socket Probe]
         ├── Connection Failed ──► Set status = 'UNREACHABLE' ──► Terminate
         └── Success
               │
               ▼
   [Parse Peer Certificate] ──► Read Serial, Fingerprint, notAfter
               │
               ├───────────────────────────────────────────────────────┐
               ▼                                                       ▼
      [Examine Fingerprint]                                  [Examine notAfter]
               │                                                       │
   Fingerprint != Managed Cert?                             Active Lifetime <= 28 Days?
               │                                                       │
        ┌──────┴──────┐                                         ┌──────┴──────┐
       YES            NO                                       YES            NO
        │              │                                        │              │
        ▼              ▼                                        ▼              ▼
  [Flag DRIFT]    [Maintain]                              [Check Stored]  [Maintain]
        │          IN_SYNC                                [Cert Expiry]    IN_SYNC
        ▼                                                       │
  [Auto-Deploy]                                           <= 28 Days?
  (Push valid                                            ┌──────┴──────┐
   cert now)                                            YES            NO
                                                         │              │
                                                         ▼              ▼
                                                    [acme.sh]      [Auto-Deploy]
                                                    (Renew)        (Push stored)

```

### 8.2 Workflow: HP M283fdw Plugin Deployment Sequence

1. **Packaging:** Generate PKCS#12 archive using OpenSSL bindings containing only the issued leaf certificate and private key with a temporary one-time password (the M283fdw firmware rejects certificates containing intermediate chains in the same file).
2. **Session Initialization:** Execute `GET https://<printer-ip>/Security/Certificates` to acquire session cookies and extract CSRF tokens.
3. **Payload Submission:** Execute authenticated `POST` to `/Security/Certificates/Import` supplying the encrypted `.pfx` payload and temporary password.
4. **Verification Probe:** Wait 15 seconds for EWS daemon to cycle, re-open raw TLS socket to port 443, confirm active SHA256 fingerprint matches the newly uploaded certificate.

---

## 9. Security & Hardening Requirements

* **Local Private Key Protection:** Certificate private keys stored in SQLite must be encrypted at rest using Fernet symmetric encryption. The encryption master key is supplied via the environment variable `CERTFABRIC_SECRET_KEY` or read from a local file restricted with permissions `0400`.
* **Zero Network Egress for Certificates:** The server never uploads private keys or certificates to external endpoints. External network activity is strictly limited to ACME DNS-01 API interactions with configured DNS providers.
* **Log Redaction:** All plugin and `acme.sh` output passes through a redactor that masks known secrets (DNS tokens, Device passwords, PFX passphrases, key material) before it is stored in `deployment_logs` or streamed over WebSockets.
* **Key Loss and Rotation:** Losing `CERTFABRIC_SECRET_KEY` makes all stored secrets unreadable; there is no escrow, and the install docs must say so. A `certfabric rotate-key` command re-encrypts everything under a new key.
* **Strict Subprocess Sanitization:** The `acme.sh` CLI wrapper must sanitize all domain names and arguments to prevent shell injection vulnerabilities. Execution is handled strictly through argument arrays (`asyncio.create_subprocess_exec`) without enabling `shell=True`.

---

## 10. Non-Functional Requirements & Performance

* **Footprint:** The entire backend and frontend bundle must execute smoothly within a container allocated **512 MB of RAM** and **1 vCPU core**.
* **Scan Latency:** The polling engine must utilize asynchronous socket coroutines (`asyncio.open_connection`), enabling concurrent probing of up to 250 network devices in under 15 seconds.
* **Database Resiliency:** SQLite in WAL mode must support continuous write operations during high-frequency polling while allowing simultaneous read transactions from the frontend API without lock contention.

---

## 11. Implementation Phasing & Milestones

```text
Phase 1 (Foundation)
├── Database models, Alembic migrations, Fernet crypto vault
├── acme.sh Python execution harness + DNS-01 credential providers
└── Raw TLS socket scanning engine (SAN, serial, fingerprint, expiry parser)

Phase 2 (Plugin Framework & First Integrations)
├── BaseDevicePlugin architecture and dynamic loader
├── HP LaserJet Pro EWS implementation (tested on M283fdw)
├── Dell iDRAC (Redfish API) and Proxmox VE (PVE API) plugins
└── Generic SSH deployment hook

Phase 3 (Self-Healing Automation & Frontend Delivery)
├── Per-Certificate renewal and Drift/Outdated auto-remediation loops, with backoff and webhooks
├── React SPA implementation (High-contrast White/Blue/Black/Red theme)
├── Real-time terminal log streaming via WebSockets
└── Production deployment artifacts (Docker Compose, Proxmox LXC install script)

```

