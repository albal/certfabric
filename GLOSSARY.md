# CertFabric

Agentless certificate lifecycle management for LAN and homelab devices that lack native ACME support: it issues certificates, pushes them to devices, and keeps watching that they stay installed.

## Language

**Certificate**:
An issued certificate with its private key, stored and managed by CertFabric. One Certificate can be assigned to many Devices.
_Avoid_: Managed certificate, cert artifact, stored cert

**Superseded**:
The status of a Certificate replaced by a renewal. It is kept so Deployment history can still classify a Device as Outdated rather than Drift; its private key is deleted after a retention period.
_Avoid_: Old, archived, rotated

**Presented Certificate**:
The certificate a Device is actually serving, as observed by a Probe.
_Avoid_: Active certificate, live cert, device cert

**Device**:
A network endpoint CertFabric probes and deploys Certificates to, handled by exactly one Plugin.
_Avoid_: Target, host, appliance, endpoint

**Plugin**:
The connector that knows how to install a Certificate on one type of Device hardware.
_Avoid_: Connector, driver, integration

**DNS Provider**:
A configured DNS service with credentials, used to prove domain ownership when issuing a Certificate.
_Avoid_: DNS account, DNS credential

## Observation and healing

**Probe**:
A non-invasive TLS connection to a Device that reads its Presented Certificate without authenticating.
_Avoid_: Scan, poll, check

**Deployment**:
One attempt to install a Certificate on a Device through its Plugin, followed by verification.
_Avoid_: Push, upload, install

**Drift**:
A Device serving a Presented Certificate that CertFabric never deployed to it, such as a factory self-signed certificate after a purge. Raises a warning event.
_Avoid_: Purge, reversion, mismatch

**Outdated**:
A Device serving an earlier Certificate that CertFabric itself deployed, because a newer Certificate has since been assigned. Redeployed quietly, without an alarm.
_Avoid_: Stale, drifted after renewal

**Deploy Failed**:
The state of a Device whose Deployments have failed three times in a row. Automatic retries stop until someone intervenes.
_Avoid_: Stuck, locked out

**Monitor-only**:
A Device with no Certificate assigned. It is Probed and its Presented Certificate is shown, but it is never classified as Drift or Outdated and never deployed to.
_Avoid_: Unmanaged, passive

**Unreachable**:
The state of a Device whose last three Probes all failed. Entering and leaving it each raise a notification.
_Avoid_: Offline, down

## Relationships

- A **Certificate** is assigned to zero or more **Devices**; renewal is decided per **Certificate**, never per **Device**.
- A **Certificate** can only be assigned to a **Device** whose hostname it covers.
- A **Probe** yields a **Presented Certificate**, which is compared against the Device's **Deployment** history to classify it as in sync, **Outdated** or **Drift**.
