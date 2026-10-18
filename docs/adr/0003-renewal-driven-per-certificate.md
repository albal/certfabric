# Drive renewal from the Certificate's expiry, not from Device Probes

The PRD triggered `acme.sh` renewal when a Device's Presented Certificate reached 28 days from expiry. One wildcard Certificate can serve many Devices, and a Device that is down or unprobed would never trigger renewal. We renew per Certificate on its own `expires_at` (≤ 28 days); Probes only detect Drift and Outdated and trigger redeployment, never issuance. This also keeps CA rate limits safe: one renewal per Certificate however many Devices share it.
