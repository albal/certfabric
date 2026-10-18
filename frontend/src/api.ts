// Typed access to the CertFabric API. Every call carries the session cookie.

export class AuthRequired extends Error {}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 && !path.startsWith("/api/auth/")) throw new AuthRequired();
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const data = await response.json();
      detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      // not JSON
    }
    throw new ApiError(response.status, detail);
  }
  return response.status === 204 ? (undefined as T) : response.json();
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  delete: (path: string) => request<void>("DELETE", path),
};

export type AuthStatus = { setup_required: boolean; authenticated: boolean };

export type DeviceState =
  | "IN_SYNC"
  | "OUTDATED"
  | "DRIFT_DETECTED"
  | "UNREACHABLE"
  | "DEPLOY_FAILED"
  | "MONITOR_ONLY"
  | "UNKNOWN";

export type PresentedCertificate = {
  common_name: string | null;
  sans: string[];
  issuer: string | null;
  serial_number: string | null;
  fingerprint_sha256: string;
  expires_at: string | null;
};

export type Device = {
  id: string;
  name: string;
  hostname: string;
  port: number;
  sni: string | null;
  plugin_id: string;
  plugin_options: Record<string, unknown>;
  credentials: {
    username: string | null;
    password: string | null;
    api_token: string | null;
    pfx_passphrase: string | null;
    extra: Record<string, string>;
  };
  polling_interval_minutes: number;
  assigned_certificate_id: string | null;
  state: DeviceState;
  presented_certificate: PresentedCertificate | null;
  consecutive_probe_failures: number;
  consecutive_deploy_failures: number;
  next_retry_at: string | null;
  last_probe_error: string | null;
  last_scanned_at: string | null;
  created_at: string;
};

export type Certificate = {
  id: string;
  domain_primary: string;
  sans: string[];
  dns_provider_id: string;
  key_type: string;
  serial_number: string;
  fingerprint_sha256: string;
  issued_at: string;
  expires_at: string;
  status: "VALID" | "EXPIRING" | "EXPIRED" | "REVOKED" | "SUPERSEDED";
  superseded_by: string | null;
  has_private_key: boolean;
  renewal_attempted_at: string | null;
  renewal_error: string | null;
};

export type Plugin = {
  plugin_id: string;
  plugin_name: string;
  target_category: string;
  supported_models: string[];
  description: string | null;
};

export type Summary = {
  server_time: string;
  active_certificates: number;
  devices_monitored: number;
  drift_alerts: number;
  expiring_devices: number;
  renewal_threshold_days: number;
  next_sweep_at: string | null;
  next_renewal_check_at: string | null;
};

export type AuditEvent = {
  id: string;
  timestamp: string;
  level: "info" | "warning" | "error";
  event: string;
  message: string;
  device_id: string | null;
  certificate_id: string | null;
};
