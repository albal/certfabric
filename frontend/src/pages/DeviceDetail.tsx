import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { api, type Certificate, type Deployment, type Device } from "../api";
import { parseAnsi } from "../ansi";
import { RedeployButton } from "../components/RedeployButton";
import { StateBadge } from "../components/StateBadge";
import { formatDate } from "../format";

const TRIGGERS: Record<string, string> = {
  MANUAL: "Manual",
  DRIFT_HEAL: "Drift heal",
  OUTDATED_HEAL: "Outdated heal",
  RENEWAL: "Renewal",
  RETRY: "Retry",
  INITIAL_SETUP: "Initial setup",
};

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-all text-sm text-slate-900">{children}</dd>
    </div>
  );
}

function Log({ text }: { text: string }) {
  return (
    <pre className="mt-2 max-h-80 overflow-auto bg-slate-950 p-3 font-mono text-xs text-slate-100">
      {text.split("\n").map((line, i) => (
        <div key={i}>
          {parseAnsi(line).map((s, j) => (
            <span key={j} className={s.className || undefined}>
              {s.text}
            </span>
          ))}
        </div>
      ))}
    </pre>
  );
}

export function DeviceDetailPage({ deviceId }: { deviceId: string }) {
  const device = useQuery({ queryKey: ["devices", deviceId], queryFn: () => api.get<Device>(`/api/devices/${deviceId}`), refetchInterval: 10_000 });
  const history = useQuery({
    queryKey: ["devices", deviceId, "deployments"],
    queryFn: () => api.get<Deployment[]>(`/api/devices/${deviceId}/deployments`),
    refetchInterval: 10_000,
  });
  const certificates = useQuery({ queryKey: ["certificates"], queryFn: () => api.get<Certificate[]>("/api/certificates") });
  if (!device.data) return <div className="p-6 text-slate-500">Loading…</div>;
  const d = device.data;
  const cert = certificates.data?.find((c) => c.id === d.assigned_certificate_id);
  const presented = d.presented_certificate;

  return (
    <div className="space-y-6 p-6">
      <div>
        <Link to="/" className="text-sm text-blue-600 hover:underline">
          ← Device Fleet
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-bold text-slate-900">{d.name}</h1>
          <StateBadge state={d.state} />
          <span className="ml-auto">
            <RedeployButton device={d} />
          </span>
        </div>
      </div>

      <section className="border border-black bg-white p-4">
        <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Field label="Target">
            {d.hostname}:{d.port}
          </Field>
          <Field label="TLS name">{d.sni ?? d.hostname}</Field>
          <Field label="Plugin">{d.plugin_id}</Field>
          <Field label="Probe interval">{d.polling_interval_minutes} min</Field>
          <Field label="Managed Certificate">{cert ? `${cert.domain_primary} (expires ${formatDate(cert.expires_at)})` : "None (Monitor only)"}</Field>
          <Field label="Last probe">{d.last_scanned_at ? new Date(d.last_scanned_at).toLocaleString() : "Never"}</Field>
          <Field label="Failed Deployments in a row">
            <span data-testid="deploy-failures">{d.consecutive_deploy_failures}</span>
            {d.next_retry_at && <span className="text-slate-500"> · retry {new Date(d.next_retry_at).toLocaleString()}</span>}
          </Field>
          <Field label="Last probe error">{d.last_probe_error ?? "—"}</Field>
        </dl>
      </section>

      <section className="border border-black bg-white p-4">
        <h2 className="mb-3 text-sm font-bold uppercase tracking-wide text-slate-900">Presented Certificate</h2>
        {presented ? (
          <dl className="grid grid-cols-2 gap-4 md:grid-cols-3">
            <Field label="Common name">{presented.common_name ?? "—"}</Field>
            <Field label="SANs">{presented.sans.join(", ") || "—"}</Field>
            <Field label="Expires">{formatDate(presented.expires_at)}</Field>
            <Field label="Issuer">{presented.issuer}</Field>
            <Field label="Serial">{presented.serial_number}</Field>
            <Field label="SHA-256">
              <span className="font-mono text-xs" data-testid="presented-fingerprint">
                {presented.fingerprint_sha256}
              </span>
            </Field>
          </dl>
        ) : (
          <p className="text-sm text-slate-500">Not probed yet.</p>
        )}
      </section>

      <section className="border border-black bg-white">
        <h2 className="border-b border-black px-4 py-3 text-sm font-bold uppercase tracking-wide text-slate-900">Deployment history</h2>
        {history.data?.length === 0 && <p className="px-4 py-6 text-sm text-slate-500">No Deployments yet.</p>}
        <ul data-testid="deployment-history">
          {history.data?.map((entry) => (
            <li key={entry.id} data-testid="deployment" className="border-t border-slate-200 px-4 py-3 first:border-t-0">
              <details>
                <summary className="flex cursor-pointer flex-wrap items-center gap-3 text-sm">
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ${entry.success ? "bg-slate-900 text-white" : "bg-red-600 text-white"}`}>
                    {entry.success ? "Succeeded" : "Failed"}
                  </span>
                  <span className="font-semibold">{TRIGGERS[entry.trigger_source] ?? entry.trigger_source}</span>
                  <span className="text-slate-500">{new Date(entry.timestamp).toLocaleString()}</span>
                  <span className="text-slate-500">{(entry.execution_time_ms / 1000).toFixed(1)} s</span>
                </summary>
                <Log text={entry.log_output ?? ""} />
              </details>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
