import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";

import { api, type Certificate, type Device, type Plugin, type Summary } from "../api";
import { RedeployButton } from "../components/RedeployButton";
import { ExpiringBadge, StateBadge } from "../components/StateBadge";
import { daysUntil, formatDate } from "../format";

export function FleetPage() {
  const devices = useQuery({ queryKey: ["devices"], queryFn: () => api.get<Device[]>("/api/devices"), refetchInterval: 15_000 });
  const certificates = useQuery({ queryKey: ["certificates"], queryFn: () => api.get<Certificate[]>("/api/certificates") });
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: () => api.get<Plugin[]>("/api/plugins") });
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/api/dashboard/summary") });

  const certById = new Map((certificates.data ?? []).map((c) => [c.id, c]));
  const pluginById = new Map((plugins.data ?? []).map((p) => [p.plugin_id, p]));
  const threshold = summary.data?.renewal_threshold_days ?? 28;
  const now = summary.data ? new Date(summary.data.server_time) : new Date();

  return (
    <div className="p-6">
      <div className="mb-4 flex items-center">
        <h1 className="text-xl font-bold text-slate-900">Device Fleet</h1>
        <Link to="/devices/new" className="ml-auto bg-blue-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-blue-700">
          Add Device
        </Link>
      </div>
      <div className="overflow-x-auto border border-black bg-white">
        <table className="w-full text-left text-sm" data-testid="fleet-table">
          <thead className="bg-slate-900 text-xs uppercase tracking-wide text-white">
            <tr>
              <th className="px-4 py-2">Device</th>
              <th className="px-4 py-2">Target</th>
              <th className="px-4 py-2">Hardware Plugin</th>
              <th className="px-4 py-2">Managed Certificate</th>
              <th className="px-4 py-2">Active Expiration</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {devices.data?.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No Devices yet.
                </td>
              </tr>
            )}
            {devices.data?.map((device) => {
              const cert = device.assigned_certificate_id ? certById.get(device.assigned_certificate_id) : undefined;
              const expires = device.presented_certificate?.expires_at ?? null;
              const days = expires ? daysUntil(expires, now) : null;
              return (
                <tr key={device.id} data-testid="device-row" data-device-id={device.id} className="border-t border-slate-200">
                  <td className="px-4 py-2 font-semibold text-slate-900">
                    <Link to="/devices/$deviceId" params={{ deviceId: device.id }} className="hover:text-blue-600 hover:underline">
                      {device.name}
                    </Link>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">
                    {device.hostname}:{device.port}
                  </td>
                  <td className="px-4 py-2">{pluginById.get(device.plugin_id)?.plugin_name ?? device.plugin_id}</td>
                  <td className="px-4 py-2">{cert ? cert.domain_primary : <span className="text-slate-400">—</span>}</td>
                  <td className="px-4 py-2" data-testid="expires">
                    {formatDate(expires)}
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <StateBadge state={device.state} />
                      {days !== null && days <= threshold && <ExpiringBadge days={days} />}
                      {(device.state === "DRIFT_DETECTED" || device.state === "DEPLOY_FAILED") && (
                        <RedeployButton device={device} compact />
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
