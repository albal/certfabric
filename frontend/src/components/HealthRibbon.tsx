import { useQuery } from "@tanstack/react-query";

import { api, type Summary } from "../api";
import { relative } from "../format";

function Metric({ label, value, alert, testId }: { label: string; value: string; alert?: boolean; testId: string }) {
  return (
    <div className="flex flex-col gap-1 border-r border-black px-5 py-3 last:border-r-0">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</span>
      <span
        data-testid={testId}
        className={
          alert
            ? "w-fit animate-pulse rounded bg-red-600 px-2 text-2xl font-bold text-white"
            : "text-2xl font-bold text-slate-900"
        }
      >
        {value}
      </span>
    </div>
  );
}

export function HealthRibbon() {
  const { data } = useQuery({
    queryKey: ["summary"],
    queryFn: () => api.get<Summary>("/api/dashboard/summary"),
    refetchInterval: 15_000,
  });
  if (!data) return <div className="h-20 border-b border-black bg-white" />;
  return (
    <section aria-label="Global health" className="grid grid-cols-2 border-b border-black bg-white md:grid-cols-4">
      <Metric label="Active Certificates" value={String(data.active_certificates)} testId="metric-certificates" />
      <Metric label="Devices Monitored" value={String(data.devices_monitored)} testId="metric-devices" />
      <Metric
        label="Purge / Drift Alerts"
        value={String(data.drift_alerts)}
        alert={data.drift_alerts > 0}
        testId="metric-drift"
      />
      <Metric label="Next Automatic Sweep" value={relative(data.next_sweep_at, new Date(data.server_time))} testId="metric-next-sweep" />
    </section>
  );
}
