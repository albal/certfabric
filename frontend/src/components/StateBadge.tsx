import type { DeviceState } from "../api";

// Pill styles follow PRD §7.2: slate/blue for healthy, red for anything needing attention.
const STYLES: Record<DeviceState, { label: string; className: string; dot?: string }> = {
  IN_SYNC: { label: "In Sync", className: "bg-slate-900 text-white", dot: "bg-blue-500" },
  OUTDATED: { label: "Outdated", className: "border border-slate-900 text-slate-900", dot: "bg-blue-600" },
  DRIFT_DETECTED: { label: "Drift Detected: Reverted", className: "bg-red-600 text-white" },
  DEPLOY_FAILED: { label: "Deploy Failed", className: "bg-red-600 text-white" },
  UNREACHABLE: { label: "Unreachable", className: "bg-gray-200 text-gray-600 border border-black" },
  MONITOR_ONLY: { label: "Monitor only", className: "border border-gray-400 text-gray-600" },
  UNKNOWN: { label: "Pending", className: "border border-gray-400 text-gray-600" },
};

export function StateBadge({ state }: { state: DeviceState }) {
  const style = STYLES[state];
  return (
    <span
      data-testid="state-badge"
      data-state={state}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded px-2 py-0.5 text-xs font-semibold ${style.className}`}
    >
      {style.dot && <span className={`h-2 w-2 rounded-full ${style.dot}`} />}
      {style.label}
    </span>
  );
}

export function ExpiringBadge({ days }: { days: number }) {
  return (
    <span
      data-testid="expiring-badge"
      className="inline-flex items-center gap-1 whitespace-nowrap rounded border border-red-600 px-2 py-0.5 text-xs font-semibold text-red-600"
    >
      <svg aria-hidden viewBox="0 0 16 16" className="h-3 w-3 fill-current">
        <path d="M8 1 15 14H1L8 1Zm-.75 5v4h1.5V6h-1.5Zm0 5v1.5h1.5V11h-1.5Z" />
      </svg>
      {days < 0 ? "Expired" : `Expiring (${days}d)`}
    </span>
  );
}
