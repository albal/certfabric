import { useState } from "react";

import { api, ApiError, type Device } from "../api";
import { useTerminal } from "./Terminal";

export function RedeployButton({ device, compact = false }: { device: Device; compact?: boolean }) {
  const openTerminal = useTerminal();
  const [error, setError] = useState<string | null>(null);
  if (!device.assigned_certificate_id) return null;

  async function redeploy() {
    setError(null);
    try {
      const { job_id } = await api.post<{ job_id: string }>(`/api/devices/${device.id}/deploy`);
      openTerminal(job_id, `Deploying to ${device.name}`);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : String(exc));
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      <button
        onClick={redeploy}
        className={`bg-blue-600 font-semibold text-white hover:bg-blue-700 ${compact ? "px-2 py-0.5 text-xs" : "px-4 py-2 text-sm"}`}
      >
        Redeploy Now
      </button>
      {error && (
        <span role="alert" className="text-xs font-semibold text-red-600">
          {error}
        </span>
      )}
    </span>
  );
}
