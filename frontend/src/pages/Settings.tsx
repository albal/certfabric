import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { api, type Summary } from "../api";
import { Button, Card, Checkbox, ErrorText, Page, Select, TextField, errorMessage } from "../components/ui";

type InstallSettings = { acme_ca: string; acme_use_staging: boolean; renewal_threshold_days: number };

export function SettingsPage() {
  const settings = useQuery({ queryKey: ["settings"], queryFn: () => api.get<InstallSettings>("/api/settings") });
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/api/dashboard/summary") });
  const [ca, setCa] = useState("letsencrypt");
  const [customUrl, setCustomUrl] = useState("");
  const [staging, setStaging] = useState(false);
  const [threshold, setThreshold] = useState("28");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!settings.data) return;
    const known = ["letsencrypt", "zerossl"].includes(settings.data.acme_ca);
    setCa(known ? settings.data.acme_ca : "custom");
    setCustomUrl(known ? "" : settings.data.acme_ca);
    setStaging(settings.data.acme_use_staging);
    setThreshold(String(settings.data.renewal_threshold_days));
  }, [settings.data]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSaved(false);
    try {
      await api.put("/api/settings", {
        acme_ca: ca === "custom" ? customUrl : ca,
        acme_use_staging: ca === "letsencrypt" && staging,
        renewal_threshold_days: Number(threshold),
      });
      await queryClient.invalidateQueries();
      setSaved(true);
    } catch (exc) {
      setError(errorMessage(exc));
    }
  }

  return (
    <Page title="Settings">
      <Card title="Certificate Authority">
        <form onSubmit={submit} className="max-w-xl space-y-3" aria-label="Settings">
          <Select
            label="ACME CA"
            value={ca}
            onChange={setCa}
            options={[
              { value: "letsencrypt", label: "Let's Encrypt" },
              { value: "zerossl", label: "ZeroSSL" },
              { value: "custom", label: "Custom ACME directory" },
            ]}
          />
          {ca === "custom" && <TextField label="ACME directory URL" value={customUrl} onChange={setCustomUrl} placeholder="https://ca.example.com/acme/directory" />}
          {ca === "letsencrypt" && <Checkbox label="Use the staging CA (for testing; certificates are not trusted)" checked={staging} onChange={setStaging} />}
          <TextField label="Renew this many days before expiry" type="number" value={threshold} onChange={setThreshold} />
          <ErrorText error={error} />
          {saved && <p role="status" className="text-sm font-semibold text-slate-900">Saved.</p>}
          <Button type="submit">Save settings</Button>
        </form>
      </Card>
      <Card title="Schedule">
        <dl className="grid gap-4 text-sm md:grid-cols-2">
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Next automatic sweep</dt>
            <dd data-testid="next-sweep">{summary.data?.next_sweep_at ? new Date(summary.data.next_sweep_at).toLocaleString() : "No Devices"}</dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Next renewal check</dt>
            <dd data-testid="next-renewal-check">
              {summary.data?.next_renewal_check_at ? new Date(summary.data.next_renewal_check_at).toLocaleString() : "—"}
            </dd>
          </div>
        </dl>
      </Card>
    </Page>
  );
}
