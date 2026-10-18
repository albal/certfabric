import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { api, type Certificate, type Summary } from "../api";
import { useTerminal } from "../components/Terminal";
import { Button, Card, ErrorText, Page, Select, TextArea, errorMessage } from "../components/ui";
import { formatDate } from "../format";

type DnsProvider = { id: string; name: string };

const STATUS_STYLES: Record<Certificate["status"], string> = {
  VALID: "bg-slate-900 text-white",
  EXPIRING: "border border-red-600 text-red-600",
  EXPIRED: "bg-red-600 text-white",
  REVOKED: "bg-red-600 text-white",
  SUPERSEDED: "border border-gray-400 text-gray-500",
};

function RequestForm({ onDone }: { onDone: () => void }) {
  const providers = useQuery({ queryKey: ["dns-providers"], queryFn: () => api.get<DnsProvider[]>("/api/dns-providers") });
  const [domains, setDomains] = useState("");
  const [provider, setProvider] = useState("");
  const [keyType, setKeyType] = useState("RSA2048");
  const [error, setError] = useState<string | null>(null);
  const openTerminal = useTerminal();
  const providerId = provider || providers.data?.[0]?.id || "";

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const list = domains.split(/[\s,]+/).filter(Boolean);
    try {
      const { job_id } = await api.post<{ job_id: string }>("/api/certificates", { domains: list, dns_provider_id: providerId, key_type: keyType });
      openTerminal(job_id, `Issuing ${list[0]}`);
      onDone();
    } catch (exc) {
      setError(errorMessage(exc));
    }
  }

  if (providers.data?.length === 0) return <p className="text-sm">Add a DNS Provider first.</p>;
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Request a Certificate">
      <TextArea label="Domains" value={domains} onChange={setDomains} hint="One per line; the first is the primary name. Wildcards like *.lan.example.com are allowed." />
      <div className="grid gap-3 md:grid-cols-2">
        <Select label="DNS Provider" value={providerId} onChange={setProvider} options={(providers.data ?? []).map((p) => ({ value: p.id, label: p.name }))} />
        <Select
          label="Key type"
          value={keyType}
          onChange={setKeyType}
          options={[
            { value: "RSA2048", label: "RSA 2048 (works on legacy hardware)" },
            { value: "ECDSA_P256", label: "ECDSA P-256" },
          ]}
        />
      </div>
      <ErrorText error={error} />
      <div className="flex gap-2">
        <Button type="submit">Request Certificate</Button>
        <Button variant="secondary" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function CertificatesPage() {
  const certificates = useQuery({ queryKey: ["certificates"], queryFn: () => api.get<Certificate[]>("/api/certificates"), refetchInterval: 15_000 });
  const summary = useQuery({ queryKey: ["summary"], queryFn: () => api.get<Summary>("/api/dashboard/summary") });
  const [requesting, setRequesting] = useState(false);
  const [showSuperseded, setShowSuperseded] = useState(false);
  const shown = (certificates.data ?? []).filter((c) => showSuperseded || c.status !== "SUPERSEDED");

  return (
    <Page title="Certificates" actions={!requesting && <Button onClick={() => setRequesting(true)}>Request Certificate</Button>}>
      {requesting && (
        <Card title="Request a Certificate">
          <RequestForm onDone={() => setRequesting(false)} />
        </Card>
      )}
      <p className="text-sm text-slate-600" data-testid="renewal-info">
        Certificates renew automatically {summary.data?.renewal_threshold_days ?? 28} days before expiry. Next renewal check:{" "}
        {summary.data?.next_renewal_check_at ? new Date(summary.data.next_renewal_check_at).toLocaleString() : "—"}.
      </p>
      <div className="overflow-x-auto border border-black bg-white">
        <table className="w-full text-left text-sm" data-testid="certificates-table">
          <thead className="bg-slate-900 text-xs uppercase tracking-wide text-white">
            <tr>
              <th className="px-4 py-2">Primary name</th>
              <th className="px-4 py-2">SANs</th>
              <th className="px-4 py-2">Key</th>
              <th className="px-4 py-2">Expires</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  No Certificates yet.
                </td>
              </tr>
            )}
            {shown.map((cert) => (
              <tr key={cert.id} data-testid="certificate-row" className="border-t border-slate-200 align-top">
                <td className="px-4 py-2 font-semibold">{cert.domain_primary}</td>
                <td className="px-4 py-2 text-xs">{cert.sans.join(", ")}</td>
                <td className="px-4 py-2 text-xs">{cert.key_type}</td>
                <td className="px-4 py-2">{formatDate(cert.expires_at)}</td>
                <td className="px-4 py-2">
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold ${STATUS_STYLES[cert.status]}`}>{cert.status}</span>
                  {cert.renewal_error && <p className="mt-1 max-w-sm text-xs text-red-600">Renewal failed: {cert.renewal_error}</p>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={showSuperseded} onChange={(e) => setShowSuperseded(e.target.checked)} />
        Show superseded Certificates
      </label>
    </Page>
  );
}
