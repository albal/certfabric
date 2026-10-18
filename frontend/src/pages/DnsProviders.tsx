import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { api } from "../api";
import { Button, Card, ErrorText, KeyValueEditor, Page, TextField, errorMessage, toObject } from "../components/ui";

type DnsProvider = { id: string; name: string; acme_dns_type: string; credentials: Record<string, string>; created_at: string };

function ProviderForm({ provider, onDone }: { provider?: DnsProvider; onDone: () => void }) {
  const [name, setName] = useState(provider?.name ?? "");
  const [dnsType, setDnsType] = useState(provider?.acme_dns_type ?? "dns_cf");
  // Existing values are masked by the API; editing replaces all credentials.
  const [credentials, setCredentials] = useState<[string, string][]>(
    provider ? Object.keys(provider.credentials).map((k) => [k, ""]) : [["CF_Token", ""]],
  );
  const [error, setError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    const creds = toObject(credentials);
    const rotate = Object.values(creds).some((v) => v);
    try {
      if (provider) {
        await api.patch(`/api/dns-providers/${provider.id}`, { name, acme_dns_type: dnsType, ...(rotate ? { credentials: creds } : {}) });
      } else {
        await api.post("/api/dns-providers", { name, acme_dns_type: dnsType, credentials: creds });
      }
      await queryClient.invalidateQueries({ queryKey: ["dns-providers"] });
      onDone();
    } catch (exc) {
      setError(errorMessage(exc));
    }
  }

  return (
    <form onSubmit={submit} className="space-y-3" aria-label={provider ? `Edit ${provider.name}` : "New DNS Provider"}>
      <div className="grid gap-3 md:grid-cols-2">
        <TextField label="Name" value={name} onChange={setName} />
        <TextField label="acme.sh DNS API" value={dnsType} onChange={setDnsType} hint="e.g. dns_cf, dns_aws, dns_porkbun" />
      </div>
      <KeyValueEditor
        label="Credentials"
        rows={credentials}
        onChange={setCredentials}
        secret
        hint={provider ? "Leave values empty to keep the stored credentials; fill them in to replace all of them." : "Environment variables acme.sh needs, e.g. CF_Token."}
      />
      <ErrorText error={error} />
      <div className="flex gap-2">
        <Button type="submit">{provider ? "Save" : "Add DNS Provider"}</Button>
        <Button variant="secondary" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

export function DnsProvidersPage() {
  const providers = useQuery({ queryKey: ["dns-providers"], queryFn: () => api.get<DnsProvider[]>("/api/dns-providers") });
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  async function remove(provider: DnsProvider) {
    setError(null);
    try {
      await api.delete(`/api/dns-providers/${provider.id}`);
      await queryClient.invalidateQueries({ queryKey: ["dns-providers"] });
    } catch (exc) {
      setError(errorMessage(exc));
    }
  }

  return (
    <Page title="DNS Providers" actions={editing === null && <Button onClick={() => setEditing("new")}>Add DNS Provider</Button>}>
      {editing === "new" && (
        <Card title="New DNS Provider">
          <ProviderForm onDone={() => setEditing(null)} />
        </Card>
      )}
      <ErrorText error={error} />
      <Card testId="dns-providers">
        {providers.data?.length === 0 && <p className="text-sm text-slate-500">No DNS Providers yet.</p>}
        <ul className="divide-y divide-slate-200">
          {providers.data?.map((provider) => (
            <li key={provider.id} data-testid="dns-provider" className="py-3">
              {editing === provider.id ? (
                <ProviderForm provider={provider} onDone={() => setEditing(null)} />
              ) : (
                <div className="flex flex-wrap items-center gap-3">
                  <span className="font-semibold">{provider.name}</span>
                  <span className="font-mono text-xs">{provider.acme_dns_type}</span>
                  <span className="font-mono text-xs text-slate-500" data-testid="masked-credentials">
                    {Object.entries(provider.credentials).map(([k, v]) => `${k}=${v}`).join("  ")}
                  </span>
                  <span className="ml-auto flex gap-2">
                    <Button variant="secondary" onClick={() => setEditing(provider.id)}>
                      Edit
                    </Button>
                    <Button variant="danger" onClick={() => remove(provider)}>
                      Delete
                    </Button>
                  </span>
                </div>
              )}
            </li>
          ))}
        </ul>
      </Card>
    </Page>
  );
}
