import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { api } from "../api";
import { Button, Card, ErrorText, Page, TextField, errorMessage } from "../components/ui";

type Webhook = { id: string; url: string; created_at: string };

export function WebhooksPage() {
  const hooks = useQuery({ queryKey: ["webhooks"], queryFn: () => api.get<Webhook[]>("/api/webhooks") });
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["webhooks"] });

  async function add(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api.post("/api/webhooks", { url });
      setUrl("");
      await refresh();
    } catch (exc) {
      setError(errorMessage(exc).includes("url") ? "Enter an http:// or https:// URL" : errorMessage(exc));
    }
  }

  async function test() {
    await api.post("/api/webhooks/test");
    setNotice("Test event sent to every webhook.");
  }

  return (
    <Page title="Webhooks" actions={<Button variant="secondary" onClick={test}>Send test event</Button>}>
      <p className="text-sm text-slate-600">
        Every webhook receives a JSON POST for Drift, Unreachable and recovery, Deploy Failed and Renewal failure. Payloads never contain secrets.
      </p>
      {notice && <p className="text-sm font-semibold text-slate-900" role="status">{notice}</p>}
      <Card title="Add a webhook">
        <form onSubmit={add} className="flex flex-wrap items-end gap-2" aria-label="Add a webhook">
          <div className="min-w-64 flex-1">
            <TextField label="URL" value={url} onChange={setUrl} placeholder="https://hooks.example.com/certfabric" />
          </div>
          <Button type="submit">Add</Button>
        </form>
        <div className="mt-2">
          <ErrorText error={error} />
        </div>
      </Card>
      <Card testId="webhooks">
        {hooks.data?.length === 0 && <p className="text-sm text-slate-500">No webhooks yet.</p>}
        <ul className="divide-y divide-slate-200">
          {hooks.data?.map((hook) => (
            <li key={hook.id} data-testid="webhook" className="flex items-center gap-3 py-2">
              <span className="font-mono text-sm">{hook.url}</span>
              <span className="ml-auto">
                <Button
                  variant="danger"
                  onClick={async () => {
                    await api.delete(`/api/webhooks/${hook.id}`);
                    await refresh();
                  }}
                >
                  Delete
                </Button>
              </span>
            </li>
          ))}
        </ul>
      </Card>
    </Page>
  );
}
