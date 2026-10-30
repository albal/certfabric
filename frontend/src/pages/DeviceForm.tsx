import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";

import { api, type Certificate, type Device, type Plugin } from "../api";
import { Button, Card, ErrorText, KeyValueEditor, Page, Select, Spinner, TextField, errorMessage, toObject } from "../components/ui";

type TestResult = { success: boolean; message: string };

// Plugin options are typed loosely in the form; turn obvious booleans and numbers back into values.
function parseOption(value: string): unknown {
  if (value === "true" || value === "false") return value === "true";
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

export function DeviceFormPage({ device }: { device?: Device }) {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: () => api.get<Plugin[]>("/api/plugins") });
  const certificates = useQuery({ queryKey: ["certificates"], queryFn: () => api.get<Certificate[]>("/api/certificates") });
  const [name, setName] = useState(device?.name ?? "");
  const [hostname, setHostname] = useState(device?.hostname ?? "");
  const [port, setPort] = useState(String(device?.port ?? 443));
  const [sni, setSni] = useState(device?.sni ?? "");
  const [pluginId, setPluginId] = useState(device?.plugin_id ?? "");
  const [interval, setInterval] = useState(String(device?.polling_interval_minutes ?? 360));
  const [options, setOptions] = useState<[string, string][]>(Object.entries(device?.plugin_options ?? {}).map(([k, v]) => [k, String(v)]));
  const [username, setUsername] = useState(device?.credentials.username ?? "");
  const [password, setPassword] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [pfxPassphrase, setPfxPassphrase] = useState("");
  const [extra, setExtra] = useState<[string, string][]>(Object.keys(device?.credentials.extra ?? {}).map((k) => [k, ""]));
  const [certificateId, setCertificateId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const plugin = pluginId || plugins.data?.[0]?.plugin_id || "";
  const selectedPlugin = plugins.data?.find((p) => p.plugin_id === plugin);
  const secretsTouched = Boolean(password || apiToken || pfxPassphrase || extra.some(([, v]) => v));
  const credentials = {
    username: username || null,
    password: password || null,
    api_token: apiToken || null,
    pfx_passphrase: pfxPassphrase || null,
    extra: toObject(extra),
  };
  const body = {
    name,
    hostname,
    port: Number(port),
    sni: sni || null,
    plugin_id: plugin,
    polling_interval_minutes: Number(interval),
    plugin_options: Object.fromEntries(Object.entries(toObject(options)).map(([k, v]) => [k, parseOption(v)])),
  };

  async function testConnection() {
    setTest(null);
    setError(null);
    setTesting(true);
    try {
      // Saved Devices without new secrets are tested with what is stored.
      setTest(
        device && !secretsTouched
          ? await api.post<TestResult>(`/api/devices/${device.id}/test-connection`)
          : await api.post<TestResult>("/api/devices/test-connection", { ...body, credentials }),
      );
    } catch (exc) {
      setError(errorMessage(exc));
    } finally {
      setTesting(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const saved = device
        ? await api.patch<Device>(`/api/devices/${device.id}`, {
            ...body,
            ...(secretsTouched || username !== (device.credentials.username ?? "") ? { credentials } : {}),
          })
        : await api.post<Device>("/api/devices", { ...body, credentials, certificate_id: certificateId || null });
      await queryClient.invalidateQueries();
      await navigate({ to: "/devices/$deviceId", params: { deviceId: saved.id } });
    } catch (exc) {
      setError(errorMessage(exc));
    }
  }

  const keep = device ? "Leave empty to keep the stored value" : undefined;
  return (
    <Page title={device ? `Edit ${device.name}` : "Add a Device"}>
      <form onSubmit={submit} className="space-y-6" aria-label="Device">
        <Card title="Device">
          <div className="grid gap-3 md:grid-cols-2">
            <TextField label="Name" value={name} onChange={setName} />
            <Select
              label="Plugin"
              value={plugin}
              onChange={setPluginId}
              options={(plugins.data ?? []).map((p) => ({ value: p.plugin_id, label: p.plugin_name }))}
            />
            <TextField label="Hostname or IP" value={hostname} onChange={setHostname} />
            <TextField label="Port" type="number" value={port} onChange={setPort} />
            <TextField
              label="TLS name (SNI)"
              value={sni}
              onChange={setSni}
              hint="The name the Certificate must cover. Required when the Device is addressed by IP."
            />
            <TextField label="Probe interval (minutes)" type="number" value={interval} onChange={setInterval} />
          </div>
          {selectedPlugin && (
            <p className="mt-3 text-xs text-slate-500" data-testid="plugin-models">
              Supports: {selectedPlugin.supported_models.join(", ")}
            </p>
          )}
          {selectedPlugin?.description && (
            <details className="mt-2 text-xs">
              <summary className="cursor-pointer font-semibold text-blue-600">Plugin options and credentials</summary>
              <pre className="mt-2 whitespace-pre-wrap bg-slate-50 p-3">{selectedPlugin.description}</pre>
            </details>
          )}
        </Card>

        <Card title="Credentials">
          <div className="grid gap-3 md:grid-cols-2">
            <TextField label="Username" value={username} onChange={setUsername} />
            <TextField label="Password" type="password" value={password} onChange={setPassword} hint={keep} />
            <TextField label="API token" type="password" value={apiToken} onChange={setApiToken} hint={keep} />
            <TextField
              label="Fixed PKCS#12 passphrase"
              type="password"
              value={pfxPassphrase}
              onChange={setPfxPassphrase}
              hint="Only for devices that need one; otherwise a fresh one is generated per Deployment"
            />
          </div>
          <div className="mt-3">
            <KeyValueEditor label="Extra secrets" rows={extra} onChange={setExtra} secret hint="e.g. ssh_private_key or ssh_password" />
          </div>
          {device && <p className="mt-3 text-xs text-slate-500">Changing any secret replaces all stored credentials, so fill in every one the Plugin needs.</p>}
        </Card>

        <Card title="Plugin options">
          <KeyValueEditor label="Options" rows={options} onChange={setOptions} hint="Non-secret settings, e.g. reload_command or node" />
        </Card>

        {!device && (
          <Card title="Certificate">
            <Select
              label="Assign a Certificate"
              value={certificateId}
              onChange={setCertificateId}
              options={[
                { value: "", label: "None (Monitor only)" },
                ...(certificates.data ?? [])
                  .filter((c) => c.status !== "SUPERSEDED" && c.status !== "REVOKED")
                  .map((c) => ({ value: c.id, label: `${c.domain_primary} (${c.sans.join(", ")})` })),
              ]}
            />
          </Card>
        )}

        {test && (
          <p role="status" data-testid="test-result" className={`text-sm font-semibold ${test.success ? "text-slate-900" : "text-red-600"}`}>
            {test.success ? "✓ " : "✗ "}
            {test.message}
          </p>
        )}
        <ErrorText error={error} />
        <div className="flex items-center gap-2">
          <Button type="submit">{device ? "Save Device" : "Add Device"}</Button>
          <Button variant="secondary" onClick={testConnection} disabled={testing}>
            Test connection
          </Button>
          {testing && (
            <span role="status" data-testid="test-progress" className="ml-1 inline-flex items-center gap-2 text-sm text-slate-600">
              <Spinner />
              Testing connection…
            </span>
          )}
        </div>
      </form>
    </Page>
  );
}

export function EditDevicePage({ deviceId }: { deviceId: string }) {
  const device = useQuery({ queryKey: ["devices", deviceId], queryFn: () => api.get<Device>(`/api/devices/${deviceId}`) });
  return device.data ? <DeviceFormPage device={device.data} /> : <div className="p-6 text-slate-500">Loading…</div>;
}
