// Small form and layout building blocks shared by the management screens.

import { useId, useState, type ReactNode } from "react";

import { ApiError } from "../api";

export function errorMessage(exc: unknown): string {
  return exc instanceof ApiError ? exc.message : String(exc);
}

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-bold text-slate-900">{title}</h1>
        <div className="ml-auto flex gap-2">{actions}</div>
      </div>
      {children}
    </div>
  );
}

export function Card({ title, children, testId }: { title?: string; children: ReactNode; testId?: string }) {
  return (
    <section data-testid={testId} className="border border-black bg-white">
      {title && <h2 className="border-b border-black px-4 py-3 text-sm font-bold uppercase tracking-wide text-slate-900">{title}</h2>}
      <div className="p-4">{children}</div>
    </section>
  );
}

const inputClass = "w-full border border-black px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600";

export function TextField({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="text-sm">
      <label htmlFor={id} className="mb-1 block font-semibold">
        {label}
      </label>
      <input
        id={id}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className={inputClass}
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && (
        <span id={`${id}-hint`} className="mt-1 block text-xs text-slate-500">
          {hint}
        </span>
      )}
    </div>
  );
}

export function TextArea({ label, value, onChange, hint }: { label: string; value: string; onChange: (v: string) => void; hint?: string }) {
  const id = useId();
  return (
    <div className="text-sm">
      <label htmlFor={id} className="mb-1 block font-semibold">
        {label}
      </label>
      <textarea
        id={id}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className={`${inputClass} font-mono`}
        rows={4}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {hint && (
        <span id={`${id}-hint`} className="mt-1 block text-xs text-slate-500">
          {hint}
        </span>
      )}
    </div>
  );
}

export function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-semibold">{label}</span>
      <select className={inputClass} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function Checkbox({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm font-semibold">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="h-4 w-4 accent-blue-600" />
      {label}
    </label>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  type = "button",
  disabled = false,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger";
  type?: "button" | "submit";
  disabled?: boolean;
}) {
  const styles = {
    primary: "bg-blue-600 text-white hover:bg-blue-700",
    secondary: "border border-black bg-white text-slate-900 hover:bg-slate-100",
    danger: "border border-red-600 bg-white text-red-600 hover:bg-red-50",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`px-3 py-1.5 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50 ${styles}`}>
      {children}
    </button>
  );
}

export function Spinner() {
  return <span aria-hidden="true" className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-blue-600" />;
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="text-sm font-semibold text-red-600">
      {error}
    </p>
  );
}

/** Editable list of name/value pairs. Existing secrets arrive masked; leave them out to keep them. */
export function KeyValueEditor({
  label,
  rows,
  onChange,
  secret = false,
  hint,
}: {
  label: string;
  rows: [string, string][];
  onChange: (rows: [string, string][]) => void;
  secret?: boolean;
  hint?: string;
}) {
  const update = (index: number, column: 0 | 1, value: string) =>
    onChange(rows.map((row, i) => (i === index ? ((column === 0 ? [value, row[1]] : [row[0], value]) as [string, string]) : row)));
  return (
    <fieldset className="text-sm">
      <legend className="mb-1 font-semibold">{label}</legend>
      <div className="space-y-2">
        {rows.map(([key, value], i) => (
          <div key={i} className="flex gap-2">
            <input aria-label={`${label} name ${i + 1}`} className={inputClass} placeholder="NAME" value={key} onChange={(e) => update(i, 0, e.target.value)} />
            <input
              aria-label={`${label} value ${i + 1}`}
              className={inputClass}
              type={secret ? "password" : "text"}
              placeholder="value"
              value={value}
              onChange={(e) => update(i, 1, e.target.value)}
            />
            <Button variant="secondary" onClick={() => onChange(rows.filter((_, j) => j !== i))}>
              ✕
            </Button>
          </div>
        ))}
      </div>
      <button type="button" className="mt-2 text-sm font-semibold text-blue-600 hover:underline" onClick={() => onChange([...rows, ["", ""]])}>
        + Add {label.toLowerCase()}
      </button>
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </fieldset>
  );
}

export const toObject = (rows: [string, string][]) => Object.fromEntries(rows.filter(([k]) => k.trim()).map(([k, v]) => [k.trim(), v]));

export function useFormError() {
  return useState<string | null>(null);
}
