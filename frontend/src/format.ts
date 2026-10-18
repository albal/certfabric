// Date helpers. Timestamps from the API are ISO 8601 in UTC.

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toISOString().slice(0, 10);
}

export function daysUntil(iso: string, now: Date = new Date()): number {
  return Math.floor((new Date(iso).getTime() - now.getTime()) / 86_400_000);
}

export function relative(iso: string | null, now: Date = new Date()): string {
  if (!iso) return "—";
  const minutes = Math.round((new Date(iso).getTime() - now.getTime()) / 60_000);
  if (Math.abs(minutes) < 1) return "now";
  const unit = Math.abs(minutes) < 60 ? `${Math.abs(minutes)} min` : `${Math.round(Math.abs(minutes) / 60)} h`;
  return minutes > 0 ? `in ${unit}` : `${unit} ago`;
}
