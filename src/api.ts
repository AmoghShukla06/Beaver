import type { Method, Snapshot } from "./types";
export const desktop = Boolean(window.beaver);
export async function request<T = any>(
  method: Method,
  params: object = {},
): Promise<T> {
  if (window.beaver) return window.beaver[method](params);
  if (method !== "snapshot")
    throw new Error(
      "This action requires the Beaver desktop app. The browser preview is read-only.",
    );
  const response = await fetch("/api/snapshot", {
    cache: "no-store",
    signal: AbortSignal.timeout(15000),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      data.error || "The local telemetry service is unavailable.",
    );
  return data;
}
export function bytes(value: number | null | undefined, rate = false): string {
  if (value == null || !Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return (
    value.toLocaleString(undefined, { maximumFractionDigits: i ? 1 : 0 }) +
    " " +
    units[i] +
    (rate ? "/s" : "")
  );
}
export function when(value: number | null | undefined): string {
  return value ? new Date(value * 1000).toLocaleString() : "Not yet";
}
export const isStale = (snapshot: Snapshot | null, now = Date.now()) =>
  !snapshot?.sampled_at ||
  now / 1000 - snapshot.sampled_at > 10 ||
  Boolean(snapshot.coverage.inventory_error);
