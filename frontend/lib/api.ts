import type { Health, ScanDetail, ScanListItem } from "./types";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body.detail || r.statusText);
  }
  return r.json();
}

export const api = {
  health: () => call<Health>("/api/health"),
  scans: () => call<ScanListItem[]>("/api/scans"),
  scan: (id: string) => call<ScanDetail>(`/api/scans/${id}`),
  remove: (id: string) => call<{ deleted: string }>(`/api/scans/${id}`, { method: "DELETE" }),
  start: (target: string, ai: boolean, aiReview: boolean, incremental = false) =>
    call<{ id: string }>("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ai, ai_review: aiReview, incremental }),
    }),
  upload: (file: File, ai: boolean, aiReview: boolean) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("ai", String(ai));
    fd.append("ai_review", String(aiReview));
    return call<{ id: string }>("/api/scans/upload", { method: "POST", body: fd });
  },
  reportUrl: (id: string, fmt: string) => `/api/scans/${id}/report.${fmt}`,
};

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export const shortTime = (iso: string) =>
  new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

export const lastParts = (path: string, n = 2) => path.split(/[\\/]/).filter(Boolean).slice(-n).join("/");
