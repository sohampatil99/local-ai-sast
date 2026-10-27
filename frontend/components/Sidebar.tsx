"use client";
import { useRef, useState } from "react";
import { api, lastParts, shortTime } from "@/lib/api";
import type { ScanListItem } from "@/lib/types";

export function NewScan({ onStarted }: { onStarted: (id: string) => void }) {
  const [target, setTarget] = useState("");
  const [ai, setAi] = useState(false);
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const zip = useRef<HTMLInputElement>(null);

  const run = async (start: () => Promise<{ id: string }>) => {
    setBusy(true);
    setError("");
    try {
      onStarted((await start()).id);
    } catch (e) {
      setError((e as Error).message);
    }
    setBusy(false);
  };

  return (
    <section className="rounded-card border border-line bg-surface p-4">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-lilacInk">New scan</h2>
      <form onSubmit={(e) => { e.preventDefault(); run(() => api.start(target, ai, review)); }} className="grid gap-3">
        <label htmlFor="target" className="text-xs text-muted">Local folder or Git URL</label>
        <input id="target" value={target} onChange={(e) => setTarget(e.target.value)} required autoComplete="off"
          placeholder="C:\path\to\repo"
          className="w-full rounded-lg border border-line bg-bg px-3 py-2 font-mono text-sm placeholder:text-muted/60" />
        <label className="flex items-center gap-2 text-sm">
          <input id="ai" type="checkbox" checked={ai} onChange={(e) => setAi(e.target.checked)} className="accent-[rgb(var(--citrine))]" />
          AI triage and fix patches
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input id="aiReview" type="checkbox" checked={review} onChange={(e) => setReview(e.target.checked)} className="accent-[rgb(var(--citrine))]" />
          AI review for auth and logic flaws
        </label>
        <button type="submit" disabled={busy}
          className="rounded-lg bg-citrine px-3 py-2 text-sm font-semibold text-void transition hover:brightness-95 disabled:opacity-60">
          {busy ? "Starting..." : "Scan"}
        </button>
      </form>
      <div className="mt-3 border-t border-line pt-3">
        <input ref={zip} id="zip" type="file" accept=".zip" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) run(() => api.upload(f, ai, review)); e.target.value = ""; }} />
        <button type="button" onClick={() => zip.current?.click()} disabled={busy}
          className="w-full rounded-lg border border-dashed border-line px-3 py-2 text-sm text-muted hover:border-lilac hover:text-ink">
          or upload a .zip
        </button>
      </div>
      {error && <p role="alert" className="mt-2 text-sm text-crit">{error}</p>}
    </section>
  );
}

export function History({ items, current, onOpen }:
  { items: ScanListItem[]; current?: string; onOpen: (id: string) => void }) {
  return (
    <section className="rounded-card border border-line bg-surface p-4">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-lilacInk">Scan history</h2>
      {items.length === 0 && <p className="text-sm text-muted">No scans yet. Start one above.</p>}
      <ul className="grid max-h-[55vh] gap-1 overflow-auto">
        {items.map((s) => (
          <li key={s.id}>
            <button type="button" onClick={() => onOpen(s.id)}
              className={`w-full rounded-lg border px-3 py-2 text-left transition ${s.id === current
                ? "border-citrine/70 bg-raised" : "border-transparent hover:bg-raised"}`}>
              <div className="truncate font-mono text-[13px]" title={s.target}>{lastParts(s.target)}</div>
              <div className="mt-0.5 flex items-center gap-2 text-xs text-muted">
                <span>{shortTime(s.started_at)}</span>
                {s.status === "done" ? (
                  <>
                    <span>·</span><span>{s.total} findings</span>
                    <span className="ml-auto rounded bg-lilac/20 px-1.5 font-semibold text-ink">{s.grade}</span>
                  </>
                ) : (
                  <span className={s.status === "failed" ? "text-crit" : "text-accent"}>{s.status}</span>
                )}
              </div>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
