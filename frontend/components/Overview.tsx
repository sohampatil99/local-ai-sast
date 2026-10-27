"use client";
import { api, SEVERITIES, shortTime } from "@/lib/api";
import type { ScanResult } from "@/lib/types";

const SEV_TEXT: Record<string, string> = { critical: "text-crit", high: "text-high", medium: "text-med", low: "text-low" };

export function ScanHeader({ r }: { r: ScanResult }) {
  const formats = ["html", "pdf", "json", "sarif", ...(r.fix_patch ? ["patch"] : [])];
  const langs = Object.entries(r.repo.languages).map(([k, v]) => `${k} ${v}`).join(", ");
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="break-all font-mono text-lg font-semibold">{r.target}</h1>
        <p className="mt-1 text-sm text-muted">
          {r.repo.files_scanned} files · {r.repo.total_loc.toLocaleString()} lines · {r.duration_seconds}s · {langs}
        </p>
        <p className="text-sm text-muted">AI: {r.ai.detail}{r.ai.enabled && r.ai.triaged ? ` · ${r.ai.triaged} triaged · ${r.ai.patched ?? 0} patches` : ""}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        {formats.map((f) => (
          <a key={f} href={api.reportUrl(r.id, f)} target="_blank" rel="noopener"
            className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition ${f === "patch"
              ? "border-citrine bg-citrine text-void hover:brightness-95" : "border-line bg-surface hover:border-lilac"}`}>
            {f === "patch" ? "Download fixes (.patch)" : f.toUpperCase()}
          </a>
        ))}
      </div>
    </div>
  );
}

export function ScoreAndTiles({ r }: { r: ScanResult }) {
  const s = r.summary;
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(240px,300px)_1fr]">
      <div className="glow relative flex min-h-[190px] flex-col justify-end overflow-hidden rounded-card p-5 text-void">
        <span className="absolute right-5 top-4 text-xs font-semibold uppercase tracking-[0.14em] text-citrine">Security score</span>
        <div className="flex items-end gap-3">
          <span className="text-6xl font-bold leading-none tabular-nums">{s.security_score}</span>
          <span className="mb-1 text-lg font-semibold opacity-70">/100</span>
          <span className="mb-1 ml-auto rounded-xl bg-void px-3 py-1 text-2xl font-bold text-citrine">{s.grade}</span>
        </div>
        <p className="mt-2 text-sm font-medium opacity-75">{s.total} findings counted · {s.ai_false_positives} dismissed by AI</p>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {SEVERITIES.map((sev) => (
          <div key={sev} className="rounded-card border border-line bg-surface p-4">
            <div className="text-xs capitalize text-muted">{sev}</div>
            <div className={`mt-1 text-3xl font-bold tabular-nums ${SEV_TEXT[sev]}`}>{s.by_severity[sev] ?? 0}</div>
          </div>
        ))}
        <div className="rounded-card border border-line bg-surface p-4">
          <div className="text-xs text-muted">Secrets exposed</div>
          <div className="mt-1 text-3xl font-bold tabular-nums">{s.secrets_exposed}</div>
        </div>
        <div className="rounded-card border border-lilac/40 bg-lilac/10 p-4">
          <div className="text-xs text-muted">Dismissed by AI</div>
          <div className="mt-1 text-3xl font-bold tabular-nums">{s.ai_false_positives}</div>
        </div>
      </div>
    </div>
  );
}

/** New / fixed / unchanged against the previous scan of this target, and what an incremental scan reused. */
export function SinceLastScan({ r }: { r: ScanResult }) {
  const c = r.comparison;
  if (!c) return null;
  const inc = c.incremental;
  return (
    <section className="grid gap-3 rounded-card border border-lilac/40 bg-lilac/10 p-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <h3 className="text-sm font-semibold text-lilacInk">Since the scan of {shortTime(c.baseline_started_at)}</h3>
        <span className="text-sm"><b className="text-xl tabular-nums text-crit">{c.new}</b> new</span>
        <span className="text-sm"><b className="text-xl tabular-nums text-ok">{c.fixed}</b> fixed</span>
        <span className="text-sm"><b className="text-xl tabular-nums">{c.existing}</b> unchanged</span>
        {inc && (
          <span className="ml-auto rounded-full border border-line bg-surface px-3 py-1 text-xs">
            Incremental: re-analyzed {inc.rescanned} of {inc.rescanned + inc.reused_files} files
            ({inc.changed.length} changed)
          </span>
        )}
      </div>
      {c.fixed_findings.length > 0 && (
        <details>
          <summary className="cursor-pointer text-sm text-muted">Fixed since last scan ({c.fixed_findings.length})</summary>
          <ul className="mt-2 grid gap-1 text-sm">
            {c.fixed_findings.map((f, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2">
                <span className="rounded bg-ok/15 px-1.5 text-xs font-semibold text-ok">FIXED</span>
                <span className="font-medium line-through decoration-ok/60">{f.title}</span>
                <span className="font-mono text-xs text-muted">{f.file}:{f.line}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

export function TopFiles({ r }: { r: ScanResult }) {
  const files = Object.entries(r.summary.by_file).slice(0, 8);
  const max = Math.max(1, ...files.map(([, n]) => n));
  if (!files.length) return <p className="text-sm text-muted">No findings.</p>;
  return (
    <ul className="grid gap-2">
      {files.map(([f, n]) => (
        <li key={f} className="grid grid-cols-[minmax(0,1fr)_minmax(60px,35%)_2.5rem] items-center gap-3 text-sm">
          <span className="truncate font-mono text-[13px]" title={f}>{f}</span>
          <span className="h-2 rounded-full bg-raised"><span className="block h-2 rounded-full bg-lilac" style={{ width: `${(n / max) * 100}%` }} /></span>
          <span className="text-right tabular-nums text-muted">{n}</span>
        </li>
      ))}
    </ul>
  );
}
