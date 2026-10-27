"use client";
import { Fragment, useMemo, useState } from "react";
import type { Finding } from "@/lib/types";
import { Panel, SeverityPill, VerdictBadge } from "./ui";

const key = (f: Finding) => `${f.file}:${f.line}:${f.category}`;

export function Findings({ findings, initialOpen }: { findings: Finding[]; initialOpen?: string }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("");
  const [cat, setCat] = useState("");
  const [det, setDet] = useState("");
  const [onlyNew, setOnlyNew] = useState(false);
  const hasStatus = findings.some((f) => f.status);
  const [open, setOpen] = useState<string | null>(() => {
    const f = initialOpen ? findings.find((x) => `${x.file}:${x.line}` === initialOpen) : undefined;
    return f ? key(f) : null;
  });

  const cats = useMemo(() => [...new Set(findings.map((f) => f.category))].sort(), [findings]);
  const dets = useMemo(() => [...new Set(findings.map((f) => f.detector))].sort(), [findings]);
  const list = findings.filter((f) =>
    (!sev || f.severity === sev) && (!cat || f.category === cat) && (!det || f.detector === det) &&
    (!onlyNew || f.status === "new") &&
    (!q || `${f.title} ${f.file} ${f.cwe} ${f.owasp} ${f.message}`.toLowerCase().includes(q.toLowerCase())));

  const select = "rounded-lg border border-line bg-bg px-2.5 py-1.5 text-sm";
  return (
    <Panel
      title={<>Findings <span className="font-normal text-muted">({list.length} of {findings.length})</span></>}
      aside={
        <div className="flex flex-wrap items-center gap-2">
          {hasStatus && (
            <label className="flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-sm">
              <input id="onlyNew" type="checkbox" checked={onlyNew} onChange={(e) => setOnlyNew(e.target.checked)}
                className="accent-[rgb(var(--citrine))]" />
              Only new
            </label>
          )}
          <input id="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search file, title, CWE..."
            className={`${select} w-56 placeholder:text-muted/60`} />
          <select id="fSeverity" value={sev} onChange={(e) => setSev(e.target.value)} className={select}>
            <option value="">All severities</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select id="fCategory" value={cat} onChange={(e) => setCat(e.target.value)} className={select}>
            <option value="">All categories</option>
            {cats.map((c) => <option key={c}>{c}</option>)}
          </select>
          <select id="fDetector" value={det} onChange={(e) => setDet(e.target.value)} className={select}>
            <option value="">All detectors</option>
            {dets.map((d) => <option key={d}>{d}</option>)}
          </select>
        </div>
      }>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-sm">
          <thead>
            <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.08em] text-lilacInk">
              <th className="px-2 py-2 font-medium">Severity</th>
              <th className="px-2 py-2 font-medium">Finding</th>
              <th className="px-2 py-2 font-medium">Location</th>
              <th className="px-2 py-2 font-medium">CWE / OWASP</th>
              <th className="px-2 py-2 font-medium">AI</th>
            </tr>
          </thead>
          <tbody>
            {list.map((f) => {
              const k = key(f);
              const isOpen = open === k;
              return (
                <Fragment key={k}>
                  <tr data-finding={`${f.file}:${f.line}`} onClick={() => setOpen(isOpen ? null : k)}
                    className={`cursor-pointer border-b border-line align-top transition hover:bg-raised ${isOpen ? "bg-raised" : ""}`}>
                    <td className="px-2 py-2.5"><SeverityPill severity={f.severity} /></td>
                    <td className="px-2 py-2.5">
                      <div className="flex items-center gap-2 font-semibold">
                        {f.title}
                        {f.status === "new" && (
                          <span className="rounded bg-citrine px-1.5 py-px text-[10px] font-bold uppercase tracking-wide text-void">New</span>
                        )}
                      </div>
                      <div className="text-xs text-muted">{f.detector} · confidence {f.confidence}</div>
                    </td>
                    <td className="px-2 py-2.5 font-mono text-[13px]">{f.file}:{f.line}</td>
                    <td className="px-2 py-2.5">{f.cwe}<div className="text-xs text-muted">{f.owasp}</div></td>
                    <td className="px-2 py-2.5"><VerdictBadge verdict={f.ai?.verdict} /></td>
                  </tr>
                  {isOpen && (
                    <tr className="border-b border-line bg-raised/60">
                      <td colSpan={5} className="px-3 pb-4 pt-1"><Detail f={f} /></td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {list.length === 0 && <p className="py-6 text-center text-sm text-muted">No findings match these filters.</p>}
      </div>
    </Panel>
  );
}

function Detail({ f }: { f: Finding }) {
  const ai = f.ai;
  const checks = (ai?.checks ?? []).filter((c) => c.kind !== "other");
  return (
    <div className="grid gap-3">
      <pre className="overflow-x-auto rounded-lg bg-bg px-3 py-2 font-mono text-[13px]">{f.snippet}</pre>
      <p>{f.message}</p>
      <p><span className="font-semibold">Remediation:</span> {f.remediation}</p>
      {ai && (ai.explanation || ai.reason) && (
        <div className="grid gap-2 rounded-xl border border-lilac/40 bg-lilac/10 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-lilac px-2 py-0.5 text-xs font-semibold text-void">AI analysis</span>
            <span className="text-xs text-muted">{ai.model}{ai.confidence != null ? ` · ${Math.round(ai.confidence * 100)}% confident` : ""}</span>
            <span className="ml-auto"><VerdictBadge verdict={ai.verdict} /></span>
          </div>
          {ai.reason && <p><span className="font-semibold">Why this verdict:</span> {ai.reason}</p>}
          {checks.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted">Checks found:</span>
              {checks.map((c, i) => (
                <span key={i} className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-line bg-surface px-2 py-0.5">
                  <code className="truncate font-mono text-xs">{c.code}</code>
                  <span className="whitespace-nowrap text-xs text-muted">{c.kind.replace(/_/g, " ")}</span>
                </span>
              ))}
            </div>
          )}
          {ai.explanation && <p className="text-sm"><span className="text-muted">{ai.reason ? "Model notes: " : ""}</span>{ai.explanation}</p>}
          {ai.exploit_scenario && <p className="text-sm"><span className="text-muted">Attack: </span>{ai.exploit_scenario}</p>}
          {ai.fix && <p className="text-sm"><span className="text-muted">Fix: </span>{ai.fix}</p>}
          {ai.patch ? <Patch patch={ai.patch} /> : ai.fixed_code && (
            <pre className="overflow-x-auto rounded-lg bg-bg px-3 py-2 font-mono text-[13px]">{ai.fixed_code}</pre>
          )}
          {ai.patch_rejected && <p className="text-sm text-muted">{ai.patch_rejected}</p>}
        </div>
      )}
    </div>
  );
}

function Patch({ patch }: { patch: string }) {
  const [copied, setCopied] = useState("Copy patch");
  const lines = patch.split("\n").filter((l) => !l.startsWith("---") && !l.startsWith("+++") && l !== "");
  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(patch);
      setCopied("Copied");
    } catch {
      setCopied("Copy failed: select the diff");
    }
  };
  return (
    <div className="grid gap-2">
      <div className="flex items-center gap-3">
        <span className="text-sm font-semibold">Suggested fix</span>
        <span className="text-xs text-muted">review before applying</span>
        <button type="button" onClick={copy}
          className="ml-auto rounded-md bg-citrine px-2.5 py-1 text-xs font-semibold text-void hover:brightness-95">{copied}</button>
      </div>
      <pre className="overflow-x-auto rounded-lg bg-bg py-2 font-mono text-[13px] leading-6">
        {lines.map((l, i) => (
          <div key={i} className={`px-3 ${l.startsWith("+") ? "bg-ok/10 text-ok" : l.startsWith("-") ? "bg-crit/10 text-crit" : l.startsWith("@@") ? "text-muted" : ""}`}>{l}</div>
        ))}
      </pre>
    </div>
  );
}
