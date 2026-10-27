"use client";
import { useEffect, useState } from "react";
import type { Severity, Verdict } from "@/lib/types";

export function Panel({ title, aside, children, className = "" }:
  { title?: React.ReactNode; aside?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={`rounded-card border border-line bg-surface p-4 min-w-0 ${className}`}>
      {(title || aside) && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          {title && <h3 className="text-sm font-semibold">{title}</h3>}
          {aside}
        </div>
      )}
      {children}
    </section>
  );
}

const SEV_CLASS: Record<string, string> = {
  critical: "bg-crit/15 text-crit ring-crit/40",
  high: "bg-high/15 text-high ring-high/40",
  medium: "bg-med/15 text-med ring-med/40",
  low: "bg-low/15 text-low ring-low/40",
};

export function SeverityPill({ severity }: { severity: Severity | string }) {
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ${SEV_CLASS[severity] ?? "bg-raised text-muted ring-line"}`}>
      {severity}
    </span>
  );
}

const VERDICT: Record<Verdict, [string, string]> = {
  true_positive: ["Confirmed", "text-high"],
  false_positive: ["Dismissed", "text-ok"],
  needs_review: ["Needs review", "text-med"],
};

export function VerdictBadge({ verdict }: { verdict?: Verdict }) {
  if (!verdict) return <span className="text-muted">-</span>;
  const [label, cls] = VERDICT[verdict];
  return <span className={`text-xs font-semibold ${cls}`}>{label}</span>;
}

/** Theme colors as hex-free CSS strings for Recharts, refreshed when the OS theme flips. */
export function useThemeColors() {
  const read = () => {
    if (typeof window === "undefined") return null;
    const s = getComputedStyle(document.documentElement);
    const c = (n: string) => `rgb(${s.getPropertyValue(`--${n}`).trim().split(/\s+/).join(",")})`;
    return { ink: c("ink"), muted: c("muted"), line: c("line"), citrine: c("citrine"), lilac: c("lilac"), lilacInk: c("lilac-ink"),
             accent: c("accent"), crit: c("crit"), high: c("high"), med: c("med"), low: c("low"),
             ok: c("ok"), surface: c("surface") };
  };
  const [colors, setColors] = useState<ReturnType<typeof read>>(null);
  useEffect(() => {
    setColors(read());
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const on = () => setColors(read());
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return colors;
}

export function ShieldMark() {
  return (
    <span className="grid h-8 w-8 place-items-center rounded-full bg-citrine text-void">
      <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" strokeWidth="2.2" />
        <path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" strokeWidth="2.2" />
      </svg>
    </span>
  );
}
