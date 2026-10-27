"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { Charts } from "@/components/Charts";
import { Findings } from "@/components/Findings";
import { ScanHeader, ScoreAndTiles, TopFiles } from "@/components/Overview";
import { History, NewScan } from "@/components/Sidebar";
import { Panel, ShieldMark } from "@/components/ui";
import { api } from "@/lib/api";
import type { Health, ScanDetail, ScanListItem } from "@/lib/types";

export default function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [history, setHistory] = useState<ScanListItem[]>([]);
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [focus, setFocus] = useState<string | undefined>();
  const poll = useRef<ReturnType<typeof setInterval> | undefined>(undefined);

  const loadHealth = useCallback(() => {
    api.health().then((h) => { setHealth(h); setHealthError(false); }).catch(() => setHealthError(true));
  }, []);

  const loadHistory = useCallback(async () => {
    const items = await api.scans();
    setHistory(items);
    return items;
  }, []);

  // Only the most recently opened scan may update the view: a slower response for an earlier click is dropped
  const wanted = useRef<string | undefined>(undefined);
  const open = useCallback(async (id: string) => {
    wanted.current = id;
    clearInterval(poll.current);
    const s = await api.scan(id);
    if (wanted.current !== id) return;
    setScan(s);
    if (s.status !== "running") {
      loadHistory();  // a fast scan can finish before the first look; refresh its "running" row
      return;
    }
    poll.current = setInterval(async () => {
      const p = await api.scan(id);
      if (wanted.current !== id) return;
      setScan(p);
      if (p.status !== "running") {
        clearInterval(poll.current);
        loadHistory();
      }
    }, 1000);
  }, [loadHistory]);

  useEffect(() => {
    loadHealth();
    const t = setInterval(loadHealth, 15000);
    // Links like /?scan=<id>&finding=<file:line> open that scan with the finding expanded
    const q = new URLSearchParams(window.location.search);
    setFocus(q.get("finding") ?? undefined);
    loadHistory().then((items) => {
      const id = q.get("scan") ?? items[0]?.id;
      if (id) open(id);
    }).catch(() => setHealthError(true));
    return () => { clearInterval(t); clearInterval(poll.current); };
  }, [loadHealth, loadHistory, open]);

  useEffect(() => {
    if (!focus || !scan?.result) return;
    const row = document.querySelector(`[data-finding="${CSS.escape(focus)}"]`);
    row?.scrollIntoView({ block: "start" });
  }, [focus, scan?.result]);

  const started = async (id: string) => {
    await loadHistory();
    open(id);
  };

  const r = scan?.result;
  return (
    <div className="min-h-full">
      <header className="topbar sticky top-0 z-10 border-b backdrop-blur">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <ShieldMark />
            <div>
              <div className="font-semibold leading-tight">Local AI SAST</div>
              <div className="sub text-xs">Offline security scanning with a local LLM</div>
            </div>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            {healthError ? (
              <span className="rounded-full border border-crit/50 px-3 py-1 text-crit">Backend unreachable: start it with start.bat</span>
            ) : !health ? (
              <span className="chip sub rounded-full px-3 py-1">Checking the local AI...</span>
            ) : (
              <>
                <span className="rounded-full bg-citrine px-3 py-1 font-semibold text-void">Code stays on this machine</span>
                <span className="chip rounded-full px-3 py-1">Database: {health.database}</span>
                <span title={health.llm.detail}
                  className={`rounded-full px-3 py-1 ${health.llm.available ? "chip bg-lilac/15" : "border border-med/60 text-med"}`}>
                  {health.llm.available ? `AI: ${health.llm.model}` : "AI unavailable"}
                </span>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto grid max-w-[1500px] gap-5 px-4 py-5 sm:px-6 lg:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="grid content-start gap-4">
          <NewScan onStarted={started} />
          <History items={history} current={scan?.id} onOpen={open} />
        </aside>

        <div className="grid min-w-0 content-start gap-5">
          {!scan && <Empty />}
          {scan?.status === "running" && (
            <Panel>
              <div className="flex items-center gap-3">
                <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-citrine" />
                <span className="font-mono text-sm">{scan.target}</span>
              </div>
              <p className="mt-2 text-sm text-muted">Scanning... {scan.progress}</p>
            </Panel>
          )}
          {scan?.status === "failed" && (
            <Panel><p className="text-crit">Scan failed: {scan.error}</p></Panel>
          )}
          {r && (
            <>
              <ScanHeader r={r} />
              <ScoreAndTiles r={r} />
              <Charts r={r} history={history} />
              <Findings key={r.id} findings={r.findings} initialOpen={focus} />
              <Panel title="Files with the most findings"><TopFiles r={r} /></Panel>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function Empty() {
  return (
    <div className="glow grid min-h-[280px] content-end rounded-card p-8 text-void">
      <h1 className="text-3xl font-bold">Scan a repository</h1>
      <p className="mt-2 max-w-xl font-medium opacity-80">
        Enter a local folder or a Git URL, or upload a .zip. Everything runs on this machine and no source code leaves it.
      </p>
    </div>
  );
}
