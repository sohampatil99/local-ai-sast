"use client";
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITIES, shortTime } from "@/lib/api";
import type { ScanListItem, ScanResult } from "@/lib/types";
import { Panel, useThemeColors } from "./ui";

const box = "h-[230px]";

export function Charts({ r, history }: { r: ScanResult; history: ScanListItem[] }) {
  const c = useThemeColors();
  if (!c) return <div className="grid gap-4 lg:grid-cols-3"><Panel title="Severity">{null}</Panel></div>;
  const tip = { contentStyle: { background: c.surface, border: `1px solid ${c.line}`, borderRadius: 10, color: c.ink },
                itemStyle: { color: c.ink }, labelStyle: { color: c.muted } };
  const axis = { stroke: c.line, tick: { fill: c.muted, fontSize: 12 } };

  const sevColor: Record<string, string> = { critical: c.crit, high: c.high, medium: c.med, low: c.low };
  const sev = SEVERITIES.map((s) => ({ name: s, value: r.summary.by_severity[s] ?? 0 })).filter((d) => d.value > 0);
  const owasp = Object.entries(r.summary.by_owasp).map(([k, v]) => ({ code: k.split(" ")[0].replace(":2021", ""), name: k, value: v }));
  const trend = history.filter((h) => h.target === r.target && h.status === "done").reverse()
    .map((h) => ({ when: shortTime(h.started_at), findings: h.total ?? 0, score: h.score ?? 0 }));

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Panel title="Severity">
        <div className={box}>
          <ResponsiveContainer>
            <PieChart>
              <Pie data={sev} dataKey="value" nameKey="name" innerRadius="58%" outerRadius="86%" paddingAngle={2} stroke="none">
                {sev.map((d) => <Cell key={d.name} fill={sevColor[d.name]} />)}
              </Pie>
              <Tooltip {...tip} />
              <Legend verticalAlign="middle" align="right" layout="vertical" iconType="circle"
                formatter={(v) => <span style={{ color: c.ink, textTransform: "capitalize" }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </Panel>
      <Panel title="OWASP Top 10 (2021)">
        <div className={box}>
          <ResponsiveContainer>
            <BarChart data={owasp} layout="vertical" margin={{ left: 0, right: 16 }}>
              <CartesianGrid horizontal={false} stroke={c.line} />
              <XAxis type="number" allowDecimals={false} {...axis} />
              <YAxis type="category" dataKey="code" width={44} {...axis} />
              <Tooltip {...tip} cursor={{ fill: c.line, opacity: 0.4 }}
                labelFormatter={(_, p) => (p?.[0]?.payload as { name?: string })?.name ?? ""} />
              <Bar dataKey="value" name="Findings" fill={c.citrine} stroke={c.accent} strokeWidth={1} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>
      <Panel title="Trend for this target">
        <div className={box}>
          {trend.length < 2 ? (
            <p className="grid h-full place-items-center text-center text-sm text-muted">Scan this target again to see a trend.</p>
          ) : (
            <ResponsiveContainer>
              <LineChart data={trend} margin={{ left: -12, right: 12, top: 8 }}>
                <CartesianGrid vertical={false} stroke={c.line} />
                <XAxis dataKey="when" {...axis} tick={{ ...axis.tick, fontSize: 11 }} minTickGap={24} />
                <YAxis allowDecimals={false} {...axis} />
                <Tooltip {...tip} />
                <Legend formatter={(v) => <span style={{ color: c.ink }}>{v}</span>} />
                <Line type="monotone" dataKey="findings" name="Findings" stroke={c.high} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="score" name="Score" stroke={c.lilacInk} strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </Panel>
    </div>
  );
}
