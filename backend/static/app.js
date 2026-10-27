const SEVERITIES = ["critical", "high", "medium", "low"];
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const localTime = (iso) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

let history = [];
let current = null;
let charts = {};
let poller = null;
let openRow = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

async function loadHealth() {
  try {
    const h = await api("/api/health");
    $("badges").innerHTML =
      `<span class="badge ok">Offline: code stays local</span>` +
      `<span class="badge ok">DB: ${esc(h.database)}</span>` +
      `<span class="badge ${h.llm.available ? "ok" : "warn"}">LLM: ${esc(h.llm.available ? h.llm.model : "unavailable")}</span>`;
    $("badges").title = h.llm.detail;
  } catch { $("badges").innerHTML = `<span class="badge warn">API unreachable</span>`; }
}

async function loadHistory(selectId) {
  history = await api("/api/scans");
  $("history").innerHTML = history.map((s) => `
    <li data-id="${s.id}" class="${current && current.id === s.id ? "active" : ""}">
      <div class="t">${esc(s.target.split(/[\\/]/).slice(-2).join("/"))}</div>
      <div class="s">${esc(localTime(s.started_at))} &middot; ${s.status === "done"
        ? `${s.total} findings &middot; ${s.grade} (${s.score})` : esc(s.status)}</div>
    </li>`).join("") || `<li class="s">No scans yet</li>`;
  $("history").querySelectorAll("li[data-id]").forEach((li) => li.onclick = () => openScan(li.dataset.id));
  if (selectId) openScan(selectId);
  else if (!current && history.length) openScan(history[0].id);
}

async function openScan(id) {
  clearInterval(poller);
  const s = await api(`/api/scans/${id}`);
  current = s;
  document.querySelectorAll("#history li").forEach((li) => li.classList.toggle("active", li.dataset.id === id));
  $("empty").hidden = true;
  $("scanView").hidden = false;
  $("scanTitle").textContent = s.target;
  if (s.status === "running") {
    $("progress").hidden = false;
    $("progress").textContent = `Scanning... ${s.progress || ""}`;
    $("scanMeta").textContent = "";
    $("tiles").innerHTML = ""; $("rows").innerHTML = ""; $("exports").innerHTML = "";
    poller = setInterval(async () => {
      const p = await api(`/api/scans/${id}`);
      $("progress").textContent = `Scanning... ${p.progress || ""}`;
      if (p.status !== "running") { clearInterval(poller); loadHistory(id); }
    }, 1000);
    return;
  }
  if (s.status === "failed") {
    $("progress").hidden = false;
    $("progress").textContent = `Scan failed: ${s.error}`;
    return;
  }
  $("progress").hidden = true;
  render(s.result);
}

function render(r) {
  const sm = r.summary;
  $("scanMeta").innerHTML = `${r.repo.files_scanned} files &middot; ${r.repo.total_loc.toLocaleString()} LOC &middot; ` +
    `${r.duration_seconds}s &middot; ${Object.entries(r.repo.languages).map(([k, v]) => `${k} ${v}`).join(", ")} &middot; AI: ${esc(r.ai.detail)}`;
  $("exports").innerHTML = ["html", "pdf", "json", "sarif", ...(r.fix_patch ? ["patch"] : [])].map((f) =>
    `<a href="/api/scans/${r.id}/report.${f}" target="_blank" rel="noopener">${f.toUpperCase()}</a>`).join("");
  $("tiles").innerHTML =
    tile("Security score", `${sm.security_score}<small class="muted">/100</small>`, `grade-${sm.grade}`, `Grade ${sm.grade}`) +
    SEVERITIES.map((s) => tile(s[0].toUpperCase() + s.slice(1), sm.by_severity[s] || 0, s)).join("") +
    tile("Secrets exposed", sm.secrets_exposed, "high") +
    tile("AI false positives", sm.ai_false_positives, "");
  drawCharts(r);
  fillFilters(r);
  renderRows();
  const files = Object.entries(sm.by_file).slice(0, 10);
  const max = Math.max(1, ...files.map(([, n]) => n));
  $("fileList").innerHTML = files.map(([f, n]) =>
    `<div class="f"><span class="name" title="${esc(f)}">${esc(f)}</span><span class="bar" style="width:${(n / max) * 50}%"></span><span>${n}</span></div>`).join("");
}

function tile(k, v, cls, sub) {
  return `<div class="tile ${cls}"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="muted">${sub}</div>` : ""}</div>`;
}

function drawCharts(r) {
  Object.values(charts).forEach((c) => c.destroy());
  const sm = r.summary;
  const sevColors = [css("--crit"), css("--high"), css("--med"), css("--low")];
  Chart.defaults.color = css("--muted");
  Chart.defaults.borderColor = css("--line");
  charts.sev = new Chart($("sevChart"), {
    type: "doughnut",
    data: { labels: SEVERITIES, datasets: [{ data: SEVERITIES.map((s) => sm.by_severity[s] || 0), backgroundColor: sevColors, borderWidth: 0 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "right" } }, cutout: "60%" },
  });
  const ow = Object.entries(sm.by_owasp);
  charts.owasp = new Chart($("owaspChart"), {
    type: "bar",
    data: { labels: ow.map(([k]) => k.split(" ")[0]), datasets: [{ data: ow.map(([, v]) => v), backgroundColor: css("--accent") }] },
    options: { maintainAspectRatio: false, indexAxis: "y", plugins: { legend: { display: false },
      tooltip: { callbacks: { title: (i) => ow[i[0].dataIndex][0] } } }, scales: { x: { ticks: { precision: 0 } } } },
  });
  const same = history.filter((h) => h.target === current.target && h.status === "done").reverse();
  charts.trend = new Chart($("trendChart"), {
    type: "line",
    data: {
      labels: same.map((h) => localTime(h.started_at)),
      datasets: [
        { label: "Findings", data: same.map((h) => h.total), borderColor: css("--high"), tension: 0.2 },
        { label: "Score", data: same.map((h) => h.score), borderColor: css("--ok"), tension: 0.2 },
      ],
    },
    options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true } } },
  });
}

function fillFilters(r) {
  const cats = [...new Set(r.findings.map((f) => f.category))].sort();
  const dets = [...new Set(r.findings.map((f) => f.detector))].sort();
  $("fCategory").innerHTML = `<option value="">All categories</option>` + cats.map((c) => `<option>${esc(c)}</option>`).join("");
  $("fDetector").innerHTML = `<option value="">All detectors</option>` + dets.map((c) => `<option>${esc(c)}</option>`).join("");
}

function renderRows() {
  if (!current || !current.result) return;
  const q = $("search").value.toLowerCase();
  const sev = $("fSeverity").value, cat = $("fCategory").value, det = $("fDetector").value;
  const list = current.result.findings.filter((f) =>
    (!sev || f.severity === sev) && (!cat || f.category === cat) && (!det || f.detector === det) &&
    (!q || `${f.title} ${f.file} ${f.cwe} ${f.owasp} ${f.message}`.toLowerCase().includes(q)));
  $("count").textContent = `(${list.length} of ${current.result.findings.length})`;
  $("rows").innerHTML = list.map((f, i) => `
    <tr class="row" data-i="${i}">
      <td><span class="pill ${f.severity}">${f.severity}</span></td>
      <td><strong>${esc(f.title)}</strong><div class="muted">${esc(f.detector)} &middot; confidence ${esc(f.confidence)}</div></td>
      <td><code>${esc(f.file)}:${f.line}</code></td>
      <td>${esc(f.cwe)}<div class="muted">${esc(f.owasp)}</div></td>
      <td>${f.ai && f.ai.verdict ? `<span class="verdict ${f.ai.verdict}">${f.ai.verdict.replace("_", " ")}</span>` : `<span class="muted">-</span>`}</td>
    </tr>`).join("");
  $("rows").querySelectorAll("tr.row").forEach((tr) => tr.onclick = () => toggleDetail(tr, list[+tr.dataset.i]));
}

function toggleDetail(tr, f) {
  if (openRow) {
    const wasThis = openRow.previousSibling === tr;
    openRow.remove();
    openRow = null;
    if (wasThis) return;
  }
  const d = document.createElement("tr");
  d.className = "detail";
  const ai = f.ai && f.ai.explanation ? `
    <div class="ai-box"><strong>AI analysis</strong> (${esc(f.ai.model || "")}${f.ai.confidence != null ? `, ${Math.round(f.ai.confidence * 100)}% confident` : ""})
      ${f.ai.reason ? `<div><strong>Why this verdict:</strong> ${esc(f.ai.reason)}</div>` : ""}
      <div>${f.ai.reason ? "<em>Model notes:</em> " : ""}${esc(f.ai.explanation)}</div>
      ${f.ai.exploit_scenario ? `<div><em>Attack:</em> ${esc(f.ai.exploit_scenario)}</div>` : ""}
      ${f.ai.fix ? `<div><em>Fix:</em> ${esc(f.ai.fix)}</div>` : ""}
      ${f.ai.checks && f.ai.checks.length ? `<div><em>Checks found:</em> ${f.ai.checks.map((c) => `<code>${esc(c.code)}</code> (${esc(c.kind.replace("_", " "))})`).join("; ")}</div>` : ""}
      ${f.ai.patch ? `<div class="patch-head"><em>Suggested fix (review before applying)</em><button type="button" class="copy">Copy patch</button></div>${diffHtml(f.ai.patch)}`
        : f.ai.fixed_code ? `<pre>${esc(f.ai.fixed_code)}</pre>` : ""}
      ${f.ai.patch_rejected ? `<div class="muted">${esc(f.ai.patch_rejected)}</div>` : ""}
    </div>` : "";
  d.innerHTML = `<td colspan="5"><pre>${esc(f.snippet)}</pre><div>${esc(f.message)}</div>
    <div><strong>Remediation:</strong> ${esc(f.remediation)}</div>${ai}</td>`;
  tr.after(d);
  openRow = d;
  const copy = d.querySelector("button.copy");
  if (copy) copy.onclick = async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(f.ai.patch); copy.textContent = "Copied"; }
    catch { copy.textContent = "Copy failed: select the diff"; }
  };
}

function diffHtml(patch) {
  return `<pre class="diff">${patch.split("\n").filter((l) => !l.startsWith("---") && !l.startsWith("+++")).map((l) =>
    `<span class="${l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("@@") ? "hunk" : ""}">${esc(l)}</span>`).join("\n")}</pre>`;
}

$("scanForm").onsubmit = async (e) => {
  e.preventDefault();
  $("formMsg").textContent = "";
  $("scanBtn").disabled = true;
  try {
    const res = await api("/api/scans", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: $("target").value, ai: $("ai").checked, ai_review: $("aiReview").checked }),
    });
    current = { id: res.id };
    await loadHistory(res.id);
  } catch (err) { $("formMsg").textContent = err.message; }
  $("scanBtn").disabled = false;
};

$("zip").onchange = async () => {
  const file = $("zip").files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  fd.append("ai", $("ai").checked);
  fd.append("ai_review", $("aiReview").checked);
  try {
    const res = await api("/api/scans/upload", { method: "POST", body: fd });
    current = { id: res.id };
    await loadHistory(res.id);
  } catch (err) { $("formMsg").textContent = err.message; }
  $("zip").value = "";
};

["search", "fSeverity", "fCategory", "fDetector"].forEach((id) => $(id).addEventListener("input", renderRows));

// Links like /?scan=<id>&finding=<file:line> open a scan with that finding expanded
async function openFromLink() {
  const q = new URLSearchParams(location.search);
  if (!q.get("scan")) return loadHistory();
  await loadHistory(q.get("scan"));
  const want = q.get("finding");
  if (!want) return;
  const wait = setInterval(() => {
    const rows = [...document.querySelectorAll("#rows tr.row")];
    const tr = rows.find((r) => r.querySelector("code") && r.querySelector("code").textContent === want);
    if (!tr) return;
    clearInterval(wait);
    tr.click();
    tr.scrollIntoView({ block: "start" });
  }, 200);
}

loadHealth();
openFromLink();
setInterval(loadHealth, 15000);
