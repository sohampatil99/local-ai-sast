// Shapes returned by the FastAPI backend (backend/api.py, backend/sast/engine.py)

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "true_positive" | "false_positive" | "needs_review";

export interface AiCheck { code: string; kind: string; in_code: boolean }

export interface AiResult {
  model?: string;
  verdict?: Verdict;
  reason?: string;
  origin?: string;
  checks?: AiCheck[];
  confidence?: number | null;
  explanation?: string;
  exploit_scenario?: string;
  fix?: string;
  fixed_code?: string;
  patch?: string;
  patch_rejected?: string;
  source?: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  file: string;
  line: number;
  snippet: string;
  message: string;
  detector: string;
  confidence: string;
  language: string;
  cwe: string;
  owasp: string;
  remediation: string;
  ai: AiResult | null;
}

export interface Summary {
  total: number;
  ai_false_positives: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_owasp: Record<string, number>;
  by_cwe: Record<string, number>;
  by_file: Record<string, number>;
  by_detector: Record<string, number>;
  security_score: number;
  grade: string;
  secrets_exposed: number;
}

export interface ScanResult {
  id: string;
  target: string;
  started_at: string;
  duration_seconds: number;
  static_seconds: number;
  repo: { files_scanned: number; total_loc: number; languages: Record<string, number>; js_engine: string; java_engine?: string };
  ai: { enabled: boolean; model?: string; detail: string; triaged?: number; patched?: number; reviewed_files?: number };
  summary: Summary;
  findings: Finding[];
  fix_patch?: boolean | string;
}

export interface ScanListItem {
  id: string;
  target: string;
  status: "running" | "done" | "failed";
  progress?: string;
  started_at: string;
  score?: number;
  grade?: string;
  total?: number;
  error?: string;
}

export interface ScanDetail extends ScanListItem { result?: ScanResult }

export interface Health {
  status: string;
  database: string;
  offline: boolean;
  llm: { available: boolean; model: string; detail: string };
}
