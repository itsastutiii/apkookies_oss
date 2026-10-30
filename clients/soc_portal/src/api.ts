const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export type Severity = "low" | "medium" | "high" | "critical";
export type VerdictLabel = "benign" | "suspicious" | "malicious" | "unknown";
export type ReportStatus = "processing" | "complete" | "failed";

// Mirrors schemas/report.py (Report, schema 1.0.0). Optional fields are ones older
// reports may not have.
export interface ScoreStep {
  step: string;            // model | kg_context | runtime_* | rule:<id> | remembered_verdict
  kind: "base" | "add" | "floor";
  delta: number;
  score_after: number;
  detail: string;
}

export interface RuleHit {
  rule_id: string;
  description: string;
  hard_override: boolean;
  min_score?: number;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  evidence_refs?: string[];
  evidence_strength?: "permission" | "api_call" | "runtime" | string | null;
  attack_version?: string | null;
}

export interface StageStatus {
  status: string;          // observed | heuristic | failed | unavailable | disabled | ...
  reason?: string;
}

export interface Report {
  schema_version: string;
  report_id: string;
  status: ReportStatus;
  sandbox_job_id?: string | null;
  created_at: string;
  completed_at?: string | null;
  human_review_required: boolean;
  input: { input_type: "apk" | "url"; source_touchpoint?: string; url?: string | null; filename?: string | null; package_name?: string | null };
  hashes?: {
    sha256?: string | null;
    dex_sha256?: string | null;
    tlsh?: string | null;
    dex_tlsh?: string | null;
    fuzzy_status?: string | null;
    cluster_id?: string | null;
    inherited_verdict_from?: string | null;
  };
  verdict: {
    label: VerdictLabel;
    confidence: number;
    decision_path: string[];
    provenance?: { source?: string; scoring_version?: string; fingerprint?: string; recorded_at?: string } | null;
    stale_previous_verdict?: string | null;
  };
  risk: {
    score: number;
    severity: Severity;
    components: Record<string, number>;
    breakdown?: ScoreStep[];
    rules_triggered: RuleHit[];
    scoring_mode?: string | null;
  };
  static_bundle?: ({ analysis_status?: Record<string, StageStatus> } & Record<string, unknown>) | null;
  dynamic_bundle?: Record<string, unknown> | null;
  static_findings: {
    permissions: string[];
    capabilities: string[];
    obfuscation: string[];
    api_usage?: { category: string; context: string; suspicious: boolean; rule_id?: string | null; evidence?: string | null }[];
    anti_analysis: { technique: string; mitre_id: string; detected_where: string; evidence?: string | null; common_in_benign?: boolean }[];
  };
  dynamic_findings?: {
    executed: boolean;
    sandbox_run_id?: string | null;
    runtime_behaviors: string[];
    network: { kind: string; indicator: string; is_c2: boolean; is_exfil: boolean }[];
    syscall_traces: string[];
    overlay_attempts: number;
  } | null;
  threat_intel: {
    family?: string | null;
    family_confidence?: number | null;
    iocs: { type: string; value: string; enrichment?: Record<string, unknown> | null; telegram_c2_live?: boolean | null }[];
    stix_bundle_ref?: string | null;
  };
  mitre_attack: MitreTechnique[];
  evidence: { evidence_id: string; source: string; summary: string; raw_ref?: string | null }[];
  explanation?: { plain_language: string; grounded: boolean; cited_evidence_ids: string[] } | null;
  recommendations: { action: string; rationale: string; priority: string }[];
}

export interface ReportSummary {
  report_id: string;
  created_at: string;
  status: ReportStatus;
  input_type: string;
  name: string;
  verdict: VerdictLabel;
  score: number;
  severity: Severity;
  scoring_mode?: string | null;
}

export interface JobStatus {
  job_id: string;
  status: "queued" | "running" | "done" | "failed";
  report_id: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
}

export interface TelegramLivenessResponse {
  tokens_found: number;
  note: string;
}

export interface ExternalAnalysisResponse {
  result: string;
  model: string;
}

async function request<T>(url: string, init?: RequestInit, timeoutMs = 20_000): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: init?.signal ?? controller.signal });
    if (!response.ok) {
      throw new Error(`${response.status}: ${await response.text()}`);
    }
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("The request timed out. Check that the backend and Gemini service are available.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function listReports(): Promise<ReportSummary[]> {
  return request<ReportSummary[]>(`${API_BASE}/v1/reports/summaries`);
}

export async function getReport(id: string): Promise<Report> {
  return request<Report>(`${API_BASE}/v1/reports/${id}`);
}

export async function getJob(id: string): Promise<JobStatus> {
  return request<JobStatus>(`${API_BASE}/v1/jobs/${id}`);
}

export async function getMitreHeatmap(id: string): Promise<Report["mitre_attack"]> {
  return request<Report["mitre_attack"]>(`${API_BASE}/v1/reports/${id}/mitre-heatmap`);
}

export async function checkTelegramLiveness(id: string): Promise<TelegramLivenessResponse> {
  return request<TelegramLivenessResponse>(`${API_BASE}/v1/reports/${id}/telegram-liveness`, {
    method: "POST",
  });
}

export async function analyzeExternalOutput(analysisText: string): Promise<ExternalAnalysisResponse> {
  return request<ExternalAnalysisResponse>(`${API_BASE}/v1/genai/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analysis_text: analysisText }),
  }, 90_000);
}
