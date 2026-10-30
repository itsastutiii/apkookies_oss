import { useCallback, useEffect, useState } from "react";
import {
  analyzeExternalOutput, checkTelegramLiveness, getJob, getReport, listReports,
  type MitreTechnique, type Report, type ReportSummary, type ScoreStep,
} from "./api";
import "./styles.css";

export default function App() {
  const [rows, setRows] = useState<ReportSummary[]>([]);
  const [selected, setSelected] = useState<Report | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<"reports" | "evidence">("reports");

  const refreshList = useCallback(async () => {
    try {
      const next = await listReports();
      setRows(next);
      setSelectedId((current) => current ?? next[0]?.report_id ?? null);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refreshList(); }, [refreshList]);

  useEffect(() => {
    if (!selectedId) return;
    setLoading(true);
    getReport(selectedId).then(setSelected).catch((err) => setError(errorMessage(err))).finally(() => setLoading(false));
  }, [selectedId]);

  const refreshSelectedReport = useCallback(async () => {
    if (!selectedId) return;
    try {
      setSelected(await getReport(selectedId));
    } catch (err) {
      setError(errorMessage(err));
    }
  }, [selectedId]);

  return (
    <div className="portal-shell">
      <header className="topbar"><div className="brand"><span className="brand-mark">A</span><div><strong>APKookies</strong><small>SOC ANALYST CONSOLE</small></div></div><span className="connection"><i /> {error ? "API unreachable" : "API connected"}</span></header>
      <div className="workspace">
        <aside className="sidebar">
          <div className="sidebar-title"><div><span className="eyebrow">CASE INBOX</span><h2>Submissions</h2></div><b>{rows.length}</b></div>
          <button className={`nav-button ${activeView === "reports" ? "active" : ""}`} onClick={() => setActiveView("reports")}>⌁ <span>Case reports</span></button>
          <button className={`nav-button ${activeView === "evidence" ? "active" : ""}`} onClick={() => setActiveView("evidence")}>✦ <span>Evidence analyst</span><em className="soon">experimental</em></button>
          {activeView === "reports" && (
            loading && rows.length === 0 ? <p className="empty">Loading cases...</p>
              : rows.length === 0 ? <p className="empty">No reports yet. Run scripts/seed_demo_reports.py.</p>
                : <div className="case-list">
                  <button className="refresh" onClick={() => void refreshList()}>↻ Refresh</button>
                  {rows.map((row) => (
                    <button className={`case-row ${selectedId === row.report_id ? "active" : ""}`} key={row.report_id} onClick={() => { setActiveView("reports"); setSelectedId(row.report_id); }}>
                      <span className={`case-dot ${row.verdict}`} />
                      <span><strong>{row.name}</strong><small>{row.verdict} · {row.score.toFixed(2)} · {formatDate(row.created_at)}</small></span>
                      <em>›</em>
                    </button>
                  ))}
                </div>
          )}
          <div className="sidebar-footer"><span>REPORT STORE</span><strong>Local evidence vault</strong><small>Read-only analyst access</small></div>
        </aside>
        <main className="content">{error && <div className="error-banner"><strong>{activeView === "evidence" ? "Gemini analysis unavailable" : "Unable to load report"}</strong><span>{error}</span><button onClick={() => setError(null)}>Dismiss</button></div>}{activeView === "evidence" ? <EvidenceAnalyzer onError={setError} /> : loading && !selected ? <div className="loading">Loading report...</div> : selected ? <ReportView report={selected} onRefresh={refreshSelectedReport} /> : <div className="welcome"><span>+</span><h1>Select a submission</h1><p>Choose a case from the inbox to inspect its evidence and response guidance.</p></div>}</main>
      </div>
    </div>
  );
}

function EvidenceAnalyzer({ onError }: { onError: (message: string | null) => void }) {
  const [analysisText, setAnalysisText] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [model, setModel] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const canSubmit = Boolean(analysisText.trim() && !submitting);

  async function analyze() {
    if (!canSubmit) return;
    onError(null);
    setSubmitting(true);
    setResult(null);
    try {
      const response = await analyzeExternalOutput(analysisText);
      setResult(response.result);
      setModel(response.model);
    } catch (err) {
      onError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return <><div className="page-heading"><div><span className="eyebrow">GENAI / EVIDENCE ANALYST</span><h1>Explain model output</h1><p className="muted">Paste one complete analysis result and receive a human-readable SOC explanation.</p></div><span className="status-pill"><i /> Gemini</span></div><div className="evidence-intro">The text is treated as analyst-supplied data. Gemini explains the supplied score and evidence without changing the verdict.</div><section className="evidence-inputs single"><label><span>Analysis result</span><textarea value={analysisText} onChange={(event) => setAnalysisText(event.target.value)} placeholder="Paste the complete RiskResult dictionary or JSON here..." disabled={submitting} /></label></section><button className="analyze-button" onClick={() => void analyze()} disabled={!canSubmit}>{submitting && <span className="spinner" />}{submitting ? "Generating explanation..." : "Explain with Gemini"}</button>{result && <Panel title="Analyst interpretation" eyebrow={model ? `GENERATED BY ${model}` : "GENAI RESULT"}><div className="analysis-result">{result}</div></Panel>}</>;
}

function ReportView({ report, onRefresh }: { report: Report; onRefresh: () => void }) {
  const [telegramMessage, setTelegramMessage] = useState<string | null>(null);
  const [jobMessage, setJobMessage] = useState<string | null>(null);
  useEffect(() => {
    if (report.status !== "processing") {
      setJobMessage(null);
      return;
    }
    const poll = async () => {
      if (report.sandbox_job_id) {
        try {
          const job = await getJob(report.sandbox_job_id);
          setJobMessage(`Sandbox job: ${job.status}`);
        } catch (err) {
          setJobMessage(errorMessage(err));
        }
      }
      onRefresh();
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 5000);
    return () => window.clearInterval(timer);
  }, [report.status, report.sandbox_job_id, onRefresh]);
  async function telegramCheck() { setTelegramMessage("Checking..."); try { const result = await checkTelegramLiveness(report.report_id); setTelegramMessage(`${result.tokens_found} token(s) found. ${result.note}`); } catch (err) { setTelegramMessage(errorMessage(err)); } }
  const mode = report.risk.scoring_mode ?? "model";
  const prov = report.verdict.provenance;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">ANALYSIS REPORT / {report.report_id.slice(0, 12)}</span>
          <h1>{report.input.filename || report.input.url || "Untitled submission"}</h1>
          <p className="muted">Created {formatDate(report.created_at)} · {report.input.input_type.toUpperCase()}{report.input.source_touchpoint ? ` via ${labelize(report.input.source_touchpoint)}` : ""} · Schema {report.schema_version}</p>
        </div>
        <div className="heading-pills"><span className={`mode-pill ${mode}`} title={MODE_HELP[mode] ?? ""}>scoring: {mode}{mode === "model" ? " (experimental)" : ""}</span><StatusPill status={report.status} /></div>
      </div>
      {report.status === "processing" && <div className="processing"><span className="spinner" /> Sandbox analysis is running. This report refreshes automatically.{jobMessage ? ` ${jobMessage}.` : ""}</div>}
      {report.human_review_required && <div className="review-banner"><b>!</b><div><strong>Human review required before action</strong><span>Critical-severity findings must be approved before automated response.</span></div></div>}
      {report.verdict.stale_previous_verdict && <div className="processing">Re-analysed: a remembered verdict ({report.verdict.stale_previous_verdict}) was made by an older model or config.</div>}
      <section className="summary-grid">
        <div className={`summary-card verdict ${report.verdict.label}`}><span className="eyebrow">VERDICT</span><strong>{report.verdict.label}</strong><small>{prov?.source ? `from ${prov.source} analysis` : `${Math.round(report.verdict.confidence * 100)}% confidence`}{prov?.scoring_version ? ` · scoring ${prov.scoring_version}` : ""}</small></div>
        <div className={`summary-card severity ${report.risk.severity}`}><span className="eyebrow">SEVERITY</span><strong>{report.risk.severity}</strong><small>Risk tier</small></div>
        <div className="summary-card score"><div><span className="eyebrow">RISK SCORE</span><strong>{report.risk.score.toFixed(2)}</strong></div><div className="score-ring" style={{ ["--score" as string]: `${Math.round(report.risk.score * 100)}%` }}><span>{Math.round(report.risk.score * 100)}</span></div></div>
      </section>
      <Panel title="How the score was built" eyebrow="RISK BREAKDOWN · STEPS ADD UP TO THE SCORE"><Breakdown steps={report.risk.breakdown ?? []} rules={report.risk.rules_triggered} /></Panel>
      <div className="columns">
        <div className="stack">
          <Panel title="Analysis stages" eyebrow="WHAT RAN, AND HOW SURE IT IS"><Stages report={report} /></Panel>
          <Panel title="Static findings" eyebrow="MANIFEST AND CODE">
            <Findings label="API use (from bytecode)" values={(report.static_findings.api_usage ?? []).map((item) => `${item.category}: ${item.context}`)} />
            <Findings label="Anti-analysis" values={report.static_findings.anti_analysis.map((item) => `${item.technique} · ${item.mitre_id}${item.common_in_benign ? " · common in benign apps" : ""}`)} />
            <Findings label="Obfuscation" values={report.static_findings.obfuscation} />
            <Findings label="Permissions" values={report.static_findings.permissions} />
          </Panel>
          <Panel title="Hashes and look-alikes" eyebrow="EXACT · DEX CONTENT · FUZZY"><Hashes report={report} /></Panel>
          <Panel title="Dynamic findings" eyebrow="SANDBOX TELEMETRY · EXPERIMENTAL">{report.dynamic_findings ? <><Findings label="Runtime behavior" values={report.dynamic_findings.runtime_behaviors} /><Findings label="Network" values={report.dynamic_findings.network.map((item) => `${item.kind}: ${item.indicator}${item.is_c2 ? " · C2" : ""}${item.is_exfil ? " · exfil" : ""}`)} /><Findings label="Overlays" values={report.dynamic_findings.overlay_attempts ? [`${report.dynamic_findings.overlay_attempts} attempt(s)`] : []} /></> : <Empty text="No sandbox run for this report (the sandbox only runs when the static score is uncertain)." />}</Panel>
        </div>
        <div className="stack">
          <Panel title="MITRE ATT&CK" eyebrow="TECHNIQUES · COLOURED BY EVIDENCE STRENGTH"><Heatmap techniques={report.mitre_attack} /></Panel>
          <Panel title="Evidence ledger" eyebrow={`${report.evidence.length} ITEMS`}><div className="evidence-list">{report.evidence.length ? report.evidence.map((item) => <div className="evidence" key={item.evidence_id}><span>{item.evidence_id}</span><div><b>{item.source}</b><p>{item.summary}</p></div></div>) : <Empty text="No evidence recorded." />}</div></Panel>
          <Panel title="Analyst guidance" eyebrow="RESPONSE ACTIONS"><div className="recommendations">{report.recommendations.length ? report.recommendations.map((item, index) => <div className="recommendation" key={`${item.action}-${index}`}><i data-priority={item.priority} /><div><b>{labelize(item.action)}</b><p>{item.rationale}</p></div></div>) : <Empty text="No recommendations." />}</div>{report.threat_intel.iocs.some((item) => item.type === "telegram_token") && <><button className="action-button" onClick={() => void telegramCheck()}>Check Telegram token liveness (coming soon)</button>{telegramMessage && <p className="action-result">{telegramMessage}</p>}</>}</Panel>
        </div>
      </div>
      <Panel title="Explanation" eyebrow={report.explanation?.grounded ? "EVIDENCE GROUNDED" : "TEMPLATE TEXT · REVIEW REQUIRED"}><div className="explanation"><span>“</span><p>{report.explanation?.plain_language || "No explanation was generated for this report."}</p></div>{report.explanation?.cited_evidence_ids?.length ? <div className="citations">{report.explanation.cited_evidence_ids.map((id) => <em key={id}>{id}</em>)}</div> : null}</Panel>
    </>
  );
}

const MODE_HELP: Record<string, string> = {
  rules: "Transparent: static analysis + knowledge graph + rules, no ML model.",
  model: "The shipped ML model plus rules. Experimental: trained on a permissions dataset, not on APKs analysed by this pipeline.",
  retrained: "The model retrained on real APKs analysed by this pipeline.",
};

function Breakdown({ steps, rules }: { steps: ScoreStep[]; rules: Report["risk"]["rules_triggered"] }) {
  if (!steps.length) return <Empty text="This report predates score breakdowns." />;
  const ruleText = Object.fromEntries(rules.map((r) => [r.rule_id, r.description]));
  return (
    <div className="breakdown">
      {steps.map((s, i) => {
        const ruleId = s.step.startsWith("rule:") ? s.step.slice(5) : null;
        return (
          <div className={`step ${s.kind} ${Math.abs(s.delta) < 0.0005 ? "noop" : ""}`} key={`${s.step}-${i}`}>
            <span className="step-name">{ruleId ?? labelize(s.step)}<small>{s.kind}</small></span>
            <span className="step-delta">{s.delta >= 0 ? "+" : ""}{s.delta.toFixed(3)}</span>
            <span className="step-bar"><i style={{ left: `${Math.min((s.score_after - Math.max(s.delta, 0)) * 100, 100)}%`, width: `${Math.min(Math.max(s.delta, 0) * 100, 100)}%` }} /></span>
            <span className="step-after">{s.score_after.toFixed(2)}</span>
            <p>{ruleId && ruleText[ruleId] ? ruleText[ruleId] + " " : ""}{s.detail}</p>
          </div>
        );
      })}
    </div>
  );
}

function Stages({ report }: { report: Report }) {
  const status = report.static_bundle?.analysis_status ?? {};
  return (
    <>
      <div className="path">{report.verdict.decision_path.map((stage, i) => <em key={`${stage}-${i}`}>{labelize(stage)}</em>)}</div>
      <div className="stages">{Object.entries(status).length ? Object.entries(status).map(([name, s]) => <div className="stage" key={name}><span className={`stage-status ${s.status}`}>{s.status}</span><div><b>{labelize(name)}</b><p>{s.reason}</p></div></div>) : <Empty text="No per-stage status (fast path: no new analysis ran)." />}</div>
    </>
  );
}

function Hashes({ report }: { report: Report }) {
  const h = report.hashes ?? {};
  const rows: [string, string | null | undefined][] = [
    ["File SHA-256", h.sha256], ["DEX-content SHA-256", h.dex_sha256], ["DEX TLSH", h.dex_tlsh],
    ["Fuzzy hashing", h.fuzzy_status], ["Family cluster", h.cluster_id], ["Verdict inherited from", h.inherited_verdict_from],
  ];
  return <dl className="hashes">{rows.filter(([, v]) => v).map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}

function Panel({ title, eyebrow, children }: { title: string; eyebrow: string; children: React.ReactNode }) { return <section className="panel"><span className="eyebrow">{eyebrow}</span><h2>{title}</h2>{children}</section>; }
function StatusPill({ status }: { status: string }) { return <span className={`status-pill ${status}`}><i />{status}</span>; }
function Heatmap({ techniques }: { techniques: MitreTechnique[] }) {
  const tactics = [...new Set(techniques.map((item) => item.tactic))];
  if (!techniques.length) return <Empty text="No ATT&CK techniques mapped." />;
  return (
    <>
      <div className="heatmap">{tactics.map((tactic) => <div className="tactic" key={tactic}><span>{labelize(tactic)}</span><div>{techniques.filter((item) => item.tactic === tactic).map((item) => <em className={`strength ${item.evidence_strength ?? "unknown"}`} title={`${item.technique_name}${item.evidence_strength ? ` · evidence: ${item.evidence_strength}` : ""}${item.evidence_refs?.length ? ` · ${item.evidence_refs.join(", ")}` : ""}`} key={item.technique_id}>{item.technique_id}<small>{item.technique_name}</small></em>)}</div></div>)}</div>
      <div className="legend"><em className="strength permission">permission only</em><em className="strength api_call">code calls the API</em><em className="strength runtime">seen at runtime</em>{techniques[0]?.attack_version ? <small>ATT&CK Mobile {techniques[0].attack_version}</small> : null}</div>
    </>
  );
}
function Findings({ label, values }: { label: string; values: string[] }) { return <div className="findings"><span>{label}</span>{values.length ? <div>{values.map((value, i) => <em key={`${value}-${i}`}>{value}</em>)}</div> : <small>None observed</small>}</div>; }
function Empty({ text }: { text: string }) { return <p className="empty-line">{text}</p>; }
function errorMessage(error: unknown) { return error instanceof Error ? error.message : "Unexpected error"; }
function formatDate(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value.endsWith("Z") || value.includes("+") ? value : value + "Z")); }
function labelize(value: string) { return value.replace(/_/g, " "); }
