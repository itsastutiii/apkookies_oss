"""Pydantic models mirroring schemas/report.schema.json.

The JSON Schema is the source of truth for cross-language clients (Kotlin SDK,
JS extension, React portal); these models are the Python-side binding used by
the backend. Keep the two in sync — see tests/test_report_schema.py.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


# --- enums ---------------------------------------------------------------
class InputType(str, Enum):
    apk = "apk"
    url = "url"


class Touchpoint(str, Enum):
    bank_sdk = "bank_sdk"
    whatsapp_bot = "whatsapp_bot"
    browser_extension = "browser_extension"
    soc_portal = "soc_portal"
    api = "api"


class VerdictLabel(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    unknown = "unknown"


class ReportStatus(str, Enum):
    processing = "processing"
    complete = "complete"
    failed = "failed"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Stage(str, Enum):
    hash_exact_lookup = "hash_exact_lookup"
    fuzzy_cluster_inheritance = "fuzzy_cluster_inheritance"
    dex_content_match = "dex_content_match"
    static_analysis = "static_analysis"
    static_rule_scoring = "static_rule_scoring"
    kg_rgcn_scoring = "kg_rgcn_scoring"
    rules_engine_override = "rules_engine_override"
    dynamic_sandbox = "dynamic_sandbox"
    genai_summary = "genai_summary"


class RecommendationAction(str, Enum):
    block = "block"
    warn = "warn"
    allow = "allow"
    credential_reset = "credential_reset"
    ioc_blacklist = "ioc_blacklist"
    sandbox_escalation = "sandbox_escalation"
    fraud_team_notify = "fraud_team_notify"


# --- sub-models ----------------------------------------------------------
class InputInfo(BaseModel):
    input_type: InputType
    source_touchpoint: Touchpoint = Touchpoint.api
    url: Optional[str] = None
    filename: Optional[str] = None
    package_name: Optional[str] = None


class Hashes(BaseModel):
    md5: Optional[str] = None
    sha256: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    # Content hashes (uncompressed DEX bytecode / binary manifest): survive re-zip and re-sign.
    dex_count: Optional[int] = None
    dex_sha256: Optional[str] = None
    dex_ssdeep: Optional[str] = None
    dex_tlsh: Optional[str] = None
    manifest_sha256: Optional[str] = None
    manifest_ssdeep: Optional[str] = None
    manifest_tlsh: Optional[str] = None
    fuzzy_status: Optional[str] = None   # available | partial | unavailable
    fuzzy_note: Optional[str] = None
    cluster_id: Optional[str] = None
    inherited_verdict_from: Optional[str] = None


class Verdict(BaseModel):
    label: VerdictLabel = VerdictLabel.unknown
    confidence: float = 0.0
    decision_path: list[Stage] = Field(default_factory=list)
    # What produced this verdict: source (static|sandbox|analyst), scoring version,
    # code commit, model/config file hashes, fingerprint, time (common/provenance.py).
    provenance: Optional[dict] = None
    # A remembered verdict existed but was made by an older model/config, so the
    # sample was re-analysed; this is what the old system had said.
    stale_previous_verdict: Optional[str] = None


class RuleHit(BaseModel):
    rule_id: str
    description: str
    hard_override: bool = False
    min_score: Optional[float] = None
    weight: Optional[float] = None      # added to the score (graded evidence)
    stage: Optional[int] = None         # evidence stage 1-5 (scoring/rules_engine.py)


class ScoreStep(BaseModel):
    step: str                 # model | kg_context | runtime_* | rule:<id> | remembered_verdict
    kind: str                 # base | add | floor
    delta: float
    score_after: float
    detail: str = ""


class Risk(BaseModel):
    score: float = 0.0
    severity: Severity = Severity.low
    # rules (transparent, no ML) | model (shipped, experimental) | retrained (AndroZoo-trained models).
    # None on reports made before scoring modes existed (backend/scoring/modes.py).
    scoring_mode: Optional[str] = None
    components: dict[str, float] = Field(default_factory=dict)   # model inputs / diagnostics
    breakdown: list[ScoreStep] = Field(default_factory=list)     # deltas sum to `score`
    rules_triggered: list[RuleHit] = Field(default_factory=list)


class ApiUsage(BaseModel):
    category: str
    context: str
    suspicious: bool = False
    rule_id: Optional[str] = None
    evidence: Optional[str] = None   # api_call | string_ref | subclass
    locations: list[str] = Field(default_factory=list)   # in-app methods (Lpkg/Cls;->method)


class AntiAnalysis(BaseModel):
    technique: str
    mitre_id: str
    detected_where: str = "static"
    markers: list[str] = Field(default_factory=list)     # APIs/strings that matched
    locations: list[str] = Field(default_factory=list)   # Lpkg/Cls;->method
    evidence: Optional[str] = None   # api_call | string_ref | field_read+string | manifest
    common_in_benign: bool = False   # legitimate apps also do this -> weak evidence


class Certificate(BaseModel):
    sha256: str
    sha1: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    debug: bool = False


class BankAllowlistCheck(BaseModel):
    status: str = "not_listed"   # not_listed | genuine | impersonation | unavailable
    bank: Optional[str] = None
    detail: Optional[str] = None
    matched_by: Optional[str] = None   # package (strong) | app_name (weaker)


class CertReuse(BaseModel):
    other_samples: int = 0       # other analysed samples signed with the same certificate
    malicious_samples: int = 0   # ...of which had a malicious verdict


class Signing(BaseModel):
    schemes: list[str] = Field(default_factory=list)
    debug_signed: Optional[bool] = None
    app_name: Optional[str] = None
    certificates: list[Certificate] = Field(default_factory=list)
    bank_allowlist: BankAllowlistCheck = Field(default_factory=BankAllowlistCheck)
    cert_reuse: CertReuse = Field(default_factory=CertReuse)


class Behaviour(BaseModel):
    source: str = "quark"        # analyser that produced it
    rule: str
    description: str
    confidence: int              # 0..100
    score: float = 0.0
    labels: list[str] = Field(default_factory=list)


class StaticFindings(BaseModel):
    permissions: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    signing: Signing = Field(default_factory=Signing)
    api_usage: list[ApiUsage] = Field(default_factory=list)
    obfuscation: list[str] = Field(default_factory=list)
    anti_analysis: list[AntiAnalysis] = Field(default_factory=list)
    behaviours: list[Behaviour] = Field(default_factory=list)   # optional Quark rules


class NetworkEvent(BaseModel):
    kind: str
    indicator: str
    is_c2: bool = False
    is_exfil: bool = False


class DynamicFindings(BaseModel):
    executed: bool = False
    sandbox_run_id: Optional[str] = None
    runtime_behaviors: list[str] = Field(default_factory=list)
    network: list[NetworkEvent] = Field(default_factory=list)
    syscall_traces: list[str] = Field(default_factory=list)
    overlay_attempts: int = 0


class IOC(BaseModel):
    type: str
    value: str
    enrichment: Optional[dict] = None
    telegram_c2_live: Optional[bool] = None


class ThreatIntel(BaseModel):
    family: Optional[str] = None
    family_confidence: Optional[float] = None
    iocs: list[IOC] = Field(default_factory=list)
    stix_bundle_ref: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str = ""
    tactic: str
    evidence_refs: list[str] = Field(default_factory=list)
    evidence_strength: Optional[str] = None   # permission < api_call < runtime
    attack_version: Optional[str] = None       # pinned ATT&CK Mobile release


class Evidence(BaseModel):
    evidence_id: str
    source: str
    summary: str
    raw_ref: Optional[str] = None


class Explanation(BaseModel):
    plain_language: str = ""
    grounded: bool = False
    cited_evidence_ids: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    action: RecommendationAction
    rationale: str
    priority: str = "medium"


# --- top-level report ----------------------------------------------------
class Report(BaseModel):
    schema_version: str = SCHEMA_VERSION
    report_id: str
    status: ReportStatus = ReportStatus.complete
    sandbox_job_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    human_review_required: bool = False

    input: InputInfo
    hashes: Hashes = Field(default_factory=Hashes)
    verdict: Verdict = Field(default_factory=Verdict)
    risk: Risk = Field(default_factory=Risk)
    static_bundle: Optional[dict] = None
    dynamic_bundle: Optional[dict] = None
    static_findings: StaticFindings = Field(default_factory=StaticFindings)
    dynamic_findings: Optional[DynamicFindings] = None
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    mitre_attack: list[MitreTechnique] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: Optional[Explanation] = None
    recommendations: list[Recommendation] = Field(default_factory=list)
