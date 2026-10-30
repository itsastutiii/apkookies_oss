"""Rules engine: graded evidence, with hard overrides only for decisive evidence.

Rules turn specific evidence into score steps, independently of the ML model, so
a model regression can't hide a known-bad pattern. But a rule may only be as
strong as its evidence. A genuine bank app once scored 0.90 because permission-
and API-presence rules set block floors over a model score of 0.16; this module
is organised so that can't happen.

EVIDENCE STAGES (Quark-Engine's five confidence stages, https://github.com/quark-engine/quark-engine;
each stage adds 20% confidence):
  1 permission     the manifest requests the permissions
  2 API call       the app's own code calls the API (libraries excluded)
  3 combination    the app's own code uses the combination of APIs
  4 call sequence  the APIs are called in sequence (same method, in order)
  5 data flow      data flows from one call into the next (e.g. SMS body -> network)
Our own analysis reaches stage 3 at most: it finds call sites, not call order or
data flow. Stages 4-5 come only from Quark-Engine's behaviour rules (optional,
confidence 80% / 100%; static_analysis/quark_rules.py). Data-flow evidence of our
own is planned.

WHAT EACH KIND OF EVIDENCE MAY DO
  stage 1          a small capped weight; NEVER a floor
  stage 2          a larger capped weight; no floor
  stage 3          a warn-level floor (WARN_FLOOR: warn on every touchpoint, inside the
                   0.40-0.70 sandbox band, so the sandbox can decide) and/or a weight
  IOC strings      warn-level floor at most (a Telegram token proves nothing alone)
  hard override    floor 0.90 + no sandbox, ONLY for:
                     * an exact known-malicious hash (handled before scoring, in hashing/lookup.py)
                     * R004: the package name of a listed bank app with another certificate
                     * R005: stage 4-5 behavioural evidence for a fraud behaviour
`evaluate()` enforces this: a hard RuleHit from any other rule is a programming error.
A rule must also fire on fewer than ~1% of benign apps before it may be hard
(ml/eval/benign_firing_rates.py measures it; tests/test_benign_firing.py checks it).

The model's probability is the base of the score; rule weights are added; floors
apply last. Every step is in risk.breakdown.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Optional

import yaml

from backend.static_analysis import StaticBundle
from backend.static_analysis.category import infer_category


class Stage(IntEnum):
    PERMISSION = 1
    API_CALL = 2
    COMBINATION = 3
    CALL_SEQUENCE = 4
    DATA_FLOW = 5


HARD_FLOOR = 0.90
WARN_FLOOR = 0.44          # warn on every touchpoint (browser extension blocks from 0.45)
DECLARED_TOOL_FLOOR = 0.40
STAGE_WEIGHT = {Stage.PERMISSION: 0.05, Stage.API_CALL: 0.10}
SECOND_SIGNAL_WEIGHT, SECOND_SIGNAL_CAP = 0.05, 0.10
# Rules allowed to be hard overrides (see the module docstring).
HARD_RULES = frozenset({"R004_BANK_IMPERSONATION", "R005_BEHAVIOUR"})


@dataclass
class RuleHit:
    rule_id: str
    description: str
    hard_override: bool       # floor 0.90 and no sandbox; only HARD_RULES may set it
    min_score: float = 0.0    # floor this rule enforces (0 = none)
    weight: float = 0.0       # added to the score (graded evidence)
    stage: Optional[int] = None   # Stage reached (None: identity or IOC evidence)


@dataclass
class RuleContext:
    permissions: set[str]
    app_category: str | None
    suspicious_api_categories: set[str]
    api_categories: set[str]                      # observed in the app's own code
    anti_analysis_techniques: set[str]
    has_telegram_token: bool
    bank_impersonation: Optional[str] = None      # allowlist detail when impersonating
    bank_impersonation_by: Optional[str] = None   # package | app_name
    accessibility_tool_declared: Optional[bool] = None
    c2_ips: list[str] = field(default_factory=list)        # IPs in a network context (not ip_like)
    bank_targets: list[str] = field(default_factory=list)  # bank/UPI packages named in code
    api_markers: set[str] = field(default_factory=set)     # api_usage rule ids, app's own code
    declares_a11y_service: bool = False
    behaviours: list = field(default_factory=list)         # Quark behaviours (QuarkBehaviour)


Rule = Callable[[RuleContext], Optional[RuleHit]]

_SMS_PERMISSIONS = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}
_SMS_READ_APIS = {"sms_read_incoming", "sms_inbox_query"}
_NETWORK_APIS = {"http_client", "okhttp", "raw_socket"}
_SAW = "android.permission.SYSTEM_ALERT_WINDOW"


def _graded(rule_id: str, stage: Stage, what: str, extra_weight: float = 0.0,
            floor_at_stage3: float = WARN_FLOOR) -> RuleHit:
    """A RuleHit for evidence that reached `stage` (1-3)."""
    weight = STAGE_WEIGHT.get(stage, 0.0) + extra_weight
    floor = floor_at_stage3 if stage >= Stage.COMBINATION else 0.0
    return RuleHit(rule_id, f"{what} [evidence stage {int(stage)}: {stage.name.lower().replace('_', ' ')}]",
                   hard_override=False, min_score=floor, weight=round(weight, 4), stage=int(stage))


# R001: SMS read/receive outside messaging apps = the OTP-forwarding pattern of Indian
# bank-fraud apps. But Indian bank/UPI apps legitimately read SMS for OTP auto-fill and
# send SMS for UPI device binding, so it is graded evidence, never a block on its own.
def _sms_interception_non_comm(ctx: RuleContext) -> RuleHit | None:
    if ctx.app_category is None or ctx.app_category.lower() in ("communication", "messaging"):
        return None
    reads_sms = ctx.api_markers & _SMS_READ_APIS
    networks = ctx.api_markers & _NETWORK_APIS
    if reads_sms and networks:
        return _graded("R001_SMS_INTERCEPT_NONCOMM", Stage.COMBINATION,
                       "The app's own code reads SMS and makes network calls outside a messaging app "
                       "(OTP-forwarding pattern; no data flow between them checked)")
    if reads_sms:
        return _graded("R001_SMS_INTERCEPT_NONCOMM", Stage.API_CALL,
                       "The app's own code reads SMS outside a messaging app")
    if _SMS_PERMISSIONS & ctx.permissions and "android.permission.INTERNET" in ctx.permissions:
        return _graded("R001_SMS_INTERCEPT_NONCOMM", Stage.PERMISSION,
                       "Requests SMS read/receive and internet outside a messaging app "
                       "(also normal for bank apps reading OTPs)")
    return None


# R002: accessibility + overlay = screen takeover + fake login. The pair is also used by
# password managers (autofill), launchers and screen-dimmers; Google Play's
# AccessibilityService policy (https://support.google.com/googleplay/android-developer/answer/10964491)
# allows the API for people with disabilities plus listed uses such as password managers
# and automation. So: the combination in the app's own code (stage 3) is warn-level;
# a declared accessibility tool (category below, or android:isAccessibilityTool="true")
# lowers that floor slightly; second signals add small weights. Malware can fake the
# declarations, which is why neither a declaration nor this rule ever decides alone.
# Only stage 4-5 behaviour (R005) blocks.
A11Y_OVERLAY_ALLOWED_CATEGORIES = frozenset({
    "accessibility", "password_manager", "passwordmanager", "automation",
})


def _a11y_overlay_second_signals(ctx: RuleContext) -> list[str]:
    signals = []
    if _SMS_PERMISSIONS & ctx.permissions or "sms" in ctx.api_categories:
        signals.append("SMS interception")
    if ctx.has_telegram_token:
        signals.append("Telegram bot token")
    if ctx.c2_ips:
        signals.append(f"hardcoded IP in a network context {ctx.c2_ips[0]}")
    if ctx.bank_impersonation:
        signals.append("bank impersonation")
    if ctx.bank_targets:
        signals.append("bank/UPI app names in code: " + ", ".join(ctx.bank_targets[:3]))
    return signals


def _accessibility_plus_overlay(ctx: RuleContext) -> RuleHit | None:
    category = (ctx.app_category or "").strip().lower().replace(" ", "_")
    declared = []
    if category in A11Y_OVERLAY_ALLOWED_CATEGORIES:
        declared.append(f"category '{ctx.app_category}'")
    if ctx.accessibility_tool_declared:
        declared.append("isAccessibilityTool=true")
    note = (f"; declares itself an accessibility tool ({' and '.join(declared)}), which malware "
            "can fake" if declared else "")
    floor = DECLARED_TOOL_FLOOR if declared else WARN_FLOOR
    if "accessibility" in ctx.api_categories and "overlay" in ctx.api_categories:
        signals = _a11y_overlay_second_signals(ctx)
        if signals:
            extra = min(SECOND_SIGNAL_WEIGHT * len(signals), SECOND_SIGNAL_CAP)
            return _graded("R002_A11Y_OVERLAY", Stage.COMBINATION,
                           "Accessibility service + screen overlay in the app's own code, together with "
                           + "; ".join(signals) + " (banking-trojan takeover pattern)" + note,
                           extra_weight=extra, floor_at_stage3=floor)
        return _graded("R002B_A11Y_OVERLAY_ALONE", Stage.COMBINATION,
                       "Accessibility service + screen overlay in the app's own code with no second "
                       "warning sign (also used by password managers, launchers, screen-dimmers)" + note,
                       floor_at_stage3=floor)
    if ctx.declares_a11y_service and _SAW in ctx.permissions:
        return _graded("R002B_A11Y_OVERLAY_ALONE", Stage.PERMISSION,
                       "Declares an accessibility service and requests draw-over-apps, with no "
                       "matching calls in the app's own code" + note)
    return None


# R003: a hardcoded Telegram bot token = a common free C2/exfil channel. String evidence:
# warn-level (0.40, inside the sandbox band), never a block on its own.
def _telegram_c2(ctx: RuleContext) -> RuleHit | None:
    if ctx.has_telegram_token:
        return RuleHit("R003_TELEGRAM_C2", "Hardcoded Telegram bot token (common exfil/C2 channel).",
                       hard_override=False, min_score=0.40)
    return None


def _bank_impersonation(ctx: RuleContext) -> RuleHit | None:
    # Identity evidence, not behaviour: a genuine bank app is always signed with the
    # bank's own key.
    # - Same PACKAGE name + any other certificate cannot be the bank's release build:
    #   repackaged or fake app -> hard override (one of the three allowed), floor 0.90.
    # - Same APP NAME only (different package): could be a look-alike, but also an
    #   unrelated app that shares the name -> warning-level floor 0.40.
    # Only fires for config/bank_allowlist.yaml entries that have a certificate.
    if not ctx.bank_impersonation:
        return None
    if ctx.bank_impersonation_by == "app_name":
        return RuleHit("R004B_BANK_NAME_LOOKALIKE", ctx.bank_impersonation,
                       hard_override=False, min_score=0.40)
    return RuleHit("R004_BANK_IMPERSONATION", ctx.bank_impersonation,
                   hard_override=True, min_score=HARD_FLOOR)


# R005: behavioural evidence at Quark stage 4-5 (APIs called in sequence, or data flowing
# between them) for a fraud-relevant behaviour. The only behavioural hard override.
# Which Quark rules count is decided by keywords in the rule's labels/description; the
# keyword list hasn't been checked against the full quark-rules set yet (planned after the
# next, with a labelled test set).
FRAUD_BEHAVIOUR_KEYWORDS = ("sms", "accessibility", "overlay")


def _behaviour(ctx: RuleContext) -> RuleHit | None:
    strong = []
    for b in ctx.behaviours:
        text = " ".join([b.crime, *b.labels]).lower()
        if b.confidence >= 80 and any(k in text for k in FRAUD_BEHAVIOUR_KEYWORDS):
            strong.append(b)
    if not strong:
        return None
    best = max(strong, key=lambda b: b.confidence)
    stage = Stage.DATA_FLOW if best.confidence >= 100 else Stage.CALL_SEQUENCE
    return RuleHit("R005_BEHAVIOUR",
                   f"Quark-Engine behaviour at {best.confidence}% ({stage.name.lower().replace('_', ' ')}): "
                   f"{best.crime} [{best.rule}]" + (f" (+{len(strong) - 1} more)" if len(strong) > 1 else ""),
                   hard_override=True, min_score=HARD_FLOOR, stage=int(stage))


_RULES: list[Rule] = [
    _sms_interception_non_comm,
    _accessibility_plus_overlay,
    _telegram_c2,
    _bank_impersonation,
    _behaviour,
]


_CONFIG = Path(__file__).resolve().parents[2] / "config"


@lru_cache
def _bank_target_pattern() -> Optional[re.Pattern]:
    packages = set()
    for name, key in (("bank_targets.yaml", "packages"), ("bank_allowlist.yaml", "banks")):
        try:
            data = yaml.safe_load((_CONFIG / name).read_text(encoding="utf-8")) or {}
        except OSError:
            continue
        for entry in data.get(key) or []:
            packages.update([entry] if isinstance(entry, str) else entry.get("packages") or [])
    if not packages:
        return None
    alts = "|".join(re.escape(p) for p in sorted(packages, key=len, reverse=True))
    return re.compile(rf"(?<![\w.])({alts})(?![\w])")


def bank_targets_in(strings: Iterable[str], own_package: Optional[str]) -> list[str]:
    """Bank/UPI package names that appear in the app's strings, except its own."""
    pattern = _bank_target_pattern()
    if pattern is None:
        return []
    found = set()
    for s in strings:
        if len(s) >= 8:
            found.update(pattern.findall(s))
    found.discard(own_package)
    return sorted(found)


def evaluate(bundle: StaticBundle, app_category: str | None = None) -> list[RuleHit]:
    ctx = RuleContext(
        permissions=set(bundle.structural.manifest.permissions),
        app_category=app_category if app_category is not None else infer_category(bundle),
        suspicious_api_categories={o.category.value for o in bundle.api_usage.own() if o.suspicious},
        api_categories={o.category.value for o in bundle.api_usage.own()},
        anti_analysis_techniques={f.technique for f in bundle.anti_analysis.findings},
        has_telegram_token=bool(bundle.iocs.by_type("telegram_token")),
        bank_impersonation=(bundle.structural.signing.allowlist.detail
                            if bundle.structural.signing.allowlist.status == "impersonation"
                            else None),
        bank_impersonation_by=bundle.structural.signing.allowlist.matched_by,
        accessibility_tool_declared=bundle.structural.manifest.accessibility_tool_declared,
        c2_ips=sorted(i.value for i in bundle.iocs.actionable_iocs("ip")),
        bank_targets=bank_targets_in(bundle.code_intel.dex_strings,
                                     bundle.structural.manifest.package_name),
        api_markers={o.marker for o in bundle.api_usage.own()},
        declares_a11y_service=any(
            c.kind == "service" and c.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
            for c in bundle.structural.manifest.components),
        behaviours=list(getattr(getattr(bundle, "quark", None), "behaviours", []) or []),
    )
    hits = [h for h in (r(ctx) for r in _RULES) if h is not None]
    for h in hits:
        if h.hard_override and h.rule_id not in HARD_RULES:
            raise AssertionError(f"{h.rule_id} may not be a hard override (rules_engine docstring)")
    return hits
