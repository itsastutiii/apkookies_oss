"""Behavior analysis: turn raw runtime signals into structured findings.

Consumes hook events (instrumentation), captured network (network_capture),
UI-run results (ui_automation), device/runtime metadata, and artifacts.

Produces the report's `dynamic_findings` with evidence-backed behaviors.

Every finding includes evidence references. Distinguishes:
- "observed behavior" (direct evidence)
- "inferred potential behavior" (indirect/correlative evidence)

Absence of evidence is NOT proof that behavior never occurred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from backend.sandbox.instrumentation import HookEvent
from backend.sandbox.network_capture import NetworkIndicator
from backend.sandbox.ui_automation import UIRunResult


@dataclass
class BehaviorFinding:
    """A single behavior finding with evidence."""
    behavior: str                    # e.g., "sms_interception"
    category: str                    # e.g., "exfiltration", "evasion", "persistence"
    severity: str                    # low, medium, high, critical
    confidence: float                # 0.0 - 1.0
    observed: bool                   # True = directly observed, False = inferred
    description: str
    evidence_refs: list[str] = field(default_factory=list)  # Artifact paths or event IDs
    raw_indicators: list[str] = field(default_factory=list)  # Raw indicator values


@dataclass
class BehaviorReport:
    """Complete dynamic behavior analysis report."""
    executed: bool = True
    findings: list[BehaviorFinding] = field(default_factory=list)

    # Legacy fields for compatibility
    runtime_behaviors: list[str] = field(default_factory=list)
    network: list[NetworkIndicator] = field(default_factory=list)
    syscall_traces: list[str] = field(default_factory=list)
    overlay_attempts: int = 0
    anti_analysis_runtime: list[str] = field(default_factory=list)
    verdict_confidence_penalty: float = 0.0

    # Summary counts
    sms_interception_count: int = 0
    accessibility_abuse_count: int = 0
    dynamic_loading_count: int = 0
    crypto_operations_count: int = 0
    anti_analysis_checks_count: int = 0
    suspicious_network_count: int = 0
    potential_c2_count: int = 0
    potential_exfil_count: int = 0
    overlay_detected_count: int = 0

    def add_finding(self, finding: BehaviorFinding):
        self.findings.append(finding)
        # Update legacy fields for backward compatibility
        if finding.behavior not in self.runtime_behaviors:
            self.runtime_behaviors.append(finding.behavior)

        # Update counters
        if finding.behavior == "sms_interception":
            self.sms_interception_count += 1
        elif finding.behavior == "accessibility_abuse":
            self.accessibility_abuse_count += 1
        elif finding.behavior == "dynamic_code_loading":
            self.dynamic_loading_count += 1
        elif finding.behavior == "runtime_crypto":
            self.crypto_operations_count += 1
        elif finding.behavior == "anti_analysis":
            self.anti_analysis_checks_count += 1
        elif finding.behavior == "suspicious_network":
            self.suspicious_network_count += 1
        elif finding.behavior == "potential_c2":
            self.potential_c2_count += 1
        elif finding.behavior == "potential_exfiltration":
            self.potential_exfil_count += 1
        elif finding.behavior == "overlay_activity":
            self.overlay_attempts += 1
            self.overlay_detected_count += 1


# --- Behavior detection rules ---

_BEHAVIOR_RULES = {
    # SMS-related
    "sms_interception": {
        "category": "exfiltration",
        "severity": "high",
        "hooks": ["SmsMessage.createFromPdu", "BroadcastReceiver.onReceive(SMS_RECEIVED)"],
        "description": "App intercepts or reads incoming SMS messages",
    },
    "sms_sending": {
        "category": "exfiltration",
        "severity": "medium",
        "hooks": ["SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage"],
        "description": "App sends SMS messages programmatically",
    },

    # Accessibility
    "accessibility_abuse": {
        "category": "credential_theft",
        "severity": "high",
        "hooks": ["AccessibilityService.onAccessibilityEvent",
                  "AccessibilityService.onServiceConnected",
                  "ViewGroup.addView(TYPE_APPLICATION_OVERLAY)"],
        "description": "App consumes accessibility events (keystroke/screen capture)",
    },

    # Crypto
    "runtime_crypto": {
        "category": "payload_decryption",
        "severity": "medium",
        "hooks": ["Cipher.doFinal", "Cipher.init", "SecretKeySpec.<init>",
                  "MessageDigest.digest", "KeyGenerator.generateKey"],
        "description": "App performs cryptographic operations at runtime",
    },

    # Dynamic loading
    "dynamic_code_loading": {
        "category": "evasion",
        "severity": "high",
        "hooks": ["DexClassLoader.<init>", "PathClassLoader.<init>",
                  "Class.forName", "Method.invoke", "Constructor.newInstance",
                  "System.loadLibrary", "Runtime.load"],
        "description": "App loads code dynamically (DEX, reflection, native)",
    },

    # Anti-analysis
    "anti_analysis": {
        "category": "evasion",
        "severity": "medium",
        "hooks": ["Build.getSerial", "Debug.isDebuggerConnected",
                  "Runtime.exec", "File.exists", "SensorManager.getSensorList",
                  "PackageManager.getPackageInfo", "System.getProperty"],
        "description": "App performs anti-analysis/anti-emulator checks",
    },

    # Network
    "suspicious_network": {
        "category": "c2",
        "severity": "medium",
        "description": "App makes suspicious network connections",
    },
    "potential_c2": {
        "category": "c2",
        "severity": "high",
        "description": "Network traffic matches C2 patterns (beaconing, encryption, etc.)",
    },
    "potential_exfiltration": {
        "category": "exfiltration",
        "severity": "high",
        "description": "Network traffic suggests data exfiltration",
    },

    # Overlay
    "overlay_activity": {
        "category": "ui_attack",
        "severity": "medium",
        "description": "App creates overlay windows (phishing/credential theft)",
    },
}


def _group_events_by_type(events: list[HookEvent]) -> dict[str, list[HookEvent]]:
    """Group hook events by their group/category."""
    grouped = {}
    for event in events:
        if event.group not in grouped:
            grouped[event.group] = []
        grouped[event.group].append(event)
    return grouped


def _find_hook_events(events: list[HookEvent], api_patterns: list[str]) -> list[HookEvent]:
    """Find events matching any of the API patterns."""
    matches = []
    for event in events:
        for pattern in api_patterns:
            if pattern.lower() in event.api.lower():
                matches.append(event)
                break
    return matches


def _extract_evidence_refs(events: list[HookEvent]) -> list[str]:
    """Extract evidence references from events."""
    refs = []
    for event in events:
        ref = f"{event.group}:{event.api}@{event.timestamp:.3f}"
        refs.append(ref)
    return refs


def analyze(events: list[HookEvent],
            network: list[NetworkIndicator] | None = None,
            ui: UIRunResult | None = None,
            device_profile: dict | None = None) -> BehaviorReport:
    """Analyze runtime behavior from hooks, network, and UI automation.

    Args:
        events: Frida hook events
        network: Captured network indicators
        ui: UI automation results
        device_profile: Device profile info

    Returns:
        BehaviorReport with evidence-backed findings
    """
    report = BehaviorReport()
    network = network or []
    ui = ui or UIRunResult()

    # Group events by type
    grouped = _group_events_by_type(events)

    # --- 1. SMS Interception ---
    sms_events = grouped.get("sms", [])
    if sms_events:
        # Check for interception (incoming SMS read)
        intercept_events = _find_hook_events(sms_events,
            ["SmsMessage.createFromPdu", "BroadcastReceiver.onReceive(SMS_RECEIVED)"])
        if intercept_events:
            report.add_finding(BehaviorFinding(
                behavior="sms_interception",
                category="exfiltration",
                severity="high",
                confidence=0.9,
                observed=True,
                description="App intercepts incoming SMS messages (OTP theft vector)",
                evidence_refs=_extract_evidence_refs(intercept_events),
                raw_indicators=[e.args.get("originatingAddress", "") for e in intercept_events if e.args.get("originatingAddress")]
            ))

        # Check for SMS sending
        send_events = _find_hook_events(sms_events,
            ["SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage"])
        if send_events:
            report.add_finding(BehaviorFinding(
                behavior="sms_sending",
                category="exfiltration",
                severity="medium",
                confidence=0.8,
                observed=True,
                description="App sends SMS messages programmatically",
                evidence_refs=_extract_evidence_refs(send_events),
                raw_indicators=[e.args.get("destAddr", "") for e in send_events if e.args.get("destAddr")]
            ))

    # --- 2. Accessibility Abuse ---
    access_events = grouped.get("accessibility", [])
    if access_events:
        # Check for event consumption
        consume_events = _find_hook_events(access_events,
            ["AccessibilityService.onAccessibilityEvent"])
        if consume_events:
            report.add_finding(BehaviorFinding(
                behavior="accessibility_abuse",
                category="credential_theft",
                severity="high",
                confidence=0.85,
                observed=True,
                description="App consumes accessibility events (keystroke/screen capture)",
                evidence_refs=_extract_evidence_refs(consume_events),
                raw_indicators=[e.args.get("eventType", "") for e in consume_events if e.args.get("eventType")]
            ))

        # Check for overlay window creation
        overlay_events = _find_hook_events(access_events,
            ["ViewGroup.addView(TYPE_APPLICATION_OVERLAY)"])
        if overlay_events or ui.overlay_detected:
            report.add_finding(BehaviorFinding(
                behavior="overlay_activity",
                category="ui_attack",
                severity="medium",
                confidence=0.9 if overlay_events else 0.7,
                observed=bool(overlay_events),
                description="App creates overlay windows (phishing/credential theft)",
                evidence_refs=_extract_evidence_refs(overlay_events) if overlay_events else [f"ui:overlay_detected@{time.time()}"],
                raw_indicators=[]
            ))

    # --- 3. Runtime Crypto ---
    crypto_events = grouped.get("crypto", [])
    if crypto_events:
        # Focus on decryption operations (Cipher.doFinal with DECRYPT_MODE)
        decrypt_events = _find_hook_events(crypto_events, ["Cipher.doFinal"])
        init_events = _find_hook_events(crypto_events, ["Cipher.init"])

        if decrypt_events or init_events:
            all_crypto = decrypt_events + init_events
            report.add_finding(BehaviorFinding(
                behavior="runtime_crypto",
                category="payload_decryption",
                severity="medium",
                confidence=0.7,
                observed=True,
                description="App performs cryptographic operations at runtime (possible payload decryption)",
                evidence_refs=_extract_evidence_refs(all_crypto),
                raw_indicators=[e.args.get("algorithm", "") for e in all_crypto if e.args.get("algorithm")]
            ))

    # --- 4. Dynamic Code Loading ---
    dynload_events = grouped.get("dynamic_loading", [])
    if dynload_events:
        load_events = _find_hook_events(dynload_events,
            ["DexClassLoader.<init>", "PathClassLoader.<init>", "Class.forName",
             "Method.invoke", "Constructor.newInstance", "System.loadLibrary", "Runtime.load"])
        if load_events:
            report.add_finding(BehaviorFinding(
                behavior="dynamic_code_loading",
                category="evasion",
                severity="high",
                confidence=0.85,
                observed=True,
                description="App loads code dynamically (DEX, reflection, native libraries)",
                evidence_refs=_extract_evidence_refs(load_events),
                raw_indicators=[e.args.get("className", e.args.get("dexPath", e.args.get("libraryName", "")))
                                for e in load_events if e.args]
            ))

    # --- 5. Anti-Analysis ---
    anti_events = grouped.get("anti_analysis", [])
    if anti_events:
        check_events = _find_hook_events(anti_events,
            ["Build.getSerial", "Debug.isDebuggerConnected", "Runtime.exec",
             "File.exists", "SensorManager.getSensorList", "PackageManager.getPackageInfo",
             "System.getProperty"])
        if check_events:
            # Count unique check types
            check_types = set()
            for e in check_events:
                check_types.add(e.api)

            report.add_finding(BehaviorFinding(
                behavior="anti_analysis",
                category="evasion",
                severity="medium",
                confidence=min(0.5 + 0.1 * len(check_types), 0.95),
                observed=True,
                description=f"App performs {len(check_types)} types of anti-analysis/anti-emulator checks",
                evidence_refs=_extract_evidence_refs(check_events),
                raw_indicators=list(check_types)
            ))

            # Add individual checks to legacy field
            for check_type in check_types:
                if check_type not in report.anti_analysis_runtime:
                    report.anti_analysis_runtime.append(check_type)

    # --- 6. Network Analysis ---
    if network:
        # Suspicious network connections
        suspicious_indicators = [n for n in network if n.is_c2 or n.is_exfil or n.kind in ("dns", "tcp")]
        if suspicious_indicators:
            report.add_finding(BehaviorFinding(
                behavior="suspicious_network",
                category="c2",
                severity="medium",
                confidence=0.6,
                observed=True,
                description=f"App made {len(suspicious_indicators)} suspicious network connections",
                evidence_refs=[f"network:{n.indicator}@{n.timestamp:.3f}" for n in suspicious_indicators],
                raw_indicators=[n.indicator for n in suspicious_indicators]
            ))

        # Potential C2
        c2_indicators = [n for n in network if n.is_c2]
        if c2_indicators:
            report.add_finding(BehaviorFinding(
                behavior="potential_c2",
                category="c2",
                severity="high",
                confidence=0.75,
                observed=True,
                description=f"Network traffic matches C2 patterns: {len(c2_indicators)} indicators",
                evidence_refs=[f"network:{n.indicator}@{n.timestamp:.3f}" for n in c2_indicators],
                raw_indicators=[n.indicator for n in c2_indicators]
            ))

        # Potential exfiltration
        exfil_indicators = [n for n in network if n.is_exfil]
        if exfil_indicators:
            report.add_finding(BehaviorFinding(
                behavior="potential_exfiltration",
                category="exfiltration",
                severity="high",
                confidence=0.75,
                observed=True,
                description=f"Network traffic suggests data exfiltration: {len(exfil_indicators)} indicators",
                evidence_refs=[f"network:{n.indicator}@{n.timestamp:.3f}" for n in exfil_indicators],
                raw_indicators=[n.indicator for n in exfil_indicators]
            ))

        # Add network indicators to legacy field
        report.network = network

    # --- 7. UI Automation Observations ---
    if ui.overlay_detected and not any(f.behavior == "overlay_activity" for f in report.findings):
        report.add_finding(BehaviorFinding(
            behavior="overlay_activity",
            category="ui_attack",
            severity="medium",
            confidence=0.7,
            observed=True,
            description="Overlay window detected during UI automation",
            evidence_refs=[f"ui:overlay_detected@{ui.elapsed_sec:.1f}s"],
            raw_indicators=[]
        ))

    # --- 8. Calculate confidence penalty ---
    evasion_findings = [f for f in report.findings if f.category == "evasion"]
    if evasion_findings:
        max_evasion_confidence = max(f.confidence for f in evasion_findings)
        report.verdict_confidence_penalty = max_evasion_confidence * 0.3  # Up to 30% penalty

    return report


import time  # for timestamp in fallback