"""Anti-analysis / emulator-detection countermeasures (static side).

Detects the malware's OWN evasion logic so a clean sandbox run can't be taken at
face value: evasive samples that refuse to run under an emulator otherwise look
benign. Detection uses bytecode cross-references and records WHERE each check
happens (class + method), so the sandbox side (Frida hooks in
backend/sandbox/instrumentation.py) can later confirm the same check fired.

What counts (exact matches only; no substring guessing):
  * emulator:  code loading emulator-only paths/properties, or one method that
               reads Build.* fields AND compares with emulator names.
  * debugger:  Debug.isDebuggerConnected/waitingForDebugger, the TracerPid string.
  * root:      su / Magisk / SuperSU paths and package names, "test-keys".
  * timing / trigger gating: exact alarms, SIM-country/state reads, boot receivers.

`common_in_benign` marks techniques that legitimate apps also use (bank apps do
root checks; many apps schedule alarms or read the SIM country), so they are
reported as weak evidence, not proof.

Limitation: field reads like Build.MODEL can be detected statically but not
hooked at runtime (planned).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.static_analysis.dex_analysis import DexIndex


class Technique:
    EMULATOR_DETECTION = "emulator_detection"
    DEBUGGER_DETECTION = "debugger_detection"
    ROOT_DETECTION = "root_detection"
    TIMING_STALL = "timing_stall"
    TRIGGER_GATING = "trigger_gating"


# MITRE ATT&CK for Mobile technique IDs (names/tactics: reporting/mitre_mapping.py).
# Mobile has no separate "Debugger Evasion" (T1622 and T1480 are Enterprise IDs):
# debugger checks are a form of analysis-environment check, so System Checks.
MITRE_MAP = {
    Technique.EMULATOR_DETECTION: "T1633.001",  # Virtualization/Sandbox Evasion: System Checks
    Technique.DEBUGGER_DETECTION: "T1633.001",  # (was Enterprise T1622)
    Technique.ROOT_DETECTION: "T1633",           # Virtualization/Sandbox Evasion (mapping to be revisited)
    Technique.TIMING_STALL: "T1633.001",
    Technique.TRIGGER_GATING: "T1627",           # Execution Guardrails (was Enterprise T1480)
}

COMMON_IN_BENIGN = {Technique.ROOT_DETECTION, Technique.TIMING_STALL, Technique.TRIGGER_GATING}

_EMULATOR_ARTIFACTS = [
    "/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/sys/qemu_trace",
    "/system/lib/libc_malloc_debug_qemu.so", "/system/bin/qemu-props", "ro.kernel.qemu",
    "init.goldfish.rc", "fstab.ranchu", "/system/bin/androVM-prop", "/dev/vboxguest",
    "/dev/vboxuser", "000000000000000",  # default emulator IMEI
]
_EMULATOR_NAMES = [
    "generic", "generic_x86", "generic_x86_64", "google_sdk", "sdk", "sdk_x86", "sdk_gphone",
    "sdk_gphone_x86", "sdk_gphone64_x86_64", "goldfish", "ranchu", "vbox86", "vbox86p",
    "Genymotion", "Android SDK built for x86", "Emulator", "nox", "ttVM_x86",
]
_BUILD_FIELDS = ["FINGERPRINT", "MODEL", "HARDWARE", "PRODUCT", "BRAND", "DEVICE",
                 "MANUFACTURER", "BOARD", "HOST", "TAGS"]
_ROOT_ARTIFACTS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su", "/system/sd/xbin/su",
    "/system/bin/failsafe/su", "/system/app/Superuser.apk", "Superuser.apk",
    "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
    "com.koushikdutta.superuser", "test-keys",
]

_MAX_LOCATIONS = 5


@dataclass
class AntiAnalysisFinding:
    technique: str
    mitre_id: str
    markers_hit: list[str] = field(default_factory=list)   # APIs/strings that matched
    detected_where: str = "static"
    locations: list[str] = field(default_factory=list)     # Lpkg/Cls;->method
    evidence: str = "api_call"                              # api_call | string_ref | field_read+string | manifest
    common_in_benign: bool = False


@dataclass
class AntiAnalysisReport:
    findings: list[AntiAnalysisFinding] = field(default_factory=list)
    status: str = "observed"
    reason: str = "Evasion checks resolved from DEX bytecode cross-references."


def analyze(index: DexIndex, manifest=None) -> AntiAnalysisReport:
    if not index.available:
        return AntiAnalysisReport(status="unavailable",
                                  reason=f"Anti-analysis not analysed: {index.error}.")
    report = AntiAnalysisReport()
    for technique, (markers, locations, evidence) in (
        (Technique.EMULATOR_DETECTION, _emulator(index)),
        (Technique.DEBUGGER_DETECTION, _debugger(index)),
        (Technique.ROOT_DETECTION, _strings(index, _ROOT_ARTIFACTS)),
        (Technique.TIMING_STALL, _calls(index, [
            ("Landroid/app/AlarmManager;", "setExact|setExactAndAllowWhileIdle|setAlarmClock")])),
        (Technique.TRIGGER_GATING, _trigger_gating(index, manifest)),
    ):
        if markers:
            report.findings.append(AntiAnalysisFinding(
                technique=technique,
                mitre_id=MITRE_MAP[technique],
                markers_hit=sorted(markers),
                locations=sorted(locations)[:_MAX_LOCATIONS],
                evidence=evidence,
                common_in_benign=technique in COMMON_IN_BENIGN,
            ))
    return report


def _emulator(index: DexIndex):
    markers: set[str] = set()
    locations: set[str] = set()
    evidence = "string_ref"
    for value, users in index.string_users(_EMULATOR_ARTIFACTS).items():
        markers.add(value)
        locations.update(users)
    # Same-method co-occurrence: Build.* read + emulator name comparison.
    build_readers = set(index.static_field_readers("Landroid/os/Build;", _BUILD_FIELDS))
    for loc, names in index.strings_by_method(_EMULATOR_NAMES).items():
        if loc in build_readers:
            markers.update(f"Build.* vs '{n}'" for n in names)
            locations.add(loc)
            evidence = "field_read+string"
    return markers, locations, evidence


def _debugger(index: DexIndex):
    markers, locations, evidence = _calls(
        index, [("Landroid/os/Debug;", "isDebuggerConnected|waitingForDebugger")])
    s_markers, s_locations, _ = _strings(index, ["TracerPid"])
    if not markers and s_markers:
        evidence = "string_ref"
    return markers | s_markers, locations | s_locations, evidence


def _trigger_gating(index: DexIndex, manifest):
    markers, locations, evidence = _calls(
        index, [("Landroid/telephony/TelephonyManager;", "getSimCountryIso|getSimState|getNetworkCountryIso")])
    boot = [c.name for c in getattr(manifest, "components", [])
            if c.kind == "receiver" and "android.intent.action.BOOT_COMPLETED" in c.intent_filters]
    if boot:
        markers.add("BOOT_COMPLETED receiver")
        locations.update(boot)
        evidence = evidence if locations - set(boot) else "manifest"
    return markers, locations, evidence


def _calls(index: DexIndex, apis: list[tuple[str, str]]):
    markers: set[str] = set()
    locations: set[str] = set()
    for cls, method in apis:
        found = index.callers_of(cls, method)
        if found:
            markers.add(f"{cls}->{method}")
            locations.update(found)
    return markers, locations, "api_call"


def _strings(index: DexIndex, strings: list[str]):
    markers: set[str] = set()
    locations: set[str] = set()
    for value, users in index.string_users(strings).items():
        markers.add(value)
        locations.update(users)
    return markers, locations, "string_ref"
