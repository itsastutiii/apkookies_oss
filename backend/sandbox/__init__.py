"""Dynamic analysis / sandbox package.

This package provides local dynamic analysis on any ADB-connected Android emulator:

- emulator.py: ADB-connected emulator host management
- device_spoof.py: Device profiling and optional spoofing (opt-in)
- instrumentation.py: Frida instrumentation with hook scripts
- frida_scripts/: JavaScript hook scripts for SMS, Accessibility, Crypto, Dynamic Loading, Anti-Analysis, Device Spoofing
- ui_automation.py: Scripted UI automation via ADB/uiautomator2
- network_capture.py: Controlled network capture via mitmproxy
- artifacts.py: Artifact collection and indexing
- behavior_analysis.py: Runtime behavior analysis
- run.py: Main orchestrator for end-to-end dynamic analysis
"""

from backend.sandbox.emulator import (
    EmulatorHost,
    LocalAdbHost,
    LocalGenymotionHost,
    SandboxSession,
    clean_session,
    default_host,
    collect_device_profile,
)
from backend.sandbox.device_spoof import (
    DeviceProfile,
    SpoofConfig,
    collect_device_profile as collect_device_profile_alt,
    apply_spoof_props,
    build_profile,
    get_spoof_props_for_frida,
)
from backend.sandbox.instrumentation import (
    InstrumentationResult,
    HookEvent,
    InstrumentationSession,
    attach,
    detach,
    wait_for_events,
    collect_events,
    is_frida_available,
    check_frida_server,
)
from backend.sandbox.ui_automation import (
    UIAutomation,
    UIRunResult,
    ActionType,
    Step,
    DEFAULT_SCRIPT,
    run_script,
)
from backend.sandbox.network_capture import (
    NetworkMode,
    NetworkIndicator,
    ProxyStatus,
    CaptureResult,
    NetworkCapture,
    start_capture,
    stop_capture,
)
from backend.sandbox.artifacts import (
    Artifact,
    RunArtifacts,
    ArtifactCollector,
    collect,
    wipe,
)
from backend.sandbox.behavior_analysis import (
    BehaviorFinding,
    BehaviorReport,
    analyze,
)
from backend.sandbox.run import (
    DynamicFindings,
    DynamicBundle,
    run_dynamic,
)

__all__ = [
    # Emulator
    "EmulatorHost",
    "LocalGenymotionHost",
    "LocalAdbHost",
    "SandboxSession",
    "clean_session",
    "default_host",
    "collect_device_profile",
    # Device spoof
    "DeviceProfile",
    "SpoofConfig",
    "apply_spoof_props",
    "build_profile",
    "get_spoof_props_for_frida",
    # Instrumentation
    "InstrumentationResult",
    "HookEvent",
    "InstrumentationSession",
    "attach",
    "detach",
    "wait_for_events",
    "collect_events",
    "is_frida_available",
    "check_frida_server",
    # UI automation
    "UIAutomation",
    "UIRunResult",
    "ActionType",
    "Step",
    "DEFAULT_SCRIPT",
    "run_script",
    # Network capture
    "NetworkMode",
    "NetworkIndicator",
    "ProxyStatus",
    "CaptureResult",
    "NetworkCapture",
    "start_capture",
    "stop_capture",
    # Artifacts
    "Artifact",
    "RunArtifacts",
    "ArtifactCollector",
    "collect",
    "wipe",
    # Behavior analysis
    "BehaviorFinding",
    "BehaviorReport",
    "analyze",
    # Orchestrator
    "DynamicFindings",
    "DynamicBundle",
    "run_dynamic",
]