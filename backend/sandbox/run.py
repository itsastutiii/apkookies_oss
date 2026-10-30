"""Dynamic analysis orchestrator — end-to-end sandbox run.

Flow:
1. Static analysis (structural, code_intel, api_usage, ioc_extraction, anti_analysis)
2. Connect to any ADB-connected Android emulator, including Android Studio AVD
3. Install APK
4. Launch app + resolve package/activity/PID
5. Attach Frida with selected hook groups
6. Run UI automation script
7. Capture network traffic (controlled)
8. Collect all artifacts (logs, screenshots, UI dumps, Frida events, network)
9. Behavior analysis (correlate hooks + network + UI + device profile)
10. Return DynamicBundle
11. Teardown + sanitize artifacts
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

try:
    from config.settings import get_settings
except ImportError:
    def get_settings():
        class _S:
            artifact_store_path = Path("./.artifacts")
        return _S()

from backend.static_analysis import StaticBundle, run as static_run
from backend.sandbox.emulator import (
    EmulatorHost,
    LocalGenymotionHost,
    SandboxSession,
    clean_session,
    default_host,
    collect_device_profile,
)
from backend.sandbox.instrumentation import (
    InstrumentationResult,
    HookEvent,
    attach as frida_attach,
    detach as frida_detach,
    wait_for_events as frida_wait,
    collect_events as frida_collect,
    is_frida_available,
    check_frida_server,
)
from backend.sandbox.ui_automation import (
    UIRunResult,
    DEFAULT_SCRIPT,
    run_script as ui_run_script,
)
from backend.sandbox.network_capture import (
    NetworkMode,
    NetworkCapture,
    start_capture,
    stop_capture,
    CaptureResult,
)
from backend.sandbox.artifacts import (
    Artifact,
    ArtifactCollector,
    RunArtifacts,
    wipe as artifact_wipe,
)
from backend.sandbox.behavior_analysis import analyze as behavior_analyze
from backend.sandbox.device_spoof import SpoofConfig


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class CommandResult:
    """Structured result of an ADB/shell command."""
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    success: bool
    error: Optional[str] = None


@dataclass
class SandboxSession:
    run_id: str
    device_serial: str          # e.g. "192.168.56.101:5555" or "emulator-5554"
    proxy_port: int
    fingerprint: dict = field(default_factory=dict)
    package_name: Optional[str] = None
    main_activity: Optional[str] = None
    pid: Optional[int] = None


class EmulatorHost(Protocol):
    """Where/how the emulator runs. Swap local <-> cloud without touching callers."""

    def boot_clean(self, proxy_port: int) -> SandboxSession:
        """Connect to existing Genymotion instance restored to clean snapshot, egress -> proxy."""
        ...

    def install(self, session: SandboxSession, apk_path: str) -> CommandResult:
        """Install APK on the device."""
        ...

    def launch(self, session: SandboxSession) -> CommandResult:
        """Launch the app's main activity."""
        ...

    def force_stop(self, session: SandboxSession) -> CommandResult:
        """Force-stop the app."""
        ...

    def clear_data(self, session: SandboxSession) -> CommandResult:
        """Clear app data."""
        ...

    def uninstall(self, session: SandboxSession) -> CommandResult:
        """Uninstall the app."""
        ...

    def get_prop(self, session: SandboxSession, prop: str) -> CommandResult:
        """Get a system property via adb shell getprop."""
        ...

    def get_props(self, session: SandboxSession, props: list[str]) -> dict[str, CommandResult]:
        """Get multiple system properties."""
        ...

    def logcat(self, session: SandboxSession, duration_sec: int = 10) -> CommandResult:
        """Collect logcat for a duration."""
        ...


@dataclass
class DynamicFindings:
    """Results of the dynamic analysis phase."""
    behavior_report: dict
    frida_events: list[HookEvent]
    network_indicators: list[dict]
    ui_result: Optional[UIRunResult]
    device_profile: dict


@dataclass
class DynamicBundle:
    """Complete dynamic analysis result."""
    run_id: str
    apk_path: str
    static_bundle: StaticBundle
    dynamic: DynamicFindings
    artifacts: RunArtifacts
    session: Optional[SandboxSession] = None
    analysis_status: dict = field(default_factory=dict)
    coverage: float = 0.0


def run_dynamic(
    apk_path: str | Path,
    static_bundle: Optional[StaticBundle] = None,
    host: Optional[EmulatorHost] = None,
    network_mode: NetworkMode = NetworkMode.controlled_proxy,
    proxy_port: int = 8080,
    ui_script: Optional[list] = None,
    ui_time_limit: int = 60,
    ui_action_limit: int = 50,
    frida_groups: Optional[list[str]] = None,
    spoof_config: Optional[SpoofConfig] = None,
    enable_frida: bool = True,
    artifact_store: Optional[Path] = None,
    wipe_after: bool = True,
) -> DynamicBundle:
    """Run full dynamic analysis on an APK.

    Args:
        apk_path: Path to APK file
        static_bundle: Pre-computed StaticBundle (will run static if None)
        host: Emulator host (uses the default ADB-connected emulator if None)
        network_mode: Network capture mode
        proxy_port: mitmproxy port
        ui_script: Custom UI automation script (uses DEFAULT_SCRIPT if None)
        ui_time_limit: Max seconds for UI automation
        ui_action_limit: Max actions for UI automation
        frida_groups: Frida hook groups to enable (None = all except spoof)
        spoof_config: Device spoofing configuration (opt-in only)
        enable_frida: Whether to attempt Frida instrumentation
        artifact_store: Override artifact store path
        wipe_after: Whether to wipe artifacts after (ephemeral policy)

    Returns:
        DynamicBundle with all findings and artifacts
    """
    apk_path = Path(apk_path)
    run_id = uuid.uuid4().hex[:12]
    start_time = time.time()

    # --- Addition 1: Log run configuration ---
    config = {
        "run_id": run_id,
        "ui_script": [
            {
                "action": step.action.value if hasattr(step.action, 'value') else str(step.action),
                "target": step.target,
                "value": step.value,
                "x": step.x,
                "y": step.y,
                "duration": step.duration
            } for step in (ui_script if ui_script is not None else DEFAULT_SCRIPT)
        ],
        "ui_script_is_default": ui_script is None,
        "network_mode": network_mode.value if hasattr(network_mode, 'value') else str(network_mode),
        "ui_time_limit": ui_time_limit,
        "ui_action_limit": ui_action_limit,
        "frida_groups": frida_groups,
        "wipe_after": wipe_after,
    }
    # We will add this artifact after initializing the collector

    # Initialize artifact collector
    if artifact_store:
        from config.settings import get_settings
        settings = get_settings()
        settings.artifact_store_path = artifact_store

    # Device serial will be known after boot
    collector = ArtifactCollector(run_id, device_serial="pending")
    # Add the run config artifact
    collector._write_artifact("run_config", "host", json.dumps(config, indent=2),
                              f"run_config_{run_id}.json", {"config": config})

    partial_failure = False
    failure_reasons = []

    # Use default host if not provided
    if host is None:
        host = default_host()

    # Track session for cleanup
    session: Optional[SandboxSession] = None
    instrumentation_result: Optional[InstrumentationResult] = None
    network_capture: Optional[NetworkCapture] = None

    # --- Group 7: Configure logger to persist to console_log_<run_id>.txt ---
    log_file = collector.run_dir / f"console_log_{run_id}.txt"
    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s.%(msecs)03d %(message)s",
                                  datefmt="%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # Logger already had no file handler before this group; every logger.info()
    # call only went to console before. This handler persists to artifacts.

    try:
        # --- 1. Static analysis ---
        logger.info(f"[{run_id}] Starting static analysis")
        if static_bundle is None:
            static_bundle = static_run(apk_path)
        logger.info(f"[{run_id}] Static analysis complete")

        # --- 2. Connect to ADB-connected Android emulator ---
        logger.info(f"[{run_id}] Connecting to ADB-connected Android emulator")
        with clean_session(host, proxy_port) as session:
            # Update collector with actual device serial
            collector.device_serial = session.device_serial

            # --- Addition 2: Force-stop watcher ---
            logcat_proc = None
            stop_event = threading.Event()
            def force_stop_watcher():
                nonlocal logcat_proc
                processed_lines = set()
                # Start a persistent logcat process for continuous line reading
                cmd = ["adb", "-s", session.device_serial, "logcat"]
                try:
                    logcat_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        bufsize=1,
                        universal_newlines=True,
                    )
                except Exception as e:
                    logger.error(f"[{run_id}] Failed to start logcat process: {e}")
                    return

                while not stop_event.is_set():
                    try:
                        line = logcat_proc.stdout.readline()
                        if line == '':
                            # Process ended; break to allow cleanup
                            break
                        line = line.strip()
                        if not line:
                            continue
                        if "Force stopping com.apkookies.cryptotest" in line:
                            if line not in processed_lines:
                                processed_lines.add(line)
                                # Extract killer PID
                                match = re.search(r'from pid (\d+)', line)
                                killer_pid = None
                                if match:
                                    killer_pid = int(match.group(1))
                                # Now gather info about the killer PID
                                killer_info = {}
                                # Try to run `ps` command
                                try:
                                    ps_result = host._run_adb(
                                        ["shell", "ps", "-p", str(killer_pid), "-o", "pid,ppid,uid,args"],
                                        serial=session.device_serial,
                                        timeout=5
                                    )
                                    if ps_result.success:
                                        killer_info["ps"] = ps_result.stdout.strip()
                                    else:
                                        killer_info["ps_error"] = ps_result.stderr.strip()
                                except Exception as e:
                                    killer_info["ps_error"] = str(e)
                                # Try to read /proc/<pid>/cmdline
                                try:
                                    cmdline_result = host._run_adb(
                                        ["shell", "cat", f"/proc/{killer_pid}/cmdline"],
                                        serial=session.device_serial,
                                        timeout=5
                                    )
                                    if cmdline_result.success:
                                        killer_info["cmdline"] = cmdline_result.stdout.strip()
                                    else:
                                        killer_info["cmdline_error"] = cmdline_result.stderr.strip()
                                except Exception as e:
                                    killer_info["cmdline_error"] = str(e)
                                # Try to read /proc/<pid>/status
                                try:
                                    status_result = host._run_adb(
                                        ["shell", "cat", f"/proc:{killer_pid}/status"],
                                        serial=session.device_serial,
                                        timeout=5
                                    )
                                    if status_result.success:
                                        killer_info["status"] = status_result.stdout.strip()
                                    else:
                                        killer_info["status_error"] = status_result.stderr.strip()
                                except Exception as e:
                                    killer_info["status_error"] = str(e)
                                # Try to get activity processes info
                                try:
                                    activity_result = host._run_adb(
                                        ["shell", "dumpsys", "activity", "processes"],
                                        serial=session.device_serial,
                                        timeout=5
                                    )
                                    if activity_result.success:
                                        killer_info["activity_processes"] = activity_result.stdout.strip()
                                    else:
                                        killer_info["activity_processes_error"] = activity_result.stderr.strip()
                                except Exception as e:
                                    killer_info["activity_processes_error"] = str(e)
                                # Now create an artifact for this event
                                event_artifact = Artifact(
                                    run_id=run_id,
                                    artifact_type="force_stop_watch",
                                    provenance="host",
                                    path=f"force_stop_watch_{run_id}.json",
                                    timestamp=time.time(),
                                    metadata={
                                        "triggered": True,
                                        "logcat_line": line,
                                        "killer_pid": killer_pid,
                                        "killer_info": killer_info
                                    },
                                    size_bytes=len(json.dumps({
                                        "triggered": True,
                                        "logcat_line": line,
                                        "killer_pid": killer_pid,
                                        "killer_info": killer_info
                                    }).encode('utf-8'))
                                )
                                collector.artifacts.artifacts.append(event_artifact)
                    except Exception as e:
                        # Ignore errors in the watcher to avoid breaking the main thread
                        pass
                # Note: logcat subprocess lifecycle is managed by main thread finally block only.
                # The watcher reads lines only and never terminates/waits/kills the process.

            watcher_thread = threading.Thread(target=force_stop_watcher, daemon=True)
            watcher_thread.start()

            try:
                # --- 3. Install APK ---
                logger.info(f"[{run_id}] Installing APK: {apk_path}")
                install_result = host.install(session, str(apk_path))
                collector.log_command(["install", str(apk_path)], install_result, "install")
                if not install_result.success:
                    partial_failure = True
                    failure_reasons.append(f"Install failed: {install_result.error}")
                    logger.error(f"[{run_id}] Install failed: {install_result.error}")
                else:
                    logger.info(f"[{run_id}] Install successful")

                # --- 4. Launch app + resolve package/activity/PID ---
                logger.info(f"[{run_id}] Launching app")
                launch_result = host.launch(session)
                collector.log_command(["launch"], launch_result, "launch")
                if not launch_result.success:
                    partial_failure = True
                    failure_reasons.append(f"Launch failed: {launch_result.error}")
                    logger.error(f"[{run_id}] Launch failed: {launch_result.error}")
                else:
                    logger.info(f"[{run_id}] Launch successful")

                # Resolve package and activity
                if not session.package_name or not session.main_activity:
                    package, activity = host._resolve_package_and_activity(session)
                    if package:
                        session.package_name = package
                    if activity:
                        session.main_activity = activity

                if not session.package_name or not session.main_activity:
                    partial_failure = True
                    failure_reasons.append("Could not resolve package/activity")
                    logger.error(f"[{run_id}] Could not resolve package/activity")
                else:
                    logger.info(f"[{run_id}] Package: {session.package_name}, Activity: {session.main_activity}")

                # Get PID (with retry)
                session.pid = None
                for attempt in range(1, 6):
                    session.pid = host.get_pid(session)
                    if session.pid is not None:
                        logger.info(f"[{run_id}] PID obtained on attempt {attempt}: {session.pid}")
                        break
                    logger.debug(f"[{run_id}] get_pid() returned None, attempt {attempt}/5")
                    if attempt < 5:
                        time.sleep(1.0)
                if session.pid is None:
                    logger.warning(f"[{run_id}] Could not get PID of {session.package_name} after 5 attempts")
                else:
                    logger.info(f"[{run_id}] PID: {session.pid}")

                # --- 5. Attach Frida with selected hook groups ---
                logger.info(f"[{run_id}] Attaching Frida")
                if enable_frida and session.pid:
                    # Check Frida server availability
                    if not check_frida_server(session.device_serial)["available"]:
                        partial_failure = True
                        failure_reasons.append("Frida server not available")
                        logger.error(f"[{run_id}] Frida server not available")
                    else:
                        instrumentation_result = frida_attach(
                            session.device_serial,
                            session.pid,
                            target_package=session.package_name,
                            groups=frida_groups,
                            spoof_config=spoof_config,
                        )
                        # Check if any session is active (success = session.status == "active")
                        active_sessions = [s for s in instrumentation_result.sessions if s.status == "active"] if instrumentation_result else []
                        if active_sessions:
                            logger.info(f"[{run_id}] Frida attached successfully")
                        else:
                            partial_failure = True
                            failure_reasons.append(f"Frida attach failed: {instrumentation_result.errors if instrumentation_result else 'Unknown error'}")
                            logger.error(f"[{run_id}] Frida attach failed: {instrumentation_result.errors if instrumentation_result else 'Unknown error'}")
                else:
                    logger.info(f"[{run_id}] Frida attachment skipped (enable_frida={enable_frida}, pid={session.pid})")


                # ============================================================
                # 6. Capture network traffic BEFORE UI automation
                # ============================================================
                logger.info(f"[{run_id}] Starting network capture")

                network_capture = start_capture(
                    session.device_serial,
                    proxy_port=proxy_port,
                    mode=network_mode,
                    artifact_dir=Path("./.artifacts/network") / run_id,
                )

                logger.info(f"[{run_id}] Network capture started")


                # ============================================================
                # 7. Run UI automation script
                # ============================================================

                logger.info(f"[{run_id}] Starting UI automation")

                ui_result = ui_run_script(
                    session.device_serial,
                    script=ui_script,
                    time_limit_sec=ui_time_limit,
                    action_limit=ui_action_limit,
                    artifact_dir=Path("./.artifacts/ui") / run_id,
                )

                logger.info(
                    f"[{run_id}] UI automation completed: "
                    f"{ui_result.steps_executed} steps executed"
                )

                if ui_result.errors:
                    logger.warning(
                        f"[{run_id}] UI automation errors: "
                        f"{ui_result.errors}"
                    )

                # Collect UI automation artifacts

                if ui_result.ui_dumps:
                    for dump_path in ui_result.ui_dumps:
                        collector.collect_ui_dump(dump_path)

                if ui_result.screenshots:
                    for shot in ui_result.screenshots:
                        collector.collect_screenshot(shot)

                # ============================================================
                # 8. Wait for Frida events
                # ============================================================

                logger.info(f"[{run_id}] Waiting for Frida events")

                if instrumentation_result:
                    frida_wait(
                        instrumentation_result,
                        timeout_sec=5
                    )        


                # # --- 6. Run UI automation script ---
                # logger.info(f"[{run_id}] Starting UI automation")
                # ui_result = ui_run_script(
                #     session.device_serial,
                #     script=ui_script,
                #     time_limit_sec=ui_time_limit,
                #     action_limit=ui_action_limit,
                #     artifact_dir=Path("./.artifacts/ui") / run_id,
                # )
                # logger.info(f"[{run_id}] UI automation completed: {ui_result.steps_executed} steps executed")
                # if ui_result.errors:
                #     logger.warning(f"[{run_id}] UI automation errors: {ui_result.errors}")
                # # Collect UI automation artifacts
                # if ui_result.ui_dumps:
                #     for dump_path in ui_result.ui_dumps:
                #         collector.collect_ui_dump(dump_path)
                # if ui_result.screenshots:
                #     for shot in ui_result.screenshots:
                #         collector.collect_screenshot(shot)

                # # --- 7. Capture network traffic (controlled) ---
                # logger.info(f"[{run_id}] Starting network capture")
                # network_capture = start_capture(
                #     session.device_serial,
                #     proxy_port=proxy_port,
                #     mode=network_mode,
                #     artifact_dir=Path("./.artifacts/network") / run_id,
                # )
                # logger.info(f"[{run_id}] Network capture started")

                # # --- 8. Wait for Frida events ---
                # logger.info(f"[{run_id}] Waiting for Frida events")
                # if instrumentation_result:
                #     frida_wait(instrumentation_result, timeout_sec=5)

                # --- 9. Collect Frida events ---
                if instrumentation_result:
                    logger.info(f"[{run_id}] Collecting Frida events")
                    frida_events = frida_collect(instrumentation_result)
                    if frida_events:
                        logger.info(f"[{run_id}] Collected {len(frida_events)} Frida events")
                        collector.collect_frida_events(frida_events)

                # --- 10. Collect logcat ---
                logger.info(f"[{run_id}] Collecting logcat")
                collector.collect_logcat(duration_sec=10)

                # --- 11. Stop network capture & collect ---
                logger.info(f"[{run_id}] Stopping network capture")
                capture_result = stop_capture(network_capture)
                network_capture = None
                if capture_result.indicators:
                    logger.info(f"[{run_id}] Collected {len(capture_result.indicators)} network indicators")
                    collector.collect_network_indicators(capture_result.indicators)

                # --- 12. Collect package info ---
                if session.package_name:
                    logger.info(f"[{run_id}] Collecting package info")
                    collector.collect_package_info(session.package_name)

                # --- 13. Collect device profile ---
                logger.info(f"[{run_id}] Collecting device profile")
                device_profile = collect_device_profile(host, session)
                collector.collect_device_profile(device_profile)

            finally:
                # --- Addition 2: Stop the force-stop watcher ---
                logger.info(f"[{run_id}] Stopping force-stop watcher")
                stop_event.set()
                if logcat_proc is not None:
                    logcat_proc.terminate()
                watcher_thread.join(timeout=5.0)
                if logcat_proc is not None and watcher_thread.is_alive():
                    logcat_proc.kill()
                    try:
                        logcat_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass

        # --- 13. Behavior analysis ---
        logger.info(f"[{run_id}] Running behavior analysis")
        behavior_report = behavior_analyze(
            events=frida_events if 'frida_events' in locals() else [],
            network=capture_result.indicators if 'capture_result' in locals() else [],
            ui=ui_result if 'ui_result' in locals() else None,
            device_profile=device_profile if 'device_profile' in locals() else {},
        )

        # --- 14. Finalize artifacts ---
        artifacts = collector.finalize()

        # --- 15. Build DynamicFindings ---
        dynamic = DynamicFindings(
            behavior_report=behavior_report,
            frida_events=frida_events if 'frida_events' in locals() else [],
            network_indicators=capture_result.indicators if 'capture_result' in locals() else [],
            ui_result=ui_result if 'ui_result' in locals() else None,
            device_profile=device_profile if 'device_profile' in locals() else {},
        )

        analysis_status = {
            "adb": {"status": "observed", "reason": "ADB emulator session established."},
            "install": {"status": "observed" if install_result.success else "failed", "reason": install_result.error or "APK installed."},
            "launch": {"status": "observed" if launch_result.success else "failed", "reason": launch_result.error or "Application launch requested."},
            "pid": {"status": "observed" if session.pid else "failed", "reason": "Application PID resolved." if session.pid else "Application PID was not found."},
            "frida": {"status": "observed" if instrumentation_result and instrumentation_result.sessions else "unavailable", "reason": "Frida instrumentation attached." if instrumentation_result and instrumentation_result.sessions else "Frida produced no active session."},
            "ui": {"status": "observed" if ui_result else "failed", "reason": "UI automation completed." if ui_result else "UI automation returned no result."},
            "network": {"status": "observed" if capture_result is not None else "failed", "reason": "Network capture completed." if capture_result is not None else "Network capture returned no result."},
            "logcat": {"status": "observed", "reason": "Logcat collection attempted."},
            "artifacts": {"status": "observed", "reason": "Artifacts finalized."},
        }
        coverage = 0.9 if session.pid else 0.35

        # --- 16. Build DynamicBundle ---
        bundle = DynamicBundle(
            run_id=run_id,
            apk_path=str(apk_path),
            static_bundle=static_bundle,
            dynamic=dynamic,
            artifacts=artifacts,
            session=session,
            analysis_status=analysis_status,
            coverage=coverage,
        )

        # --- 17. Teardown + sanitize artifacts ---
        logger.info(f"[{run_id}] Teardown complete")
        if wipe_after:
            artifact_wipe(run_id)

        return bundle

    except Exception as e:
        logger.error(f"[{run_id}] Unexpected error: {e}", exc_info=True)
        partial_failure = True
        failure_reasons.append(f"Unexpected error: {e}")
        # Still try to return a bundle with what we have
        if 'collector' in locals():
            artifacts = collector.finalize()
        else:
            artifacts = RunArtifacts(run_id)
        dynamic = DynamicFindings(
            behavior_report={},
            frida_events=[],
            network_indicators=[],
            ui_result=None,
            device_profile={},
        )
        bundle = DynamicBundle(
            run_id=run_id,
            apk_path=str(apk_path),
            static_bundle=static_bundle if 'static_bundle' in locals() else None,
            dynamic=dynamic,
            artifacts=artifacts,
            session=session,
            analysis_status={
                "sandbox": {"status": "failed", "reason": str(e)},
                "adb": {"status": "observed" if session else "failed", "reason": "Session established." if session else "No usable emulator session."},
                "artifacts": {"status": "observed", "reason": "Partial artifacts finalized."},
            },
            coverage=0.1 if not session else 0.25,
        )
        if wipe_after:
            artifact_wipe(run_id)
        return bundle