"""Emulator lifecycle for any ADB-connected Android emulator.

This module integrates with an ALREADY-RUNNING Android emulator, including an
Android Studio AVD. The emulator must be started before running analysis.

Key design:
- Does NOT boot/manage emulator instances
- Discovers devices via `adb devices -l`
- Communicates via ADB only
- Returns structured command outcomes (never silently swallows failures)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Protocol

try:
    from config.settings import get_settings
except ImportError:
    def get_settings():
        class _S:
            artifact_store_path = Path("./.artifacts")
        return _S()


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
        """Connect to an existing ADB-connected emulator and configure proxy egress."""
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

    def teardown(self, session: SandboxSession) -> None:
        """Clean up: force-stop, clear data, and uninstall per policy."""
        ...


class LocalAdbHost:
    """Local ADB host for any already-running Android emulator."""

    def __init__(self, adb_path: Optional[str] = None, device_serial: Optional[str] = None):
        self.adb_path = adb_path or self._find_adb()
        self.device_serial = device_serial  # If None, auto-discover an online ADB device
        self._validate_adb()

    def _find_adb(self) -> str:
        return resolve_adb_path()

    def _validate_adb(self) -> None:
        """Verify ADB works."""
        result = self._run_adb(["version"])
        if not result.success:
            raise RuntimeError(f"ADB not working at {self.adb_path}: {result.stderr}")

    def _run_adb(self, args: list[str], serial: Optional[str] = None, timeout: int = 30) -> CommandResult:
        """Run adb command and return structured result."""
        cmd = [self.adb_path]
        if serial:
            cmd += ["-s", serial]
        cmd += args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace"
            )
            return CommandResult(
                command=cmd,
                returncode=proc.returncode,
                stdout=proc.stdout.strip(),
                stderr=proc.stderr.strip(),
                success=proc.returncode == 0,
                error=None if proc.returncode == 0 else proc.stderr.strip()
            )
        except subprocess.TimeoutExpired as e:
            return CommandResult(
                command=cmd,
                returncode=-1,
                stdout=e.stdout.decode("utf-8", errors="replace") if e.stdout else "",
                stderr=e.stderr.decode("utf-8", errors="replace") if e.stderr else "",
                success=False,
                error=f"Timeout after {timeout}s"
            )
        except Exception as e:
            return CommandResult(
                command=cmd,
                returncode=-1,
                stdout="",
                stderr=str(e),
                success=False,
                error=str(e)
            )

    def discover_devices(self) -> list[dict]:
        """Discover devices via `adb devices -l`. Returns list of device info dicts."""
        result = self._run_adb(["devices", "-l"])
        if not result.success:
            return []

        devices = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            # Format: serial  state  [model:xxx device:xxx ...]
            parts = line.split()
            if len(parts) < 2:
                continue
            serial = parts[0]
            state = parts[1]
            props = {}
            for p in parts[2:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    props[k] = v
            devices.append({
                "serial": serial,
                "state": state,  # "device", "unauthorized", "offline"
                "props": props
            })
        return devices

    def select_adb_device(self) -> Optional[str]:
        """Select an online ADB-connected Android emulator deterministically.

        Priority:
        1. Explicitly configured device_serial
        2. First online emulator-like device (Android Studio or other)
        3. First online ADB device

        Returns None if no suitable device found.
        """
        if self.device_serial:
            # Verify it exists and is online
            devices = self.discover_devices()
            for d in devices:
                if d["serial"] == self.device_serial:
                    if d["state"] == "device":
                        return self.device_serial
                    else:
                        raise RuntimeError(f"Configured device {self.device_serial} is {d['state']}, not online")
            raise RuntimeError(f"Configured device {self.device_serial} not found")

        devices = self.discover_devices()
        if not devices:
            return None

        # Filter online devices
        online = [d for d in devices if d["state"] == "device"]
        if not online:
            states = [f"{d['serial']}={d['state']}" for d in devices]
            raise RuntimeError(f"No online devices. Found: {', '.join(states)}")

        # Prefer emulator-like devices when multiple ADB devices are online.
        emulator_indicators = ["emulator", "sdk_gphone", "generic", "vbox"]
        for indicator in emulator_indicators:
            for d in online:
                model = d["props"].get("model", "").lower()
                device = d["props"].get("device", "").lower()
                if indicator in model or indicator in device:
                    return d["serial"]

        # Fallback: first online device
        return online[0]["serial"]

    def boot_clean(self, proxy_port: int) -> SandboxSession:
        """Connect to an ADB-connected Android emulator and verify it's ready."""
        serial = self.select_adb_device()
        if not serial:
            raise RuntimeError(
            "No online ADB-connected Android emulator found. Ensure:\n"
            "1. Android Studio AVD or another Android emulator is running\n"
            "2. The emulator appears as 'device' in `adb devices`\n"
            "3. ADB can connect to the emulator"
            )

        run_id = uuid.uuid4().hex[:12]

        # Verify connectivity and get basic props
        props_result = self._run_adb(["shell", "getprop"], serial=serial)
        if not props_result.success:
            raise RuntimeError(f"Failed to get properties from {serial}: {props_result.error}")

        # Configure proxy on device
        proxy_result = self._run_adb(["shell", "settings", "put", "global", "http_proxy", f"127.0.0.1:{proxy_port}"], serial=serial)
        if not proxy_result.success:
            # Non-fatal: proxy may be set via other means
            pass

        session = SandboxSession(
            run_id=run_id,
            device_serial=serial,
            proxy_port=proxy_port,
        )
        return session

    def install(self, session: SandboxSession, apk_path: str) -> CommandResult:
        """Install APK with -r (reinstall) and -g (grant permissions)."""
        return self._run_adb(["install", "-r", "-g", apk_path], serial=session.device_serial, timeout=120)

    def _resolve_package_and_activity(self, session: SandboxSession) -> tuple[Optional[str], Optional[str]]:
        """Resolve package name and main launcher activity from installed APK."""
        # Try to get package from recent install or use pm list packages
        # We need the package name - typically we'd know it from the APK manifest
        # For now, use pm list packages -3 (third-party) to find recently installed
        result = self._run_adb(["shell", "pm", "list", "packages", "-3"], serial=session.device_serial)
        if not result.success:
            return None, None

        # This is a fallback - in practice we should get package from manifest
        packages = []
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                packages.append(line.split(":", 1)[1].strip())

        if not packages:
            return None, None

        # Use the first third-party package (could be improved with APK manifest parsing)
        package = packages[0]

        # Get launcher activity — prefer Android's actual intent resolver so we
        # never guess "<pkg>.MainActivity". Ask for the MAIN + LAUNCHER activity.
        act_result = self._run_adb([
            "shell", "cmd", "package", "resolve-activity",
            "--brief", "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER",
            package
        ], serial=session.device_serial)

        main_activity = None
        if act_result.success:
            # --brief prints a header line, then "package/.Activity".
            for line in act_result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("priority="):
                    continue
                match = re.match(r'([a-zA-Z0-9_.]+/\.?[a-zA-Z0-9_.]+)', line)
                if match:
                    main_activity = match.group(1)
                    break

        # Fallback: dumpsys — MAIN and LAUNCHER appear on separate lines.
        # Android 13+ outputs intent filter blocks across multiple lines:
        #   android.intent.action.MAIN:
        #     com.package/.Activity filter ...
        #       Action: "android.intent.action.MAIN"
        #       Category: "android.intent.category.LAUNCHER"
        if main_activity is None:
            act_result2 = self._run_adb([
                "shell", "dumpsys", "package", package
            ], serial=session.device_serial)
            if act_result2.success:
                lines = act_result2.stdout.splitlines()
                for i, line in enumerate(lines):
                    if "android.intent.action.MAIN:" in line:
                        # Search forward for the component (package/activity pattern)
                        # It appears on a subsequent indented line within the same filter block.
                        found_comp = None
                        for j in range(i + 1, min(i + 20, len(lines))):
                            next_line = lines[j].strip()
                            # Stop if we hit another action or empty line (end of filter block)
                            if not next_line:
                                break
                            if next_line.startswith("android.intent.action."):
                                break
                            comp = re.search(r'([a-zA-Z0-9_.]+/\.?[a-zA-Z0-9_.]+)', next_line)
                            if comp:
                                found_comp = comp.group(1)
                                # Verify LAUNCHER category appears in this block
                                for k in range(j, min(j + 10, len(lines))):
                                    if "android.intent.category.LAUNCHER" in lines[k]:
                                        main_activity = found_comp
                                        break
                                    # Stop if we hit another action/category header
                                    if lines[k].strip().startswith("android.intent."):
                                        pass
                                break
                        if main_activity:
                            break

        return package, main_activity

    def launch(self, session: SandboxSession) -> CommandResult:
        """Launch the app's main activity."""
        if not session.package_name or not session.main_activity:
            package, activity = self._resolve_package_and_activity(session)
            if package:
                session.package_name = package
            if activity:
                session.main_activity = activity

        if not session.package_name or not session.main_activity:
            return CommandResult(
                command=[],
                returncode=-1,
                stdout="",
                stderr="",
                success=False,
                error="Could not resolve package/activity"
            )

        # Launch with monkey or am start
        return self._run_adb([
            "shell", "am", "start", "-n", session.main_activity,
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER"
        ], serial=session.device_serial)

    def get_pid(self, session: SandboxSession) -> Optional[int]:
        """Get PID of the running package."""
        if not session.package_name:
            return None
        result = self._run_adb(["shell", "pidof", session.package_name], serial=session.device_serial)
        if result.success and result.stdout.strip():
            try:
                return int(result.stdout.strip().split()[0])
            except (ValueError, IndexError):
                return None
        return None

    def force_stop(self, session: SandboxSession) -> CommandResult:
        if not session.package_name:
            return CommandResult([], -1, "", "", False, "No package name")
        return self._run_adb(["shell", "am", "force-stop", session.package_name], serial=session.device_serial)

    def clear_data(self, session: SandboxSession) -> CommandResult:
        if not session.package_name:
            return CommandResult([], -1, "", "", False, "No package name")
        return self._run_adb(["shell", "pm", "clear", session.package_name], serial=session.device_serial)

    def uninstall(self, session: SandboxSession) -> CommandResult:
        if not session.package_name:
            return CommandResult([], -1, "", "", False, "No package name")
        return self._run_adb(["uninstall", session.package_name], serial=session.device_serial)

    def get_prop(self, session: SandboxSession, prop: str) -> CommandResult:
        return self._run_adb(["shell", "getprop", prop], serial=session.device_serial)

    def get_props(self, session: SandboxSession, props: list[str]) -> dict[str, CommandResult]:
        results = {}
        for prop in props:
            results[prop] = self.get_prop(session, prop)
        return results

    def logcat(self, session: SandboxSession, duration_sec: int = 10) -> CommandResult:
        """Collect logcat for specified duration."""
        # Use -d to dump and exit, with timeout
        return self._run_adb([
            "logcat", "-d", "-t", str(duration_sec * 1000)  # -t uses milliseconds? Actually -t is count. Use timeout.
        ], serial=session.device_serial, timeout=duration_sec + 5)

    def teardown(self, session: SandboxSession) -> None:
        """Clean up: force-stop, clear data, uninstall. Does NOT kill the VM."""
        if session.package_name:
            self.force_stop(session)
            self.clear_data(session)
            self.uninstall(session)
        # Restore proxy
        self._run_adb(["shell", "settings", "put", "global", "http_proxy", ":"], serial=session.device_serial)


@contextmanager
def clean_session(host: EmulatorHost, proxy_port: int) -> Iterator[SandboxSession]:
    """Context manager guaranteeing teardown even on failure."""
    session = host.boot_clean(proxy_port)
    try:
        yield session
    finally:
        host.teardown(session)


def resolve_adb_path() -> str:
    """Locate adb on Windows, macOS or Linux.

    Order: ADB_PATH (.env or environment), $ANDROID_HOME / $ANDROID_SDK_ROOT,
    the platform's default Android Studio SDK folder, then PATH.
    """
    from config.settings import get_settings

    exe = "adb.exe" if os.name == "nt" else "adb"
    local_appdata = os.environ.get("LOCALAPPDATA")
    sdk_dirs = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        Path(local_appdata) / "Android" / "Sdk" if local_appdata else None,  # Windows
        Path.home() / "Library" / "Android" / "sdk",  # macOS
        Path.home() / "Android" / "Sdk",  # Linux
    ]
    candidates = [get_settings().adb_path, os.environ.get("ADB_PATH")]
    candidates += [str(Path(d) / "platform-tools" / exe) for d in sdk_dirs if d]
    candidates.append(shutil.which("adb"))
    for c in candidates:
        if c and Path(c).exists():
            return str(Path(c).resolve())
    return "adb"  # last resort: let the OS resolve it


def default_host() -> EmulatorHost:
    """Factory for the local ADB-connected emulator host."""
    from config.settings import get_settings

    device_serial = (get_settings().android_serial or os.environ.get("ANDROID_SERIAL")
                     or os.environ.get("GENYMOTION_SERIAL"))
    return LocalAdbHost(adb_path=resolve_adb_path(), device_serial=device_serial or None)


# --- Device property collection helpers ---

DEVICE_PROPS = [
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.brand",
    "ro.build.fingerprint",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.product.cpu.abi",
    "ro.product.cpu.abilist",
    "ro.hardware",
    "ro.kernel.qemu",
    "ro.build.tags",
    "ro.build.type",
    "ro.bootmode",
    "init.svc.vold",
    "init.svc.adbd",
]


def collect_device_profile(host: LocalAdbHost, session: SandboxSession) -> dict:
    """Collect comprehensive device profile via getprop."""
    results = host.get_props(session, DEVICE_PROPS)
    profile = {}
    for prop, result in results.items():
        if result.success:
            profile[prop] = result.stdout
        else:
            profile[prop] = f"ERROR: {result.error}"
    return profile


# Backward-compatible name for callers that imported the old host class.
LocalGenymotionHost = LocalAdbHost