"""Scripted UI automation — drive the app to trigger dormant behavior.

Uses ADB and uiautomator2 (if available) for:
  * app launch
  * wait
  * permission granting
  * taps
  * text input
  * UI hierarchy dump
  * screenshots
  * bounded exploration
  * synthetic login (fake credentials)
  * accessibility interaction
  * overlay/window anomaly observation

All credentials are synthetic/generated locally. Never use real credentials.
"""

from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

try:
    from config.settings import get_settings
except ImportError:
    def get_settings():
        class _S:
            artifact_store_path = Path("./.artifacts")
        return _S()

logger = __import__("logging").getLogger(__name__)


class ActionType(str, Enum):
    tap_text = "tap_text"
    tap_xy = "tap_xy"
    input_text = "input_text"
    grant_permission = "grant_permission"
    enable_accessibility = "enable_accessibility"
    simulate_login = "simulate_login"
    wait = "wait"
    dump_ui = "dump_ui"
    screenshot = "screenshot"
    press_key = "press_key"
    scroll = "scroll"
    swipe = "swipe"
    back = "back"
    home = "home"
    launch_app = "launch_app"


@dataclass
class Step:
    action: ActionType
    target: str = ""
    value: str = ""
    # Optional: x, y for tap_xy
    x: int = 0
    y: int = 0
    # Optional: duration for swipe
    duration: int = 300


# Default interaction script for triggering dormant malware.
DEFAULT_SCRIPT: list[Step] = [
    Step(ActionType.grant_permission, target="all"),
    Step(ActionType.wait, value="2"),
    Step(ActionType.enable_accessibility, target="self"),
    Step(ActionType.wait, value="3"),
    # Trigger the APK's crypto operations
    Step(ActionType.tap_text, target="Run Crypto Test"),
    Step(ActionType.wait, value="5"),
    Step(ActionType.dump_ui),
    Step(ActionType.screenshot),
]


@dataclass
class UIRunResult:
    steps_executed: int = 0
    dialogs_auto_accepted: int = 0
    overlay_detected: bool = False
    screenshots: list[str] = field(default_factory=list)
    ui_dumps: list[str] = field(default_factory=list)
    observed_packages: list[str] = field(default_factory=list)
    observed_windows: list[str] = field(default_factory=list)
    elapsed_sec: float = 0.0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class UIAutomation:
    """UI automation driver using ADB and optional uiautomator2."""

    def __init__(self, device_serial: str, artifact_dir: Optional[Path] = None):
        self.device_serial = device_serial
        self.artifact_dir = artifact_dir or Path("./.artifacts/ui")
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self._u2 = None
        self._adbp = None
        self._has_u2 = False

        # Try to import uiautomator2
        try:
            import uiautomator2 as u2
            self._u2 = u2
            self._has_u2 = True
        except ImportError:
            pass

    def _run_adb(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run adb command."""
        from backend.sandbox.emulator import resolve_adb_path

        cmd = [resolve_adb_path()]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += args
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")

    def connect_u2(self) -> bool:
        """Connect to uiautomator2 if available."""
        if not self._has_u2:
            return False
        try:
            self._adbp = self._u2.connect(self.device_serial)
            # Start uiautomator2 server if needed
            self._adbp.app_stop_all()
            return True
        except Exception as e:
            logger.warning(f"uiautomator2 connection failed: {e}")
            self._adbp = None
            return False

    def run_script(self, script: list[Step] | None = None,
                   time_limit_sec: int = 60,
                   action_limit: int = 50) -> UIRunResult:
        """Execute a UI-interaction script against the running app."""
        if script is None:
            script = DEFAULT_SCRIPT

        start_time = time.time()
        result = UIRunResult()
        actions_executed = 0

        # Connect uiautomator2 if available
        if self._has_u2 and self._adbp is None:
            self.connect_u2()

        for step in script:
            if actions_executed >= action_limit:
                result.notes.append(f"Action limit ({action_limit}) reached")
                break

            if time.time() - start_time > time_limit_sec:
                result.notes.append(f"Time limit ({time_limit_sec}s) reached")
                break

            try:
                self._execute_step(step, result)
                actions_executed += 1
                result.steps_executed += 1
            except Exception as e:
                result.errors.append(f"Step {step.action}: {e}")

        result.elapsed_sec = time.time() - start_time
        return result

    def _execute_step(self, step: Step, result: UIRunResult):
        """Execute a single automation step."""
        if step.action == ActionType.wait:
            duration = float(step.value) if step.value else 1.0
            time.sleep(duration)

        elif step.action == ActionType.dump_ui:
            dump_path = self._dump_ui()
            if dump_path:
                result.ui_dumps.append(dump_path)

        elif step.action == ActionType.screenshot:
            screenshot_path = self._screenshot()
            if screenshot_path:
                result.screenshots.append(screenshot_path)

        elif step.action == ActionType.tap_text:
            self._tap_text(step.target)

        elif step.action == ActionType.tap_xy:
            self._tap_xy(step.x, step.y)

        elif step.action == ActionType.input_text:
            self._input_text(step.value)

        elif step.action == ActionType.press_key:
            self._press_key(step.value)

        elif step.action == ActionType.scroll:
            self._scroll(step.value)

        elif step.action == ActionType.swipe:
            self._swipe(step.x, step.y, int(step.value) if step.value else 0, step.duration)

        elif step.action == ActionType.back:
            self._run_adb(["shell", "input", "keyevent", "4"])  # KEYCODE_BACK

        elif step.action == ActionType.home:
            self._run_adb(["shell", "input", "keyevent", "3"])  # KEYCODE_HOME

        elif step.action == ActionType.launch_app:
            self._launch_app(step.target)

        elif step.action == ActionType.grant_permission:
            self._grant_permissions(step.target, result)

        elif step.action == ActionType.enable_accessibility:
            self._enable_accessibility(step.target, result)

        elif step.action == ActionType.simulate_login:
            self._simulate_login(step.value, result)

    def _dump_ui(self) -> Optional[str]:
        """Dump UI hierarchy to XML file."""
        filename = f"ui_dump_{uuid.uuid4().hex[:8]}.xml"
        filepath = self.artifact_dir / filename

        # Try uiautomator2 first
        if self._adbp:
            try:
                xml = self._adbp.dump_hierarchy()
                filepath.write_text(xml, encoding="utf-8")
                return str(filepath)
            except Exception:
                pass

        # Fallback to ADB uiautomator dump
        try:
            self._run_adb(["shell", "uiautomator", "dump", f"/sdcard/{filename}"])
            self._run_adb(["pull", f"/sdcard/{filename}", str(filepath)])
            self._run_adb(["shell", "rm", f"/sdcard/{filename}"])
            if filepath.exists():
                return str(filepath)
        except Exception:
            pass

        return None

    def _screenshot(self) -> Optional[str]:
        """Take screenshot."""
        filename = f"screenshot_{uuid.uuid4().hex[:8]}.png"
        filepath = self.artifact_dir / filename

        # Try uiautomator2
        if self._adbp:
            try:
                img = self._adbp.screenshot()
                img.save(str(filepath))
                return str(filepath)
            except Exception:
                pass

        # Fallback to ADB screencap
        try:
            self._run_adb(["shell", "screencap", "-p", f"/sdcard/{filename}"])
            self._run_adb(["pull", f"/sdcard/{filename}", str(filepath)])
            self._run_adb(["shell", "rm", f"/sdcard/{filename}"])
            if filepath.exists():
                return str(filepath)
        except Exception:
            pass

        return None

    def _tap_text(self, text: str):
        """Tap element containing text."""
        if self._adbp:
            try:
                el = self._adbp(text=text)
                if el.exists:
                    el.click()
                    return
            except Exception:
                pass

        # Fallback: uiautomator dump + grep + tap via coordinates
        # This is complex without u2; just use input tap with rough coords
        pass

    def _tap_xy(self, x: int, y: int):
        """Tap at coordinates."""
        self._run_adb(["shell", "input", "tap", str(x), str(y)])

    def _input_text(self, text: str):
        """Input text (escapes spaces)."""
        # Escape spaces and special chars
        escaped = text.replace(" ", "%s").replace("'", "\\'").replace('"', '\\"')
        self._run_adb(["shell", "input", "text", escaped])

    def _press_key(self, key: str):
        """Press keyevent by name or code."""
        keycodes = {
            "enter": "66", "back": "4", "home": "3", "menu": "82",
            "del": "67", "tab": "61", "esc": "111",
        }
        code = keycodes.get(key.lower(), key)
        self._run_adb(["shell", "input", "keyevent", code])

    def _launch_app(self, component: str):
        """Launch specific app component via ADB."""
        if component:
            self._run_adb(["shell", "am", "start", "-n", component])

    def _scroll(self, direction: str):
        """Scroll in direction."""
        # u2 handles this better
        if self._adbp:
            try:
                if direction.lower() in ("down", "up"):
                    self._adbp(scrollable=True).scroll(direction.lower())
                return
            except Exception:
                pass

        # Fallback: swipe
        if direction.lower() == "down":
            self._swipe(500, 1500, 500, 500, 500)
        elif direction.lower() == "up":
            self._swipe(500, 500, 500, 1500, 500)

    def _swipe(self, x1: int, y1: int, x2: int, y2: int, duration: int = 300):
        """Swipe from (x1,y1) to (x2,y2)."""
        if self._adbp:
            try:
                self._adbp.swipe(x1, y1, x2, y2, duration / 1000.0)
                return
            except Exception:
                pass
        self._run_adb(["shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration)])

    def _grant_permissions(self, target: str, result: UIRunResult):
        """Grant permissions to the app."""
        # Get package name
        pkg_result = self._run_adb(["shell", "pm", "list", "packages", "-3"])
        packages = []
        for line in pkg_result.stdout.splitlines():
            if line.startswith("package:"):
                packages.append(line.split(":", 1)[1].strip())

        if not packages:
            result.notes.append("No third-party packages found for permission grant")
            return

        # Common dangerous permissions
        dangerous_perms = [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]

        for pkg in packages:
            for perm in dangerous_perms:
                perm_result = self._run_adb(["shell", "pm", "grant", pkg, perm])
                if perm_result.returncode == 0:
                    result.dialogs_auto_accepted += 1

    def _enable_accessibility(self, target: str, result: UIRunResult):
        """Enable accessibility service for the app."""
        # This is complex and varies by Android version
        # For now, note it as attempted
        result.notes.append("Accessibility enable attempted (requires manual setup or u2)")

        if self._adbp:
            try:
                # Try to open accessibility settings
                self._run_adb(["shell", "am", "start", "-n", "com.android.settings/.Settings\\$AccessibilitySettingsActivity"])
                time.sleep(1)
            except Exception:
                pass

    def _simulate_login(self, credentials: str, result: UIRunResult):
        """Simulate login with fake credentials."""
        # Parse credentials: "username:password"
        parts = credentials.split(":", 1)
        username = parts[0] if parts else "fakeuser"
        password = parts[1] if len(parts) > 1 else "Password123!"

        result.notes.append(f"Simulated login with synthetic credentials (username: {username})")

        if self._adbp:
            try:
                # Find EditText fields
                edit_texts = self._adbp(className="android.widget.EditText")
                for i in range(edit_texts.count):
                    el = edit_texts[i]
                    # Check hint or content description for username/password
                    hint = el.get_text() or ""
                    if "user" in hint.lower() or "email" in hint.lower() or "login" in hint.lower():
                        el.set_text(username)
                    elif "pass" in hint.lower():
                        el.set_text(password)

                # Find and click login button
                buttons = self._adbp(className="android.widget.Button")
                for i in range(buttons.count):
                    btn = buttons[i]
                    text = btn.get_text() or ""
                    if any(kw in text.lower() for kw in ["login", "sign in", "enter", "submit", "ok"]):
                        btn.click()
                        break
            except Exception as e:
                result.errors.append(f"Simulate login failed: {e}")

    def observe_current_state(self) -> dict:
        """Observe current UI state: packages, windows, overlays."""
        state = {
            "current_package": None,
            "current_activity": None,
            "windows": [],
            "overlay_detected": False,
        }

        # Get current package/activity
        try:
            result = self._run_adb(["shell", "dumpsys", "activity", "activities"])
            for line in result.stdout.splitlines():
                if "mResumedActivity" in line or "mFocusedActivity" in line:
                    # Parse activity info
                    if "u0 " in line:
                        parts = line.split()
                        for p in parts:
                            if "/" in p and not p.startswith("."):
                                state["current_activity"] = p
                                state["current_package"] = p.split("/")[0]
                                break
        except Exception:
            pass

        # Get window info
        try:
            result = self._run_adb(["shell", "dumpsys", "window", "windows"])
            for line in result.stdout.splitlines():
                if "Window{" in line and "TYPE_APPLICATION_OVERLAY" in line:
                    state["overlay_detected"] = True
                    state["windows"].append(line.strip())
                elif "mCurrentFocus" in line or "mFocusedApp" in line:
                    state["windows"].append(line.strip())
        except Exception:
            pass

        return state


def run_script(device_serial: str, script: list[Step] | None = None,
               time_limit_sec: int = 60,
               action_limit: int = 50,
               artifact_dir: Optional[Path] = None) -> UIRunResult:
    """Convenience function to run UI automation script."""
    automation = UIAutomation(device_serial, artifact_dir)
    return automation.run_script(script, time_limit_sec, action_limit)