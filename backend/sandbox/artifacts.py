"""Artifact collection + indexing for sandbox runs.

Collects logs, screenshots, UI XML, Frida events, network artifacts,
device profile, command outcomes, runtime errors, package/process metadata.

Each artifact has:
- timestamp
- provenance
- type
- reference/path
- relevant session/run ID

Preserves partial evidence if later analysis fails.
Sanitizes sensitive values before persistence.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Any

try:
    from config.settings import get_settings
except ImportError:
    def get_settings():
        class _S:
            artifact_store_path = Path("./.artifacts")
        return _S()

logger = logging.getLogger(__name__)


@dataclass
class Artifact:
    """Single collected artifact."""
    run_id: str
    artifact_type: str  # logcat, screenshot, ui_dump, frida_event, network, device_profile, command, error, package_info
    provenance: str     # adb, frida, mitmproxy, host, analysis
    path: str           # relative to run_dir
    timestamp: float = field(default_factory=time.time)
    size_bytes: int = 0
    metadata: dict = field(default_factory=dict)  # type-specific extra info
    sanitized: bool = True


@dataclass
class RunArtifacts:
    """Collection of all artifacts for a single sandbox run."""
    run_id: str
    artifacts: list[Artifact] = field(default_factory=list)
    logcat_ref: Optional[str] = None
    pcap_ref: Optional[str] = None
    screenshots: list[str] = field(default_factory=list)
    ui_dumps: list[str] = field(default_factory=list)
    frida_events: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)
    device_profile_ref: Optional[str] = None
    command_log_ref: Optional[str] = None
    error_log_ref: Optional[str] = None
    package_info_ref: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

    def add_artifact(self, artifact: Artifact):
        self.artifacts.append(artifact)
        # Update convenience lists
        if artifact.artifact_type == "logcat":
            self.logcat_ref = artifact.path
        elif artifact.artifact_type == "pcap":
            self.pcap_ref = artifact.path
        elif artifact.artifact_type == "screenshot":
            self.screenshots.append(artifact.path)
        elif artifact.artifact_type == "ui_dump":
            self.ui_dumps.append(artifact.path)
        elif artifact.artifact_type == "frida_event":
            self.frida_events.append(artifact.path)
        elif artifact.artifact_type == "network":
            self.network_indicators.append(artifact.path)
        elif artifact.artifact_type == "device_profile":
            self.device_profile_ref = artifact.path
        elif artifact.artifact_type == "command":
            self.command_log_ref = artifact.path
        elif artifact.artifact_type == "error":
            self.error_log_ref = artifact.path
        elif artifact.artifact_type == "package_info":
            self.package_info_ref = artifact.path

    def finalize(self):
        self.end_time = time.time()


def run_dir(run_id: str) -> Path:
    """Get the artifact directory for a run."""
    root = get_settings().artifact_store_path / "sandbox" / run_id
    root.mkdir(parents=True, exist_ok=True)
    return root


class ArtifactCollector:
    """Collects and indexes artifacts during a sandbox run."""

    def __init__(self, run_id: str, device_serial: str):
        self.run_id = run_id
        self.device_serial = device_serial
        self.run_dir = run_dir(run_id)
        self.artifacts = RunArtifacts(run_id=run_id)
        self._command_log: list[dict] = []
        self._error_log: list[dict] = []

    def _run_adb(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run adb command."""
        from backend.sandbox.emulator import resolve_adb_path

        cmd = [resolve_adb_path()]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += args
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")

    def _write_artifact(self, artifact_type: str, provenance: str,
                        content: str | bytes, filename: str,
                        metadata: dict | None = None) -> Artifact:
        """Write artifact content to file and create Artifact record."""
        filepath = self.run_dir / filename
        if isinstance(content, str):
            filepath.write_text(content, encoding="utf-8")
            size = len(content.encode("utf-8"))
        else:
            filepath.write_bytes(content)
            size = len(content)

        artifact = Artifact(
            run_id=self.run_id,
            artifact_type=artifact_type,
            provenance=provenance,
            path=str(filepath.relative_to(self.run_dir.parent.parent)),  # relative to artifact store root
            size_bytes=size,
            metadata=metadata or {},
        )
        self.artifacts.add_artifact(artifact)
        return artifact

    def _sanitize_content(self, content: str) -> str:
        """Sanitize sensitive data from content before persistence."""
        import re

        # Patterns to redact
        patterns = [
            # Authorization headers
            (r'(Authorization:\s*)([^\r\n]+)', r'\1[REDACTED]'),
            (r'(Bearer\s+)([A-Za-z0-9\-_\.]+)', r'\1[REDACTED]'),
            # Passwords in URLs
            (r'(password[=:]\s*)([^\s&]+)', r'\1[REDACTED]'),
            (r'(pwd[=:]\s*)([^\s&]+)', r'\1[REDACTED]'),
            # OTPs (6-digit codes)
            (r'(otp|one.?time|code|verification)[\s:=]+(\d{4,8})', r'\1=[REDACTED]'),
            # Session cookies
            (r'(sessionid|session_id|PHPSESSID|JSESSIONID)[=:]\s*([^\s;]+)', r'\1=[REDACTED]'),
            # Access tokens (long alphanumeric strings)
            (r'(access.?token|token)[=:]\s*([A-Za-z0-9\-_\.]{20,})', r'\1=[REDACTED]'),
            # Private keys
            (r'(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----)', '[REDACTED PRIVATE KEY]'),
            # Credit card numbers
            (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '[REDACTED CARD]'),
            # Social security numbers
            (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED SSN]'),
        ]

        sanitized = content
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def collect_logcat(self, duration_sec: int = 10) -> Optional[Artifact]:
        """Collect logcat from device."""
        try:
            # Use -d to dump and exit, limit to recent entries
            result = self._run_adb(["logcat", "-d", "-t", "5000"], timeout=duration_sec + 5)
            if result.returncode != 0:
                self.log_error("logcat", f"logcat failed: {result.stderr}")
                return None

            sanitized = self._sanitize_content(result.stdout)
            return self._write_artifact(
                "logcat", "adb", sanitized,
                f"logcat_{self.run_id}.txt",
                {"duration_sec": duration_sec, "line_count": len(sanitized.splitlines())}
            )
        except Exception as e:
            self.log_error("logcat", str(e))
            return None

    def collect_screenshot(self, name: str = "screenshot") -> Optional[Artifact]:
        """Take and collect screenshot."""
        try:
            filename = f"{name}_{uuid.uuid4().hex[:8]}.png"
            remote_path = f"/sdcard/{filename}"
            local_path = self.run_dir / filename

            # Take screenshot
            result = self._run_adb(["shell", "screencap", "-p", remote_path])
            if result.returncode != 0:
                self.log_error("screenshot", f"screencap failed: {result.stderr}")
                return None

            # Pull it
            pull_result = self._run_adb(["pull", remote_path, str(local_path)])
            if pull_result.returncode != 0:
                self.log_error("screenshot", f"pull failed: {pull_result.stderr}")
                return None

            # Clean up remote
            self._run_adb(["shell", "rm", remote_path])

            return self._write_artifact(
                "screenshot", "adb", b"",  # Binary handled by pull
                filename,
                {"source": "screencap", "local_path": str(local_path)}
            )
        except Exception as e:
            self.log_error("screenshot", str(e))
            return None

    def collect_ui_dump(self, name: str = "ui_dump") -> Optional[Artifact]:
        """Collect UI hierarchy dump."""
        try:
            filename = f"{name}_{uuid.uuid4().hex[:8]}.xml"
            remote_path = f"/sdcard/{filename}"
            local_path = self.run_dir / filename

            # Dump UI
            result = self._run_adb(["shell", "uiautomator", "dump", remote_path])
            if result.returncode != 0:
                self.log_error("ui_dump", f"uiautomator dump failed: {result.stderr}")
                return None

            # Pull it
            pull_result = self._run_adb(["pull", remote_path, str(local_path)])
            if pull_result.returncode != 0:
                self.log_error("ui_dump", f"pull failed: {pull_result.stderr}")
                return None

            # Clean up remote
            self._run_adb(["shell", "rm", remote_path])

            # Read and sanitize content
            content = local_path.read_text(encoding="utf-8")
            sanitized = self._sanitize_content(content)
            local_path.write_text(sanitized, encoding="utf-8")

            return self._write_artifact(
                "ui_dump", "adb", sanitized,
                filename,
                {"source": "uiautomator", "local_path": str(local_path)}
            )
        except Exception as e:
            self.log_error("ui_dump", str(e))
            return None

    def collect_frida_events(self, events: list[Any]) -> Optional[Artifact]:
        """Save Frida hook events as JSON."""
        try:
            filename = f"frida_events_{self.run_id}.json"
            local_path = self.run_dir / filename

            # Convert events to serializable format
            event_data = []
            for event in events:
                if hasattr(event, '__dataclass_fields__'):
                    event_data.append(asdict(event))
                elif isinstance(event, dict):
                    event_data.append(event)
                else:
                    event_data.append(str(event))

            content = json.dumps(event_data, indent=2)
            sanitized = self._sanitize_content(content)
            local_path.write_text(sanitized, encoding="utf-8")

            return self._write_artifact(
                "frida_event", "frida", sanitized,
                filename,
                {"event_count": len(event_data)}
            )
        except Exception as e:
            self.log_error("frida_event", str(e))
            return None

    def collect_network_indicators(self, indicators: list[Any]) -> Optional[Artifact]:
        """Save network indicators as JSON."""
        try:
            filename = f"network_indicators_{self.run_id}.json"
            local_path = self.run_dir / filename

            indicator_data = []
            for ind in indicators:
                if hasattr(ind, '__dataclass_fields__'):
                    indicator_data.append(asdict(ind))
                elif isinstance(ind, dict):
                    indicator_data.append(ind)
                else:
                    indicator_data.append(str(ind))

            content = json.dumps(indicator_data, indent=2)
            return self._write_artifact(
                "network", "mitmproxy", content,
                filename,
                {"indicator_count": len(indicator_data)}
            )
        except Exception as e:
            self.log_error("network", str(e))
            return None

    def collect_device_profile(self, profile: Any) -> Optional[Artifact]:
        """Save device profile."""
        try:
            filename = f"device_profile_{self.run_id}.json"
            local_path = self.run_dir / filename

            if hasattr(profile, '__dataclass_fields__'):
                data = asdict(profile)
            elif isinstance(profile, dict):
                data = profile
            else:
                data = {"raw": str(profile)}

            content = json.dumps(data, indent=2)
            sanitized = self._sanitize_content(content)
            local_path.write_text(sanitized, encoding="utf-8")

            return self._write_artifact(
                "device_profile", "adb", sanitized,
                filename,
                {}
            )
        except Exception as e:
            self.log_error("device_profile", str(e))
            return None

    def collect_package_info(self, package_name: str) -> Optional[Artifact]:
        """Collect detailed package information."""
        try:
            filename = f"package_info_{self.run_id}.json"
            local_path = self.run_dir / filename

            # Get package info
            info = {"package_name": package_name}

            # Version info
            result = self._run_adb(["shell", "dumpsys", "package", package_name])
            if result.returncode == 0:
                info["dumpsys"] = result.stdout[:10000]  # Limit size

            # Permissions
            perm_result = self._run_adb(["shell", "pm", "list", "permissions", "-g", "-d"])
            if perm_result.returncode == 0:
                info["permissions"] = perm_result.stdout[:5000]

            content = json.dumps(info, indent=2)
            sanitized = self._sanitize_content(content)
            local_path.write_text(sanitized, encoding="utf-8")

            return self._write_artifact(
                "package_info", "adb", sanitized,
                filename,
                {"package": package_name}
            )
        except Exception as e:
            self.log_error("package_info", str(e))
            return None

    def log_command(self, command: list[str], result: subprocess.CompletedProcess,
                    operation: str = "command"):
        """Log a command execution."""
        entry = {
            "timestamp": time.time(),
            "operation": operation,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout[:2000] if result.stdout else "",
            "stderr": result.stderr[:2000] if result.stderr else "",
            "success": result.returncode == 0,
        }
        self._command_log.append(entry)

    def log_error(self, operation: str, error: str):
        """Log an error."""
        entry = {
            "timestamp": time.time(),
            "operation": operation,
            "error": error,
        }
        self._error_log.append(entry)

    def save_command_log(self) -> Optional[Artifact]:
        """Save command log as artifact."""
        try:
            filename = f"command_log_{self.run_id}.json"
            local_path = self.run_dir / filename
            content = json.dumps(self._command_log, indent=2)
            sanitized = self._sanitize_content(content)
            local_path.write_text(sanitized, encoding="utf-8")

            return self._write_artifact(
                "command", "host", sanitized,
                filename,
                {"command_count": len(self._command_log)}
            )
        except Exception as e:
            self.log_error("command_log", str(e))
            return None

    def save_error_log(self) -> Optional[Artifact]:
        """Save error log as artifact."""
        try:
            filename = f"error_log_{self.run_id}.json"
            local_path = self.run_dir / filename
            content = json.dumps(self._error_log, indent=2)
            local_path.write_text(content, encoding="utf-8")

            return self._write_artifact(
                "error", "host", content,
                filename,
                {"error_count": len(self._error_log)}
            )
        except Exception as e:
            self.log_error("error_log", str(e))
            return None

    def finalize(self) -> RunArtifacts:
        """Finalize collection, save logs, return RunArtifacts."""
        self.artifacts.finalize()
        self.save_command_log()
        self.save_error_log()
        return self.artifacts

    def get_manifest(self) -> dict:
        """Get artifact manifest for reporting."""
        return {
            "run_id": self.run_id,
            "artifacts": [
                {
                    "type": a.artifact_type,
                    "provenance": a.provenance,
                    "path": a.path,
                    "timestamp": a.timestamp,
                    "size_bytes": a.size_bytes,
                    "metadata": a.metadata,
                }
                for a in self.artifacts.artifacts
            ],
            "summary": {
                "total_artifacts": len(self.artifacts.artifacts),
                "logcat": self.artifacts.logcat_ref is not None,
                "screenshots": len(self.artifacts.screenshots),
                "ui_dumps": len(self.artifacts.ui_dumps),
                "frida_events": len(self.artifacts.frida_events),
                "network_indicators": len(self.artifacts.network_indicators),
                "errors": len(self._error_log),
            }
        }


def collect(device_serial: str, run_id: str) -> RunArtifacts:
    """Legacy function for compatibility. Creates collector but doesn't collect automatically."""
    collector = ArtifactCollector(run_id, device_serial)
    return collector.finalize()


def wipe(run_id: str) -> None:
    """Delete all raw artifacts for a run (ephemeral-storage policy)."""
    d = get_settings().artifact_store_path / "sandbox" / run_id
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
        logger.info(f"Wiped artifacts for run {run_id}")