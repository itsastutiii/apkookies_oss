"""
Controlled network capture via mitmproxy.

APKookies Android emulator validation environment.

Architecture:

    Android Emulator
          |
          | HTTP proxy
          v
    10.0.2.2:8080
          |
          v
       mitmproxy
          |
          v
      Internet

The implementation supports:

- Android proxy configuration
- Android -> Windows connectivity validation
- mitmproxy startup/shutdown
- HTTP traffic capture
- HTTPS flow metadata capture when the emulator trusts the mitmproxy CA
- indicator persistence
- controlled cleanup
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


logger = logging.getLogger(__name__)


# ================================================================
# ENUMS
# ================================================================

class NetworkMode(str, Enum):
    disabled = "disabled"
    metadata_only = "metadata_only"
    controlled_proxy = "controlled_proxy"


# ================================================================
# DATA CLASSES
# ================================================================

@dataclass
class NetworkIndicator:
    kind: str = ""
    indicator: str = ""
    method: str = ""

    request_summary: str = ""
    response_summary: str = ""

    is_c2: bool = False
    is_exfil: bool = False

    tls_version: str = ""
    tls_cipher: str = ""
    sni: str = ""

    timestamp: float = 0.0
    direction: str = ""

    request_size: int = 0
    response_size: int = 0


@dataclass
class ProxyStatus:
    mode: NetworkMode = NetworkMode.disabled

    proxy_configured: bool = False
    proxy_reachable: bool = False
    traffic_observed: bool = False
    https_intercepted: bool = False

    mitmproxy_running: bool = False
    mitmproxy_port: int = 0

    proxy_host: str = ""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class CaptureResult:
    indicators: list[NetworkIndicator] = field(default_factory=list)
    status: ProxyStatus = field(default_factory=ProxyStatus)
    duration_sec: float = 0.0


# ================================================================
# NETWORK CAPTURE
# ================================================================

class NetworkCapture:
    """Controlled network capture manager."""

    def __init__(
        self,
        device_serial: str,
        proxy_port: int = 8080,
        proxy_host: str = "10.0.2.2",
        artifact_dir: Optional[Path] = None,
    ):

        self.device_serial = device_serial

        self.proxy_port = proxy_port

        # IMPORTANT:
        #
        # This is the address Android uses to reach Windows.
        #
        # For the Android Studio emulator:
        #
        #     10.0.2.2
        #
        self.proxy_host = proxy_host

        self.artifact_dir = (
            artifact_dir
            or Path(".artifacts/network")
        )

        self.artifact_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._mitmproxy_process: Optional[
            subprocess.Popen
        ] = None

        self._mitmproxy_script: Optional[Path] = None

        self._indicators: list[
            NetworkIndicator
        ] = []

        self._status = ProxyStatus()

        self._mode = NetworkMode.disabled


    # ============================================================
    # ADB
    # ============================================================

    def _get_adb_path(self) -> str:
        from backend.sandbox.emulator import resolve_adb_path

        return resolve_adb_path()


    def _run_adb(
        self,
        args: list[str],
        timeout: int = 10,
    ) -> subprocess.CompletedProcess:

        adb_path = self._get_adb_path()

        cmd = [adb_path]

        if self.device_serial:
            cmd += [
                "-s",
                self.device_serial,
            ]

        cmd += args

        logger.debug(
            "Running ADB: %s",
            cmd,
        )

        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )


    # ============================================================
    # MITMDUMP
    # ============================================================

    def _find_mitmdump(self) -> Optional[str]:

        found = shutil.which(
            "mitmdump"
        )

        if found:
            return found

        python_scripts = (
            Path(os.sys.executable).parent
            / "Scripts"
            / "mitmdump.exe"
        )

        if python_scripts.exists():
            return str(
                python_scripts
            )

        return None


    # ============================================================
    # CONNECTIVITY
    # ============================================================

    def _device_can_reach_proxy(
        self,
    ) -> tuple[bool, list[str]]:

        details: list[str] = []

        try:

            result = self._run_adb(
                [
                    "shell",
                    "ping",
                    "-c",
                    "1",
                    "-W",
                    "2",
                    self.proxy_host,
                ],
                timeout=10,
            )

            reachable = (
                result.returncode == 0
            )

            details.append(
                f"Android -> "
                f"{self.proxy_host} ping: "
                f"{reachable}"
            )

            if not reachable:

                stderr = (
                    result.stderr.strip()
                )

                if stderr:
                    details.append(
                        f"Ping error: {stderr}"
                    )

            return reachable, details

        except Exception as exc:

            details.append(
                "Android proxy reachability "
                f"error: {exc}"
            )

            return False, details


    def _device_can_reach_proxy_port(
        self,
    ) -> tuple[bool, list[str]]:

        details: list[str] = []

        try:

            # Android emulator images normally
            # contain nc.

            command = (
                "nc -w 3 "
                f"{self.proxy_host} "
                f"{self.proxy_port} "
                "</dev/null"
            )

            result = self._run_adb(
                [
                    "shell",
                    command,
                ],
                timeout=10,
            )

            reachable = (
                result.returncode == 0
            )

            details.append(
                f"Android -> "
                f"{self.proxy_host}:"
                f"{self.proxy_port} TCP: "
                f"{reachable}"
            )

            if not reachable:

                stderr = (
                    result.stderr.strip()
                )

                if stderr:
                    details.append(
                        f"TCP error: {stderr}"
                    )

            return reachable, details

        except Exception as exc:

            details.append(
                f"Android TCP test error: {exc}"
            )

            return False, details


    def _host_proxy_port_open(
        self,
    ) -> bool:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

            sock.settimeout(2)

            sock.connect(
                (
                    "127.0.0.1",
                    self.proxy_port,
                )
            )

            sock.close()

            return True

        except Exception:

            return False


    def check_connectivity(self) -> dict:

        result = {
            "adb_ok": False,
            "device_reachable": False,
            "host_reachable_from_device": False,
            "proxy_port_open": False,
            "proxy_reachable_from_device": False,
            "details": [],
        }

        # --------------------------------------------------------
        # ADB
        # --------------------------------------------------------

        try:

            adb_result = self._run_adb(
                ["get-state"]
            )

            result["adb_ok"] = (
                adb_result.returncode == 0
            )

            result["device_reachable"] = (
                adb_result.returncode == 0
            )

            result["details"].append(
                "ADB state: "
                + adb_result.stdout.strip()
            )

        except Exception as exc:

            result["details"].append(
                f"ADB error: {exc}"
            )


        # --------------------------------------------------------
        # Android -> Windows
        # --------------------------------------------------------

        reachable, details = (
            self._device_can_reach_proxy()
        )

        result[
            "host_reachable_from_device"
        ] = reachable

        result[
            "details"
        ].extend(details)


        # --------------------------------------------------------
        # Windows listener
        # --------------------------------------------------------

        result[
            "proxy_port_open"
        ] = self._host_proxy_port_open()

        result[
            "details"
        ].append(
            f"Host 127.0.0.1:"
            f"{self.proxy_port} listening: "
            f"{result['proxy_port_open']}"
        )


        # --------------------------------------------------------
        # Android -> proxy TCP
        # --------------------------------------------------------

        if result[
            "proxy_port_open"
        ]:

            reachable, details = (
                self._device_can_reach_proxy_port()
            )

            result[
                "proxy_reachable_from_device"
            ] = reachable

            result[
                "details"
            ].extend(details)

        return result


    # ============================================================
    # DEVICE PROXY
    # ============================================================

    def configure_device_proxy(
        self,
        mode: NetworkMode,
    ) -> bool:

        self._mode = mode

        self._status.mode = mode


        # --------------------------------------------------------
        # Disable proxy
        # --------------------------------------------------------

        if mode == NetworkMode.disabled:

            result = self._run_adb(
                [
                    "shell",
                    "settings",
                    "put",
                    "global",
                    "http_proxy",
                    ":",
                ]
            )

            self._status.proxy_configured = (
                result.returncode == 0
            )

            return (
                self._status.proxy_configured
            )


        # --------------------------------------------------------
        # Controlled proxy
        # --------------------------------------------------------

        proxy_value = (
            f"{self.proxy_host}:"
            f"{self.proxy_port}"
        )

        result = self._run_adb(
            [
                "shell",
                "settings",
                "put",
                "global",
                "http_proxy",
                proxy_value,
            ]
        )

        self._status.proxy_configured = (
            result.returncode == 0
        )

        self._status.proxy_host = (
            proxy_value
        )

        if not self._status.proxy_configured:

            self._status.errors.append(
                "Failed to configure Android "
                "proxy: "
                + result.stderr.strip()
            )

        return (
            self._status.proxy_configured
        )


    # ============================================================
    # MITMPROXY ADDON
    # ============================================================

    def create_mitmproxy_script(
        self,
    ) -> Path:

        script_path = (
            self.artifact_dir
            / "mitm_addon.py"
        )

        script_content = r'''
from mitmproxy import http
from pathlib import Path

import json
import time


class CaptureAddon:

    def __init__(self):

        self.indicators = []

        self.indicator_file = ""


    def load(self, loader):

        loader.add_option(
            name="indicator_file",
            typespec=str,
            default="",
            help="Path to captured network indicators JSON file",
        )


    def configure(self, updated):

        try:

            from mitmproxy import ctx

            self.indicator_file = (
                str(ctx.options.indicator_file)
            )

            print(
                "[APKookies] indicator_file =",
                self.indicator_file,
            )

        except Exception as exc:

            print(
                "[APKookies] configure error:",
                repr(exc),
            )


    def _write_indicators(self):

        try:

            if not self.indicator_file:

                print(
                    "[APKookies] "
                    "indicator_file is empty"
                )

                return


            path = Path(
                self.indicator_file
            )

            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )


            # Write atomically so the Python
            # validator never reads a half-written
            # JSON document.

            temp_path = path.with_suffix(
                ".tmp"
            )


            with temp_path.open(
                "w",
                encoding="utf-8",
            ) as handle:

                json.dump(
                    self.indicators,
                    handle,
                    indent=2,
                )

                handle.flush()


            temp_path.replace(
                path
            )


            print(
                "[APKookies] wrote",
                len(self.indicators),
                "indicators to",
                str(path),
            )


        except Exception as exc:

            # IMPORTANT:
            # Do NOT silently swallow this error.

            print(
                "[APKookies] "
                "WRITE ERROR:",
                repr(exc),
            )


    def request(
        self,
        flow: http.HTTPFlow,
    ):

        try:

            request = flow.request


            scheme = (
                request.scheme
                or ""
            )


            indicator = {

                "kind":
                    "https"
                    if scheme.lower()
                    == "https"
                    else "http",

                "indicator":
                    request.pretty_host
                    or "",

                "method":
                    request.method
                    or "",

                "request_summary":
                    (
                        f"{request.method} "
                        f"{request.path}"
                    ),

                "response_summary":
                    "",

                "is_c2":
                    False,

                "is_exfil":
                    False,

                "tls_version":
                    "",

                "tls_cipher":
                    "",

                "sni":
                    "",

                "timestamp":
                    time.time(),

                "direction":
                    "outbound",

                "request_size":
                    (
                        len(request.content)
                        if request.content
                        else 0
                    ),

                "response_size":
                    0,
            }


            if flow.server_conn:

                try:

                    indicator[
                        "sni"
                    ] = (
                        flow.server_conn.sni
                        or ""
                    )

                except Exception:
                    pass


                try:

                    indicator[
                        "tls_version"
                    ] = (
                        flow.server_conn.tls_version
                        or ""
                    )

                except Exception:
                    pass


                try:

                    indicator[
                        "tls_cipher"
                    ] = (
                        flow.server_conn.cipher_name
                        or ""
                    )

                except Exception:
                    pass


            self.indicators.append(
                indicator
            )


            print(
                "[APKookies] CAPTURED:",
                indicator[
                    "kind"
                ],
                indicator[
                    "method"
                ],
                indicator[
                    "indicator"
                ],
                indicator[
                    "request_summary"
                ],
            )


            self._write_indicators()


        except Exception as exc:

            print(
                "[APKookies] "
                "REQUEST ERROR:",
                repr(exc),
            )


    def response(
        self,
        flow: http.HTTPFlow,
    ):

        try:

            if not self.indicators:

                return


            request_host = (
                flow.request.pretty_host
                if flow.request
                else ""
            )


            # Match the most recent request for
            # this host instead of blindly assuming
            # the last flow belongs to this response.

            indicator = None

            for item in reversed(
                self.indicators
            ):

                if (
                    item.get("indicator")
                    == request_host
                    and not item.get(
                        "response_summary"
                    )
                ):

                    indicator = item

                    break


            if indicator is None:

                indicator = (
                    self.indicators[-1]
                )


            if flow.response:

                indicator[
                    "response_summary"
                ] = (
                    f"HTTP "
                    f"{flow.response.status_code}"
                )


                indicator[
                    "response_size"
                ] = (
                    len(flow.response.content)
                    if flow.response.content
                    else 0
                )


            self._write_indicators()


        except Exception as exc:

            print(
                "[APKookies] "
                "RESPONSE ERROR:",
                repr(exc),
            )


    def error(
        self,
        flow: http.HTTPFlow,
    ):

        try:

            if not self.indicators:

                return


            request_host = (
                flow.request.pretty_host
                if flow.request
                else ""
            )


            indicator = None

            for item in reversed(
                self.indicators
            ):

                if (
                    item.get("indicator")
                    == request_host
                    and not item.get(
                        "response_summary"
                    )
                ):

                    indicator = item

                    break


            if indicator is None:

                indicator = (
                    self.indicators[-1]
                )


            indicator[
                "response_summary"
            ] = "ERROR"


            self._write_indicators()


        except Exception as exc:

            print(
                "[APKookies] "
                "ERROR CALLBACK:",
                repr(exc),
            )


addons = [
    CaptureAddon()
]
'''

        script_path.write_text(
            script_content,
            encoding="utf-8",
        )

        self._mitmproxy_script = (
            script_path
        )

        return script_path


    # ============================================================
    # START MITMPROXY
    # ============================================================

    def start_mitmproxy(
        self,
        mode: NetworkMode = (
            NetworkMode.controlled_proxy
        ),
    ) -> bool:

        if mode != (
            NetworkMode.controlled_proxy
        ):

            self._status.mitmproxy_running = (
                False
            )

            return True


        # --------------------------------------------------------
        # Port already occupied?
        # --------------------------------------------------------

        if self._host_proxy_port_open():

            self._status.errors.append(
                f"Port {self.proxy_port} "
                "is already occupied. "
                "Stop the existing mitmproxy "
                "before starting capture."
            )

            return False


        # --------------------------------------------------------
        # Find mitmdump
        # --------------------------------------------------------

        mitmdump = (
            self._find_mitmdump()
        )

        if not mitmdump:

            self._status.errors.append(
                "mitmdump executable was "
                "not found."
            )

            return False


        # --------------------------------------------------------
        # Create addon
        # --------------------------------------------------------

        script_path = (
            self.create_mitmproxy_script()
        )


        indicator_file = (
            self.artifact_dir
            / "indicators.json"
        )


        # Remove stale indicators

        try:

            if indicator_file.exists():

                indicator_file.unlink()

        except Exception as exc:

            self._status.warnings.append(
                "Could not remove old "
                f"indicator file: {exc}"
            )


        # IMPORTANT:
        #
        # Use an absolute POSIX-style path.
        #
        # This avoids Windows backslash problems
        # inside mitmproxy's option parser.

        indicator_file_arg = (
            indicator_file
            .resolve()
            .as_posix()
        )


        script_path_arg = (
            script_path
            .resolve()
            .as_posix()
        )


        cmd = [

            mitmdump,

            "-s",
            script_path_arg,

            "--set",
            f"indicator_file={indicator_file_arg}",

            "--listen-host",
            "0.0.0.0",

            "--listen-port",
            str(
                self.proxy_port
            ),

            "--set",
            "console_eventlog_verbosity=info",
        ]


        logger.info(
            "Starting mitmdump: %s",
            cmd,
        )


        try:

            self._mitmproxy_process = (
                subprocess.Popen(

                    cmd,

                    stdout=subprocess.PIPE,

                    stderr=subprocess.STDOUT,

                    text=True,

                    encoding="utf-8",

                    errors="replace",
                )
            )

        except Exception as exc:

            self._status.errors.append(
                "Failed to launch mitmdump: "
                f"{exc}"
            )

            return False


        # --------------------------------------------------------
        # Wait for listener
        # --------------------------------------------------------

        deadline = (
            time.time() + 8
        )


        while time.time() < deadline:

            if (
                self._mitmproxy_process.poll()
                is not None
            ):

                output = ""

                try:

                    if (
                        self._mitmproxy_process
                        .stdout
                    ):

                        output = (
                            self._mitmproxy_process
                            .stdout
                            .read()
                        )

                except Exception:
                    pass


                self._status.errors.append(
                    "mitmproxy failed to start."
                )


                if output.strip():

                    self._status.errors.append(
                        output.strip()
                    )


                self._mitmproxy_process = None

                return False


            if self._host_proxy_port_open():

                self._status.mitmproxy_running = (
                    True
                )

                self._status.mitmproxy_port = (
                    self.proxy_port
                )

                logger.info(
                    "mitmproxy listening on %s",
                    self.proxy_port,
                )

                return True


            time.sleep(
                0.25
            )


        self._status.errors.append(
            "mitmproxy process started but "
            f"port {self.proxy_port} did "
            "not become available."
        )

        return False


    # ============================================================
    # STOP MITMPROXY
    # ============================================================

    def stop_mitmproxy(self):

        if not self._mitmproxy_process:

            return


        try:

            self._mitmproxy_process.terminate()

            self._mitmproxy_process.wait(
                timeout=5
            )


        except subprocess.TimeoutExpired:

            try:

                self._mitmproxy_process.kill()

            except Exception:
                pass


        except Exception:
            pass


        finally:

            self._mitmproxy_process = None

            self._status.mitmproxy_running = (
                False
            )

            self._status.mitmproxy_port = 0


    # ============================================================
    # VERIFY PROXY
    # ============================================================

    def verify_proxy(
        self,
    ) -> ProxyStatus:

        self._status.proxy_reachable = (
            False
        )

        self._status.traffic_observed = (
            False
        )

        self._status.https_intercepted = (
            False
        )


        if self._mode == (
            NetworkMode.disabled
        ):

            return self._status


        if not self._status.proxy_configured:

            self._status.errors.append(
                "Proxy not configured "
                "on Android."
            )

            return self._status


        connectivity = (
            self.check_connectivity()
        )


        self._status.proxy_reachable = (
            connectivity.get(
                "proxy_reachable_from_device",
                False,
            )
        )


        if not self._status.proxy_reachable:

            self._status.errors.append(
                "Android device cannot reach "
                f"{self.proxy_host}:"
                f"{self.proxy_port}"
            )

            return self._status


        # --------------------------------------------------------
        # Read indicator file
        # --------------------------------------------------------

        indicator_file = (
            self.artifact_dir
            / "indicators.json"
        )


        if indicator_file.exists():

            try:

                with indicator_file.open(
                    "r",
                    encoding="utf-8",
                ) as handle:

                    data = json.load(
                        handle
                    )


                if isinstance(
                    data,
                    list,
                ):

                    self._status.traffic_observed = (
                        len(data) > 0
                    )

                    self._status.https_intercepted = (
                        any(
                            item.get(
                                "kind"
                            )
                            == "https"
                            for item in data
                        )
                    )


            except Exception as exc:

                self._status.errors.append(
                    "Could not read indicator "
                    f"file: {exc}"
                )


        return self._status


    # ============================================================
    # COLLECT INDICATORS
    # ============================================================

    def collect_indicators(
        self,
    ) -> list[NetworkIndicator]:

        indicators: list[
            NetworkIndicator
        ] = []


        # --------------------------------------------------------
        # In-memory indicators
        # --------------------------------------------------------

        indicators.extend(
            self._indicators
        )


        # --------------------------------------------------------
        # File indicators
        # --------------------------------------------------------

        indicator_file = (
            self.artifact_dir
            / "indicators.json"
        )


        if indicator_file.exists():

            try:

                with indicator_file.open(
                    "r",
                    encoding="utf-8",
                ) as handle:

                    data = json.load(
                        handle
                    )


                if isinstance(
                    data,
                    list,
                ):

                    for item in data:

                        try:

                            indicators.append(
                                NetworkIndicator(
                                    **item
                                )
                            )

                        except TypeError as exc:

                            logger.warning(
                                "Invalid indicator: "
                                "%s",
                                exc,
                            )


            except Exception as exc:

                logger.warning(
                    "Could not load indicators: "
                    "%s",
                    exc,
                )


        # --------------------------------------------------------
        # Remove duplicates
        # --------------------------------------------------------

        unique = []

        seen = set()


        for indicator in indicators:

            key = (
                indicator.timestamp,
                indicator.indicator,
                indicator.method,
                indicator.request_summary,
            )


            if key in seen:
                continue


            seen.add(key)

            unique.append(
                indicator
            )


        self._indicators = unique

        return unique


    # ============================================================
    # STATUS
    # ============================================================

    def get_status(
        self,
    ) -> ProxyStatus:

        return self._status


    # ============================================================
    # CLEANUP
    # ============================================================

    def cleanup(self):

        # Clear Android proxy

        try:

            self._run_adb(
                [
                    "shell",
                    "settings",
                    "put",
                    "global",
                    "http_proxy",
                    ":",
                ]
            )

        except Exception:
            pass


        # Stop mitmproxy

        self.stop_mitmproxy()


        self._status = ProxyStatus()


# ================================================================
# REPLAY PROXY
# ================================================================

class ReplayProxy:

    """
    mitmproxy addon for controlled response replay.
    """

    def __init__(
        self,
        replay_map: Optional[
            dict[str, bytes]
        ] = None,
    ):

        self.replay_map = (
            replay_map or {}
        )

        self.indicators = []


    def request(self, flow):

        indicator = NetworkIndicator(

            kind=(
                "https"
                if flow.request.scheme
                == "https"
                else "http"
            ),

            indicator=(
                flow.request.pretty_host
            ),

            method=(
                flow.request.method
            ),

            request_summary=(
                f"{flow.request.method} "
                f"{flow.request.path}"
            ),

            timestamp=time.time(),

            direction="outbound",

            request_size=(
                len(flow.request.content)
                if flow.request.content
                else 0
            ),
        )


        host = (
            flow.request.pretty_host
        )


        if host in self.replay_map:

            from mitmproxy import http

            flow.response = (
                http.Response.make(
                    200,
                    self.replay_map[host],
                    {
                        "Content-Type":
                            "application/octet-stream"
                    },
                )
            )

            indicator.is_c2 = True


        self.indicators.append(
            indicator
        )


    def response(self, flow):

        if not self.indicators:

            return


        indicator = (
            self.indicators[-1]
        )


        if flow.response:

            indicator.response_summary = (
                f"HTTP "
                f"{flow.response.status_code}"
            )

            indicator.response_size = (
                len(flow.response.content)
                if flow.response.content
                else 0
            )


# ================================================================
# CONVENIENCE FUNCTIONS
# ================================================================

def start_capture(
    device_serial: str,
    proxy_port: int = 8080,
    mode: NetworkMode = (
        NetworkMode.controlled_proxy
    ),
    artifact_dir: Optional[Path] = None,
    proxy_host: str = "10.0.2.2",
) -> NetworkCapture:

    capture = NetworkCapture(

        device_serial=device_serial,

        proxy_port=proxy_port,

        proxy_host=proxy_host,

        artifact_dir=artifact_dir,
    )


    if not capture.configure_device_proxy(
        mode
    ):

        return capture


    if mode == (
        NetworkMode.controlled_proxy
    ):

        capture.start_mitmproxy(
            mode
        )


    return capture


def stop_capture(
    capture: NetworkCapture,
) -> CaptureResult:

    indicators = (
        capture.collect_indicators()
    )


    status = (
        capture.verify_proxy()
    )


    result = CaptureResult(

        indicators=indicators,

        status=status,
    )


    capture.cleanup()


    return result