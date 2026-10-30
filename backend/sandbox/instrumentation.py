"""Runtime instrumentation via Frida hooks.

Attaches to the target process and injects JavaScript hook scripts for:
  - SMS: SmsManager.send*, incoming SMS interception
  - Accessibility: AccessibilityService event handling (keystroke/overlay abuse)
  - Crypto: Cipher.doFinal (payload decryption -> reveals plaintext IOCs)
  - Dynamic loading: DexClassLoader, reflection, native library loading
  - Anti-analysis: emulator/root/debugger probes
  - Device spoofing: TelephonyManager, Build, sensors (opt-in)

Produces structured HookEvent objects from Frida messages.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from pathlib import Path

try:  # optional
    import frida  # type: ignore
    _HAS_FRIDA = True
except ImportError:  # pragma: no cover
    _HAS_FRIDA = False

from backend.sandbox.frida_scripts import HOOK_SCRIPTS, load_script

logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)

# Hook groups -> the API surfaces they instrument.
HOOK_GROUPS = {
    "sms": ["SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage",
             "SmsMessage.createFromPdu", "BroadcastReceiver.onReceive(SMS_RECEIVED)"],
    "accessibility": ["AccessibilityService.onAccessibilityEvent",
                      "AccessibilityService.onServiceConnected",
                      "ViewGroup.addView(TYPE_APPLICATION_OVERLAY)"],
    "crypto": ["Cipher.doFinal", "Cipher.init", "SecretKeySpec.<init>",
               "MessageDigest.digest", "KeyGenerator.generateKey"],
    "dynamic_loading": ["DexClassLoader.<init>", "Class.forName",
                        "Method.invoke", "System.loadLibrary", "Runtime.load"],
    "anti_analysis": ["Build.getSerial", "Debug.isDebuggerConnected",
                      "Runtime.exec", "File.exists", "SensorManager.getSensorList",
                      "PackageManager.getPackageInfo", "System.getProperty"],
    "device_spoof": ["TelephonyManager.getDeviceId", "TelephonyManager.getImei",
                     "Settings.Secure.getString(android_id)"],
}


@dataclass
class HookEvent:
    """Structured runtime hook event."""
    timestamp: float = 0.0
    group: str = ""
    api: str = ""
    args: dict = field(default_factory=dict)
    stack_hint: str = ""
    package: str = ""
    pid: int = 0
    source: str = "frida"


@dataclass
class InstrumentationSession:
    """Active Frida instrumentation session."""
    device_serial: str
    target_pid: int
    target_package: str
    groups: list[str] = field(default_factory=list)
    active: bool = False
    events: list[HookEvent] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    status: str = "not_started"  # not_started | attaching | active | error | detached

    # Internal state (not serialized)
    _frida_session: object = field(default=None, repr=False, init=False)
    _frida_device: object = field(default=None, repr=False, init=False)


@dataclass
class InstrumentationResult:
    sessions: list[InstrumentationSession] = field(default_factory=list)
    events: list[HookEvent] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    duration_sec: float = 0.0
    frida_available: bool = _HAS_FRIDA


def _connect_frida_device(device_serial: str):
    """Connect to a Frida device, trying ADB forward first for Genymotion VMs.

    Genymotion devices (192.168.x.x:5555) run behind VirtualBox NAT which blocks
    direct IP connections to frida-server. The ADB forward at 127.0.0.1:27042
    (frida-server's default listen port) works reliably.

    Raises the last connection exception if all methods fail.
    """
    is_genymotion = ":" in device_serial and device_serial.startswith(
        ("192.168.", "10.0.", "172.16.")
    )
    last_error: Optional[Exception] = None

    if is_genymotion:
        try:
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            logger.info("Frida connected via ADB forward (127.0.0.1:27042) for %s", device_serial)
            return device
        except Exception as e:
            logger.debug("ADB forward connection failed, trying USB device: %s", e)
            last_error = e

    # Try USB device enumeration (works for ADB-connected devices incl. Genymotion TCP)
    try:
        device = frida.get_usb_device()
        logger.info("Frida connected via USB device enumeration")
        return device
    except Exception as e:
        logger.debug("USB device enumeration failed, trying direct IP: %s", e)
        if last_error is None:
            last_error = e

    # Last resort: direct IP of the device serial
    try:
        device = frida.get_device_manager().add_remote_device(device_serial)
        logger.info("Frida connected via direct IP %s", device_serial)
        return device
    except Exception as e:
        raise last_error or e


def _connect_frida_device(device_serial: str):
    """Connect to frida device, preferring ADB forward (127.0.0.1:27042) for
    Genymotion/TCP devices since VirtualBox NAT blocks direct IP connections."""
    is_genymotion = ":" in device_serial and device_serial.startswith(("192.168.", "10.0.", "172.16."))
    if is_genymotion:
        try:
            return frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        except Exception as e:
            logger.debug("ADB forward connection failed, falling back: %s", e)
    try:
        return frida.get_device_manager().add_remote_device(device_serial)
    except Exception:
        return frida.get_usb_device()


def _make_callback(session: InstrumentationSession, events: list[HookEvent], errors: list[dict]):
    """Create a callback for Frida script messages."""
    def on_message(message: dict, data):
        try:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        payload = {"raw": payload}
                elif isinstance(payload, dict):
                    pass
                else:
                    payload = {"raw": str(payload)}

                event = HookEvent(
                    timestamp=time.time(),
                    group=payload.get("group", "unknown"),
                    api=payload.get("api", "unknown"),
                    args=payload.get("args", {}),
                    stack_hint=payload.get("stack", ""),
                    package=session.target_package,
                    pid=session.target_pid,
                )
                events.append(event)

            elif message.get("type") == "error":
                error_info = {
                    "timestamp": time.time(),
                    "type": "frida_script_error",
                    "description": message.get("description", ""),
                    "stack": message.get("stack", ""),
                    "package": session.target_package,
                    "pid": session.target_pid,
                }
                errors.append(error_info)
                logger.warning("Frida script error: %s", error_info["description"])

        except Exception as e:
            errors.append({
                "timestamp": time.time(),
                "type": "callback_error",
                "description": str(e),
            })
    return on_message


def _connect_frida_device(device_serial: str):
    """Connect to the Frida device given an ADB serial.

    For ADB-connected devices (including Genymotion over TCP, e.g.
    "192.168.192.102:5555"), frida.get_usb_device() tunnels through ADB —
    this works even when the device's IP is unreachable directly due to
    VirtualBox NAT. Direct remote-device connections are tried as fallback.

    Returns (device, connection_method) or raises the last exception.
    """
    last_exc: Exception | None = None

    # 1) ADB tunnel — works for any device visible via `adb devices`
    try:
        mgr = frida.get_device_manager()
        for dev in mgr.enumerate_devices():
            # ADB-connected devices show up as type "usb"
            if dev.type == "usb":
                return dev, "adb_tunnel"
    except Exception as e:
        last_exc = e
        logger.debug("USB/ADB device enumeration failed: %s", e)

    # 2) ADB forward to standard frida port (common in Genymotion setups)
    try:
        device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        device.enumerate_processes()  # verify it's actually alive
        return device, "adb_forward"
    except Exception as e:
        last_exc = e
        logger.debug("127.0.0.1:27042 connection failed: %s", e)

    # 3) Direct remote connection using the serial/IP
    try:
        device = frida.get_device_manager().add_remote_device(device_serial)
        device.enumerate_processes()
        return device, "direct_ip"
    except Exception as e:
        last_exc = e
        logger.debug("Direct connection to %s failed: %s", device_serial, e)

    raise last_exc if last_exc else RuntimeError("No Frida connection method succeeded")


def attach(device_serial: str, pid: int, target_package: str = "",
           groups: list[str] | None = None,
           spoof_config: dict | None = None) -> InstrumentationResult:
    """Attach Frida to the target process and inject hook scripts.

    Args:
        device_serial: ADB device serial (e.g., "192.168.56.101:5555")
        pid: Target process PID
        target_package: Package name of the target app
        groups: Hook groups to enable. Default: all except device_spoof
        spoof_config: Optional device spoof configuration (only used if 'device_spoof' in groups)

    Returns:
        InstrumentationResult containing all captured events and session info.
    """
    if not _HAS_FRIDA:
        return InstrumentationResult(
            errors=[{"type": "frida_unavailable", "description": "Frida Python bindings not installed"}],
            frida_available=False
        )

    if groups is None:
        groups = ["sms", "accessibility", "crypto", "dynamic_loading", "anti_analysis"]

    # Only include device_spoof if spoof_config is provided
    if spoof_config and "device_spoof" not in groups:
        groups.append("device_spoof")

    result = InstrumentationResult(frida_available=True)
    session = InstrumentationSession(
        device_serial=device_serial,
        target_pid=pid,
        target_package=target_package,
        groups=groups,
        status="attaching",
    )

    try:
        # Genymotion VMs (192.168.x.x:5555 etc.) and Android Emulators
        # (emulator-5554) block/deny direct frida connections via the serial —
        # frida-server on the device is reachable through ADB forward at
        # 127.0.0.1:27042 instead.
        is_genymotion = ":" in device_serial and device_serial.startswith(
            ("192.168.", "10.0.", "172.16."))
        is_emulator = device_serial.startswith("emulator-")
        device = None
        if is_genymotion or is_emulator:
            try:
                device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
                session.status = "device_connected"
                logger.info("Frida connected via ADB forward (127.0.0.1:27042)")
            except Exception:
                device = None
                logger.debug("ADB forward failed, falling back to direct IP")

        if device is None:
            try:
                device = frida.get_device_manager().add_remote_device(device_serial)
                session.status = "device_connected"
            except Exception:
                # Try as USB device
                try:
                    device = frida.get_usb_device()
                    session.status = "device_connected"
                except Exception as e:
                    session.status = "error"
                    error_detail = {
                        "type": "frida_device_error",
                        "description": f"Failed to connect to Frida device: {e}",
                        "details": "Ensure frida-server is running on the Android device: "
                                   f"adb -s {device_serial} shell /data/local/tmp/frida-server &"
                    }
                    result.errors.append(error_detail)
                    result.sessions.append(session)
                    return result

        # Attach to process
        try:
            frida_session = device.attach(pid)
            session._frida_device = device
            session._frida_session = frida_session
            session.status = "active"
            session.active = True
        except frida.ProcessNotFoundError:
            session.status = "error"
            result.errors.append({
                "type": "process_not_found",
                "description": f"PID {pid} not found",
            })
            result.sessions.append(session)
            return result
        except Exception as e:
            session.status = "error"
            result.errors.append({
                "type": "frida_attach_error",
                "description": f"Failed to attach to PID {pid}: {e}",
            })
            result.sessions.append(session)
            return result

        # Load and inject scripts
        events: list[HookEvent] = []
        errors: list[dict] = []
        callback = _make_callback(session, events, errors)

        for group in groups:
            try:
                script_source = load_script(group)
                script = frida_session.create_script(script_source)
                script.on("message", callback)
                script.load()

                # If it's the device_spoof script, configure it with spoof_config
                if group == "device_spoof" and spoof_config:
                    try:
                        script.exports_sync.configure(spoof_config)
                    except Exception as e:
                        errors.append({
                            "type": "spoof_config_error",
                            "description": f"Failed to configure spoof script: {e}",
                        })

            except Exception as e:
                errors.append({
                    "type": "script_load_error",
                    "group": group,
                    "description": f"Failed to load {group}.js: {e}",
                })

        session.events = events
        session.errors = errors
        result.sessions.append(session)

    except Exception as e:
        session.status = "error"
        result.errors.append({
            "type": "frida_general_error",
            "description": str(e),
        })
        result.sessions.append(session)

    return result


def detach(result: InstrumentationResult) -> InstrumentationResult:
    """Detach all Frida sessions."""
    for session in result.sessions:
        try:
            if session._frida_session and session.active:
                session._frida_session.detach()
                session.active = False
                session.status = "detached"
        except Exception as e:
            session.errors.append({
                "type": "detach_error",
                "description": str(e),
            })
    return result


def collect_events(result: InstrumentationResult) -> list[HookEvent]:
    """Collect all events from all sessions."""
    all_events = list(result.events)
    for session in result.sessions:
        all_events.extend(session.events)
    return all_events


def wait_for_events(result: InstrumentationResult, timeout_sec: float = 10.0) -> list[HookEvent]:
    """Wait for events to accumulate. Non-blocking — just sleeps and returns collected events.

    The Frida scripts continue running. This provides a observation window.
    """
    import time
    start = time.time()
    while time.time() - start < timeout_sec:
        time.sleep(0.5)

    all_events = collect_events(result)
    result.events = all_events
    result.duration_sec += (time.time() - start)
    return all_events


def _get_frida_device(device_serial: str) -> tuple:
    """Get a Frida device connection, trying ADB forward first for Genymotion.

    Returns (device, connection_method, address).
    Raises Exception if all methods fail.
    """
    errors = []

    # For Genymotion VMs, try ADB forward first (127.0.0.1:27042)
    is_genymotion = ":" in device_serial and device_serial.startswith(("192.168.", "10.0.", "172.16."))

    if is_genymotion:
        try:
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            # Verify it's working by listing processes
            device.enumerate_processes()
            return device, "adb_forward", "127.0.0.1:27042"
        except Exception as e:
            errors.append(f"ADB forward failed: {e}")
            logger.debug("ADB forward connection failed, trying alternatives")

    # Try direct IP connection
    try:
        device = frida.get_device_manager().add_remote_device(device_serial)
        device.enumerate_processes()
        return device, "direct_ip", device_serial
    except Exception as e:
        errors.append(f"Direct IP failed: {e}")

    # Last resort: USB device (may work if ADB sees it as USB)
    try:
        device = frida.get_usb_device()
        device.enumerate_processes()
        return device, "usb", device_serial
    except Exception as e:
        errors.append(f"USB failed: {e}")

    raise ConnectionError(f"All Frida connection methods failed: {'; '.join(errors)}")


def is_frida_available() -> bool:
    """Check if Frida Python bindings are installed."""
    return _HAS_FRIDA


def _connect_frida_device(device_serial: str):
    """Connect to a frida device, trying ADB forward first for Genymotion IPs.

    Genymotion devices (192.168.x.x:5555) need 127.0.0.1:27042 (the ADB forward)
    because VirtualBox NAT blocks direct IP connections to frida-server.

    Returns: frida device object.
    """
    is_genymotion = ":" in device_serial and device_serial.startswith(("192.168.", "10.0.", "172.16."))

    if is_genymotion:
        # Try ADB forward first — frida-server listens on 127.0.0.1:27042 on the device
        try:
            return frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        except Exception:
            pass  # fall through to direct IP attempt

    return frida.get_device_manager().add_remote_device(device_serial)


def _is_genymotion_serial(device_serial: str) -> bool:
    """Check if serial looks like a Genymotion/VM network serial."""
    return ":" in device_serial and device_serial.split(":")[0].startswith(("192.168.", "10.0.", "172.16."))


def _is_emulator_serial(device_serial: str) -> bool:
    """Check if serial looks like an Android Emulator serial (e.g., 'emulator-5554')."""
    return device_serial.startswith("emulator-")


def _connect_frida_device(device_serial: str):
    """Connect to frida device with fallback: ADB forward -> direct IP -> USB.

    Returns tuple of (device, connection_method, details) or raises on total failure.
    """
    is_genymotion = _is_genymotion_serial(device_serial)
    is_emulator = _is_emulator_serial(device_serial)

    if is_genymotion or is_emulator:
        # Try ADB forward first (frida-server typically on 127.0.0.1:27042).
        # Genymotion: VirtualBox NAT blocks direct IP to frida-server.
        # Android Emulator: serial (e.g. emulator-5554) is not a hostname.
        try:
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            # Verify it works by enumerating
            processes = device.enumerate_processes()
            return device, "adb_forward", f"Connected via ADB forward to 127.0.0.1:27042"
        except Exception as e:
            logger.debug("ADB forward failed, trying direct: %s", e)

    # Try direct IP (or original serial for USB)
    try:
        device = frida.get_device_manager().add_remote_device(device_serial)
        processes = device.enumerate_processes()
        return device, "direct_ip", f"Connected directly to {device_serial}"
    except Exception as e:
        direct_err = e
        logger.debug("Direct connection failed: %s", e)

    # Try USB enumeration (for local emulators or USB debugging)
    try:
        usb_device = frida.get_usb_device()
        return usb_device, "usb", "Connected via USB enumeration"
    except Exception as e:
        raise RuntimeError(
            f"Failed to connect to frida-server on {device_serial}. "
            f"Tried ADB forward (127.0.0.1:27042), direct IP, USB. "
            f"Ensure: adb shell /data/local/tmp/frida-server &: {direct_err}"
        )


def check_frida_server(device_serial: str) -> dict:
    """Check if frida-server is running on the device.

    Returns a dict with status and details. Does NOT launch frida-server.

    For Genymotion devices (192.168.x.x:5555), tries ADB forward (127.0.0.1:27042) first
    since VirtualBox NAT blocks direct IP connections to frida-server.
    """
    if not _HAS_FRIDA:
        return {
            "available": False,
            "status": "frida_python_unavailable",
            "details": "Frida Python bindings not installed"
        }

    # For Genymotion VMs and Android Emulators, try ADB forward first
    # (127.0.0.1:27042 is the default frida-server port). Direct connection
    # via serial fails — Genymotion due to VirtualBox NAT, emulator because
    # the serial (e.g. emulator-5554) is not a resolvable hostname.
    is_genymotion = ":" in device_serial and device_serial.startswith(("192.168.", "10.0.", "172.16."))
    is_emulator = device_serial.startswith("emulator-")

    if is_genymotion or is_emulator:
        try:
            # Try ADB forward — frida-server typically listens on 127.0.0.1:27042 on the device
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
            processes = device.enumerate_processes()
            return {
                "available": True,
                "status": "connected",
                "process_count": len(processes),
                "details": f"Connected via ADB forward. {len(processes)} processes visible",
                "connection_method": "adb_forward",
                "address": "127.0.0.1:27042"
            }
        except Exception as e:
            logger.debug("ADB forward connection failed, trying direct IP: %s", e)
            # Fall through to direct IP attempt

    # Try direct IP connection (works for some setups)
    try:
        device = frida.get_device_manager().add_remote_device(device_serial)
        processes = device.enumerate_processes()
        return {
            "available": True,
            "status": "connected",
            "process_count": len(processes),
            "details": f"Connected via direct IP. {len(processes)} processes visible",
            "connection_method": "direct_ip",
            "address": device_serial
        }
    except Exception as e:
        return {
            "available": False,
            "status": "frida_server_unavailable",
            "details": str(e),
            "hint": "Ensure frida-server is running: adb shell /data/local/tmp/frida-server &"
        }