"""Device fingerprint profiling and optional spoofing — observe and optionally modify device identity.

IMPORTANT: Default behavior is OBSERVATION/PROFILING only.
Spoofing is explicitly opt-in, reversible, and verified after activation.
Never claim spoofing worked unless actually verified.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from config.settings import get_settings
except ImportError:
    def get_settings():
        class _S:
            artifact_store_path = Path("./.artifacts")
        return _S()

from backend.sandbox.emulator import LocalAdbHost, SandboxSession, CommandResult


@dataclass
class DeviceProfile:
    """Observable device properties."""
    manufacturer: str = "unknown"
    model: str = "unknown"
    brand: str = "unknown"
    fingerprint: str = "unknown"
    android_version: str = "unknown"
    api_level: str = "unknown"
    abi: str = "unknown"
    hardware: str = "unknown"
    build_tags: str = "unknown"
    build_type: str = "unknown"
    kernel_qemu: str = "unknown"
    is_emulator: bool = True
    emulator_indicators: list[str] = field(default_factory=list)
    props: dict[str, str] = field(default_factory=dict)

    # Spoofing-related (only populated if spoofing attempted)
    spoof_attempted: bool = False
    spoof_verified: bool = False
    spoof_changes: dict[str, str] = field(default_factory=dict)
    spoof_failures: dict[str, str] = field(default_factory=dict)


@dataclass
class SpoofConfig:
    """Configuration for spoofing (opt-in only)."""
    enabled: bool = False
    target_manufacturer: Optional[str] = None
    target_model: Optional[str] = None
    target_brand: Optional[str] = None
    target_fingerprint: Optional[str] = None
    # Runtime spoofing via Frida (IMEI, sensors, etc.) - handled in instrumentation.py
    spoof_runtime: bool = False


# Minimal catalog of real device profiles for reference
_DEVICE_CATALOG = [
    {
        "manufacturer": "Google",
        "model": "Pixel 7",
        "brand": "google",
        "fingerprint": "google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys",
        "api_level": "33",
    },
    {
        "manufacturer": "Samsung",
        "model": "SM-G991B",
        "brand": "samsung",
        "fingerprint": "samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXU5DVK1:user/release-keys",
        "api_level": "33",
    },
    {
        "manufacturer": "Xiaomi",
        "model": "M2101K6G",
        "brand": "Xiaomi",
        "fingerprint": "Xiaomi/sweet/sweet:13/RKQ1.211001.001/V14.0.1.0:user/release-keys",
        "api_level": "33",
    },
]


def collect_device_profile(host: LocalAdbHost, session: SandboxSession) -> DeviceProfile:
    """Collect observable device properties via ADB getprop."""
    from backend.sandbox.emulator import DEVICE_PROPS, collect_device_profile as _collect

    raw_props = _collect(host, session)

    # Parse key properties
    profile = DeviceProfile(props=raw_props)
    profile.manufacturer = raw_props.get("ro.product.manufacturer", "unknown")
    profile.model = raw_props.get("ro.product.model", "unknown")
    profile.brand = raw_props.get("ro.product.brand", "unknown")
    profile.fingerprint = raw_props.get("ro.build.fingerprint", "unknown")
    profile.android_version = raw_props.get("ro.build.version.release", "unknown")
    profile.api_level = raw_props.get("ro.build.version.sdk", "unknown")
    profile.abi = raw_props.get("ro.product.cpu.abi", "unknown")
    profile.hardware = raw_props.get("ro.hardware", "unknown")
    profile.build_tags = raw_props.get("ro.build.tags", "unknown")
    profile.build_type = raw_props.get("ro.build.type", "unknown")
    profile.kernel_qemu = raw_props.get("ro.kernel.qemu", "unknown")

    # Detect emulator indicators
    indicators = []
    if profile.kernel_qemu == "1":
        indicators.append("ro.kernel.qemu=1")
    if "test-keys" in profile.build_tags:
        indicators.append("test-keys in build tags")
    if "generic" in profile.model.lower() or "sdk" in profile.model.lower():
        indicators.append("generic/sdk model name")
    if "goldfish" in profile.hardware.lower() or "ranchu" in profile.hardware.lower():
        indicators.append("emulator hardware (goldfish/ranchu)")
    if "vbox" in profile.fingerprint.lower() or "genymotion" in profile.fingerprint.lower():
        indicators.append("Genymotion/VirtualBox fingerprint")

    profile.emulator_indicators = indicators
    profile.is_emulator = len(indicators) > 0

    return profile


def verify_profile(host: LocalAdbHost, session: SandboxSession, expected: dict[str, str]) -> dict[str, bool]:
    """Verify that device properties match expected values (for spoofing verification)."""
    results = {}
    for prop, expected_value in expected.items():
        result = host.get_prop(session, prop)
        if result.success:
            actual = result.stdout.strip()
            results[prop] = (actual == expected_value)
        else:
            results[prop] = False
    return results


def apply_spoof_props(host: LocalAdbHost, session: SandboxSession, config: SpoofConfig) -> DeviceProfile:
    """Apply spoofed properties via system prop overrides (requires root).

    This is BEST-EFFORT and requires:
    - Root access on the device
    - writable /system or /vendor partition (typically not available on production builds)
    - Magisk or similar for persistent prop overrides

    Returns a DeviceProfile with spoof_attempted=True and spoof_verified indicating success.
    """
    if not config.enabled:
        return collect_device_profile(host, session)

    profile = collect_device_profile(host, session)
    profile.spoof_attempted = True

    # Target properties to spoof
    spoof_map = {}
    if config.target_manufacturer:
        spoof_map["ro.product.manufacturer"] = config.target_manufacturer
    if config.target_model:
        spoof_map["ro.product.model"] = config.target_model
    if config.target_brand:
        spoof_map["ro.product.brand"] = config.target_brand
    if config.target_fingerprint:
        spoof_map["ro.build.fingerprint"] = config.target_fingerprint

    # Neutralize common emulator tells
    spoof_map["ro.kernel.qemu"] = "0"
    spoof_map["ro.build.tags"] = "release-keys"
    spoof_map["ro.hardware"] = "qcom"

    # Attempt to set props via `setprop` (requires root, typically only works until reboot)
    # Note: On production Android, setprop is restricted. This usually requires:
    # - adb root
    # - Magisk resetprop
    # - Or modifying build.prop (persistent, requires remount)

    for prop, value in spoof_map.items():
        # Try setprop first (temporary, needs root)
        result = host._run_adb(["shell", "setprop", prop, value], serial=session.device_serial)
        if result.success:
            profile.spoof_changes[prop] = value
        else:
            profile.spoof_failures[prop] = result.error or "setprop failed"

    # Verify after attempting
    verification = verify_profile(host, session, spoof_map)
    profile.spoof_verified = all(verification.values())

    return profile


def build_profile(seed: str | None = None) -> dict:
    """Build a believable randomized-but-consistent profile for reference/spoofing targets.

    This does NOT apply anything - just generates a target profile.
    Use apply_spoof_props() with SpoofConfig to attempt actual spoofing.
    """
    rng = random.Random(seed)
    device = rng.choice(_DEVICE_CATALOG)

    return {
        "manufacturer": device["manufacturer"],
        "model": device["model"],
        "brand": device["brand"],
        "fingerprint": device["fingerprint"],
        "api_level": device["api_level"],
        # Neutralize common emulator tells
        "ro.kernel.qemu": "0",
        "ro.build.tags": "release-keys",
        "ro.hardware": "qcom",
    }


def get_spoof_props_for_frida(profile: dict) -> dict[str, str]:
    """Extract spoof properties for Frida runtime hooking (IMEI, sensors, etc.).

    These are values that CANNOT be set via system props and require Frida hooks.
    """
    return {
        "imei": _fake_imei(),
        "android_id": "".join(random.Random(profile.get("fingerprint", "")).choice("0123456789abcdef") for _ in range(16)),
        "sim_serial": _fake_icc_id(),
        "phone_number": _fake_phone_number(),
    }


def _fake_imei() -> str:
    # Generate a valid-looking IMEI (15 digits with Luhn check)
    # Not cryptographically valid, just format-correct
    imei = [random.randint(0, 9) for _ in range(14)]
    # Calculate Luhn check digit
    total = 0
    for i, digit in enumerate(imei):
        if i % 2 == 0:
            d = digit * 2
            total += d if d < 10 else d - 9
        else:
            total += digit
    check = (10 - (total % 10)) % 10
    imei.append(check)
    return "".join(str(d) for d in imei)


def _fake_icc_id() -> str:
    # ICCID: 19-20 digits
    return "".join(str(random.randint(0, 9)) for _ in range(20))


def _fake_phone_number() -> str:
    return f"+1555{random.randint(100, 999)}{random.randint(1000, 9999)}"