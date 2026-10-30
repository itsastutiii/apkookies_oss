"""Frida JavaScript hook scripts for runtime instrumentation.

These scripts are loaded by instrumentation.py and injected into the target process.
Each script focuses on a specific API surface:

- sms.js: SmsManager, SmsMessage, SMS broadcast receivers
- accessibility.js: AccessibilityService, AccessibilityManager, overlay windows
- crypto.js: Cipher, SecretKeySpec, MessageDigest, KeyGenerator
- dynamic_loading.js: DexClassLoader, PathClassLoader, reflection, native loading
- anti_analysis.js: emulator/debugger/root checks, Build properties, sensor checks
- device_spoof.js: spoofed values for TelephonyManager, Build, Settings, WiFi
"""

from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent

HOOK_SCRIPTS = {
    "sms": "sms.js",
    "accessibility": "accessibility.js",
    "crypto": "crypto.js",
    "dynamic_loading": "dynamic_loading.js",
    "anti_analysis": "anti_analysis.js",
    "device_spoof": "device_spoof.js",
}


def load_script(name: str) -> str:
    """Load a Frida JS script by name. Returns the script source."""
    filename = HOOK_SCRIPTS.get(name)
    if not filename:
        raise ValueError(f"Unknown hook script: {name}. Available: {list(HOOK_SCRIPTS.keys())}")
    path = SCRIPTS_DIR / filename
    return path.read_text(encoding="utf-8")
