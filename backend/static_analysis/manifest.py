"""Manifest & permission extraction — the input to context-aware risk scoring.

Build-first module. Uses androguard when installed (real binary-XML parsing of
AndroidManifest.xml); otherwise falls back to a best-effort raw scan so the
pipeline still yields *something* in a bare environment.

The scoring stack (knowledge graph + R-GCN + Bayesian) consumes `ManifestFacts`.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:  # optional
    from androguard.core.apk import APK as _APK  # type: ignore
    from androguard.core.axml import AXMLPrinter as _AXMLPrinter  # type: ignore
except ImportError:  # pragma: no cover
    _APK = None
    _AXMLPrinter = None

BIND_ACCESSIBILITY_SERVICE = "android.permission.BIND_ACCESSIBILITY_SERVICE"
# Bounds the resource scan for accessibility-service configs on huge apps.
_MAX_RES_XML_FILES = 3000

# AndroidManifest.xml attributes live in the "android:" namespace once
# androguard decodes the binary AXML back into an element tree.
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Tag name -> Component.kind. activity-alias is folded into "activity" since
# it behaves like one from an exported-surface / intent-filter standpoint.
_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


@dataclass
class Component:
    name: str
    kind: str  # activity | service | receiver | provider
    exported: Optional[bool] = None
    intent_filters: list[str] = field(default_factory=list)
    permission: Optional[str] = None
    process: Optional[str] = None
    enabled: Optional[bool] = None


@dataclass
class ManifestFacts:
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: list[str] = field(default_factory=list)
    custom_permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    uses_features: list[str] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)
    allow_backup: Optional[bool] = None
    debuggable: Optional[bool] = None
    network_security_config: Optional[str] = None
    # App category is required for context-aware scoring. Often unknown from the
    # manifest alone -> may be inferred later (Play metadata / classifier).
    declared_category: Optional[str] = None
    # android:isAccessibilityTool from the app's accessibility-service config XML
    # (res/xml/...). None = no accessibility service, or its config wasn't found.
    # Self-declared, like declared_category: rules may use it to soften, never to clear.
    accessibility_tool_declared: Optional[bool] = None
    parser: str = "none"


def parse_apk(path: str | Path) -> ManifestFacts:
    """Extract manifest facts from an APK on disk."""
    if _APK is not None:
        return _parse_with_androguard(path)
    logger.warning("androguard not installed; using degraded raw manifest scan.")
    return _parse_raw(Path(path).read_bytes())


def _parse_with_androguard(path: str | Path) -> ManifestFacts:
    apk = _APK(str(path))

    package_name = apk.get_package()
    min_sdk = _safe_int(apk.get_min_sdk_version())
    target_sdk = _safe_int(apk.get_target_sdk_version())

    # Pull the decoded manifest tree directly so exported/intent-filter/
    # deep-link/application-level flags can be read in a way that's stable
    # across androguard versions (some expose convenience getters for these,
    # some don't or renamed them).
    manifest_root = _safe_manifest_xml(apk)
    application_el = manifest_root.find("application") if manifest_root is not None else None

    allow_backup = _bool_attr(application_el, "allowBackup")
    debuggable = _bool_attr(application_el, "debuggable")
    network_security_config = _str_attr(application_el, "networkSecurityConfig")

    components: list[Component] = []
    deep_links: set[str] = set()

    if application_el is not None:
        for child in application_el:
            kind = _COMPONENT_TAGS.get(_local_tag(child.tag))
            if kind is None:
                continue
            component, links = _parse_component(child, kind, package_name, target_sdk)
            components.append(component)
            deep_links.update(links)
    else:
        # Fallback: no decoded tree available, keep at least the component
        # names/kinds so downstream consumers don't silently lose data.
        for name in apk.get_activities():
            components.append(Component(name=name, kind="activity"))
        for name in apk.get_services():
            components.append(Component(name=name, kind="service"))
        for name in apk.get_receivers():
            components.append(Component(name=name, kind="receiver"))
        for name in apk.get_providers():
            components.append(Component(name=name, kind="provider"))

    accessibility_tool = None
    if any(c.kind == "service" and c.permission == BIND_ACCESSIBILITY_SERVICE for c in components):
        accessibility_tool = _accessibility_tool_flag(apk)

    try:
        version_name = apk.get_androidversion_name()
    except KeyError:  # some samples omit android:versionName entirely
        version_name = None

    return ManifestFacts(
        package_name=package_name,
        version_name=version_name,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=list(apk.get_permissions()),
        custom_permissions=list(apk.get_declared_permissions() or []),
        components=components,
        uses_features=list(apk.get_features() or []),
        deep_links=sorted(deep_links),
        allow_backup=allow_backup,
        debuggable=debuggable,
        network_security_config=network_security_config,
        accessibility_tool_declared=accessibility_tool,
        parser="androguard",
    )


def _accessibility_tool_flag(apk: "_APK") -> Optional[bool]:
    """Read android:isAccessibilityTool from the accessibility-service config(s).

    Finds them by their root tag rather than by following the service's
    meta-data resource reference, which is fragile on obfuscated/renamed resources.
    """
    if _AXMLPrinter is None:
        return None
    roots = []
    xml_files = [n for n in apk.get_files() if n.startswith("res/") and n.endswith(".xml")]
    for name in xml_files[:_MAX_RES_XML_FILES]:
        try:
            root = _AXMLPrinter(apk.get_file(name)).get_xml_obj()
        except Exception:  # noqa: BLE001 - a broken resource file is skipped, not fatal
            continue
        if root is not None and _local_tag(root.tag) == "accessibility-service":
            roots.append(root)
    return accessibility_tool_flag(roots)


def accessibility_tool_flag(config_roots: list) -> Optional[bool]:
    """True if any accessibility-service config declares isAccessibilityTool="true";
    None if there is no config to read."""
    if not config_roots:
        return None
    return any(_bool_attr(r, "isAccessibilityTool") for r in config_roots)


def _safe_manifest_xml(apk: "_APK"):
    """Return the decoded manifest element tree, or None if unavailable.

    Isolated so a parsing hiccup on a malformed manifest degrades to the
    getter-based fallback instead of blowing up the whole run.
    """
    try:
        return apk.get_android_manifest_xml()
    except Exception:  # pragma: no cover - defensive, androguard can raise many types
        logger.warning("Failed to decode AndroidManifest.xml tree; falling back to getters.")
        return None


def _parse_component(
    el, kind: str, package_name: Optional[str], target_sdk: Optional[int]
) -> tuple[Component, list[str]]:
    raw_name = _str_attr(el, "name")
    name = _qualify_name(raw_name, package_name) if raw_name else "<unknown>"

    intent_filter_els = [c for c in el if _local_tag(c.tag) == "intent-filter"]

    intent_filters: list[str] = []
    deep_links: list[str] = []
    for intent_filter_el in intent_filter_els:
        actions = [
            _str_attr(a, "name")
            for a in intent_filter_el
            if _local_tag(a.tag) == "action" and _str_attr(a, "name")
        ]
        categories = [
            _str_attr(c, "name")
            for c in intent_filter_el
            if _local_tag(c.tag) == "category" and _str_attr(c, "name")
        ]
        intent_filters.extend(a for a in actions if a)
        intent_filters.extend(c for c in categories if c)

        if "android.intent.action.VIEW" in actions:
            deep_links.extend(_extract_deep_links(intent_filter_el))

    return (
        Component(
            name=name,
            kind=kind,
            exported=_resolve_exported(el, kind, target_sdk, bool(intent_filter_els)),
            intent_filters=intent_filters,
            permission=_str_attr(el, "permission"),
            process=_str_attr(el, "process"),
            enabled=_bool_attr(el, "enabled"),
        ),
        deep_links,
    )


def _resolve_exported(
    el, kind: str, target_sdk: Optional[int], has_intent_filter: bool
) -> Optional[bool]:
    """Resolve the effective `exported` value, including implicit defaults.

    Returns None only when the value truly cannot be determined (an
    implicit provider default that depends on an unknown targetSdkVersion).
    """
    explicit = _bool_attr(el, "exported")
    if explicit is not None:
        return explicit

    if kind == "provider":
        # Providers default to exported=True when targetSdkVersion < 17,
        # and False otherwise, per the Android docs.
        if target_sdk is None:
            return None
        return target_sdk < 17

    # activity / service / receiver: implicit default is "has an intent filter".
    return has_intent_filter


def _extract_deep_links(intent_filter_el) -> list[str]:
    links: list[str] = []
    for data_el in intent_filter_el:
        if _local_tag(data_el.tag) != "data":
            continue
        scheme = _str_attr(data_el, "scheme")
        if not scheme:
            continue
        host = _str_attr(data_el, "host") or ""
        port = _str_attr(data_el, "port")
        path = (
            _str_attr(data_el, "path")
            or _str_attr(data_el, "pathPrefix")
            or _str_attr(data_el, "pathPattern")
            or ""
        )
        authority = f"{host}:{port}" if host and port else host
        links.append(f"{scheme}://{authority}{path}")
    return links


def _local_tag(tag) -> str:
    """Strip any namespace prefix from an element tag, e.g. '{ns}foo' -> 'foo'."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _str_attr(el, name: str) -> Optional[str]:
    if el is None:
        return None
    value = el.get(_ANDROID_NS + name)
    return value if value else None


def _bool_attr(el, name: str) -> Optional[bool]:
    value = _str_attr(el, name)
    if value is None:
        return None
    return value.strip().lower() in ("true", "1")


def _qualify_name(name: str, package_name: Optional[str]) -> str:
    if name.startswith(".") and package_name:
        return f"{package_name}{name}"
    return name


_PERM_RE = re.compile(rb"android\.permission\.[A-Z_]+")


def _parse_raw(data: bytes) -> ManifestFacts:
    """Degraded fallback: regex-scrape permission strings from raw bytes.

    NOTE: AndroidManifest.xml is compressed binary XML, so this only catches
    permission tokens that survive as plaintext elsewhere in the archive. Good
    enough to keep the pipeline moving in a bare env; NOT authoritative.
    Component-level details (exported, intent-filters, deep links,
    allowBackup, debuggable, networkSecurityConfig) require real AXML
    decoding and are left as None/empty here rather than guessed.
    TODO: bundle a lightweight AXML parser to remove the androguard hard dep.
    """
    perms = sorted({m.decode() for m in _PERM_RE.findall(data)})
    return ManifestFacts(permissions=perms, parser="raw_fallback")


def _safe_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None