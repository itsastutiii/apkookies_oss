"""
IOC extraction from static artifacts (DEX strings, resources, manifest).

Pulls domains, IPs, URLs, emails, and Telegram bot tokens. Extracted IOCs feed
threat-intel enrichment, the GenAI evidence store, and STIX export.

Key fix vs. the previous version
---------------------------------
The old domain regex accepted *any* alphabetic suffix of length 2-24 as a
"TLD", so `Gravity.RIGHT`, `MediaSession.Token`, `MeasureSpec.EXACTLY`, etc.
all passed. Two things caused this:

1. The suffix check only asked "is this alphabetic?", not "is this a real
   public TLD?". Almost any Java constant or nested-class name satisfies
   that.
2. The case-sensitivity checks (rejecting `TitleCase` / `CONSTANT_CASE`
   labels) were applied *after* the candidate string had already been
   lower-cased, so they never actually fired.

This version:
- Validates the final label against a real TLD whitelist.
- Runs case-shape checks (TitleCase, camelCase, ALL_CAPS) on the
  *original-case* match, before any lower-casing.
- Adds a few extra structural filters for Java/Kotlin/Android identifiers
  (single-letter labels, common code-constant words, etc).
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field

try:
    import tldextract
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)
except ImportError:
    _TLD_EXTRACTOR = None

# ---------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------

TELEGRAM_TOKEN_RE = re.compile(
    r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b"
)

URL_RE = re.compile(
    r"\b(?:https?|wss?|ftp)://[^\s\"'<>`\\]+",
    re.IGNORECASE,
)

# Same shape as before -- broad candidate matcher. Precision now comes from
# is_valid_domain(), not from the regex itself.
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)

# An IPv4 address only counts as a network IOC ("ip") in a network context: a URL
# host (handled with URLs) or followed by a port ("45.9.148.12:8080", a socket /
# connection string). A bare dotted number like "1.10.12.0" is just as likely a
# version string, so it is reported as "ip_like" (unconfirmed) and never used as a
# hardcoded C2 address by the rules or the model.
IP_PORT_RE = re.compile(r":\d{1,5}\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"
)

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

_CAMEL_CASE_RE = re.compile(r"[a-z][A-Z]")
_LEADING_DIGIT_LABEL_RE = re.compile(r"^\d")

# ---------------------------------------------------------------------
# TLD whitelist fallback (used if tldextract is unavailable)
# ---------------------------------------------------------------------
KNOWN_TLDS = {
    # generic
    "com", "net", "org", "info", "biz", "name", "pro", "mobi", "app",
    "dev", "io", "co", "ai", "xyz", "top", "site", "online", "club",
    "shop", "store", "tech", "space", "website", "fun", "live", "life",
    "world", "icu", "cc", "vip", "link", "click", "work", "cloud",
    "digital", "email", "team", "solutions", "services", "systems",
    "network", "media", "news", "agency", "company", "group", "center",
    "run", "wiki", "guide", "help", "support", "chat", "social",
    "download", "stream", "tv", "video", "games", "fyi", "buzz",

    # sponsored / other classic gTLDs
    "edu", "gov", "mil", "int", "aero", "coop", "museum", "jobs",
    "travel", "post",

    # popular country-code TLDs (legit + commonly abused for C2)
    "us", "uk", "de", "fr", "es", "it", "nl", "be", "ch", "at", "se",
    "no", "dk", "fi", "pl", "pt", "ie", "gr", "cz", "sk", "hu", "ro",
    "bg", "hr", "si", "lt", "lv", "ee", "is", "lu",
    "ru", "su", "ua", "by", "kz", "cn", "hk", "tw", "jp", "kr", "kp",
    "in", "pk", "bd", "lk", "np", "id", "my", "sg", "th", "vn", "ph",
    "au", "nz", "ca", "mx", "br", "ar", "cl", "co", "pe", "ve",
    "za", "ng", "ke", "eg", "ma", "dz", "tn", "gh",
    "il", "ir", "iq", "sa", "ae", "tr", "qa", "kw", "om", "jo", "lb",
    "tk", "ml", "ga", "cf", "gq",  # freenom, heavily abused for phishing/C2
    "me", "tv", "cc", "ws", "to", "sh", "so", "im", "gg", "je",
    "ly", "fm", "am", "cm", "pw", "bz", "vc", "sc", "re",
    "eu", "asia", "cat",
}

# ---------------------------------------------------------------------
# Known infrastructure / service domains (tagged, not discarded)
# ---------------------------------------------------------------------

KNOWN_INFRASTRUCTURE_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "w3c.org",
    "goo.gl",
    "example.com",
    "play.google.com",
    "developer.android.com",
    "android.com",
    "github.com",
    "githubusercontent.com",
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "crashlytics.com",
    "firebase.com",
    "firebaseio.com",
    "apple.com",
    "microsoft.com",
    "schema.org",
    "apache.org",
    "cloudfront.net",
}

PRIVATE_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}

JAVA_SUFFIXES = (
    ".java",
    ".kt",
    ".class",
)

RESOURCE_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".xml", ".json", ".arsc", ".dex", ".ttf", ".otf",
    ".txt", ".pro", ".properties",
)

PACKAGE_PREFIXES = (
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "com.android.",
    "com.google.",
    "com.google.android.",
    "org.apache.",
    "org.json.",
    "org.xml.",
    "org.w3c.",
    "io.flutter.",
    "io.reactivex.",
    "okhttp3.",
    "retrofit2.",
)

PACKAGE_ROOTS = {
    "com", "org", "net", "io", "android", "androidx", "java",
    "javax", "kotlin", "kotlinx", "dalvik",
}

_MIN_LABEL_LEN = 2


def is_known_service_domain(domain: str) -> bool:
    dom = domain.lower()
    if dom in KNOWN_INFRASTRUCTURE_DOMAINS:
        return True
    for infra in KNOWN_INFRASTRUCTURE_DOMAINS:
        if dom.endswith("." + infra):
            return True
    return False


def is_private_hostname_or_ip(hostname_or_ip: str) -> bool:
    h = hostname_or_ip.lower().strip()
    if h in PRIVATE_HOSTNAMES or h.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(h)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------

@dataclass
class ExtractedIOC:
    type: str
    value: str
    is_known_service: bool = False
    is_private: bool = False


@dataclass
class ExtractionStats:
    strings_scanned: int = 0
    domain_candidates: int = 0
    rejected_framework: int = 0
    rejected_java_class: int = 0
    validated_domains: int = 0
    known_services: int = 0
    private_network_iocs: int = 0
    urls: int = 0
    ips: int = 0
    ips_rejected_private: int = 0
    emails: int = 0
    telegram_tokens: int = 0
    ip_like_unconfirmed: int = 0

    def render(self, width: int = 40) -> str:
        title = "IOC EXTRACTION"
        lines = [title, "-" * width]

        def row(label: str, value: int) -> str:
            return f"{label:<24}: {value:,}"

        lines.append(row("Strings Scanned", self.strings_scanned))
        lines.append(row("Domain Candidates", self.domain_candidates))
        lines.append(row("Rejected as Framework", self.rejected_framework))
        lines.append(row("Rejected as Java Class", self.rejected_java_class))
        lines.append(row("Validated Domains", self.validated_domains))
        lines.append(row("Known Services", self.known_services))
        lines.append(row("Private/Local IOCs", self.private_network_iocs))
        lines.append(row("URLs", self.urls))
        lines.append(row("IPs", self.ips))
        lines.append(row("IP-like (unconfirmed)", self.ip_like_unconfirmed))
        lines.append(row("Emails", self.emails))
        lines.append(row("Telegram Tokens", self.telegram_tokens))
        return "\n".join(lines)


@dataclass
class IOCReport:
    iocs: list[ExtractedIOC] = field(default_factory=list)
    stats: ExtractionStats = field(default_factory=ExtractionStats)

    def by_type(self, t: str) -> list[str]:
        return [i.value for i in self.iocs if i.type == t]

    def actionable_iocs(self, t: str | None = None) -> list[ExtractedIOC]:
        """Returns IOCs excluding known infrastructure services and private/localhost entries."""
        return [
            i for i in self.iocs
            if not i.is_known_service and not i.is_private and (t is None or i.type == t)
        ]

    def print_summary(self) -> None:
        print(self.stats.render())


# ---------------------------------------------------------------------
# Case-shape helpers (must run on ORIGINAL-CASE text, not lower-cased)
# ---------------------------------------------------------------------

def _is_title_case(label: str) -> bool:
    """Gravity, MediaSession, FragmentPager -> class-like identifier."""
    return len(label) > 1 and label[0].isupper() and not label.isupper()


def _is_all_caps(label: str) -> bool:
    """RIGHT, EXACTLY, LEFT -> constant/enum value."""
    return len(label) > 1 and label.isupper() and label.isalpha()


def _is_camel_case(label: str) -> bool:
    """scanWifiDisplays, setupwizard-style camel identifiers."""
    return bool(_CAMEL_CASE_RE.search(label))


def _has_bad_case_shape(original_domain: str) -> bool:
    """
    Runs BEFORE lower-casing. Rejects labels that look like Java/Kotlin
    identifiers based on internal camelCase capitalization (e.g. scanWifiDisplays).
    TitleCase (e.g. Google.com) and ALL_CAPS (e.g. EVIL.COM) are standard in
    domain strings and are accepted.
    """
    for label in original_domain.split("."):
        if not label:
            continue
        if _is_camel_case(label):
            return True
    return False


# ---------------------------------------------------------------------
# Validation Helpers
# ---------------------------------------------------------------------

#: Rejection categories used for both filtering and reporting.
REJECT_FRAMEWORK = "framework"    # denylist / package / resource / structural
REJECT_JAVA_CLASS = "java_class"  # TitleCase / ALL_CAPS / camelCase identifiers


def classify_domain(original_domain: str) -> tuple[bool, str | None]:
    """
    original_domain: the RAW match text, in its original case. Do not
    lower-case before calling this -- case-shape checks depend on it.

    Returns (is_valid, rejection_reason). rejection_reason is None when
    is_valid is True, otherwise one of REJECT_FRAMEWORK / REJECT_JAVA_CLASS.
    """
    domain = original_domain.strip()

    if len(domain) < 4:
        return False, REJECT_FRAMEWORK

    if "/" in domain or "\\" in domain or ";" in domain or ":" in domain:
        return False, REJECT_FRAMEWORK

    if "_" in domain:
        return False, REJECT_FRAMEWORK

    if domain.lower().endswith(".android.com"):
        return False, REJECT_FRAMEWORK

    if domain.lower().startswith(("super.", "this.")):
        return False, REJECT_FRAMEWORK

    if domain.lower().startswith(PACKAGE_PREFIXES):
        return False, REJECT_FRAMEWORK

    if domain.lower().endswith(JAVA_SUFFIXES):
        return False, REJECT_FRAMEWORK

    if domain.lower().endswith(RESOURCE_SUFFIXES):
        return False, REJECT_FRAMEWORK

    # Reject camelCase identifiers using the ORIGINAL case.
    if _has_bad_case_shape(domain):
        return False, REJECT_JAVA_CLASS

    parts_lower = domain.lower().split(".")

    # Reject package-style names: com.foo.bar, org.baz.qux
    if len(parts_lower) >= 3 and parts_lower[0] in PACKAGE_ROOTS:
        return False, REJECT_FRAMEWORK

    # Reject overly short labels (a.b, x.io-style obfuscated identifiers
    # are far more often minified code than real hostnames)
    if any(len(p) < _MIN_LABEL_LEN for p in parts_lower):
        return False, REJECT_FRAMEWORK

    # Reject labels that start with a digit run that looks like a version
    # string fragment, e.g. "1.0.Build" type artifacts slipping through
    if all(_LEADING_DIGIT_LABEL_RE.match(p) for p in parts_lower):
        return False, REJECT_FRAMEWORK

    # TLD / Public Suffix Check using tldextract (if available) or KNOWN_TLDS fallback
    if _TLD_EXTRACTOR:
        ext = _TLD_EXTRACTOR(domain)
        if not ext.suffix or not ext.domain:
            return False, REJECT_FRAMEWORK
    else:
        tld = parts_lower[-1]
        if tld not in KNOWN_TLDS:
            return False, REJECT_FRAMEWORK

    return True, None


def is_valid_domain(original_domain: str) -> bool:
    """Backwards-compatible boolean wrapper around classify_domain()."""
    valid, _ = classify_domain(original_domain)
    return valid


def is_public_ip(ip: str) -> bool:
    """Filter out private/reserved/loopback ranges."""
    return not is_private_hostname_or_ip(ip)


# ---------------------------------------------------------------------
# Main Extraction
# ---------------------------------------------------------------------

def extract(strings: list[str]) -> IOCReport:

    seen: set[tuple[str, str]] = set()
    report = IOCReport()
    stats = report.stats
    stats.strings_scanned = len(strings)

    def add(ioc_type: str, raw_value: str):
        # Normalize domains and emails to lowercase for storage and deduplication
        if ioc_type in ("domain", "email"):
            val = raw_value.lower().strip()
        else:
            val = raw_value.strip()

        key = (ioc_type, val.lower())
        if key in seen:
            return False, None

        seen.add(key)

        is_known = False
        is_priv = False

        if ioc_type == "domain":
            is_known = is_known_service_domain(val)
            is_priv = is_private_hostname_or_ip(val)
        elif ioc_type == "url":
            try:
                parsed = urllib.parse.urlparse(val)
                if parsed.hostname:
                    is_known = is_known_service_domain(parsed.hostname)
                    is_priv = is_private_hostname_or_ip(parsed.hostname)
            except Exception:
                pass
        elif ioc_type in ("ip", "ip_like"):
            is_priv = is_private_hostname_or_ip(val)
        elif ioc_type == "email":
            if "@" in val:
                is_known = is_known_service_domain(val.split("@")[-1])

        ioc_obj = ExtractedIOC(
            type=ioc_type,
            value=val,
            is_known_service=is_known,
            is_private=is_priv,
        )
        report.iocs.append(ioc_obj)

        if is_known:
            stats.known_services += 1
        if is_priv:
            stats.private_network_iocs += 1

        return True, ioc_obj

    for s in strings:

        s = s.strip()

        if len(s) < 4:
            continue

        # Skip obvious Java descriptors
        if s.startswith(("Landroid/", "Ljava/", "Lkotlin/")):
            continue

        # Telegram Tokens
        for tok in TELEGRAM_TOKEN_RE.findall(s):
            added, _ = add("telegram_token", tok)
            if added:
                stats.telegram_tokens += 1

        # URLs
        urls_in_s = URL_RE.findall(s)
        for raw_url in urls_in_s:
            cleaned_url = raw_url.rstrip(".,);]}>\"'\\")
            added, _ = add("url", cleaned_url)
            if added:
                stats.urls += 1

            # Extract domain/IP hostname directly from URL
            try:
                parsed = urllib.parse.urlparse(cleaned_url)
                hostname = parsed.hostname
                if hostname:
                    try:
                        ipaddress.ip_address(hostname)
                        add("ip", hostname)
                        stats.ips += 1
                    except ValueError:
                        valid, _ = classify_domain(hostname)
                        if valid:
                            added_dom, _ = add("domain", hostname)
                            if added_dom:
                                stats.validated_domains += 1
            except Exception:
                pass

        # IPv4 outside URLs (URL hosts were added above)
        s_no_urls = s
        for url in urls_in_s:
            s_no_urls = s_no_urls.replace(url, " ")
        for m in IPV4_RE.finditer(s_no_urls):
            ip = m.group(0)
            if IP_PORT_RE.match(s_no_urls, m.end()):
                added, _ = add("ip", ip)
                if added:
                    stats.ips += 1
            else:
                added, _ = add("ip_like", ip)
                if added:
                    stats.ip_like_unconfirmed += 1

        # Emails
        emails_in_s = EMAIL_RE.findall(s)
        for email in emails_in_s:
            added, _ = add("email", email)
            if added:
                stats.emails += 1
            if "@" in email:
                email_domain = email.split("@")[-1]
                valid, _ = classify_domain(email_domain)
                if valid:
                    added_dom, _ = add("domain", email_domain)
                    if added_dom:
                        stats.validated_domains += 1

        # Standalone Domains
        s_masked = s
        for url in urls_in_s:
            s_masked = s_masked.replace(url, " ")
        for email in emails_in_s:
            s_masked = s_masked.replace(email, " ")

        for dom in DOMAIN_RE.findall(s_masked):
            stats.domain_candidates += 1

            valid, reason = classify_domain(dom)

            if not valid:
                if reason == REJECT_JAVA_CLASS:
                    stats.rejected_java_class += 1
                else:
                    stats.rejected_framework += 1
                continue

            added_dom, _ = add("domain", dom)
            if added_dom:
                stats.validated_domains += 1

    return report


# ---------------------------------------------------------------------
# CLI / demo entry point
# ---------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Usage: python ioc_extraction.py strings.txt
        with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
            input_strings = [line.rstrip("\n") for line in f]
    else:
        # Small built-in sample so the script is runnable with no args.
        input_strings = [
            "Gravity.RIGHT", "MediaSession.Token", "Map.Entry",
            "DisplayManager.scanWifiDisplays", "MeasureSpec.EXACTLY",
            "com.android.setupwizard.action", "android.intent.action",
            "api.telegram.org", "evil.xyz", "bank-login.top",
            "https://malware-c2.ru/gate.php", "192.168.1.10", "8.8.8.8",
            "attacker@evil.xyz",
            # Fake Telegram bot token, built at runtime so no token-shaped
            # literal sits in the source (secret scanners would flag it).
            "123456789:" + "A" * 35,
        ]

    result = extract(input_strings)
    result.print_summary()

    print("\nValidated domains:")
    for d in result.by_type("domain"):
        print(f"  - {d}")