"""risk_engine.py - PhishGuard shared URL risk analysis.

Offline, rule-based heuristics. Standard library only. No network access, no
API keys, and the URL is NEVER opened, fetched or resolved.

Public contract (shared with app.py, email_detector.py and qr_detector.py):

    analyze_url(url: str) -> {
        "score": int,                  # 0-100
        "level": str,                  # "Low" | "Medium" | "High" | "Critical"
        "findings": list[str],         # one plain-English sentence per triggered rule
        "recommendations": list[str],  # actionable advice
    }

Additional fields (documented extras; other modules may ignore them):

        "host": str | None             # hostname that was analysed
        "registered_domain": str | None
        "rules_triggered": list[dict]  # {"id", "points", "message"} for each rule
        "notes": list[str]             # limits of this analysis

Errors: raises ValueError when `url` is not a string or is empty. Malformed but
non-empty input never raises; it returns a scored result that says so.

HOW THE SCORE WORKS
The score is the sum of the points of every triggered rule, capped at 100.
It is a transparent heuristic, NOT a calibrated probability that a link is
malicious. A low score is not a guarantee of safety.

    Level      Score
    Low        0 - 24
    Medium     25 - 49
    High       50 - 74
    Critical   75 - 100

RULES AND POINTS (change weights in one place: the `hits.add(...)` calls)
    Dangerous scheme (javascript:, data:, vbscript:)        +50
    File scheme (file:, blob:)                              +30
    Other non-web scheme (mailto:, tel:, unknown://)        +15
    Malformed link                                          +30
    Credentials/userinfo before '@' in the address          +30 (+15 if it shows a domain)
    IP address instead of a domain name                     +25
    Obfuscated numeric IP (decimal / hex / octal form)      +30
    Brand name in domain that is not the official domain    +30 (+10 decoy official domain)
    Look-alike spelling of a known brand (typosquat)        +30
    International characters / punycode in the domain       +15 (+20 if scripts are mixed)
    URL shortener (destination hidden)                      +25
    Query parameter that points to another full URL         +12
    Suspicious top-level domain                             +12
    Free or user-content hosting platform                   +10
    3+ subdomain levels                                     +10
    Account/security keywords in the domain                 +8
    Account/security keywords (2+) in path or query         +8
    3+ hyphens in the domain                                +8
    Target email address inside the query or fragment       +10
    Plain http (no encryption)                              +10
    Non-standard port                                       +8
    Heavy percent-encoding                                  +8
    Percent signs inside the hostname                       +20
    Long URL (>100 chars +5, >200 chars +10, >8192 chars +10)

KNOWN LIMITATIONS
    * No domain age, DNS, reputation feeds or page content (offline by design).
    * The brand list is small and hand-written; review and extend BRANDS.
    * Registered-domain detection uses a short built-in list of multi-part
      suffixes (co.uk, com.au, ...), not the full Public Suffix List.
    * Short or common-word brands (e.g. "apple") can cause false positives.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

__all__ = ["analyze_url"]

MAX_URL_CHARS = 8192

# ---------------------------------------------------------------------------
# Reference data (edit these to tune the engine)
# ---------------------------------------------------------------------------

# Brand name -> official registered domains. Review before relying on it.
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "microsoft": frozenset({
        "microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
        "outlook.com", "msn.com", "bing.com", "azure.com", "windows.com", "skype.com",
        "xbox.com", "sharepoint.com", "onedrive.com", "hotmail.com",
    }),
    "google": frozenset({"google.com", "gmail.com", "youtube.com", "googleapis.com",
                         "gstatic.com", "google.co.in"}),
    "apple": frozenset({"apple.com", "icloud.com", "me.com"}),
    "amazon": frozenset({
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au",
        "amazon.co.jp", "amazon.fr", "amazon.es", "amazon.it", "amazon.com.br",
        "amazon.com.mx", "amazonaws.com",
    }),
    "facebook": frozenset({"facebook.com", "fb.com", "fb.me", "messenger.com", "meta.com"}),
    "instagram": frozenset({"instagram.com"}),
    "netflix": frozenset({"netflix.com"}),
    "linkedin": frozenset({"linkedin.com", "lnkd.in"}),
    "dropbox": frozenset({"dropbox.com", "dropboxusercontent.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "fedex": frozenset({"fedex.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
    "whatsapp": frozenset({"whatsapp.com", "whatsapp.net", "wa.me"}),
    "adobe": frozenset({"adobe.com", "adobe.io"}),
    "github": frozenset({"github.com", "github.io", "githubusercontent.com", "githubassets.com"}),
    "ibm": frozenset({"ibm.com"}),
    "hdfcbank": frozenset({"hdfcbank.com"}),
    "icicibank": frozenset({"icicibank.com"}),
}
ALL_OFFICIAL = frozenset(d for domains in BRANDS.values() for d in domains)

SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "icu", "cyou",
    "buzz", "monster", "sbs", "cfd", "rest", "country", "kim", "loan", "bid", "win",
})
FILE_LIKE_TLDS = frozenset({"zip", "mov"})

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "bit.do", "v.gd",
})

FREE_HOSTING = (
    "github.io", "gitlab.io", "netlify.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "herokuapp.com", "vercel.app", "glitch.me", "blogspot.com",
    "weebly.com", "wixsite.com", "000webhostapp.com", "webflow.io", "repl.co",
    "onrender.com", "azurewebsites.net", "amazonaws.com",
)

KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "secure", "security",
    "update", "confirm", "banking", "password", "wallet", "billing", "payment", "support",
    "unlock", "suspend", "recover", "auth", "invoice", "reset", "validate",
)

_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "org.in", "gov.in", "ac.in", "co.jp", "co.nz", "com.br", "com.cn", "com.sg", "com.mx",
    "co.za", "com.tr", "com.pk", "com.bd", "co.kr", "com.my", "com.ph", "com.hk",
})

_BASE_NOTES = [
    "Offline heuristic analysis only: domain age, DNS records, reputation feeds and page "
    "content were not checked, and the link was never opened.",
    "The score is a rule-based indicator, not a probability. A low score does not guarantee "
    "that a link is safe.",
]

# Look-alike letters from other alphabets mapped to the Latin letter they imitate.
_CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u04bb": "h",
    "\u051b": "q", "\u051d": "w", "\u03bf": "o", "\u03b1": "a", "\u03bd": "v", "\u03c1": "p",
    "\u03b9": "i", "\u03ba": "k", "\u03c4": "t", "\u03c5": "u",
})
_LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_OPAQUE_SCHEME_RE = re.compile(r"^(?:javascript|data|vbscript|file|blob|about|mailto|tel|sms):", re.IGNORECASE)
_NUMERIC_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_BAD_CHARS_RE = re.compile(r"[\x00-\x20\x7f]")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class _Hits:
    """Collects triggered rules, their points and any rule-specific advice."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.advice: list[str] = []

    def add(self, rule_id: str, points: int, message: str, advice: str | None = None) -> None:
        self.items.append({"id": rule_id, "points": points, "message": message})
        if advice and advice not in self.advice:
            self.advice.append(advice)

    def has(self, rule_id: str) -> bool:
        return any(item["id"] == rule_id for item in self.items)


def _clip(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _split_domain(host: str) -> tuple[str, str]:
    """Return (registered_domain, subdomain_part) using a small suffix list."""
    labels = host.split(".")
    if len(labels) < 2:
        return host, ""
    use_three = len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES
    n = 3 if use_three else 2
    return ".".join(labels[-n:]), ".".join(labels[:-n])


def _variants(text: str) -> set[str]:
    """Normalised spellings of `text` used to see through look-alike tricks."""
    base = unicodedata.normalize("NFKC", text).lower().translate(_CONFUSABLES)
    out = {base, base.replace("rn", "m").replace("vv", "w")}
    for table in (_LEET_L, _LEET_I):
        swapped = base.translate(table)
        out.add(swapped)
        out.add(swapped.replace("rn", "m").replace("vv", "w"))
    return out


def _osa_distance(a: str, b: str) -> int:
    """Edit distance counting insert, delete, substitute and adjacent swap as 1."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def _find_brand(host: str, reg: str) -> tuple[str, str, str] | None:
    """Return (brand, kind, matched_text) if the host imitates a known brand."""
    variants = _variants(host)
    tokens: set[str] = set()
    for variant in variants:
        tokens.update(t for t in re.split(r"[.\-_]+", variant) if t)

    for brand in BRANDS:                      # exact word, e.g. "paypal-login.example"
        if brand in tokens:
            return brand, "word", brand
    for brand in BRANDS:                      # embedded, e.g. "paypalsecure.example"
        if len(brand) >= 6:
            for token in tokens:
                if brand in token:
                    return brand, "embedded", token

    main_label = reg.split(".")[0] if reg else ""
    candidates: set[str] = set()
    for variant in _variants(main_label):
        candidates.add(variant)
        candidates.update(p for p in variant.split("-") if p)
    for brand in BRANDS:                      # misspelling, e.g. "paypall", "mircosoft"
        if len(brand) < 6:
            continue
        limit = 1 if len(brand) < 8 else 2
        for cand in candidates:
            if cand != brand and 0 < len(cand) <= 40 and abs(len(cand) - len(brand)) <= 2:
                if _osa_distance(cand, brand) <= limit:
                    return brand, "typo", cand
    return None


def _finish(hits: _Hits, notes: list[str], host: str | None, reg: str | None) -> dict:
    score = max(0, min(100, sum(item["points"] for item in hits.items)))
    level = _level(score)

    findings = [f"{item['message']} (+{item['points']})" for item in hits.items]

    if level in ("High", "Critical"):
        recommendations = [
            "Do not open this link or enter any password, code or payment details.",
            "Report the message to your IT or security team, or to the organisation it imitates.",
            "If you already clicked and signed in, change that password now and turn on "
            "multi-factor authentication.",
        ]
    elif level == "Medium":
        recommendations = [
            "Treat this link with caution and do not enter credentials through it.",
            "Confirm with the sender using a separate channel (a known phone number or a new email).",
        ]
    else:
        recommendations = [
            "No strong warning signs were found, but this check is offline and heuristic. "
            "Still verify unexpected messages before clicking.",
        ]
    for tip in hits.advice:
        if tip not in recommendations:
            recommendations.append(tip)

    return {
        "score": int(score),
        "level": level,
        "findings": findings,
        "recommendations": recommendations,
        "host": host,
        "registered_domain": reg,
        "rules_triggered": hits.items,
        "notes": notes,
    }


def _malformed(hits: _Hits, notes: list[str], reason: str) -> dict:
    hits.add(
        "malformed", 30,
        f"The link is malformed ({reason}). Broken or unusual links are sometimes used to confuse filters.",
        "Do not try to repair or open a malformed link; ask the sender for the correct address.",
    )
    return _finish(hits, notes, None, None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_url(url: str) -> dict:
    """Analyse one URL with transparent heuristics. See the module docstring."""
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    raw = url.strip()
    if not raw:
        raise ValueError("url must not be empty")

    hits = _Hits()
    notes = list(_BASE_NOTES)

    original_len = len(raw)
    if original_len > MAX_URL_CHARS:
        raw = raw[:MAX_URL_CHARS]
        hits.add("length_extreme", 10,
                 f"The link is extremely long ({original_len} characters). Only the first "
                 f"{MAX_URL_CHARS} were examined.")
        notes.append("Only the first part of this very long link was examined.")
    elif original_len > 200:
        hits.add("length", 10, f"The link is very long ({original_len} characters), which can hide the real destination.")
    elif original_len > 100:
        hits.add("length", 5, f"The link is long ({original_len} characters).")

    if _BAD_CHARS_RE.search(raw):
        return _malformed(hits, notes, "it contains spaces or control characters")

    # ---- Scheme handling -------------------------------------------------
    assumed_scheme = False
    if _OPAQUE_SCHEME_RE.match(raw):
        parse_target = raw
    elif _SCHEME_RE.match(raw):
        parse_target = raw
    elif raw.startswith("//"):
        parse_target, assumed_scheme = "http:" + raw, True
    else:
        parse_target, assumed_scheme = "http://" + raw, True
    if assumed_scheme:
        notes.append("No scheme (http/https) was given, so one was assumed for parsing.")

    try:
        parts = urlsplit(parse_target)
        scheme = parts.scheme.lower()
        port = parts.port
        host = parts.hostname
    except ValueError as exc:
        return _malformed(hits, notes, _clip(str(exc), 60))

    if scheme in ("javascript", "data", "vbscript"):
        hits.add("scheme_danger", 50,
                 f"The link uses the '{scheme}:' scheme, which can run code instead of opening a website.",
                 "Never open links that start with javascript:, data: or vbscript:.")
        return _finish(hits, notes, None, None)
    if scheme in ("file", "blob"):
        hits.add("scheme_local", 30, f"The link uses the '{scheme}:' scheme, which points to local or in-browser content rather than a public website.")
        return _finish(hits, notes, None, None)
    if scheme not in ("http", "https", "ftp"):
        hits.add("scheme_other", 15,
                 f"The link uses the non-web scheme '{_clip(scheme, 20)}:', which may open another app instead of a website.")
        return _finish(hits, notes, None, None)

    if not host:
        return _malformed(hits, notes, "no host name was found")
    host = host.rstrip(".")
    if not host or ".." in host or host.startswith(".") or len(host) > 253:
        return _malformed(hits, notes, "the host name is invalid")

    # ---- Transport and authority ----------------------------------------
    if scheme == "http" and not assumed_scheme:
        hits.add("http", 10, "The link uses plain http, so the connection is not encrypted.")
    if scheme == "ftp":
        hits.add("http", 10, "The link uses ftp, which is not encrypted.")

    if port is not None and port not in (80, 443):
        hits.add("port", 8, f"The link uses an unusual port ({port}).")

    netloc = parts.netloc
    if "@" in netloc:
        userinfo = netloc.rsplit("@", 1)[0]
        hits.add("userinfo", 30,
                 f"The address contains an '@' sign, so everything before it is ignored and the link really goes to '{_clip(host, 50)}'.",
                 "Ignore the name before the '@' sign; the link goes to the site after it.")
        if re.search(r"[A-Za-z0-9-]\.[A-Za-z]{2,}", userinfo):
            hits.add("userinfo_domain", 15, "The part before the '@' looks like a website name, a common trick to look trustworthy.")

    if "%" in host:
        hits.add("host_encoding", 20, "The host name contains percent-encoded characters, which can hide the real address.")

    # ---- Host type: IP address vs domain name ---------------------------
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        hits.add("ip", 25, f"The link uses an IP address ({_clip(host, 45)}) instead of a domain name.",
                 "Legitimate services rarely use a bare IP address. Do not enter credentials.")
    except ValueError:
        if _NUMERIC_HOST_RE.match(host):
            is_ip = True
            hits.add("ip_obfuscated", 30, f"The host '{_clip(host, 45)}' is a disguised numeric IP address.",
                     "Legitimate services rarely use a bare IP address. Do not enter credentials.")

    reg: str | None = None
    if not is_ip:
        reg, sub = _split_domain(host)
        labels = host.split(".")
        tld = labels[-1] if len(labels) > 1 else ""
        trusted = reg in ALL_OFFICIAL

        # International characters / punycode
        if any(ord(c) > 127 for c in host) or any(lbl.startswith("xn--") for lbl in labels):
            decoded = host
            if "xn--" in host:
                try:
                    decoded = host.encode("ascii").decode("idna")
                except Exception:
                    decoded = host
            hits.add("idn", 15,
                     f"The domain uses international characters ('{_clip(decoded, 50)}'), which can imitate familiar letters.",
                     "Check the domain letter by letter; look-alike characters can imitate real names.")
            scripts = set()
            for ch in decoded:
                if ch.isalpha():
                    scripts.add("LATIN" if ord(ch) < 128 else unicodedata.name(ch, "UNKNOWN").split(" ")[0])
            if len(scripts) > 1:
                hits.add("idn_mixed", 20, "The domain mixes letters from different alphabets, a classic look-alike (homograph) trick.")

        # Brand impersonation
        if not trusted:
            found = _find_brand(host, reg)
            if found:
                brand, kind, matched = found
                if kind == "typo":
                    hits.add("brand_typo", 30,
                             f"Possible look-alike of {brand.title()}: '{_clip(matched, 40)}' is spelled almost like '{brand}', but the domain is not an official {brand.title()} domain.",
                             f"Go to the real {brand.title()} site by typing its address yourself or using its official app.")
                else:
                    hits.add("brand", 30,
                             f"Possible brand impersonation: the domain contains '{brand}' but is not an official {brand.title()} domain.",
                             f"Go to the real {brand.title()} site by typing its address yourself or using its official app.")
                    for official in sorted(BRANDS[brand]):
                        if official in host:
                            hits.add("brand_decoy", 10, f"The real-looking name '{official}' appears inside the host as a decoy, but the actual domain is '{_clip(reg, 40)}'.")
                            break

        if tld in SUSPICIOUS_TLDS:
            if tld in FILE_LIKE_TLDS:
                hits.add("tld", 12, f"The domain ends in '.{tld}', which looks like a file extension and can trick people.")
            else:
                hits.add("tld", 12, f"The domain ends in '.{tld}', a low-cost top-level domain often abused in phishing campaigns.")

        for suffix in FREE_HOSTING:
            if host.endswith("." + suffix):
                hits.add("hosting", 10, f"The site is hosted on a free or user-content platform ({suffix}). Many legitimate sites use these, but they are also often abused.")
                break

        if host in SHORTENERS or reg in SHORTENERS:
            hits.add("shortener", 25, f"The link uses a URL shortener ({_clip(reg, 30)}), so the real destination is hidden.",
                     "Ask the sender for the full address before opening a shortened link.")

        if sub and len(sub.split(".")) >= 3:
            hits.add("subdomains", 10, f"The address has {len(sub.split('.'))} subdomain levels ('{_clip(sub, 50)}'), which can bury the real domain at the end.")

        if host.count("-") >= 3:
            hits.add("hyphens", 8, "The domain contains many hyphens, a pattern common in made-up look-alike names.")

        if not trusted:
            lowered_host = host.lower()
            keywords = [k for k in KEYWORDS if k in lowered_host]
            if keywords:
                hits.add("host_keywords", 8, f"The domain contains account or security wording ({', '.join(keywords[:3])}), often used to look official.")

    # ---- Path, query and fragment ---------------------------------------
    path_query = (unquote(parts.path) + " " + unquote(parts.query)).lower()[:2000]
    found_words = sorted({k for k in KEYWORDS if k in path_query})
    if len(found_words) >= 2:
        hits.add("path_keywords", 8, f"The path or query contains several account or security words ({', '.join(found_words[:4])}).")

    try:
        params = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        params = []
    for key, value in params:
        if re.match(r"^\s*https?://", value, re.IGNORECASE):
            hits.add("redirect_param", 12, f"The query parameter '{_clip(key, 30)}' contains another full web address, which can be used to redirect you.")
            break

    tail = (unquote(parts.query) + " " + unquote(parts.fragment))[:2000]
    if _EMAIL_RE.search(tail):
        hits.add("email_in_query", 10, "The link contains an email address, a common way to pre-fill a login page for a specific target.",
                 "Be wary of pages that already know your email address; this is a common targeting trick.")

    if len(_PCT_RE.findall(raw)) >= 6:
        hits.add("encoding", 8, "The link contains a lot of percent-encoded characters, which can hide its real content.")

    return _finish(hits, notes, host, reg)
