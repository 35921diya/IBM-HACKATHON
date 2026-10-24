
"""
PhishGuard URL Risk Engine
Offline URL analysis using transparent, explainable rules.
Never opens or fetches URLs.
"""

import ipaddress
import re
from urllib.parse import urlsplit, parse_qsl, unquote


BRANDS = {
    "microsoft": ["microsoft.com"],
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "apple": ["apple.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "outlook": ["outlook.com", "live.com"],
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

RISKY_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work",
    "country", "gq", "tk", "support",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "account",
    "password", "secure", "update", "signin",
    "banking", "wallet", "recover", "confirm",
}

REDIRECT_KEYS = {
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "returnurl", "continue", "target",
}


def _normalise_url(url):
    """Prepare a URL for parsing without accessing the internet."""
    url = str(url).strip()
    if not url:
        return None

    # Add a scheme only for parsing URLs supplied without one.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        if not hostname:
            return None
        return url, parts, hostname.lower().rstrip(".")
    except (ValueError, UnicodeError):
        return None


def analyze_url(url):
    """
    Return an explainable 0-100 risk score.

    Result keys:
      score: integer
      level: Low, Medium, High, or Critical
      findings: list of explanations
      precautions: list of recommended actions
    """
    parsed = _normalise_url(url)

    if parsed is None:
        return {
            "score": 0,
            "level": "Low",
            "findings": ["URL could not be parsed; no reliable assessment was made."],
            "precautions": [
                "Treat unrecognised or malformed links cautiously."
            ],
        }

    normalised, parts, host = parsed
    score = 0
    findings = []

    def add(points, message):
        nonlocal score
        score += points
        findings.append(message)

    # User-info tricks: trusted-looking text before @ is not the host.
    if "@" in parts.netloc:
        add(30, "The URL contains @ user information, which can disguise its real destination.")

    # IP address instead of a recognisable domain.
    try:
        ipaddress.ip_address(host.strip("[]"))
        add(20, "The URL uses an IP address instead of a conventional domain name.")
    except ValueError:
        pass

    # Internationalised domain / punycode.
    if "xn--" in host:
        add(20, "The domain contains punycode, which can represent internationalised characters.")

    # Suspicious hostname spelling and look-alike brand names.
    host_compact = host.replace("-", "").replace(".", "")
    for brand, official_domains in BRANDS.items():
        brand_compact = brand.replace("-", "")
        if brand_compact in host_compact and not any(
            host == domain or host.endswith("." + domain)
            for domain in official_domains
        ):
            add(25, f"The hostname may imitate the brand {brand.title()}.")
            break

    # URL shortener.
    if host in SHORTENERS:
        add(20, "The URL uses a link-shortening service that conceals its final destination.")

    # Domain ending.
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        add(15, f"The domain uses the potentially risky .{tld} ending.")

    # Plain HTTP.
    if parts.scheme.lower() == "http":
        add(5, "The URL uses HTTP rather than HTTPS; its connection is not encrypted by TLS.")

    # Account and verification terms.
    path_and_query = unquote(parts.path + "?" + parts.query).lower()
    matched_keywords = sorted(
        word for word in SUSPICIOUS_KEYWORDS
        if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", path_and_query)
    )
    if matched_keywords:
        add(
            min(15, 5 * len(matched_keywords)),
            "The URL contains account-related terms: " + ", ".join(matched_keywords) + ".",
        )

    # Email address embedded in the URL.
    if re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", normalised):
        add(10, "An email address appears inside the URL.")

    # Redirect parameter pointing elsewhere.
    redirect_found = False
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in REDIRECT_KEYS and (
            value.startswith(("http://", "https://", "//"))
        ):
            redirect_found = True
            break
    if redirect_found:
        add(15, "A query parameter contains another URL and may redirect elsewhere.")

    score = min(score, 100)

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append(
            "No warning signs covered by this rule set were detected. This is not a guarantee that the URL is safe."
        )

    precautions = [
        "Do not open unexpected links or attachments.",
        "Verify the sender through a separate, trusted channel.",
        "Report suspected phishing to your IT or security team.",
    ]

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "precautions": precautions,
    }
