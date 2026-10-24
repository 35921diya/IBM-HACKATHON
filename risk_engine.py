
import ipaddress
import re
from urllib.parse import urlsplit

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "buff.ly", "ow.ly", "cutt.ly", "rb.gy"
}


def analyze_url(url: str) -> dict:
    score = 0
    findings = []
    recommendations = []

    def result():
        bounded_score = max(0, min(100, int(score)))

        if bounded_score < 20:
            level = "Low"
        elif bounded_score < 40:
            level = "Medium"
        elif bounded_score < 70:
            level = "High"
        else:
            level = "Critical"

        advice = [
            "Do not enter passwords or payment details unless you trust the destination.",
            "Verify unexpected links through the organisation's official website or app.",
            "A low score does not guarantee that a URL is safe."
        ]

        return {
            "score": bounded_score,
            "level": level,
            "findings": findings or [
                "No indicators covered by these checks were detected."
            ],
            "recommendations": recommendations or advice
        }

    if not isinstance(url, str) or not url.strip():
        score = 50
        findings.append("URL input is empty or is not text.")
        recommendations.append("Provide a valid URL for analysis.")
        return result()

    url = url.strip()

    if len(url) > 2048:
        score += 15
        findings.append("URL is unusually long.")

    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        score = max(score, 60)
        findings.append("URL contains control characters.")
        recommendations.append("Check the original text carefully.")
        return result()
        # Detect dangerous or unsupported schemes before checking for ://
    try:
        initial_scheme = urlsplit(url).scheme.lower()
    except ValueError:
        initial_scheme = ""

    if initial_scheme in {"javascript", "data", "file", "vbscript"}:
        score = 70
        findings.append(
            f"Non-web scheme '{initial_scheme}:' may refer to active "
            "content or a local resource."
        )
        recommendations.append(
            "Do not execute or open this content."
        )
        return result()

    candidate = url
    if "://" not in candidate:
        if re.match(r"^[A-Za-z0-9.-]+(?::\d+)?(?:[/?#].*)?$", candidate):
            candidate = "https://" + candidate
            findings.append("No scheme provided; parsed as HTTPS.")
            score += 3
        else:
            score = max(score, 55)
            findings.append("Malformed URL structure.")
            return result()

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        score = max(score, 55)
        findings.append("URL could not be parsed safely.")
        return result()

    scheme = parsed.scheme.lower()

    if scheme in {"javascript", "data", "file", "vbscript"}:
        score = max(score, 70)
        findings.append(
            f"Non-web scheme '{scheme}:' may refer to active content or local resources."
        )
        return result()

    if scheme not in {"http", "https"}:
        score = max(score, 45)
        findings.append("Unsupported or unusual URL scheme.")
        return result()

    if not parsed.hostname:
        score = max(score, 55)
        findings.append("URL has no valid hostname.")
        return result()

    try:
        port = parsed.port
    except ValueError:
        score = max(score, 55)
        findings.append("URL contains an invalid port.")
        return result()

    if parsed.username is not None or parsed.password is not None:
        score += 25
        findings.append(
            "User information before '@' may obscure the actual destination."
        )

    host = parsed.hostname.rstrip(".").lower()

    try:
        ipaddress.ip_address(host.strip("[]"))
        score += 20
        findings.append(
            "Host is a literal IP address rather than a conventional domain."
        )
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        score = max(score, 40)
        findings.append("Hostname could not be normalized reliably.")

    if "xn--" in host:
        score += 20
        findings.append(
            "Hostname contains a punycode label; inspect for look-alike characters."
        )

    if host in SHORTENERS:
        score += 15
        findings.append(
            "Known URL-shortening service hides the final destination."
        )

    if len(host.split(".")) >= 5:
        score += 10
        findings.append("Hostname has many subdomain labels.")

    if host.count("-") >= 3:
        score += 8
        findings.append("Hostname contains several hyphens.")

    if port is not None and port not in {80, 443}:
        score += 10
        findings.append("URL uses a non-default web port.")

    if scheme == "http":
        score += 8
        findings.append("URL uses HTTP rather than HTTPS.")

    if len(parsed.path) > 150:
        score += 5
        findings.append("URL path is unusually long.")

    if score >= 40:
        recommendations.append(
            "Avoid opening this URL until you have independently verified it."
        )

    return result()
