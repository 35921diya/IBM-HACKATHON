"""email_detector.py - PhishGuard email analysis module.

Public API
----------
analyze_email(text: str) -> dict

The function never raises, never makes network requests, never opens or
fetches URLs and never executes anything found in the email. All input is
treated as untrusted text. Every extracted http(s) URL is analysed through
``risk_engine.analyze_url(url)``.

Return structure (all keys are ALWAYS present)
----------------------------------------------
{
  # --- Same shape as risk_engine.analyze_url() so the UI can reuse one renderer
  "score": int,                # 0-100 overall heuristic score (NOT a probability)
  "level": str,                # "Low" | "Medium" | "High" | "Critical"
  "findings": list[str],       # human-readable explanations (email-level + risky links)
  "recommendations": list[str],

  # --- Email-specific additions
  "status": str,               # "ok" | "empty" | "error"  (check this before showing a score)
  "error": str | None,         # message when status != "ok"
  "email_score": int,          # 0-100, email wording/sender/link-text signals only
  "urls": list[dict],          # one entry per unique URL, in order of appearance:
        # {
        #   "url": str,                    # as found (www.* gets "http://" prefixed)
        #   "display_text": str | None,    # visible link text, if the link was HTML/Markdown
        #   "display_mismatch": bool,      # visible text names a different site than the target
        #   "analysis": dict | None,       # exact dict returned by risk_engine.analyze_url()
        #   "analysis_error": str | None,  # set (and analysis is None) if the call failed
        # }
  "indicators": list[dict],    # structured form of the email-level findings:
        # {"id": str, "category": str, "points": int, "message": str, "evidence": list[str]}
  "sender": dict,              # only fields present in pasted headers; None otherwise:
        # {"headers_provided": bool, "from_display_name", "from_address",
        #  "from_domain", "reply_to_address", "reply_to_domain"}
  "subject": str | None,       # from a pasted Subject header, if any
  "notes": list[str],          # limitations / uncertainty (not evidence), e.g. truncation
  "input_info": dict,          # {"original_length", "analyzed_length", "truncated",
                               #  "url_count", "urls_truncated"}
  "disclaimer": str,
}

Scoring (transparent heuristic, documented in README):
  email_score = min(100, sum of indicator points)
  score       = min(100, max(email_score, highest URL score)
                          + min(email_score, highest URL score) // 4)
  level       = Low <25, Medium 25-49, High 50-74, Critical >=75
A clean result is NOT a guarantee of safety.
"""

from __future__ import annotations

import html
import re
import unicodedata
from email.header import decode_header, make_header
from email.utils import parseaddr
from urllib.parse import urlsplit

import risk_engine

__all__ = ["analyze_email"]

# --------------------------------------------------------------------------
# Limits and constants
# --------------------------------------------------------------------------
MAX_INPUT_CHARS = 100_000   # longer input is truncated (and flagged)
MAX_URLS = 50               # unique URLs analysed per email
MAX_URL_LENGTH = 2048       # longer URLs are truncated before analysis
EVIDENCE_MAX_CHARS = 80

# Keep in sync with risk_engine.py (coordinate with the team lead).
LEVEL_THRESHOLDS = ((75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low"))
VALID_LEVELS = frozenset(name for _, name in LEVEL_THRESHOLDS)

DISCLAIMER = (
    "PhishGuard uses transparent heuristic rules. The score is a rough "
    "indicator, not a calibrated probability, and a low score does not "
    "guarantee that a message is safe."
)

_ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
_UNSAFE_SCHEMES = ("javascript:", "data:", "vbscript:")

# Free webmail providers (a fact about the provider type, not a reputation claim).
_FREE_WEBMAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.in", "aol.com", "icloud.com", "proton.me",
    "protonmail.com", "mail.com", "gmx.com", "rediffmail.com",
})

# TLDs recognised when looking for a domain inside link text / display names.
# A limited list avoids false positives such as "john.smith".
_COMMON_TLDS = (
    "com|net|org|edu|gov|mil|int|info|biz|io|co|in|uk|us|ca|au|de|fr|es|it|nl|"
    "ru|cn|jp|br|me|ai|app|dev|xyz|top|online|site|club|shop|store|live|tech|"
    "cloud|link|click|support|help|security|bank|finance|pay"
)

# --------------------------------------------------------------------------
# Regular expressions (all bounded to avoid pathological backtracking)
# --------------------------------------------------------------------------
_ANCHOR_RE = re.compile(
    r"<a\b[^<>]{0,500}?\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s<>\"']+))"
    r"[^<>]{0,500}>(.{0,300}?)</a\s*>",
    re.I | re.S,
)
_MD_LINK_RE = re.compile(r"\[([^\]\n]{1,200})\]\(\s*(https?://[^\s)]+)[^)]*\)", re.I)
_BARE_URL_RE = re.compile(r"(?i)(?<![\w@])(?:https?://|www\.)[^\s<>\"'`\\^{|}]+")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.{0,3000}?</\1\s*>", re.I | re.S)
_TAG_RE = re.compile(r"<[^<>]{0,1000}>")
_DOMAIN_RE = re.compile(
    r"(?i)\b(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s))\b" % _COMMON_TLDS
)
_GREETING_RE = re.compile(
    r"^\W*(?:dear|hello|hi)\s+(?:valued\s+|esteemed\s+)?"
    r"(?:customer|user|member|client|account\s*holder|sir|madam|friend|"
    r"email\s+user|webmail\s+user)\b",
    re.I,
)
_OFFICIAL_NAME_RE = re.compile(
    r"\b(?:support|security|help\s*desk|billing|payroll|admin(?:istrator)?|"
    r"customer\s+(?:care|service))\b",
    re.I,
)
_AUTH_FAIL_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(?:fail|softfail|permerror)\b", re.I)
_RECEIVED_SPF_FAIL_RE = re.compile(r"\s*(?:fail|softfail|permerror)\b", re.I)

_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]{0,40}):[ \t]*(.*)$")
_KNOWN_HEADERS = frozenset({
    "from", "to", "cc", "bcc", "reply-to", "return-path", "sender", "subject",
    "date", "message-id", "received", "received-spf", "authentication-results",
    "dkim-signature", "mime-version", "content-type", "content-transfer-encoding",
    "delivered-to", "list-unsubscribe",
})

# --------------------------------------------------------------------------
# Wording rules: (id, label, points if 1 pattern matched, points if >=2, patterns)
# A rule fires on the number of DISTINCT patterns matched, never on one keyword
# being conclusive. Points are small on purpose.
# --------------------------------------------------------------------------
_RULE_DEFS = (
    ("urgency_language", "Urgent or pressuring language", 6, 12, [
        r"\burgent(?:ly)?\b",
        r"\bimmediate(?:ly)?\b",
        r"\bact now\b",
        r"\bwithin (?:the next )?\d+ (?:hours?|minutes?|days?)\b",
        r"\bas soon as possible\b",
        r"\bfinal (?:notice|warning|reminder)\b",
        r"\blast (?:chance|warning)\b",
        r"\b(?:expires?|expiring) (?:today|soon|in \d+)",
        r"\bimmediate action (?:is )?required\b",
        r"\bfailure to (?:respond|comply|verify|act)\b",
    ]),
    ("threatening_language", "Threats or claims of an account problem", 6, 10, [
        r"\b(?:account|access|service|card|mailbox)\b[^.\n]{0,40}\b"
        r"(?:suspended|locked|disabled|closed|terminated|deactivated|restricted)\b",
        r"\b(?:will be|has been|have been|was) "
        r"(?:suspended|locked|disabled|closed|terminated|deactivated|restricted)\b",
        r"\blegal action\b",
        r"\bpermanently (?:deleted|closed|lost|disabled)\b",
        r"\bunauthori[sz]ed (?:access|activity|login|sign[- ]?in|transaction)\b",
        r"\bsuspicious (?:activity|login|sign[- ]?in)\b",
    ]),
    ("credential_request", "Request to verify, enter or send credentials or sensitive details", 15, 25, [
        r"\b(?:verify|confirm|validate|update|re-?enter|reset) your "
        r"(?:account|password|identity|login|credentials|payment|billing|bank|card|details|information)\b",
        r"\b(?:enter|provide|send|submit|share|reply with) your "
        r"(?:password|passcode|pin|otp|ssn|social security|card number|credit card|bank|login|credentials|username)\b",
        r"\b(?:one[- ]time (?:password|passcode|code)|verification code|security code|login credentials)\b",
    ]),
    ("financial_pressure", "Money, payment or reward lure", 8, 14, [
        r"\bgift cards?\b",
        r"\bwire transfer\b",
        r"\b(?:bitcoin|btc|crypto(?:currency)?|usdt)\b",
        r"\binvoice (?:is )?(?:attached|overdue)\b|\bunpaid invoice\b",
        r"\bpayment (?:is )?(?:overdue|failed|declined|required)\b",
        r"\bclaim your (?:prize|reward|refund|gift|winnings)\b",
        r"\byou(?:'ve| have) won\b",
        r"\bchange (?:of |in )?(?:bank|payment) (?:details|account|information)\b|\bnew (?:bank|account) details\b",
    ]),
    ("social_engineering", "Secrecy or unusual-request wording typical of impersonation (spear-phishing / BEC style)", 8, 14, [
        r"\bkeep this (?:confidential|private|between us)\b",
        r"\bdo not (?:discuss|share) this with\b",
        r"\bare you (?:available|at your desk)\b",
        r"\bi (?:need|have) (?:a quick )?(?:favor|favour|task)\b",
        r"\bi(?:'m| am) (?:in a meeting|unable to (?:talk|take calls))\b",
    ]),
    ("risky_attachment_wording", "Risky attachment or macro wording", 8, 14, [
        r"\benable (?:macros?|content|editing)\b",
        r"\b[\w\-]{1,60}\.(?:exe|scr|vbs|jar|iso|lnk|hta|docm|xlsm|pptm|zip|rar|7z|html?)\b",
        r"\bpassword[- ]protected\b",
    ]),
    ("qr_code_lure", "Prompt to scan a QR code (possible quishing)", 10, 14, [
        r"\bscan (?:the |this |our |my |your |attached |below |above )*(?:qr|bar ?code)",
        r"\bscan (?:it |this |the code )?(?:with|using) your (?:phone|camera|mobile|smartphone)\b",
    ]),
)
_TEXT_RULES = tuple(
    {"id": i, "label": lbl, "one": one, "many": many,
     "rx": [re.compile(p, re.I) for p in pats]}
    for i, lbl, one, many, pats in _RULE_DEFS
)

_RECOMMENDATION_BY_INDICATOR = {
    "credential_request": "Never enter passwords, one-time codes or payment details after following a link in an email; open the service by typing its known address yourself.",
    "financial_pressure": "Confirm any payment, refund or bank-detail request by phoning a number you already trust, not one given in the message.",
    "social_engineering": "If the message claims to come from someone you know, confirm by a separate channel (call or message them directly).",
    "risky_attachment_wording": "Do not open attachments or enable macros/content from unexpected emails.",
    "qr_code_lure": "Do not scan QR codes from this email with your phone; decode it in PhishGuard's QR Scanner first and do not visit the result blindly.",
    "display_text_mismatch": "Hover over links to see their real destination; the visible link text does not match where the link points.",
    "unsafe_link_scheme": "Do not click links in this message; some use script or data schemes that can run code in your browser.",
    "sender_display_name_mismatch": "Check the full sender address, not just the display name; display names are easy to fake.",
    "sender_free_webmail_official_name": "Check the full sender address, not just the display name; display names are easy to fake.",
    "reply_to_mismatch": "Replying would go to a different address than the sender; verify who you are writing to.",
    "authentication_failure": "The pasted headers report failed sender authentication; treat the sender identity as unverified.",
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _level_for(score: int) -> str:
    for threshold, name in LEVEL_THRESHOLDS:
        if score >= threshold:
            return name
    return "Low"


def _clip(value: str, limit: int = EVIDENCE_MAX_CHARS) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _indicator(ind_id: str, category: str, points: int, message: str, evidence=None) -> dict:
    return {
        "id": ind_id,
        "category": category,
        "points": int(points),
        "message": message,
        "evidence": list(evidence or []),
    }


def _finding_text(ind: dict) -> str:
    text = ind["message"]
    if ind["evidence"]:
        text += " Evidence: " + ", ".join('"%s"' % e for e in ind["evidence"]) + "."
    return text


def _result(status: str, error: str | None = None) -> dict:
    """A fully populated result skeleton (used for empty/error/normal results)."""
    return {
        "score": 0,
        "level": "Low",
        "findings": [],
        "recommendations": [],
        "status": status,
        "error": error,
        "email_score": 0,
        "urls": [],
        "indicators": [],
        "sender": {
            "headers_provided": False, "from_display_name": None, "from_address": None,
            "from_domain": None, "reply_to_address": None, "reply_to_domain": None,
        },
        "subject": None,
        "notes": [],
        "input_info": {
            "original_length": 0, "analyzed_length": 0, "truncated": False,
            "url_count": 0, "urls_truncated": False,
        },
        "disclaimer": DISCLAIMER,
    }


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:  # malformed URL, e.g. invalid IPv6 literal
        return None
    if not host:
        return None
    return host.rstrip(".").removeprefix("www.")


def _hosts_related(a: str, b: str) -> bool:
    a, b = a.removeprefix("www."), b.removeprefix("www.")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _domain_in_text(text: str) -> str | None:
    match = _DOMAIN_RE.search(text[:300])
    return match.group(1).lower().removeprefix("www.") if match else None


def _display_mismatch(label: str, url: str) -> bool:
    shown, target = _domain_in_text(label), _host(url)
    return bool(shown and target and not _hosts_related(shown, target))


def _visible(fragment: str) -> str:
    return _clip(html.unescape(_TAG_RE.sub(" ", fragment)), 300)


def _decode_header_value(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _parse_address(value: str):
    name, addr = parseaddr(_decode_header_value(value))
    addr = addr.strip().lower()
    domain = addr.rsplit("@", 1)[1].strip(".") if "@" in addr else None
    if domain and not re.fullmatch(r"[a-z0-9.-]+", domain):
        domain = None
    return name.strip(), (addr or None), domain


# --------------------------------------------------------------------------
# Header handling
# --------------------------------------------------------------------------
def _split_headers(text: str):
    """Return (headers, body). Headers are only recognised as a leading block of
    well-known header lines; otherwise the whole text is the body."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    headers: dict[str, list[str]] = {}
    current = None
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            break  # blank line ends the header block
        m = _HEADER_RE.match(line)
        if m and (m.group(1).lower() in _KNOWN_HEADERS or m.group(1).lower().startswith("x-")):
            current = m.group(1).lower()
            headers.setdefault(current, []).append(m.group(2).strip())
        elif line[0] in " \t" and current:
            headers[current][-1] += " " + line.strip()  # folded header line
        else:
            break  # no blank line: the body starts here
        i += 1
    if not headers:
        return {}, text
    return headers, "\n".join(lines[i:])


def _sender_info(headers: dict):
    info = {
        "headers_provided": bool(headers), "from_display_name": None, "from_address": None,
        "from_domain": None, "reply_to_address": None, "reply_to_domain": None,
    }
    indicators = []
    if not headers:
        return info, indicators

    from_domain = None
    if headers.get("from"):
        name, addr, from_domain = _parse_address(headers["from"][0])
        info.update(from_display_name=name or None, from_address=addr, from_domain=from_domain)
        shown = _domain_in_text(name) if name else None
        if shown and from_domain and not _hosts_related(shown, from_domain):
            indicators.append(_indicator(
                "sender_display_name_mismatch", "sender", 20,
                "The sender's display name contains a different domain than the actual sending address.",
                [_clip('%s <%s>' % (name, addr))],
            ))
        elif name and from_domain in _FREE_WEBMAIL and _OFFICIAL_NAME_RE.search(name):
            indicators.append(_indicator(
                "sender_free_webmail_official_name", "sender", 8,
                "An official-sounding display name is used with a free webmail address. "
                "This can be legitimate, but organisations normally send from their own domain.",
                [_clip('%s <%s>' % (name, addr))],
            ))

    if headers.get("reply-to"):
        _, r_addr, r_domain = _parse_address(headers["reply-to"][0])
        info.update(reply_to_address=r_addr, reply_to_domain=r_domain)
        if r_domain and from_domain and not _hosts_related(r_domain, from_domain):
            indicators.append(_indicator(
                "reply_to_mismatch", "sender", 12,
                "The Reply-To domain differs from the From domain, so replies go somewhere other than the apparent sender. "
                "Some legitimate services do this.",
                ["From: %s / Reply-To: %s" % (from_domain, r_domain)],
            ))

    failures = {m.group(1).lower() for m in _AUTH_FAIL_RE.finditer(" ".join(headers.get("authentication-results", [])))}
    if any(_RECEIVED_SPF_FAIL_RE.match(v) for v in headers.get("received-spf", [])):
        failures.add("spf")
    if failures:
        points = min(25, 15 + 5 * (len(failures) - 1))
        indicators.append(_indicator(
            "authentication_failure", "sender", points,
            "The pasted headers report failed sender authentication. These headers were not independently verified and can be edited.",
            sorted(failures),
        ))
    return info, indicators


# --------------------------------------------------------------------------
# URL extraction (text only - nothing is ever fetched)
# --------------------------------------------------------------------------
def _candidate(value: str) -> str | None:
    value = value.strip()
    if re.match(r"(?i)https?://", value):
        return value
    if value.lower().startswith("www."):
        return "http://" + value
    return None


def _trim_url(url: str) -> str:
    closers = {")": "(", "]": "[", "}": "{"}
    while url:
        last = url[-1]
        if last in ".,;:!?'\"*":
            url = url[:-1]
        elif last in closers and url.count(last) > url.count(closers[last]):
            url = url[:-1]
        else:
            break
    return url


def _extract_links(body: str):
    """Return ([(url, visible_text_or_None), ...], [unsafe_href, ...])."""
    links, unsafe = [], []
    for m in _ANCHOR_RE.finditer(body):
        href = html.unescape(m.group(1) or m.group(2) or m.group(3) or "").strip()
        label = _visible(m.group(4))
        if re.sub(r"[\x00-\x20]", "", href).lower().startswith(_UNSAFE_SCHEMES):
            unsafe.append(_clip(href, 60))
            continue
        url = _candidate(href)
        if url:
            links.append((url, label))
    rest = _ANCHOR_RE.sub(" ", body)
    for m in _MD_LINK_RE.finditer(rest):
        url = _candidate(m.group(2))
        if url:
            links.append((url, m.group(1)))
    rest = _MD_LINK_RE.sub(" ", rest)
    for m in _BARE_URL_RE.finditer(rest):
        url = _candidate(_trim_url(m.group(0)))
        if url:
            links.append((url, None))
    return links, unsafe


def _safe_analyze(url: str):
    """Call risk_engine.analyze_url defensively. Returns (analysis, error)."""
    try:
        result = risk_engine.analyze_url(url)
    except Exception as exc:
        return None, "URL analysis failed (%s)." % type(exc).__name__
    if (not isinstance(result, dict)
            or not isinstance(result.get("score"), int) or isinstance(result.get("score"), bool)
            or result.get("level") not in VALID_LEVELS
            or not isinstance(result.get("findings"), list)
            or not isinstance(result.get("recommendations"), list)):
        return None, "URL analysis returned an unexpected structure."
    result = dict(result)
    result["score"] = max(0, min(100, result["score"]))
    return result, None


# --------------------------------------------------------------------------
# Text indicators
# --------------------------------------------------------------------------
def _visible_text(body: str) -> str:
    text = _SCRIPT_STYLE_RE.sub(" ", body)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return _MD_LINK_RE.sub(r" \1 ", text)


def _text_indicators(scan_text: str):
    indicators, matched_ids = [], []
    for rule in _TEXT_RULES:
        evidence = []
        for rx in rule["rx"]:
            m = rx.search(scan_text)
            if m:
                snippet = _clip(m.group(0))
                if snippet not in evidence:
                    evidence.append(snippet)
        count = sum(1 for rx in rule["rx"] if rx.search(scan_text))
        if not count:
            continue
        matched_ids.append(rule["id"])
        indicators.append(_indicator(
            rule["id"], "wording", rule["many"] if count >= 2 else rule["one"],
            "%s (%d pattern%s matched). Wording alone is not proof; legitimate messages can use it too."
            % (rule["label"], count, "" if count == 1 else "s"),
            evidence,
        ))
    if len(matched_ids) >= 3:
        indicators.append(_indicator(
            "multiple_wording_categories", "wording", 10,
            "Several different kinds of phishing wording appear together (%s). "
            "A combination is more meaningful than any single phrase." % ", ".join(matched_ids),
        ))
    return indicators


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------
def analyze_email(text: str) -> dict:
    """Analyse pasted email text. See the module docstring for the return structure.

    Never raises; problems are reported through ``status`` / ``error``.
    """
    try:
        return _analyze(text)
    except Exception as exc:  # defensive: the UI must never crash on odd input
        res = _result("error", "Unexpected error while analysing the email (%s)." % type(exc).__name__)
        res["recommendations"] = ["Try again with plain-text email content."]
        return res


def _analyze(text) -> dict:
    if text is None or (isinstance(text, str) and not text.strip()):
        res = _result("empty", "No email text was provided.")
        res["recommendations"] = ["Paste the full email text (headers are optional but useful) and try again."]
        return res
    if not isinstance(text, str):
        res = _result("error", "Input must be text (str).")
        res["recommendations"] = ["Provide the email content as plain text."]
        return res

    original_length = len(text)
    text = text.replace("\x00", " ")
    truncated = len(text) > MAX_INPUT_CHARS
    if truncated:
        text = text[:MAX_INPUT_CHARS]
    text = unicodedata.normalize("NFKC", text)
    for ch in _ZERO_WIDTH:  # hidden characters can split keywords to evade matching
        text = text.replace(ch, "")

    headers, body = _split_headers(text)
    subject = _clip(headers["subject"][0], 200) if headers.get("subject") else None
    notes: list[str] = []

    # ---- URL extraction and analysis --------------------------------------
    links, unsafe_hrefs = _extract_links(body)
    entries: dict[str, dict] = {}
    urls_truncated = long_urls = 0
    for url, label in links:
        if len(url) > MAX_URL_LENGTH:
            url, long_urls = url[:MAX_URL_LENGTH], long_urls + 1
        entry = entries.get(url)
        if entry is None:
            if len(entries) >= MAX_URLS:
                urls_truncated = True
                continue
            entry = entries[url] = {"url": url, "display_text": None, "display_mismatch": False}
        if label:
            if _display_mismatch(label, url) and not entry["display_mismatch"]:
                entry["display_mismatch"], entry["display_text"] = True, _clip(label, 120)
            elif entry["display_text"] is None and not entry["display_mismatch"]:
                entry["display_text"] = _clip(label, 120)
    url_entries = list(entries.values())
    for entry in url_entries:
        entry["analysis"], entry["analysis_error"] = _safe_analyze(entry["url"])

    # ---- Email-level indicators --------------------------------------------
    visible = _visible_text(body)
    scan_text = _BARE_URL_RE.sub(" ", (subject or "") + "\n" + visible)  # URLs are scored by risk_engine
    indicators = _text_indicators(scan_text)

    first_lines = [ln.strip() for ln in visible.splitlines() if ln.strip()][:5]
    if any(_GREETING_RE.search(ln) for ln in first_lines):
        indicators.append(_indicator(
            "generic_greeting", "wording", 4,
            "Generic greeting instead of your name. Weak signal; many bulk senders do this legitimately.",
            [first_lines[0]],
        ))

    sender, sender_inds = _sender_info(headers)
    indicators.extend(sender_inds)
    if not headers:
        notes.append("No sender headers were recognised in the pasted text, so sender checks were skipped.")

    mismatches = [e for e in url_entries if e["display_mismatch"]]
    if mismatches:
        indicators.append(_indicator(
            "display_text_mismatch", "link", min(35, 25 + 5 * (len(mismatches) - 1)),
            "Visible link text shows a different website than the link actually points to (%d link%s)."
            % (len(mismatches), "" if len(mismatches) == 1 else "s"),
            [_clip('"%s" -> %s' % (e["display_text"], e["url"]), 140) for e in mismatches[:3]],
        ))
    if unsafe_hrefs:
        indicators.append(_indicator(
            "unsafe_link_scheme", "link", 20,
            "A link uses a script or data scheme (javascript:, data: or vbscript:) instead of a normal web address. These links were not opened or analysed further.",
            unsafe_hrefs[:3],
        ))

    indicators.sort(key=lambda i: -i["points"])

    # ---- Scoring -------------------------------------------------------------
    email_score = min(100, sum(i["points"] for i in indicators))
    url_scores = [e["analysis"]["score"] for e in url_entries if e["analysis"]]
    url_max = max(url_scores, default=0)
    score = min(100, max(email_score, url_max) + min(email_score, url_max) // 4)
    level = _level_for(score)

    # ---- Findings, notes and recommendations ---------------------------------
    findings = [_finding_text(i) for i in indicators]
    for e in sorted((e for e in url_entries if e["analysis"]), key=lambda e: -e["analysis"]["score"]):
        if e["analysis"]["score"] >= LEVEL_THRESHOLDS[2][0]:
            findings.append("Link %s scored %d (%s) in URL analysis."
                            % (_clip(e["url"], 100), e["analysis"]["score"], e["analysis"]["level"]))

    failed = sum(1 for e in url_entries if e["analysis_error"])
    if failed:
        notes.append("%d link(s) could not be analysed, so the score may underestimate the risk." % failed)
    if truncated:
        notes.append("The input was longer than %d characters; only the first %d were analysed." % (MAX_INPUT_CHARS, MAX_INPUT_CHARS))
    if urls_truncated:
        notes.append("More than %d unique URLs were found; only the first %d were analysed." % (MAX_URLS, MAX_URLS))
    if long_urls:
        notes.append("%d URL(s) longer than %d characters were truncated before analysis." % (long_urls, MAX_URL_LENGTH))
    if not url_entries:
        notes.append("No http(s) links were found in the text; bare domains without a scheme are not extracted.")
    if not indicators and not any(e["analysis"] and e["analysis"]["score"] for e in url_entries):
        notes.append("No phishing indicators were detected by these heuristics. This is not a guarantee of safety.")

    recs: list[str] = []

    def add(rec: str) -> None:
        if rec not in recs:
            recs.append(rec)

    if score >= LEVEL_THRESHOLDS[2][0]:
        add("Do not click links, scan QR codes or open attachments in this message until the sender is verified through a separate, trusted channel.")
    for ind in indicators:
        if ind["id"] in _RECOMMENDATION_BY_INDICATOR:
            add(_RECOMMENDATION_BY_INDICATOR[ind["id"]])
    url_recs = 0
    for e in sorted((e for e in url_entries if e["analysis"]), key=lambda e: -e["analysis"]["score"]):
        for rec in e["analysis"]["recommendations"]:
            if isinstance(rec, str) and rec not in recs and url_recs < 6:
                recs.append(rec)
                url_recs += 1
    if score >= LEVEL_THRESHOLDS[1][0]:
        add("Report the message to your IT/security team or email provider, then delete it.")
    add("Verify unexpected requests with the sender using a contact method you already trust. A low score is not a guarantee of safety.")

    res = _result("ok")
    res.update(
        score=score, level=level, findings=findings, recommendations=recs,
        email_score=email_score, urls=url_entries, indicators=indicators,
        sender=sender, subject=subject, notes=notes,
        input_info={
            "original_length": original_length, "analyzed_length": len(text),
            "truncated": truncated, "url_count": len(url_entries), "urls_truncated": bool(urls_truncated),
        },
    )
    return res
