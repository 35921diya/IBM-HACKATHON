"""PhishGuard - Streamlit dashboard (team lead + integration module).

This file only presents and integrates. All detection logic lives in the shared
modules and is never re-implemented here:

    risk_engine.analyze_url(url: str)        -> dict  (score, level, findings, recommendations)
    email_detector.analyze_email(text: str)  -> dict  (see "Proposed email contract" below)
    qr_detector.decode_qr(uploaded_file)     -> str | None

Proposed email contract (needs confirmation from the email_detector owner).
app.py reads these keys defensively and ignores any it does not find:

    {
        "urls": [                       # one entry per extracted URL
            {"url": str, "analysis": <dict returned by analyze_url(url)>},
            # a plain string is also accepted; app.py then calls analyze_url itself
        ],
        "findings": [str | dict],       # email-level indicators (optional)
        "recommendations": [str],       # email-level advice (optional)
        "score": int,                   # optional email-level score 0-100
        "level": str,                   # optional: Low | Medium | High | Critical
    }

If any shared module cannot be imported, a clearly labelled TEMPORARY MOCK is
used instead and a warning banner is shown. Delete a mock by adding the real file.

The app never opens, fetches or executes anything found in submitted content.
"""

from __future__ import annotations

import html
import logging
import re
from typing import Any

import streamlit as st

st.set_page_config(
    page_title="PhishGuard | Phishing & QR Inspector",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

logger = logging.getLogger("phishguard.app")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VALID_LEVELS = ("Low", "Medium", "High", "Critical")
LEVEL_RANK = {name: i for i, name in enumerate(VALID_LEVELS)}
# --- Shared theme constants (PhishGuard design lock). Change colours HERE only. ---
THEME = {
    "bg": "#071426",        # main background
    "sidebar": "#0A1B33",   # sidebar background
    "card": "#102542",      # card background
    "border": "#1E3A5F",    # card borders
    "accent": "#38BDF8",    # primary accent (electric sky blue)
    "accent2": "#3B82F6",   # secondary accent (bright blue)
    "text": "#F1F5F9",      # main text
    "muted": "#94A3B8",     # secondary text
}
LEVEL_COLORS = {
    "Low": "#22C55E",
    "Medium": "#EAB308",
    "High": "#F97316",
    "Critical": "#EF4444",
}
MAX_EMAIL_CHARS = 100_000
MAX_QR_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_DISPLAY_CHARS = 2_000
QR_TYPES = ["png", "jpg", "jpeg", "bmp", "webp"]
URL_LIKE = re.compile(r"^(?:https?://|www\.)\S+$", re.IGNORECASE)

DEFAULT_RECOMMENDATIONS = [
    "Do not click links or open attachments from messages you did not expect.",
    "Verify the sender through a separate, trusted channel (official website or phone number).",
    "Report suspected phishing to your IT or security team.",
]

# ---------------------------------------------------------------------------
# Shared module loading (real modules first, clearly labelled mocks as fallback)
# ---------------------------------------------------------------------------
MODULE_STATUS: dict[str, str] = {}

try:
    from risk_engine import analyze_url  # type: ignore

    MODULE_STATUS["risk_engine.py"] = "real"
except Exception as exc:  # missing file, syntax error, bad import inside module
    logger.warning("risk_engine unavailable, using MOCK: %s", exc)
    MODULE_STATUS["risk_engine.py"] = "MOCK"

    def analyze_url(url: str) -> dict:  # type: ignore[no-redef]
        """TEMPORARY MOCK. Replace by adding risk_engine.py. Not a real analysis."""
        return {
            "score": 0,
            "level": "Low",
            "findings": ["[MOCK] risk_engine.py not found - this URL was NOT analysed."],
            "recommendations": [],
        }


try:
    from email_detector import analyze_email  # type: ignore

    MODULE_STATUS["email_detector.py"] = "real"
except Exception as exc:
    logger.warning("email_detector unavailable, using MOCK: %s", exc)
    MODULE_STATUS["email_detector.py"] = "MOCK"

    def analyze_email(text: str) -> dict:  # type: ignore[no-redef]
        """TEMPORARY MOCK. Replace by adding email_detector.py. Only lists URLs."""
        found = re.findall(r"https?://[^\s<>\"']+", text, flags=re.IGNORECASE)
        unique = list(dict.fromkeys(found))
        return {
            "urls": [{"url": u, "analysis": analyze_url(u)} for u in unique],
            "findings": ["[MOCK] email_detector.py not found - no email-level analysis was done."],
            "recommendations": [],
        }


try:
    from qr_detector import decode_qr  # type: ignore

    MODULE_STATUS["qr_detector.py"] = "real"
except Exception as exc:
    logger.warning("qr_detector unavailable, using MOCK: %s", exc)
    MODULE_STATUS["qr_detector.py"] = "MOCK"

    def decode_qr(uploaded_file):  # type: ignore[no-redef]
        """TEMPORARY MOCK. Replace by adding qr_detector.py. Needs opencv if present."""
        try:
            import cv2  # type: ignore
            import numpy as np  # type: ignore

            data = np.frombuffer(uploaded_file.getvalue(), dtype=np.uint8)
            image = cv2.imdecode(data, cv2.IMREAD_COLOR)
            if image is None:
                return None
            text, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
            return text or None
        except Exception:
            return None


MOCKS_ACTIVE = [name for name, state in MODULE_STATUS.items() if state == "MOCK"]

# ---------------------------------------------------------------------------
# Demo samples (synthetic, non-routable ".example" domains)
# ---------------------------------------------------------------------------
SAMPLE_SUSPICIOUS = """From: "IT Support" <support@secure-m1crosoft-login.example>
Subject: URGENT: Your account will be suspended in 24 hours

Dear user,

We detected unusual sign-in activity on your account. Verify your password
immediately to avoid permanent suspension:

http://secure-m1crosoft-login.example/verify?user=you@company.com

Failure to act will result in loss of access.

IT Support Team
"""

SAMPLE_LEGITIMATE = """From: "Priya" <priya@company.example>
Subject: Notes from Tuesday's meeting

Hi team,

Thanks for joining. The slides are in the shared folder, and the installer
we discussed is available from https://www.python.org/downloads/ if you
need it on your laptop.

See you Thursday,
Priya
"""

# ---------------------------------------------------------------------------
# Styling (static CSS only; no user content is ever placed in it)
# ---------------------------------------------------------------------------
_CSS_TEMPLATE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* ---- Base: navy background, Inter with offline-safe fallbacks ---- */
html, body, .stApp, [data-testid="stAppViewContainer"] {
    background-color: __BG__; color: __TEXT__;
    font-family: 'Inter', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}
[data-testid="stHeader"] {background-color: __BG__;}
[data-testid="stSidebar"] {background-color: __SIDEBAR__; border-right: 1px solid __BORDER__;}
.block-container {padding-top: 1.6rem; max-width: 1180px;}

/* ---- Text ---- */
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5 {color: __TEXT__; font-family: inherit;}
.stApp p, .stApp li, .stApp label {color: __TEXT__;}
[data-testid="stCaptionContainer"], .stApp small {color: __MUTED__;}
.stApp a {color: __ACCENT__;}

/* ---- Buttons: blue accents ---- */
.stButton > button {
    background-color: __CARD__; color: __TEXT__; border: 1px solid __BORDER__; border-radius: 8px;
}
.stButton > button:hover {border-color: __ACCENT__; color: __ACCENT__;}
.stButton > button[kind="primary"], [data-testid="stBaseButton-primary"] {
    background-color: __ACCENT2__; border: 1px solid __ACCENT2__; color: #FFFFFF;
}
.stButton > button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover {
    background-color: __ACCENT__; border-color: __ACCENT__; color: __BG__;
}
.stButton button p {color: inherit;}

/* ---- Tabs: active tab uses the primary accent ---- */
button[data-baseweb="tab"] {color: __MUTED__;}
button[data-baseweb="tab"][aria-selected="true"] {color: __ACCENT__;}
button[data-baseweb="tab"] p {color: inherit;}
[data-baseweb="tab-highlight"] {background-color: __ACCENT__;}
[data-baseweb="tab-border"] {background-color: __BORDER__;}

/* ---- Inputs, uploader, expanders, code blocks ---- */
[data-baseweb="textarea"], [data-baseweb="base-input"] {background-color: __CARD__; border-color: __BORDER__;}
.stTextArea textarea {background-color: __CARD__; color: __TEXT__; border-radius: 8px;}
[data-baseweb="textarea"]:focus-within {border-color: __ACCENT__;}
[data-testid="stFileUploaderDropzone"] {
    background-color: __CARD__; border: 1px dashed __BORDER__; border-radius: 10px;
}
[data-testid="stExpander"], [data-testid="stExpander"] details {
    background-color: __CARD__; border-color: __BORDER__; border-radius: 10px;
}
[data-testid="stCode"] {border: 1px solid __BORDER__; border-radius: 8px;}
[data-testid="stCode"] pre, [data-testid="stCode"] code {background-color: __BG__; color: __TEXT__;}

/* ---- PhishGuard components: same card style everywhere ---- */
.pg-hero {
    background-color: __CARD__; border: 1px solid __BORDER__; border-left: 4px solid __ACCENT__;
    border-radius: 14px; padding: 1.3rem 1.6rem; margin-bottom: 1.2rem;
}
.stApp .pg-hero h1 {color: __TEXT__; margin: 0; font-size: 2rem; font-weight: 700; letter-spacing: -0.5px;}
.stApp .pg-hero p {color: __MUTED__; margin: 0.35rem 0 0 0; font-size: 1rem;}
.pg-panel {
    background-color: __CARD__; color: __TEXT__; border: 1px solid __BORDER__;
    border-radius: 14px; padding: 1.2rem; height: 100%;
}
.stApp .pg-panel h3 {color: __TEXT__; margin: 0.6rem 0 0.2rem 0; font-size: 1.15rem;}
.stApp .pg-panel .pg-note {color: __MUTED__; font-size: 0.85rem; margin-top: 0.6rem;}
.pg-gauge {
    width: 170px; height: 170px; border-radius: 50%; margin: 0.2rem auto 0.6rem auto;
    display: flex; align-items: center; justify-content: center;
    background: conic-gradient(var(--pg-color) calc(var(--pg-pct) * 1%), __BORDER__ 0);
}
.pg-gauge-inner {
    width: 130px; height: 130px; border-radius: 50%; background-color: __CARD__;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.pg-score {font-size: 2.8rem; font-weight: 700; line-height: 1; color: __TEXT__;}
.pg-outof {font-size: 0.8rem; color: __MUTED__;}
.pg-badge {
    display: inline-block; padding: 0.25rem 0.8rem; border-radius: 999px;
    font-weight: 600; color: __BG__; background-color: var(--pg-color);
}
.pg-item {
    background-color: __CARD__; border: 1px solid __BORDER__; border-left: 4px solid var(--pg-color);
    color: __TEXT__; padding: 0.55rem 0.8rem; border-radius: 8px; margin-bottom: 0.45rem;
    overflow-wrap: anywhere;
}
.pg-item small {color: __MUTED__;}
.pg-footer {
    margin-top: 2rem; padding-top: 0.8rem; border-top: 1px solid __BORDER__;
    font-size: 0.82rem; color: __MUTED__;
}
@media (max-width: 640px) {
    .stApp .pg-hero h1 {font-size: 1.5rem;}
    .pg-gauge {width: 140px; height: 140px;}
    .pg-gauge-inner {width: 106px; height: 106px;}
    .pg-score {font-size: 2.2rem;}
}
</style>
"""

APP_CSS = _CSS_TEMPLATE
for _key, _value in THEME.items():
    APP_CSS = APP_CSS.replace(f"__{_key.upper()}__", _value)

# ---------------------------------------------------------------------------
# Normalisation helpers (defensive: never trust shapes coming from other modules)
# ---------------------------------------------------------------------------


def clamp_score(value: Any) -> int:
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, score))


def level_from_score(score: int) -> str:
    """Fallback ONLY when a module omits a valid level. risk_engine owns the real thresholds."""
    if score < 25:
        return "Low"
    if score < 50:
        return "Medium"
    if score < 75:
        return "High"
    return "Critical"


def normalize_findings(items: Any) -> list[dict]:
    if items is None:
        return []
    if isinstance(items, (str, dict)):
        items = [items]
    out: list[dict] = []
    for item in items:
        severity = ""
        if isinstance(item, dict):
            text = (
                item.get("message")
                or item.get("description")
                or item.get("text")
                or item.get("finding")
                or ""
            )
            severity = str(item.get("severity") or item.get("level") or "")
            if not text:
                text = str(item)
        else:
            text = str(item)
        text = text.strip()
        if text:
            out.append({"text": text, "severity": severity})
    return out


def normalize_recommendations(items: Any) -> list[str]:
    if items is None:
        return []
    if isinstance(items, str):
        items = [items]
    return [str(i).strip() for i in items if str(i).strip()]


def normalize_result(raw: Any) -> dict:
    """Validate/clean an analyze_url() style dict. Raises ValueError if unusable."""
    if not isinstance(raw, dict) or "score" not in raw:
        raise ValueError("Result is not a dict containing a 'score' key.")
    score = clamp_score(raw.get("score"))
    level = raw.get("level")
    if level not in VALID_LEVELS:
        level = level_from_score(score)
    return {
        "score": score,
        "level": level,
        "findings": normalize_findings(raw.get("findings")),
        "recommendations": normalize_recommendations(raw.get("recommendations")),
    }


def run_url_analysis(url: str) -> dict:
    """Call the shared risk engine for one URL. Always returns {url, result, error}."""
    try:
        return {"url": url, "result": normalize_result(analyze_url(url)), "error": None}
    except Exception as exc:
        logger.exception("analyze_url failed")
        return {"url": url, "result": None, "error": f"Could not analyse this URL ({type(exc).__name__})."}


def normalize_email_output(raw: Any) -> dict:
    """Turn analyze_email() output into the structure the dashboard renders."""
    if not isinstance(raw, dict):
        raise ValueError("analyze_email() did not return a dict.")

    url_entries: list[dict] = []
    for item in raw.get("urls") or []:
        if isinstance(item, str):
            url_entries.append(run_url_analysis(item))
        elif isinstance(item, dict):
            url = str(item.get("url", "")).strip()
            analysis = item.get("analysis") or item.get("result") or item
            try:
                url_entries.append({"url": url, "result": normalize_result(analysis), "error": None})
            except ValueError:
                url_entries.append(run_url_analysis(url) if url else
                                   {"url": "", "result": None, "error": "Malformed URL entry."})

    email_result = None
    if "score" in raw:
        try:
            email_result = normalize_result(raw)
        except ValueError:
            email_result = None

    findings = normalize_findings(raw.get("findings"))
    recommendations = normalize_recommendations(raw.get("recommendations"))

    # Overall = highest of the email-level score and every successfully analysed URL.
    candidates: list[tuple[int, str]] = []
    if email_result:
        candidates.append((email_result["score"], email_result["level"]))
    for entry in url_entries:
        if entry["result"]:
            candidates.append((entry["result"]["score"], entry["result"]["level"]))
    if candidates:
        score, level = max(candidates, key=lambda c: (c[0], LEVEL_RANK[c[1]]))
    else:
        score, level = 0, "Low"

    merged_recs: list[str] = []
    for rec in recommendations + [r for e in url_entries if e["result"] for r in e["result"]["recommendations"]]:
        if rec not in merged_recs:
            merged_recs.append(rec)

    return {
        "score": score,
        "level": level,
        "scored": bool(candidates),
        "findings": findings,
        "recommendations": merged_recs,
        "urls": url_entries,
    }


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def shorten(text: str, limit: int = MAX_DISPLAY_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


def defang(url: str) -> str:
    """Make a URL non-clickable and safe to paste into reports."""
    return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE).replace(".", "[.]")


def render_summary(score: int, level: str, subject: str, scored: bool = True) -> None:
    color = LEVEL_COLORS[level]
    left, right = st.columns([1, 2])
    with left:
        st.markdown(
            f"""<div class="pg-panel" style="--pg-color:{color}; --pg-pct:{score};">
                <div class="pg-gauge"><div class="pg-gauge-inner">
                    <span class="pg-score">{score}</span><span class="pg-outof">/ 100</span>
                </div></div>
            </div>""",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            f"""<div class="pg-panel" style="--pg-color:{color};">
                <span class="pg-badge">{level} risk</span>
                <h3>{html.escape(subject)}</h3>
                <p class="pg-note">This is a rule-based heuristic score, not a probability that
                the content is malicious. A low score does not guarantee safety.</p>
            </div>""",
            unsafe_allow_html=True,
        )
    if not scored:
        st.info("No URLs or scored indicators were returned, so the score of 0 means nothing was "
                "evaluated. It is not an assurance that the message is safe.")


def render_items(title: str, findings: list[dict], color: str) -> None:
    st.markdown(f"#### {title}")
    if not findings:
        st.caption("Nothing detected by the current rules. This is not proof of safety.")
        return
    for finding in findings:
        sev = f" <small>({html.escape(finding['severity'])})</small>" if finding["severity"] else ""
        st.markdown(
            f'<div class="pg-item" style="--pg-color:{color};">{html.escape(finding["text"])}{sev}</div>',
            unsafe_allow_html=True,
        )


def render_recommendations(recs: list[str]) -> None:
    st.markdown("#### Recommended precautions")
    for rec in recs or DEFAULT_RECOMMENDATIONS:
        st.markdown(
            f'<div class="pg-item" style="--pg-color:{THEME["accent2"]};">{html.escape(rec)}</div>',
            unsafe_allow_html=True,
        )


def render_url_details(entries: list[dict]) -> None:
    st.markdown(f"#### Extracted URLs ({len(entries)})")
    if not entries:
        st.caption("No URLs were extracted from this input.")
        return
    for i, entry in enumerate(entries, start=1):
        result = entry["result"]
        label = f"URL {i}: {result['level']} risk ({result['score']}/100)" if result else f"URL {i}: analysis failed"
        with st.expander(label, expanded=(i == 1)):
            st.caption("Extracted URL (shown as text only, never opened or fetched)")
            st.code(shorten(entry["url"], 500) or "(empty)", language=None)
            st.caption("Defanged copy for safe sharing")
            st.code(shorten(defang(entry["url"]), 500) or "(empty)", language=None)
            if entry["error"]:
                st.warning(entry["error"])
                continue
            render_items("Findings", result["findings"], LEVEL_COLORS[result["level"]])
            if result["recommendations"]:
                st.markdown("**Advice for this URL**")
                for rec in result["recommendations"]:
                    st.markdown(f"- {rec}")


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------


def load_sample(sample: str) -> None:
    st.session_state["email_text"] = SAMPLE_SUSPICIOUS if sample == "suspicious" else SAMPLE_LEGITIMATE


def email_tab() -> None:
    st.subheader("Email Scanner")
    st.write("Paste the email text (headers are optional). PhishGuard extracts the links and "
             "inspects them without visiting any of them.")

    with st.expander("Demo samples (synthetic, for testing only)"):
        st.caption("These are made-up examples using reserved .example domains. Not real attacks.")
        c1, c2 = st.columns(2)
        c1.button("Load suspicious sample", on_click=load_sample, args=("suspicious",), use_container_width=True)
        c2.button("Load legitimate sample", on_click=load_sample, args=("legitimate",), use_container_width=True)

    text = st.text_area(
        "Email content",
        key="email_text",
        height=260,
        max_chars=MAX_EMAIL_CHARS,
        placeholder="Paste the suspicious email here...",
    )

    if not st.button("Analyze email", type="primary", key="analyze_email_btn"):
        return
    if not text or not text.strip():
        st.warning("Paste some email text first. The input is empty.")
        return

    try:
        with st.spinner("Inspecting email..."):
            view = normalize_email_output(analyze_email(text))
    except Exception as exc:
        logger.exception("analyze_email failed")
        st.error(f"The email could not be analysed ({type(exc).__name__}). "
                 "Check that the pasted text is plain email content and try again.")
        return

    if any(e["error"] for e in view["urls"]):
        st.warning("Some URLs could not be analysed. The overall score only covers the URLs that were.")

    render_summary(view["score"], view["level"], "Email assessment", view["scored"])
    st.write("")
    render_items("Email-level findings", view["findings"], LEVEL_COLORS[view["level"]])
    render_url_details(view["urls"])
    render_recommendations(view["recommendations"])
    with st.expander("Technical details"):
        st.json(view)


def qr_tab() -> None:
    st.subheader("QR Scanner")
    st.write("Upload a screenshot or photo of a QR code. PhishGuard reads the code and inspects the "
             "destination without opening it.")

    uploaded = st.file_uploader("QR code image", type=QR_TYPES, key="qr_upload")
    if uploaded is None:
        st.caption(f"Accepted formats: {', '.join(t.upper() for t in QR_TYPES)}. Maximum size 5 MB.")
        return

    if uploaded.size > MAX_QR_BYTES:
        st.error("That image is larger than 5 MB. Upload a smaller screenshot or crop closer to the QR code.")
        return

    try:
        st.image(uploaded, caption="Uploaded image", width=260)
    except Exception:
        st.error("This file could not be displayed as an image. Upload a valid PNG, JPG, BMP or WEBP file.")
        return

    if not st.button("Decode and analyze", type="primary", key="analyze_qr_btn"):
        return

    try:
        uploaded.seek(0)
        with st.spinner("Decoding QR code..."):
            decoded = decode_qr(uploaded)
    except Exception as exc:
        logger.exception("decode_qr failed")
        st.error(f"The image could not be processed ({type(exc).__name__}). Try a clearer image.")
        return

    if not decoded or not str(decoded).strip():
        st.warning("No QR code could be decoded. Use a sharper, well-lit image with the whole code in frame.")
        return

    decoded = str(decoded).strip()
    st.markdown("#### Decoded content")
    st.caption("Shown as text only. It was not opened or fetched.")
    st.code(shorten(decoded), language=None)

    if not URL_LIKE.match(decoded):
        st.warning("The QR code does not contain a web link, so it was not URL-scored. "
                   "Treat unexpected payloads (Wi-Fi settings, contacts, phone numbers, app links) with caution.")
        render_recommendations([])
        return

    entry = run_url_analysis(decoded)
    if entry["error"]:
        st.error(entry["error"])
        return

    result = entry["result"]
    render_summary(result["score"], result["level"], "QR destination assessment")
    st.write("")
    render_items("Findings", result["findings"], LEVEL_COLORS[result["level"]])
    st.markdown("#### Destination URL")
    st.code(shorten(decoded, 500), language=None)
    st.caption("Defanged copy for safe sharing")
    st.code(shorten(defang(decoded), 500), language=None)
    render_recommendations(result["recommendations"])
    with st.expander("Technical details"):
        st.json(entry)


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------


def sidebar() -> None:
    with st.sidebar:
        st.markdown("## PhishGuard 🔒")
        st.caption("Inspect suspicious emails and QR codes before you click or scan.")
        st.markdown("**How it stays safe**")
        st.markdown("- Links are never opened or fetched\n"
                    "- Submitted content is treated as untrusted\n"
                    "- Scores come from documented rules")
        st.markdown("**Module status**")
        for name, state in MODULE_STATUS.items():
            st.markdown(f"- `{name}`: {'✅ loaded' if state == 'real' else '⚠️ TEMPORARY MOCK'}")


def main() -> None:
    st.markdown(APP_CSS, unsafe_allow_html=True)
    sidebar()

    st.markdown(
        """<div class="pg-hero"><h1>PhishGuard 🔒</h1>
        <p>Spear-phishing and QR-code (quishing) inspector with an explainable 0-100 risk score.</p></div>""",
        unsafe_allow_html=True,
    )

    if MOCKS_ACTIVE:
        st.warning("Temporary mocks are active for: " + ", ".join(MOCKS_ACTIVE) +
                   ". Results are placeholders until the real modules are added.")

    tab_email, tab_qr = st.tabs(["Email Scanner", "QR Scanner"])
    with tab_email:
        email_tab()
    with tab_qr:
        qr_tab()

    st.markdown(
        """<div class="pg-footer">PhishGuard is a prototype built for a hackathon. It cannot guarantee
        detection of every attack, and a low score is not a guarantee of safety. When in doubt,
        do not click, and ask your security team.</div>""",
        unsafe_allow_html=True,
    )


main()