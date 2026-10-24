"""try_email_detector.py - LOCAL DEMO ONLY (do not commit, do not give to the team).

Lets you run and see email_detector.py before Member 1's risk_engine.py exists.
If the real risk_engine.py is in the folder it is used; otherwise a tiny
stand-in URL checker is used so you can still see the output.

Run:  python try_email_detector.py
"""
import sys
import types

try:
    import risk_engine  # real one from Member 1
    USING = "REAL risk_engine.py"
except ImportError:
    stub = types.ModuleType("risk_engine")

    def _stand_in(url):
        risky = any(w in url.lower() for w in ("login", "verify", "secure", "update"))
        return {"score": 60 if risky else 5, "level": "High" if risky else "Low",
                "findings": ["(stand-in checker) URL contains a risky word"] if risky else [],
                "recommendations": ["(stand-in checker) Do not open this link."]}

    stub.analyze_url = _stand_in
    sys.modules["risk_engine"] = stub
    USING = "STAND-IN link checker (real risk_engine.py not found)"

from email_detector import analyze_email  # noqa: E402

SAMPLES = {
    "SUSPICIOUS EMAIL": (
        'From: "PayPal Support" <alerts@secure-mail.example>\n'
        "Reply-To: help@other-domain.example\n"
        "Subject: URGENT: account suspended\n\n"
        "Dear customer,\n\n"
        "Your account will be suspended within 24 hours. Verify your password immediately:\n"
        '<a href="http://evil-login.example/paypal">https://www.paypal.com/signin</a>\n'
    ),
    "NORMAL EMAIL": (
        "From: Priya Nair <priya.nair@acme-corp.example>\n"
        "Subject: Team lunch on Friday\n\n"
        "Hi team,\n\nLunch is on Friday at 1 pm. Menu: https://acme-corp.example/menu\nThanks, Priya\n"
    ),
    "EMAIL WITHOUT LINKS": "URGENT: verify your password immediately or your account will be suspended.",
    "EMPTY INPUT": "   ",
}

print("Using:", USING)
for title, text in SAMPLES.items():
    r = analyze_email(text)
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    if r["status"] != "ok":
        print("Status:", r["status"], "-", r["error"])
        continue
    print("Score:", r["score"], "/ 100   Level:", r["level"])
    print("\nWarning signs:")
    for f in r["findings"] or ["(none detected - not a guarantee of safety)"]:
        print(" -", f)
    print("\nURLs found:", len(r["urls"]))
    for u in r["urls"]:
        a = u["analysis"]
        print(" -", u["url"], "->", (str(a["score"]) + " (" + a["level"] + ")") if a else "not analysed")
    print("\nRecommendations:")
    for rec in r["recommendations"]:
        print(" -", rec)
