# PhishGuard
### GenAI-Enhanced Spear-Phishing and Quishing Detector

PhishGuard is a cybersecurity project designed to help users identify
potentially malicious emails, suspicious URLs, and QR-code-based phishing
attempts (quishing).

The project combines rule-based security checks, URL analysis, QR-code
decoding, and AI-assisted explanations to make suspicious content easier
to understand.

> **Project status:** Hackathon MVP in development.
> Detection results are indicators of risk, not guarantees that content
> is safe or malicious.

---

## 1. Problem Statement

Traditional phishing filters may fail to identify targeted phishing
messages that imitate trusted organizations, personalize their wording,
or direct victims to fraudulent websites.

QR-code phishing creates an additional challenge because a QR code can
hide a destination URL inside an image. Users may scan it without seeing
the destination beforehand.

PhishGuard aims to make these threats easier to inspect by combining
email analysis, URL risk indicators, QR-code decoding, and understandable
security recommendations.

## 2. Project Objectives

- Analyze pasted email content for suspicious characteristics.
- Identify potentially dangerous URLs and domain patterns.
- Decode QR codes from uploaded images and extract their destination.
- Present a risk score and explain the findings in understandable language.
- Recommend practical steps users can take when suspicious content is found.
- Provide a simple interface suitable for demonstrations and awareness.

## 3. Key Features

### Email Phishing Analysis
Accepts email text for inspection and identifies suspicious indicators,
such as urgency, requests for sensitive information, unusual links, and
other patterns supported by the implemented detector.

### URL Risk Analysis
Inspects extracted URLs for configured risk indicators. Depending on the
implemented checks, these may include suspicious URL structure, misleading
hostnames, unusual domain patterns, or other warning signs.

### QR-Code Analysis
Accepts a QR-code image, attempts to decode its contents, and extracts
the destination URL when one is present. The extracted URL can then be
passed to the URL risk engine.

### Risk Score and Findings
Presents a risk score from 0 to 100, a risk category, identified findings,
and recommended next steps.

### User Interface
The Streamlit interface is intended to bring the analysis results together
in one place, with clear risk indicators and readable explanations.

> Features depend on the final implementation and integration of the
> individual team modules.

## 4. How PhishGuard Works

```text
       User Input
           |
     +-----+------+
     |            |
 Email Text    QR Image
     |            |
     v            v
 Email         QR Decoder
 Analysis          |
     |             v
     |        Extracted URL
     |             |
     +------+\----+
             |
             v
       URL Risk Engine
             |
             v
     Findings and Score
             |
             v
    Risk Level and Advice
             |
             v
       Streamlit UI