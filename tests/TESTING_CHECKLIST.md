# PhishGuard - Testing Checklist

## 1. Purpose

This checklist is maintained by Member 5 for quality assurance of the
PhishGuard cybersecurity hackathon project.

It helps the team verify individual modules, application integration,
error handling, user experience, and repository readiness before the
final demonstration.

**Testing status:** Not started

**Rule:** Mark a test as PASS only after performing it and confirming
the expected result. Record failures and retest after fixes.

---

## 2. Test Environment

Record the environment used for testing.

- Operating system: ____________________
- Python version: ____________________
- Browser: ____________________
- Test date: ____________________
- Git commit or version: ____________________

### Environment checks

| ID | Test | Expected result | Status |
|---|---|---|---|
| ENV-01 | Activate the Python virtual environment | Environment activates without errors | NOT TESTED |
| ENV-02 | Install dependencies from requirements.txt | Installation completes successfully | NOT TESTED |
| ENV-03 | Confirm required project modules exist | Expected files are present | NOT TESTED |
| ENV-04 | Start the Streamlit application | Application starts without import errors | NOT TESTED |

---

## 3. Email Detector Tests

Perform these tests after email_detector.py is available and integrated.

| ID | Test input | Expected result | Status |
|---|---|---|---|
| EMAIL-01 | Empty email input | Clear validation message or safe empty-input handling | NOT TESTED |
| EMAIL-02 | Ordinary legitimate-looking email | Detector returns a result without crashing | NOT TESTED |
| EMAIL-03 | Synthetic email containing urgent payment demands | Relevant suspicious indicators are identified when supported | NOT TESTED |
| EMAIL-04 | Synthetic email requesting a password | Relevant credential-request warning is reported when supported | NOT TESTED |
| EMAIL-05 | Email containing a suspicious URL | URL or link indicator is identified when supported | NOT TESTED |
| EMAIL-06 | Very long email body | Input is handled without an unhandled exception | NOT TESTED |
| EMAIL-07 | Email containing unusual punctuation or symbols | Input is processed safely | NOT TESTED |
| EMAIL-08 | Malformed or incomplete email text | Detector handles the input gracefully | NOT TESTED |

Use synthetic test emails. Do not include real passwords, private messages,
or personal information in test samples.

---

## 4. URL Risk Engine Tests

Perform these tests after risk_engine.py is available.

| ID | Test input | Expected result | Status |
|---|---|---|---|
| URL-01 | Empty URL | Clear validation or safe error handling | NOT TESTED |
| URL-02 | A well-formed HTTPS URL | URL is processed and a result is returned | NOT TESTED |
| URL-03 | A malformed URL | Invalid input is handled without crashing | NOT TESTED |
| URL-04 | A URL containing an IP address as its host | Relevant indicator is reported if the engine checks for it | NOT TESTED |
| URL-05 | A URL containing an unusual hostname or subdomain pattern | Relevant warning is reported if supported | NOT TESTED |
| URL-06 | A URL containing a misleading-looking path | Engine evaluates only the indicators it actually implements | NOT TESTED |
| URL-07 | URL with query parameters | URL is processed safely | NOT TESTED |
| URL-08 | URL with unusual characters | Input is handled without an unhandled exception | NOT TESTED |
| URL-09 | URL with no scheme | Engine handles or validates it consistently | NOT TESTED |
| URL-10 | URL containing a very long string | Input does not crash the application | NOT TESTED |

Do not open or visit suspicious URLs during manual testing. Use test strings
and controlled examples. A URL pattern alone does not prove maliciousness.

---

## 5. QR-Code Detector Tests

Perform these tests after qr_detector.py is available.

| ID | Test input | Expected result | Status |
|---|---|---|---|
| QR-01 | Valid QR image containing a test URL | URL is decoded successfully | NOT TESTED |
| QR-02 | Valid QR image containing ordinary text | Decoded text is returned safely | NOT TESTED |
| QR-03 | Image containing no QR code | Clear no-code result or safe error handling | NOT TESTED |
| QR-04 | Blurry or damaged QR image | Graceful failure or successful decoding if possible | NOT TESTED |
| QR-05 | Unsupported file type | File is rejected or handled safely | NOT TESTED |
| QR-06 | Empty upload | Clear validation message | NOT TESTED |
| QR-07 | Very large image | Application handles it safely or rejects it with a message | NOT TESTED |
| QR-08 | QR image containing a suspicious-looking URL | Extracted content is passed for analysis without being opened | NOT TESTED |

Only use test QR images or images you are authorized to inspect. Decoding a
QR code must not automatically navigate to its destination.

---

## 6. Streamlit Interface Tests

Perform these tests after the main application is integrated.

| ID | Test | Expected result | Status |
|---|---|---|---|
| UI-01 | Launch the application | Main page loads successfully | NOT TESTED |
| UI-02 | Inspect page headings and navigation | Text and controls are readable | NOT TESTED |
| UI-03 | Submit valid email text | Email analysis result is displayed | NOT TESTED |
| UI-04 | Submit empty email text | Helpful validation is displayed | NOT TESTED |
| UI-05 | Upload a valid QR image | Decoded content or a clear result is displayed | NOT TESTED |
| UI-06 | Upload an invalid image | User receives a useful error message | NOT TESTED |
| UI-07 | Review the result panel | Score, category, findings, and recommendations are consistent with module output | NOT TESTED |
| UI-08 | Resize the browser window | Important controls and results remain usable | NOT TESTED |
| UI-09 | Trigger a module error | The interface handles the error without exposing a traceback to ordinary users | NOT TESTED |
| UI-10 | Review the colour contrast | Text and risk indicators remain distinguishable | NOT TESTED |

---

## 7. Integration Tests

Run these tests once the team has combined its modules.

| ID | Test | Expected result | Status |
|---|---|---|---|
| INT-01 | Import each required module | Imports complete without errors | NOT TESTED |
| INT-02 | Pass email input from the UI to the email detector | Correct function receives the input | NOT TESTED |
| INT-03 | Pass decoded QR content to URL analysis when appropriate | Extracted URL reaches the URL risk engine | NOT TESTED |
| INT-04 | Return a URL risk result to the UI | Result fields display correctly | NOT TESTED |
| INT-05 | Analyse multiple inputs in sequence | Results do not incorrectly carry over between submissions | NOT TESTED |
| INT-06 | Trigger a detector error | Error is handled without crashing the entire interface | NOT TESTED |
| INT-07 | Check result data types | Score, level, findings, and recommendations use the agreed schema | NOT TESTED |
| INT-08 | Test an input containing no URL | Application handles the case consistently | NOT TESTED |

Expected shared URL risk result:

- score: integer from 0 to 100
- level: risk category string
- findings: list of detected indicators
- recommendations: list of suggested next steps

The final category names and score bands must match the implementation.

---

## 8. Security and Privacy Checks

| ID | Check | Expected result | Status |
|---|---|---|---|
| SEC-01 | Inspect Git-tracked files for real API keys | No real secrets are committed | NOT TESTED |
| SEC-02 | Check .gitignore | Local environment and sensitive files are excluded appropriately | NOT TESTED |
| SEC-03 | Submit a suspicious URL | Application analyses it without automatically opening it | NOT TESTED |
| SEC-04 | Upload an invalid file | Input is handled safely | NOT TESTED |
| SEC-05 | Review displayed findings | Results do not claim guaranteed detection | NOT TESTED |
| SEC-06 | Review error messages | Sensitive configuration values are not exposed | NOT TESTED |
| SEC-07 | Review external API usage, if implemented | Requests follow the project's documented configuration and limitations | NOT TESTED |

Never commit actual credentials in .env.example or any other tracked file.

---

## 9. Documentation and GitHub Checks

| ID | Check | Expected result | Status |
|---|---|---|---|
| DOC-01 | Review README setup instructions | Instructions match the repository | NOT TESTED |
| DOC-02 | Review dependency list | Dependencies match the modules actually used | NOT TESTED |
| DOC-03 | Review repository structure | Documented file names match the final project | NOT TESTED |
| DOC-04 | Review screenshots | Screenshots show the real application, not mock results presented as actual output | NOT TESTED |
| DOC-05 | Review contribution section | Team roles accurately reflect actual contributions | NOT TESTED |
| DOC-06 | Review project status | Only completed and verified work is marked complete | NOT TESTED |
| DOC-07 | Check Git status | No unintended files are included | NOT TESTED |
| DOC-08 | Review commit contents | No virtual environment, secrets, or unnecessary generated files are committed | NOT TESTED |

---

## 10. Defect Log

Record issues found during testing.

| Issue ID | Test ID | Description | Severity | Status |
|---|---|---|---|---|
| BUG-001 | | | | Open |
| BUG-002 | | | | Open |
| BUG-003 | | | | Open |

Suggested severity levels:

- **Critical:** Application cannot run or a major security issue exists.
- **High:** A core feature fails.
- **Medium:** A feature works incorrectly in some cases.
- **Low:** Minor display, wording, or usability issue.

For each defect, record the steps to reproduce it, expected behaviour,
actual behaviour, and whether the fix has been retested.

---

## 11. Final QA Summary

Complete this section before the final demonstration.

- Total tests performed: __________
- Tests passed: __________
- Tests failed: __________
- Tests blocked or not applicable: __________
- Open critical or high-severity issues: __________
- Final QA date: __________
- QA notes: ______________________________________________

### Final readiness checklist

- [ ] Application launches successfully.
- [ ] Email analysis has been tested.
- [ ] QR decoding has been tested.
- [ ] URL analysis has been tested.
- [ ] Integrated result display has been tested.
- [ ] Errors and invalid inputs have been checked.
- [ ] No real secrets are committed.
- [ ] README instructions have been verified.
- [ ] Actual application screenshots have been added.
- [ ] Known limitations are documented.
- [ ] Final demonstration has been rehearsed.

**Important:** Do not mark the project as fully tested until the relevant
checks have actually been performed.