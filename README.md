# Phishing Email Detector

A lightweight, browser-only tool for reviewing email text for common phishing warning signs. Analysis happens locally in your browser; the app does not send email contents to a server.

## Run the app

No installation or build step is required. Open `index.html` in a modern browser, or serve this folder with any static web server.

## Use it

1. Paste an email, upload an `.eml` or `.txt` file, or select a sample.
2. Choose **Analyze Email** to see the findings, triage score, and recommendations.
3. Choose **Reset** to clear the current message and results.

The analyzer looks for signals such as sender-brand mismatches, reported email-authentication failures, unusual reply addresses, suspicious links, requests for sensitive information, payment-instruction changes, and potentially dangerous attachment names.

## Understanding results

The score is a heuristic triage aid, not a probability that an email is fraudulent:

| Score | Classification |
| --- | --- |
| 0 | No indicators matched |
| 1–19 | Low observed risk |
| 20–39 | Moderate observed risk |
| 40–69 | High observed risk |
| 70–100 | Critical observed risk |

Findings include the evidence detected, a severity, a confidence label, and their contribution to the score. A clean scan does **not** prove an email is safe. Verify unexpected requests using a contact method you already trust.

## Limitations

- This is a local, rule-based scan; it does not use a machine-learning model or a live reputation service.
- It does not perform DNS, URL reputation, domain registration, or mail-server checks.
- Authentication results in pasted headers cannot be independently verified and may be forged.
- Multipart email is not fully decoded. Encoded MIME parts, attachment contents, and malware are not inspected.
- Brand-domain checks cover only the small list built into the app and can produce false positives or miss impersonations.

## Project files

- `index.html` — page structure and input controls.
- `styles.css` — responsive layout and visual styles.
- `script.js` — email parsing, heuristic checks, scoring, and results rendering.
- `requirements.txt` — Python dependencies (none required).

