# ANDS Tool Verification and Examples

This document provides guidance for verifying the **Athena Noesis Decimal System (ANDS)** tool scripts and explains the purpose of the included test example files.

---

## 1. Purpose

The ANDS tool suite includes three core verification utilities:

| Script | Purpose |
|--------|----------|
| `validate_declaration.py` | Validates ANDS declarations for schema compliance and Ed25519 signature integrity. |
| `ands_scan.py` | Scans AI system declarations, retrieves metadata, and performs network-based schema checks. |
| `render_report.py` | Converts validated declarations into formatted Markdown or HTML reports for compliance review. |

This folder (`/tests`) provides standardized test data and guidance to verify that these tools function correctly and consistently.

---

## 2. Test Data Overview

Example files are located in `/tests/examples/` and serve as standardized validation inputs.

| File | Description | Expected Outcome |
|------|--------------|------------------|
| `declaration_valid.json` | Properly formatted and signed ANDS declaration. | ✅ Should pass validation and render successfully. |
| `declaration_invalid.json` | Declaration with an invalid signature. | ❌ Should fail signature verification. |
| `declaration_malformed.json` | Intentionally malformed JSON (missing commas). | ❌ Should trigger a JSON parsing or validation error. |

These files allow both manual and automated verification workflows to confirm script integrity and behavior.

---

## 3. Verification Process

1. **Environment Setup**  
   Ensure all dependencies are installed:  
   ```bash
   pip install -r tools/requirements.txt
   ```

2. **Run the Validation Script**  
   ```bash
   python tools/validate_declaration.py tests/examples/declaration_valid.json
   ```

3. **Run the Scanner Script**  
   ```bash
   python tools/ands_scan.py tests/examples/declaration_valid.json
   ```

4. **Run the Report Renderer**  
   ```bash
   python tools/render_report.py tests/examples/declaration_valid.json
   ```

5. **Review Results**  
   Confirm that the outputs align with the expected outcomes listed above.

---

## 4. Expected Verification Behavior

| Condition | Expected Behavior |
|------------|------------------|
| Valid Declaration | Passes schema and signature validation; generates report. |
| Invalid Signature | Fails validation cleanly; reports signature mismatch. |
| Malformed JSON | Raises structured parsing error; process exits gracefully. |

---

## 5. Verification Report

Once tests are completed, results should be summarized in a top-level file named `verification_report.md` at the repository root.

Include the following information:
- Date and environment
- Script versions tested
- Summary of test inputs
- Pass/fail results
- Any observed issues or dependency gaps

A template for this report is provided as `verification_report.md` in the main repository.

---

## 6. Notes for Verifiers

- Avoid using live external URLs for scanning unless authorized.
- Mocked endpoints or included examples are preferred.
- Fix small dependency or syntax issues if encountered (e.g., missing `cryptography` library).
- Document all major findings in `verification_report.md`.

---

**Maintained by:** Athena Noesis Compliance & Standards Team  
**Version:** 1.0  
**License:** CC-BY-4.0