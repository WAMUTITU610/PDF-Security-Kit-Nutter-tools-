# PDF-Security-Kit-Nutter-tools-
# PDF Static Analysis Tool 

A Python-based **static** scanner for PDFs that performs quick forensic triage: metadata checks, entropy estimation, suspicious keyword/obfuscation heuristics, IOC extraction, optional PDF structure scraping, and JSON reporting.

> Note: This tool is for **defensive analysis** and triage. Always follow legal/organizational rules.

---

## What it detects

- **File metadata & validation**
  - Confirms PDF header (`%PDF`)
  - Uses `python-magic` (if installed) for MIME type
  - Computes **MD5 / SHA-1 / SHA-256**
- **Entropy scoring** (Shannon entropy) to highlight likely compression/encryption
- **Embedded content heuristics**
  - Extracts raw printable strings and matches them against suspicious keyword weights (e.g., `openaction`, `launch`, `javascript`, `eval`, `powershell`, etc.)
  - Finds common **obfuscation indicators** (e.g., `\\x..` hex escapes, `\\u....` sequences, `eval(`, `fromCharCode(`, long repeated NOP patterns, large base64-like blobs)
- **IOC extraction**
  - URL, IP, domain, email patterns
  - Base64 “blob” detection and a small decode preview
- **PDF structure (optional, via `pdfminer.six`)**
  - Page count
  - Basic document metadata
  - Counts streams and shows snippets that look like embedded JS/Eval
- **Risk scoring & verdict**
  - Weighted score based on keyword hits, obfuscation signals, IOCs, entropy, and embedded JS snippet count
- **JSON report**
  - Produces a structured report suitable for triage pipelines.

---

## Requirements

Python 3.

Install dependencies:

```bash
pip install rich pdfminer.six python-magic
```

Optional note:
- If `python-magic` cannot be installed (or system `libmagic` is missing), MIME detection may be marked as unavailable, but the tool still runs.

---

## Usage

```bash
python3 pdf_sec_kit.py <file.pdf>
```

### JSON export

```bash
python3 pdf_sec_kit.py <file.pdf> --json
```

Write JSON to a specific file (implies `--json`):

```bash
python3 pdf_sec_kit.py <file.pdf> --output report.json
```

If `--output` is not provided and `--json` is used, the default output file name is:

- `<pdf_stem>_analysis.json`

---

## Output

The terminal output includes:

- **FILE INFORMATION**
- **PDF STRUCTURE** (when `pdfminer.six` is installed)
- **SUSPICIOUS KEYWORDS**
- **EXTRACTED IOCs**
- **OBFUSCATION HEURISTICS**
- **RISK ASSESSMENT** (risk band + recommendations)

When JSON is enabled, the report includes:

- tool version
- timestamp
- hashes
- entropy
- PDF structure highlights
- suspicious keyword hits
- IOCs
- obfuscation indicators
- overall risk score + risk level

---

## Example

```bash
python3 pdf_sec_kit.py sample.pdf --output sample_report.json
```

---

## Disclaimer

This is a static heuristic tool. Findings can include false positives/negatives. For confirmed analysis, use it alongside sandboxing/dynamic analysis, and validate hashes/indicators with trusted threat intel.
