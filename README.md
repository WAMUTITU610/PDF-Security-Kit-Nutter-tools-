# PDF Security Kit

A Python static scanner for PDFs that performs forensic triage: it walks
the actual PDF object graph (via `pikepdf`) — not just the raw file bytes —
to find auto-executing JavaScript, launch actions, suspicious keywords,
obfuscation, and network/email indicators, then produces a risk score and
an optional JSON report.

> Static heuristic tool for defensive triage only. Findings can include
> false positives/negatives. For confirmed analysis, use alongside
> sandboxing/dynamic analysis and check hashes against trusted threat
> intel. Always follow your legal/organizational rules.

## Why structural, not just byte-matching

A naive scanner that greps the raw file for keywords like `javascript` or
`eval` misses anything PDF producers routinely do to obfuscate or simply
compress content: objects packed into compressed object streams
(`/ObjStm`), filtered stream data, and on-disk `#XX` hex-escaped names
(e.g. `/J#61vaScript` → `/JavaScript`). It also false-positives on
ordinary compressed binary data that happens to contain a keyword
substring.

This tool parses the object graph with `pikepdf`, which transparently
resolves compressed object streams and decodes filtered data, then:

- Matches dangerous constructs by **exact PDF name** (`/OpenAction`,
  `/AA`, `/JS`, `/JavaScript`, `/Launch`, `/SubmitForm`, `/EmbeddedFile`,
  `/RichMedia`, `/Names/JavaScript`) rather than substring search.
- Runs keyword/IOC/obfuscation checks only against **decoded** stream and
  string content.
- Falls back to a raw-byte scan — clearly labeled and capped at a lower
  confidence — only when the file can't be parsed (encrypted without the
  right password, or corrupt).

## What it detects

- File metadata & validation: `%PDF` header check, MIME type (via
  `python-magic` if installed), MD5/SHA-1/SHA-256 hashes.
- Structural findings: `/OpenAction` auto-run JavaScript or Launch
  actions, document/page/annotation-level `/AA` actions, the
  `/Names/JavaScript` auto-run name tree, `/Launch`, `/SubmitForm`,
  `/EmbeddedFile`, `/RichMedia`, `/AcroForm`, and streams with high
  entropy but no recognized compression filter (possible packed payload).
- Suspicious keywords (`eval`, `unescape`, `powershell`, `shellcode`,
  `fromCharCode`, …), scored against decoded content.
- IOC extraction: URLs, IPs, domains, emails, and a base64-blob decode
  preview.
- Obfuscation heuristics: hex/unicode/percent-encoded chains, `eval(...)`
  / `unescape(...)` / `fromCharCode(...)` calls, NOP sleds.
- Weighted risk score and band (CLEAN / LOW / MEDIUM / HIGH / CRITICAL),
  with certain structural findings (e.g. auto-run JS on open) setting a
  minimum band regardless of the numeric score.
- JSON report export for triage pipelines.

## Requirements

Python 3.9+.

```
pip install -r requirements.txt
```

If `python-magic` can't be installed (missing system `libmagic`), MIME
detection is marked unavailable but the tool still runs fully.

## Usage

```
python3 pdf_sec_kit.py <file.pdf>
```

JSON export:

```
python3 pdf_sec_kit.py <file.pdf> --json
python3 pdf_sec_kit.py <file.pdf> --output report.json
python3 pdf_sec_kit.py <file.pdf> --password <pw>   # for encrypted PDFs
```

If `--output` is omitted and `--json` is used, the default file name is
`<pdf_stem>_analysis.json`.

## Output

Terminal sections: FILE INFORMATION, PDF STRUCTURE, STRUCTURAL FINDINGS,
SUSPICIOUS KEYWORDS, EXTRACTED IOCs, OBFUSCATION HEURISTICS, RISK
ASSESSMENT.

The JSON report additionally records `analysis_mode` (`structural` or
`raw_fallback`, with a note explaining why when it falls back),
per-finding weights and floor bands, decoded-JS snippet counts, and any
high-entropy unfiltered streams.

## Tests

`tests/make_tests.py` builds a small set of synthetic PDFs (harmless
payloads only) used to validate detection: a benign file, three variants
of the same auto-run-JS payload packaged differently (plain, in a
compressed object stream, and as a compressed stream inside a compressed
object stream — all three must score identically), a large benign report
(checks for false positives), a legitimate hyperlink PDF, and a PDF whose
`/JavaScript` name is written with an on-disk hex escape (checks the
evasion is still caught).

```
pip install -r requirements.txt
cd tests && python3 make_tests.py
python3 ../pdf_sec_kit.py t1_plain.pdf --output t1.json
```

## Disclaimer

This is a static heuristic tool. Findings can include false
positives/negatives. For confirmed analysis, use it alongside
sandboxing/dynamic analysis, and validate hashes/indicators with trusted
threat intel.
