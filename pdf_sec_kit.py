#!/usr/bin/env python3
"""
Features:
  - File metadata & magic-byte validation
  - Cryptographic hashing (MD5, SHA-1, SHA-256)
  - Shannon entropy scoring
  - Recursive PDF object / stream extraction (pdfminer)
  - Base64 & hex decoding of embedded blobs
  - URI / IP / domain / email IOC extraction
  - Obfuscation heuristics (hex encoding, eval chains, etc.)
  - Weighted risk scoring with severity levels
  - JSON report export
  - Rich terminal output with colour-coded findings

Usage:
  python3 pdf_analysis.py <file.pdf> [--json] [--output report.json]

Requirements:
  pip install rich pdfminer.six python-magic
"""

import os
import re
import sys
import math
import json
import base64
import hashlib
import argparse
import datetime
from pathlib import Path
from typing import Optional

# ── third-party ──────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    sys.exit("[ERROR] Install 'rich':  pip install rich")

try:
    import magic as libmagic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    from pdfminer.high_level import extract_text
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdftypes import PDFStream, resolve1
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    HAS_PDFMINER = True
except ImportError:
    HAS_PDFMINER = False

console = Console(highlight=False)

# ── constants ─────────────────────────────────────────────────────

TOOL_VERSION = "2.0.0"

# Weighted suspicious keywords: keyword → risk points
SUSPICIOUS_WEIGHTS: dict[str, int] = {
    # high-risk PDF actions
    "openaction":   10,
    "aa":           8,
    "acroform":     8,
    "launch":       10,
    "submitform":   7,
    # scripting
    "javascript":   10,
    "eval":         9,
    "unescape":     9,
    "this.exportdataobject": 10,
    "app.launchurl":         10,
    # shell / payload markers
    "powershell":   10,
    "cmd.exe":      10,
    "shellcode":    10,
    "payload":      8,
    "exploit":      10,
    "mshta":        10,
    "wscript":      9,
    "cscript":      9,
    # encoding / obfuscation
    "fromcharcode": 8,
    "charcodeat":   7,
    "string.fromcharcode": 9,
    # network
    "uri":          5,
    "url":          4,
    "http://":      4,
    "https://":     4,
    # suspicious structural
    "embedded":     6,
    "fileattachment": 7,
    "richmedia":    6,
    "3d":           4,
}

# Patterns for IOC extraction
PATTERNS = {
    "url":    re.compile(rb'https?://[^\s\x00-\x1f\'"<>]{8,}', re.IGNORECASE),
    "ip":     re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(rb'\b(?:[a-zA-Z0-9\-]+\.){2,}(?:com|net|org|io|co|ru|cn|tk|xyz|top|info|biz|site|online)\b', re.IGNORECASE),
    "email":  re.compile(rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
    "b64":    re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}'),
    "hex_blob": re.compile(rb'(?:[0-9a-fA-F]{2}){16,}'),
}

# Obfuscation heuristics
OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hex-encoded string",      re.compile(rb'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}')),
    ("Unicode escape sequence", re.compile(rb'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}')),
    ("Eval chain",              re.compile(rb'eval\s*\(', re.IGNORECASE)),
    ("String.fromCharCode",     re.compile(rb'fromCharCode\s*\(', re.IGNORECASE)),
    ("Unescape obfuscation",    re.compile(rb'unescape\s*\(', re.IGNORECASE)),
    ("Long repeated NOP sled",  re.compile(rb'(?:\\x90){10,}')),
    ("Base64 blob in stream",   re.compile(rb'[A-Za-z0-9+/]{200,}={0,2}')),
]

RISK_BANDS = [
    (80,  "CRITICAL",  "bold red"),
    (50,  "HIGH",      "red"),
    (25,  "MEDIUM",    "yellow"),
    (10,  "LOW",       "cyan"),
    (0,   "CLEAN",     "green"),
]


# ── helpers ───────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0–8 bits). High values suggest encryption/compression."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def entropy_label(score: float) -> tuple[str, str]:
    if score >= 7.5:
        return "Very High (likely encrypted/compressed)", "red"
    if score >= 6.5:
        return "High (possible obfuscation)", "yellow"
    if score >= 5.0:
        return "Moderate", "cyan"
    return "Normal", "green"


def try_decode_b64(blob: bytes) -> Optional[str]:
    try:
        decoded = base64.b64decode(blob + b"==")
        if len(decoded) > 8 and all(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:64]):
            return decoded[:200].decode("ascii", errors="replace")
    except Exception:
        pass
    return None


def risk_band(score: int) -> tuple[str, str]:
    for threshold, label, colour in RISK_BANDS:
        if score >= threshold:
            return label, colour
    return "CLEAN", "green"


# ── core analysis functions ────────────────────────────────────────

def read_file(file_path: str) -> Optional[bytes]:
    try:
        with open(file_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        console.print(f"[red][ERROR] File not found: {file_path}[/red]")
    except IOError as e:
        console.print(f"[red][ERROR] Could not read '{file_path}': {e}[/red]")
    return None


def compute_hashes(data: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def detect_file_type(file_path: str, data: bytes) -> dict[str, str]:
    result = {}
    # Magic bytes
    if data[:4] == b"%PDF":
        result["header"] = "Valid PDF header (%PDF)"
        result["header_version"] = data[:8].decode("ascii", errors="replace").strip()
    else:
        result["header"] = "WARNING: Does not begin with %PDF — possible spoofing"

    # libmagic MIME type
    if HAS_MAGIC:
        try:
            mime = libmagic.from_file(file_path, mime=True)
            result["mime"] = mime
        except Exception:
            result["mime"] = "unavailable"
    else:
        result["mime"] = "unavailable (install python-magic)"

    result["size_bytes"] = os.path.getsize(file_path)
    result["size_human"] = f"{result['size_bytes']:,} bytes"
    return result


def extract_raw_strings(data: bytes, min_length: int = 6) -> list[str]:
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
    return [m.decode("ascii", errors="ignore") for m in pattern.findall(data)]


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    for name, pattern in PATTERNS.items():
        matches = list({m for m in pattern.findall(data)})
        if name == "b64":
            decoded = []
            for m in matches:
                result = try_decode_b64(m)
                if result:
                    decoded.append(f"{m[:40].decode('ascii', errors='replace')}... → {result}")
            if decoded:
                iocs["base64_decoded"] = decoded[:10]
        elif matches:
            iocs[name] = [m.decode("ascii", errors="ignore") for m in matches[:20]]
    return iocs


def detect_obfuscation(data: bytes) -> list[str]:
    found = []
    for label, pattern in OBFUSCATION_PATTERNS:
        if pattern.search(data):
            found.append(label)
    return found


def detect_suspicious_keywords(strings: list[str]) -> list[tuple[str, str, int]]:
    """
    Returns list of (matched_string, keyword, risk_points).
    """
    hits = []
    seen = set()
    for s in strings:
        lower = s.lower()
        for kw, pts in SUSPICIOUS_WEIGHTS.items():
            if kw in lower and s not in seen:
                hits.append((s, kw, pts))
                seen.add(s)
                break
    return hits


def extract_pdf_structure(file_path: str) -> dict:
    """Use pdfminer to extract page count, metadata, and embedded JS."""
    result = {"page_count": "N/A", "metadata": {}, "embedded_js": [], "streams": 0, "error": None}
    if not HAS_PDFMINER:
        result["error"] = "pdfminer not installed"
        return result
    try:
        with open(file_path, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            pages = list(PDFPage.create_pages(doc))
            result["page_count"] = len(pages)

            # Metadata
            for info in doc.info:
                for k, v in info.items():
                    try:
                        val = v if isinstance(v, str) else v.decode("utf-8", errors="replace")
                        result["metadata"][k] = val
                    except Exception:
                        pass

            # Walk objects for JavaScript and stream count
            js_hits = []
            stream_count = 0
            for xref in doc.xrefs:
                for objid in xref.get_objids():
                    try:
                        obj = resolve1(doc.getobj(objid))
                        if isinstance(obj, PDFStream):
                            stream_count += 1
                            raw = obj.get_data()
                            if b"javascript" in raw.lower() or b"eval" in raw.lower():
                                js_hits.append(raw[:300].decode("utf-8", errors="replace"))
                    except Exception:
                        pass
            result["streams"] = stream_count
            result["embedded_js"] = js_hits[:5]

    except Exception as e:
        result["error"] = str(e)
    return result


def compute_risk_score(keyword_hits: list, obfuscation_hits: list, iocs: dict, entropy: float, pdf_structure: dict) -> int:
    score = 0
    # Keyword weights
    score += sum(pts for _, _, pts in keyword_hits)
    # Obfuscation
    score += len(obfuscation_hits) * 8
    # IOCs
    score += len(iocs.get("url", [])) * 3
    score += len(iocs.get("ip", [])) * 2
    score += len(iocs.get("email", [])) * 1
    # Entropy
    if entropy >= 7.5:
        score += 15
    elif entropy >= 6.5:
        score += 8
    # Embedded JS
    score += len(pdf_structure.get("embedded_js", [])) * 12
    return score


# ── reporting ─────────────────────────────────────────────────────

def print_header(file_path: str):
    console.print()
    console.print(Panel(
        f"[bold white]PDF STATIC ANALYSIS TOOL[/bold white]  v{TOOL_VERSION}\n"
        f"[dim]Analysing:[/dim] [cyan]{file_path}[/cyan]\n"
        f"[dim]Timestamp:[/dim] {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        box=box.DOUBLE_EDGE,
        style="bold blue",
        expand=False,
    ))
    console.print()


def print_section(title: str):
    console.rule(f"[bold yellow]{title}[/bold yellow]")


def print_file_info(file_path: str, file_type: dict, hashes: dict, entropy: float):
    print_section("FILE INFORMATION")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim", width=14)
    t.add_column()

    ent_label, ent_colour = entropy_label(entropy)

    t.add_row("Path",        file_path)
    t.add_row("Size",        file_type["size_human"])
    t.add_row("MIME Type",   file_type.get("mime", "N/A"))
    t.add_row("Header",      file_type.get("header", "N/A"))
    t.add_row("PDF Version", file_type.get("header_version", "N/A"))
    t.add_row("Entropy",     f"[{ent_colour}]{entropy}  —  {ent_label}[/{ent_colour}]")
    t.add_row("MD5",         hashes["md5"])
    t.add_row("SHA-1",       hashes["sha1"])
    t.add_row("SHA-256",     hashes["sha256"])
    console.print(t)


def print_pdf_structure(pdf_structure: dict):
    print_section("PDF STRUCTURE")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim", width=14)
    t.add_column()
    t.add_row("Pages",   str(pdf_structure.get("page_count", "N/A")))
    t.add_row("Streams", str(pdf_structure.get("streams", "N/A")))

    meta = pdf_structure.get("metadata", {})
    for k, v in meta.items():
        t.add_row(k, v)

    if pdf_structure.get("error"):
        t.add_row("[red]Parse error[/red]", pdf_structure["error"])

    console.print(t)

    js_hits = pdf_structure.get("embedded_js", [])
    if js_hits:
        console.print(f"  [red bold][!] Embedded JavaScript streams found: {len(js_hits)}[/red bold]")
        for snippet in js_hits:
            console.print(Panel(snippet.strip()[:400], title="JS Snippet", style="red", expand=False))


def print_keyword_hits(hits: list[tuple[str, str, int]]):
    print_section(f"SUSPICIOUS KEYWORDS  ({len(hits)} matched)")
    if not hits:
        console.print("  [green]No suspicious keywords detected.[/green]\n")
        return
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Keyword",     style="red bold", width=20)
    t.add_column("Risk Pts",    justify="right", width=8)
    t.add_column("Found In String", style="dim")
    for string, kw, pts in sorted(hits, key=lambda x: -x[2])[:30]:
        t.add_row(kw, str(pts), string[:80])
    console.print(t)


def print_iocs(iocs: dict):
    print_section(f"EXTRACTED IOCs")
    if not iocs:
        console.print("  [green]No IOCs extracted.[/green]\n")
        return
    for category, items in iocs.items():
        console.print(f"  [bold cyan]{category.upper()}[/bold cyan]  ({len(items)})")
        for item in items[:10]:
            console.print(f"    [yellow]{item[:120]}[/yellow]")
        console.print()


def print_obfuscation(hits: list[str]):
    print_section(f"OBFUSCATION HEURISTICS  ({len(hits)} detected)")
    if not hits:
        console.print("  [green]No obfuscation patterns detected.[/green]\n")
        return
    for h in hits:
        console.print(f"  [red bold][!][/red bold] {h}")
    console.print()


def print_verdict(score: int, keyword_hits: list, iocs: dict, obfuscation_hits: list):
    label, colour = risk_band(score)
    print_section("RISK ASSESSMENT")
    console.print(
        Panel(
            f"[bold {colour}]RISK LEVEL: {label}[/bold {colour}]\n"
            f"[white]Score: {score} / 100+[/white]\n\n"
            f"  Suspicious keywords : {len(keyword_hits)}\n"
            f"  Obfuscation signals : {len(obfuscation_hits)}\n"
            f"  Network IOCs        : {len(iocs.get('url', [])) + len(iocs.get('ip', [])) + len(iocs.get('domain', []))}\n"
            f"  Email IOCs          : {len(iocs.get('email', []))}\n\n"
            f"[dim]Recommendation: {'Submit to sandbox for dynamic analysis and check hashes on VirusTotal.' if score >= 25 else 'No immediate action required. Monitor and retain for 30 days.'}[/dim]",
            style=colour,
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )
    console.print()


def build_json_report(
    file_path: str,
    file_type: dict,
    hashes: dict,
    entropy: float,
    pdf_structure: dict,
    keyword_hits: list,
    iocs: dict,
    obfuscation_hits: list,
    risk_score: int,
) -> dict:
    label, _ = risk_band(risk_score)
    return {
        "tool": f"pdf_analysis v{TOOL_VERSION}",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "file": {
            "path": file_path,
            "size_bytes": file_type.get("size_bytes"),
            "mime": file_type.get("mime"),
            "header": file_type.get("header"),
            "pdf_version": file_type.get("header_version"),
            "entropy": entropy,
        },
        "hashes": hashes,
        "pdf_structure": {
            "page_count": pdf_structure.get("page_count"),
            "stream_count": pdf_structure.get("streams"),
            "metadata": pdf_structure.get("metadata", {}),
            "embedded_js_count": len(pdf_structure.get("embedded_js", [])),
        },
        "suspicious_keywords": [
            {"string": s[:120], "keyword": kw, "risk_points": pts}
            for s, kw, pts in keyword_hits
        ],
        "iocs": iocs,
        "obfuscation_detected": obfuscation_hits,
        "risk_score": risk_score,
        "risk_level": label,
        "recommendation": (
            "Submit to sandbox for dynamic analysis and check hashes on VirusTotal."
            if risk_score >= 25
            else "No immediate action required."
        ),
    }


# ── entry point ───────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Professional PDF Static Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="Path to the PDF file to analyse")
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to FILE (implies --json)")
    return parser.parse_args()


def main():
    args = parse_args()
    file_path = args.file

    print_header(file_path)

    # ── 1. Read file ──────────────────────────────────────────────
    data = read_file(file_path)
    if data is None:
        console.print("[red bold]Analysis aborted: could not read file.[/red bold]")
        sys.exit(1)

    # ── 2. File metadata ──────────────────────────────────────────
    file_type  = detect_file_type(file_path, data)
    hashes     = compute_hashes(data)
    entropy    = shannon_entropy(data)
    print_file_info(file_path, file_type, hashes, entropy)

    # ── 3. PDF structure (pdfminer) ───────────────────────────────
    pdf_structure = extract_pdf_structure(file_path)
    print_pdf_structure(pdf_structure)

    # ── 4. String extraction & analysis ──────────────────────────
    raw_strings    = extract_raw_strings(data)
    keyword_hits   = detect_suspicious_keywords(raw_strings)
    print_keyword_hits(keyword_hits)

    # ── 5. IOC extraction ─────────────────────────────────────────
    iocs = extract_iocs(data)
    print_iocs(iocs)

    # ── 6. Obfuscation heuristics ─────────────────────────────────
    obfuscation_hits = detect_obfuscation(data)
    print_obfuscation(obfuscation_hits)

    # ── 7. Risk score & verdict ───────────────────────────────────
    risk_score = compute_risk_score(keyword_hits, obfuscation_hits, iocs, entropy, pdf_structure)
    print_verdict(risk_score, keyword_hits, iocs, obfuscation_hits)

    # ── 8. Optional JSON export ───────────────────────────────────
    if args.json or args.output:
        report = build_json_report(
            file_path, file_type, hashes, entropy,
            pdf_structure, keyword_hits, iocs,
            obfuscation_hits, risk_score,
        )
        out_path = args.output or Path(file_path).stem + "_analysis.json"
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green][+] JSON report saved → {out_path}[/green]\n")


if __name__ == "__main__":
    main()
