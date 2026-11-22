#!/usr/bin/env python3
"""
pdf_sec_kit.py — PDF static analysis / triage tool (v3.0.0)

Structural approach: parses the PDF object graph with pikepdf, which
transparently resolves objects packed into compressed object streams
(/ObjStm) and decodes filtered stream data (FlateDecode, ASCIIHexDecode,
etc.). Keyword, IOC and obfuscation checks run against that decoded
content — not raw file bytes — so a compressed or escaped payload is
seen the same way a viewer/renderer would see it.

Known auto-executing and higher-risk constructs (/OpenAction -> JavaScript
or Launch, document-level /Names/JavaScript, /AA additional actions,
/Launch, /SubmitForm, /EmbeddedFile, /RichMedia) are matched by exact
PDF name, not by substring search over text, which avoids matching
compressed-binary noise that happens to contain a keyword substring.

If the file can't be parsed structurally (encrypted without a password,
or corrupt), the tool falls back to a raw-byte heuristic scan and labels
the report as degraded, with a capped risk band, since raw-byte matching
cannot see inside compressed streams and is easier to evade.

Note: static heuristic tool for defensive triage only. Findings can
include false positives/negatives. For confirmed analysis, use alongside
sandboxing/dynamic analysis and check hashes against trusted threat intel.
Always follow your legal/organizational rules.

Usage:
  python3 pdf_sec_kit.py <file.pdf> [--json] [--output report.json] [--password PW]

Requirements:
  pip install rich pikepdf
"""

import os
import re
import sys
import math
import json
import base64
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── third-party ──────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    sys.exit("[ERROR] Install 'rich':  pip install rich")

try:
    import magic as libmagic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

console = Console(highlight=False)

TOOL_VERSION = "3.0.0"

# ── structural rules (exact PDF name matches, not substring text search) ──
# Each action object's /S name tells you what it does when triggered.
AUTO_RUN_CRITICAL = {"/JavaScript", "/Launch"}
ACTION_WEIGHTS = {
    "/JavaScript": 25,
    "/Launch": 30,
    "/SubmitForm": 15,
    "/ImportData": 12,
    "/GoToE": 10,
    "/GoToR": 8,
    "/Rendition": 10,
    "/Movie": 8,
    "/ResetForm": 5,
    "/Hide": 3,
    "/Named": 2,
}
STRUCTURAL_PRESENCE_WEIGHTS = {
    "/EmbeddedFile": 10,
    "/RichMedia": 8,
    "/AcroForm": 3,
}

# Content-level keywords, scored only against decoded stream/string content.
# "/aa" and "/3d"-type short tokens are handled structurally above instead,
# since substring-matching 2-3 char tokens against free text is noisy.
SUSPICIOUS_WEIGHTS: dict[str, int] = {
    "eval":                 9,
    "unescape":              9,
    "this.exportdataobject": 10,
    "app.launchurl":         12,
    "powershell":            10,
    "cmd.exe":               10,
    "shellcode":             10,
    "payload":               6,
    "exploit":               8,
    "mshta":                 10,
    "wscript":               9,
    "cscript":               9,
    "fromcharcode":          8,
    "charcodeat":            6,
    "string.fromcharcode":   9,
}

PATTERNS = {
    "url":    re.compile(rb'https?://[^\s\x00-\x1f\'"<>]{8,}', re.IGNORECASE),
    "ip":     re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(rb'\b(?:[a-zA-Z0-9\-]+\.){2,}(?:com|net|org|io|co|ru|cn|tk|xyz|top|info|biz|site|online)\b', re.IGNORECASE),
    "email":  re.compile(rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', re.IGNORECASE),
    "b64":    re.compile(rb'[A-Za-z0-9+/]{60,}={0,2}'),
    "hex_blob": re.compile(rb'(?:[0-9a-fA-F]{2}){24,}'),
}

OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hex-encoded char sequence", re.compile(rb'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}')),
    ("Unicode escape sequence",   re.compile(rb'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}')),
    ("Percent/URL-encoded chain", re.compile(rb'(?:%[0-9a-fA-F]{2}){6,}')),
    ("eval(...) call",            re.compile(rb'eval\s*\(', re.IGNORECASE)),
    ("String.fromCharCode(...)",  re.compile(rb'fromCharCode\s*\(', re.IGNORECASE)),
    ("unescape(...) call",        re.compile(rb'unescape\s*\(', re.IGNORECASE)),
    ("Long repeated NOP sled",    re.compile(rb'(?:\\x90){10,}')),
]

RISK_BANDS = [
    (80, "CRITICAL", "bold red"),
    (50, "HIGH",     "red"),
    (25, "MEDIUM",   "yellow"),
    (10, "LOW",      "cyan"),
    (0,  "CLEAN",    "green"),
]
BAND_ORDER = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Filters that normally wrap compressed/binary data — a stream using one of
# these is expected to look high-entropy; that's not itself a signal.
EXPECTED_HIGH_ENTROPY_FILTERS = {
    "/FlateDecode", "/DCTDecode", "/JPXDecode", "/CCITTFaxDecode",
    "/JBIG2Decode", "/RunLengthDecode", "/LZWDecode",
}


# ── small helpers ───────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def entropy_label(score: float) -> tuple[str, str]:
    if score >= 7.5:
        return "Very high", "red"
    if score >= 6.5:
        return "High", "yellow"
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


def apply_floor(current: tuple[str, str], floor_label: str) -> tuple[str, str]:
    """Raise (never lower) a risk band to at least floor_label."""
    cur_label, _ = current
    if BAND_ORDER.index(floor_label) > BAND_ORDER.index(cur_label):
        for threshold, label, colour in RISK_BANDS:
            if label == floor_label:
                return label, colour
    return current


def name_str(obj) -> Optional[str]:
    """Return a PDF /Name as a plain python string, e.g. '/JavaScript', or None."""
    try:
        if obj is None:
            return None
        s = str(obj)
        return s if s.startswith("/") else None
    except Exception:
        return None


# ── file-level info ────────────────────────────────────────────

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
    if data[:4] == b"%PDF":
        result["header"] = "Valid PDF header (%PDF)"
        result["header_version"] = data[:8].decode("ascii", errors="replace").strip()
    else:
        result["header"] = "WARNING: Does not begin with %PDF — possible spoofing"
        result["header_version"] = "N/A"

    if HAS_MAGIC:
        try:
            result["mime"] = libmagic.from_file(file_path, mime=True)
        except Exception:
            result["mime"] = "unavailable"
    else:
        result["mime"] = "unavailable (install python-magic)"

    result["size_bytes"] = os.path.getsize(file_path)
    result["size_human"] = f"{result['size_bytes']:,} bytes"
    return result


# ── content-pool scanning (keywords / IOCs / obfuscation) ────────

def extract_raw_strings(data: bytes, min_length: int = 6) -> list[str]:
    pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
    return [m.decode("ascii", errors="ignore") for m in pattern.findall(data)]


def scan_keywords(content_pool: list[tuple[str, bytes]]) -> list[tuple[str, str, int, str]]:
    """Returns (matched_string, keyword, risk_points, source) for every
    (keyword, string) pair found — no early-break, so a string matching
    several keywords contributes all of them."""
    hits = []
    word_kws = {kw: re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
                for kw in SUSPICIOUS_WEIGHTS if re.match(r'^[a-z0-9_.]+$', kw)}
    literal_kws = [kw for kw in SUSPICIOUS_WEIGHTS if kw not in word_kws]

    for source, blob in content_pool:
        try:
            text = blob.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for kw, rx in word_kws.items():
            m = rx.search(text)
            if m:
                hits.append((m.group(0), kw, SUSPICIOUS_WEIGHTS[kw], source))
        lower = text.lower()
        for kw in literal_kws:
            if kw in lower:
                idx = lower.index(kw)
                hits.append((text[idx:idx + len(kw)], kw, SUSPICIOUS_WEIGHTS[kw], source))
    return hits


def extract_iocs(content_pool: list[tuple[str, bytes]]) -> dict[str, list[str]]:
    iocs: dict[str, list[str]] = {}
    joined = b"\n".join(blob for _, blob in content_pool)
    for name, pattern in PATTERNS.items():
        matches = list({m for m in pattern.findall(joined)})
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


def detect_obfuscation(content_pool: list[tuple[str, bytes]]) -> list[str]:
    found = []
    joined = b"\n".join(blob for _, blob in content_pool)
    for label, pattern in OBFUSCATION_PATTERNS:
        if pattern.search(joined):
            found.append(label)
    return found


# ── structural (pikepdf) analysis ─────────────────────────────────

def classify_action(action) -> Optional[str]:
    try:
        return name_str(action.get("/S"))
    except Exception:
        return None


def walk_actions_dict(aa_dict, findings: list[dict], where: str):
    """Walk an /AA (additional-actions) dictionary: each value is itself
    an action dict, keyed by trigger event (/O, /C, /WC, /WS, ...)."""
    try:
        for trigger, action in aa_dict.items():
            s = classify_action(action)
            if s and s in ACTION_WEIGHTS:
                findings.append({
                    "name": f"/AA action {s} (trigger {trigger})",
                    "where": where,
                    "weight": ACTION_WEIGHTS[s],
                    "floor": "CRITICAL" if s in AUTO_RUN_CRITICAL else "HIGH",
                })
    except Exception:
        pass


def analyze_structural(pdf, file_path: str) -> dict:
    result = {
        "mode": "structural",
        "page_count": "N/A",
        "metadata": {},
        "stream_count": 0,
        "findings": [],       # structural rule hits
        "content_pool": [],   # (source, bytes) fed to keyword/IOC/obfuscation scan
        "decoded_js": [],
        "high_entropy_unfiltered_streams": [],
        "error": None,
    }
    findings = result["findings"]

    try:
        result["page_count"] = len(pdf.pages)
    except Exception:
        pass

    try:
        if pdf.docinfo is not None:
            for k, v in pdf.docinfo.items():
                try:
                    result["metadata"][str(k)] = str(v)
                except Exception:
                    pass
    except Exception:
        pass

    root = pdf.Root

    # 1. Document-level /OpenAction — runs the moment the file is opened.
    try:
        oa = root.get("/OpenAction")
        if oa is not None:
            s = classify_action(oa)
            if s and s in ACTION_WEIGHTS:
                findings.append({
                    "name": f"/OpenAction executes {s} automatically on open",
                    "where": "Root/OpenAction",
                    "weight": ACTION_WEIGHTS[s] + 10,  # auto-run on open is worse than on click
                    "floor": "CRITICAL" if s in AUTO_RUN_CRITICAL else "HIGH",
                })
            else:
                findings.append({
                    "name": "/OpenAction present (type not auto-run JS/Launch)",
                    "where": "Root/OpenAction",
                    "weight": 5,
                    "floor": "LOW",
                })
    except Exception:
        pass

    # 2. Document-level /Names/JavaScript name tree — scripts that run on
    #    open independent of /OpenAction. Common real-world malware vector.
    try:
        names = root.get("/Names")
        if names is not None and names.get("/JavaScript") is not None:
            findings.append({
                "name": "/Root/Names/JavaScript name tree present (auto-run script on open)",
                "where": "Root/Names/JavaScript",
                "weight": 35,
                "floor": "CRITICAL",
            })
    except Exception:
        pass

    # 3. Document-level /AA
    try:
        if root.get("/AA") is not None:
            walk_actions_dict(root.get("/AA"), findings, "Root/AA")
    except Exception:
        pass

    # 4. Page- and annotation-level /AA, plus full object sweep for
    #    standalone action dicts, embedded files, rich media, forms.
    seen_js_objs = 0
    seen_launch = 0
    seen_embedded = 0
    seen_richmedia = 0
    seen_acroform = False

    try:
        for page in pdf.pages:
            try:
                if page.get("/AA") is not None:
                    walk_actions_dict(page.get("/AA"), findings, "Page/AA")
                annots = page.get("/Annots")
                if annots is not None:
                    for annot in annots:
                        if annot.get("/AA") is not None:
                            walk_actions_dict(annot.get("/AA"), findings, "Annot/AA")
            except Exception:
                continue
    except Exception:
        pass

    try:
        if root.get("/AcroForm") is not None:
            seen_acroform = True
    except Exception:
        pass

    # Full object sweep: a recursive walk from every top-level indirect
    # object into its dict/array values, so inline strings and inline
    # action dicts (e.g. a /JS value stored as a plain string rather than
    # its own indirect stream object — as real tools and simple test PDFs
    # both do) are seen, not just top-level indirect objects. Indirect
    # objects are deduped by objgen to avoid loops through /Parent-style
    # back-references; inline values have no objgen and are always walked
    # (bounded by max depth as a safety net).
    visited_objgen: set = set()
    MAX_DEPTH = 10

    def visit(obj, depth: int):
        nonlocal seen_js_objs, seen_launch, seen_embedded, seen_richmedia
        if depth > MAX_DEPTH or obj is None:
            return
        try:
            if obj.is_indirect:
                og = obj.objgen
                if og in visited_objgen:
                    return
                visited_objgen.add(og)
        except Exception:
            pass

        try:
            is_stream = isinstance(obj, pikepdf.Stream)
            is_array = isinstance(obj, pikepdf.Array)
            is_string = isinstance(obj, pikepdf.String)
            keys = []
            if not is_array and not is_string:
                try:
                    keys = list(obj.keys())
                except Exception:
                    pass

            if "/S" in keys:
                s = name_str(obj.get("/S"))
                if s == "/JavaScript":
                    seen_js_objs += 1
                elif s == "/Launch":
                    seen_launch += 1

            if "/Type" in keys and name_str(obj.get("/Type")) == "/EmbeddedFile":
                seen_embedded += 1

            if "/Subtype" in keys and name_str(obj.get("/Subtype")) == "/RichMedia":
                seen_richmedia += 1

            if is_stream:
                result["stream_count"] += 1
                stype = name_str(obj.get("/Type")) if keys else None
                # Object-stream (/ObjStm) containers hold the uncompressed
                # PDF syntax of every object packed inside them — i.e. the
                # same JS/strings we already see individually once we
                # visit those resolved child objects. Cross-reference
                # streams (/XRef) are binary offset tables, not content.
                # Scanning either here would double-count real hits and
                # can also produce spurious hex/entropy matches on table
                # bytes, so both are skipped as content sources.
                if stype in ("/ObjStm", "/XRef"):
                    return
                try:
                    raw = obj.read_bytes()
                except Exception:
                    raw = b""
                filt = obj.get("/Filter")
                filt_names = set()
                if filt is not None:
                    try:
                        filt_names = {name_str(f) for f in filt} if isinstance(filt, pikepdf.Array) else {name_str(filt)}
                    except Exception:
                        pass
                if raw:
                    tag = obj.objgen if obj.is_indirect else f"inline@depth{depth}"
                    result["content_pool"].append((f"stream obj {tag}", raw))
                    lower = raw.lower()
                    if b"javascript" in lower or b"eval(" in lower or b"app.launchurl" in lower:
                        result["decoded_js"].append(raw[:400].decode("utf-8", errors="replace"))
                    if not (filt_names & EXPECTED_HIGH_ENTROPY_FILTERS):
                        ent = shannon_entropy(raw)
                        if ent >= 7.2 and len(raw) >= 64:
                            result["high_entropy_unfiltered_streams"].append(
                                {"object": str(tag), "entropy": ent, "size": len(raw)}
                            )
            elif is_string:
                try:
                    sval = str(obj)
                    if sval:
                        tag = obj.objgen if obj.is_indirect else f"inline@depth{depth}"
                        result["content_pool"].append((f"string obj {tag}", sval.encode("utf-8", errors="ignore")))
                except Exception:
                    pass

            # Recurse into children.
            if is_array:
                for item in obj:
                    visit(item, depth + 1)
            elif keys:
                for k in keys:
                    try:
                        visit(obj.get(k), depth + 1)
                    except Exception:
                        continue
        except Exception:
            pass

    try:
        for obj in pdf.objects:
            visit(obj, 0)
    except Exception as e:
        result["error"] = str(e)

    if seen_js_objs:
        findings.append({
            "name": f"{seen_js_objs} /S /JavaScript action object(s) present in document",
            "where": "object sweep",
            "weight": min(15 * seen_js_objs, 30),
            "floor": "HIGH",
        })
    if seen_launch:
        findings.append({
            "name": f"{seen_launch} /S /Launch action object(s) present (runs external program/file)",
            "where": "object sweep",
            "weight": min(20 * seen_launch, 40),
            "floor": "CRITICAL",
        })
    if seen_embedded:
        findings.append({
            "name": f"{seen_embedded} embedded file object(s) present",
            "where": "object sweep",
            "weight": min(STRUCTURAL_PRESENCE_WEIGHTS["/EmbeddedFile"] * seen_embedded, 20),
            "floor": "LOW",
        })
    if seen_richmedia:
        findings.append({
            "name": f"{seen_richmedia} /RichMedia annotation(s) present (Flash/3D content)",
            "where": "object sweep",
            "weight": STRUCTURAL_PRESENCE_WEIGHTS["/RichMedia"],
            "floor": "LOW",
        })
    if seen_acroform:
        findings.append({
            "name": "/AcroForm present (interactive form)",
            "where": "Root/AcroForm",
            "weight": STRUCTURAL_PRESENCE_WEIGHTS["/AcroForm"],
            "floor": "CLEAN",
        })
    if result["high_entropy_unfiltered_streams"]:
        n = len(result["high_entropy_unfiltered_streams"])
        findings.append({
            "name": f"{n} stream(s) with high entropy but no recognized compression filter (possible packed/encrypted payload)",
            "where": "object sweep",
            "weight": min(12 * n, 24),
            "floor": "MEDIUM",
        })

    return result


def compute_risk_score_structural(structural: dict, keyword_hits: list, obfuscation_hits: list, iocs: dict) -> tuple[int, str, str]:
    score = 0
    band = ("CLEAN", "green")

    for f in structural["findings"]:
        score += f["weight"]
        band = apply_floor(band, f["floor"])

    # Keyword weight, capped per unique keyword so repeated near-identical
    # strings (e.g. many similar JS fragments) can't stack unboundedly.
    by_kw: dict[str, tuple[int, int]] = {}
    for _, kw, pts, _src in keyword_hits:
        count, _ = by_kw.get(kw, (0, pts))
        by_kw[kw] = (count + 1, pts)
    for kw, (count, pts) in by_kw.items():
        score += pts * min(count, 3)

    score += len(obfuscation_hits) * 8
    score += min(len(iocs.get("url", [])), 5) * 3
    score += min(len(iocs.get("ip", [])), 5) * 2
    score += min(len(iocs.get("email", [])), 5) * 1

    numeric_label, numeric_colour = risk_band(score)
    final = apply_floor(band, numeric_label)
    # if numeric band is higher than the structural floor, let it win
    if BAND_ORDER.index(numeric_label) > BAND_ORDER.index(final[0]):
        final = (numeric_label, numeric_colour)
    return score, final[0], final[1]


# ── raw fallback (encrypted without password / corrupt / unparseable) ──

def raw_fallback_scan(data: bytes) -> dict:
    strings = extract_raw_strings(data)
    pool = [("raw file bytes", data)]
    keyword_hits = scan_keywords([("raw file bytes", " ".join(strings).encode("utf-8", "ignore"))])
    obfuscation_hits = detect_obfuscation(pool)
    iocs = extract_iocs(pool)
    score = 0
    by_kw: dict[str, int] = {}
    for _, kw, pts, _ in keyword_hits:
        by_kw[kw] = max(by_kw.get(kw, 0), pts)
    score += sum(by_kw.values())
    score += len(obfuscation_hits) * 6
    score += min(len(iocs.get("url", [])), 5) * 2
    label, colour = risk_band(score)
    # Raw-byte matching can't see inside compressed streams and is easy to
    # evade either way, so cap confidence at MEDIUM regardless of score.
    if BAND_ORDER.index(label) > BAND_ORDER.index("MEDIUM"):
        label, colour = "MEDIUM", "yellow"
    return {
        "keyword_hits": keyword_hits,
        "obfuscation_hits": obfuscation_hits,
        "iocs": iocs,
        "score": score,
        "label": label,
        "colour": colour,
    }


# ── reporting ─────────────────────────────────────────────────────

def print_header(file_path: str, mode: str, mode_note: str):
    console.print()
    console.print(Panel(
        f"[bold white]PDF STATIC ANALYSIS TOOL[/bold white]  v{TOOL_VERSION}\n"
        f"[dim]Analysing:[/dim] [cyan]{file_path}[/cyan]\n"
        f"[dim]Timestamp:[/dim] {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"[dim]Mode:[/dim] {mode}" + (f"  [yellow]({mode_note})[/yellow]" if mode_note else ""),
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
    t.add_row("Entropy",     f"[{ent_colour}]{entropy}  —  {ent_label}[/{ent_colour}] [dim](whole-file, informational only — not scored)[/dim]")
    t.add_row("MD5",         hashes["md5"])
    t.add_row("SHA-1",       hashes["sha1"])
    t.add_row("SHA-256",     hashes["sha256"])
    console.print(t)


def print_structural(structural: dict):
    print_section("PDF STRUCTURE")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim", width=14)
    t.add_column()
    t.add_row("Pages",   str(structural.get("page_count", "N/A")))
    t.add_row("Streams", str(structural.get("stream_count", "N/A")))
    for k, v in structural.get("metadata", {}).items():
        t.add_row(k, v)
    if structural.get("error"):
        t.add_row("[red]Parse note[/red]", structural["error"])
    console.print(t)

    findings = structural.get("findings", [])
    print_section(f"STRUCTURAL FINDINGS  ({len(findings)})")
    if not findings:
        console.print("  [green]No high-risk PDF actions/objects found.[/green]\n")
    else:
        ft = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        ft.add_column("Finding", style="red bold")
        ft.add_column("Where", style="dim")
        ft.add_column("Weight", justify="right", width=8)
        ft.add_column("Floor", width=10)
        for f in sorted(findings, key=lambda x: -x["weight"]):
            ft.add_row(f["name"], f["where"], str(f["weight"]), f["floor"])
        console.print(ft)

    js_hits = structural.get("decoded_js", [])
    if js_hits:
        console.print(f"  [red bold][!] Decoded streams containing JS-like content: {len(js_hits)}[/red bold]")
        for snippet in js_hits[:5]:
            console.print(Panel(snippet.strip()[:400], title="Decoded snippet", style="red", expand=False))
    console.print()


def print_keyword_hits(hits: list):
    print_section(f"SUSPICIOUS KEYWORDS  ({len(hits)} matched)")
    if not hits:
        console.print("  [green]No suspicious keywords detected in decoded content.[/green]\n")
        return
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
    t.add_column("Keyword", style="red bold", width=20)
    t.add_column("Risk Pts", justify="right", width=8)
    t.add_column("Source", style="dim", width=20)
    t.add_column("Found In", style="dim")
    for string, kw, pts, source in sorted(hits, key=lambda x: -x[2])[:30]:
        t.add_row(kw, str(pts), source, string[:60])
    console.print(t)


def print_iocs(iocs: dict):
    print_section("EXTRACTED IOCs")
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


def print_verdict(score: int, label: str, colour: str, keyword_hits: list, iocs: dict, obfuscation_hits: list, mode: str):
    print_section("RISK ASSESSMENT")
    console.print(
        Panel(
            f"[bold {colour}]RISK LEVEL: {label}[/bold {colour}]\n"
            f"[white]Score: {score}[/white]  [dim](uncapped; bands are thresholds, not a percentage)[/dim]\n\n"
            f"  Suspicious keywords : {len(keyword_hits)}\n"
            f"  Obfuscation signals : {len(obfuscation_hits)}\n"
            f"  Network IOCs        : {len(iocs.get('url', [])) + len(iocs.get('ip', [])) + len(iocs.get('domain', []))}\n"
            f"  Email IOCs          : {len(iocs.get('email', []))}\n\n"
            f"[dim]Mode: {mode}[/dim]\n"
            f"[dim]Recommendation: {'Submit to sandbox for dynamic analysis and check hashes on VirusTotal.' if label in ('HIGH', 'CRITICAL') or score >= 25 else 'No immediate action required. Monitor and retain for 30 days.'}[/dim]",
            style=colour,
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )
    console.print()


def build_json_report(file_path, file_type, hashes, entropy, mode, mode_note,
                       structural: Optional[dict], keyword_hits, iocs, obfuscation_hits,
                       score, label) -> dict:
    report = {
        "tool": f"pdf_sec_kit v{TOOL_VERSION}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_mode": mode,
        "analysis_mode_note": mode_note,
        "file": {
            "path": file_path,
            "size_bytes": file_type.get("size_bytes"),
            "mime": file_type.get("mime"),
            "header": file_type.get("header"),
            "pdf_version": file_type.get("header_version"),
            "whole_file_entropy_informational_only": entropy,
        },
        "hashes": hashes,
        "suspicious_keywords": [
            {"string": s[:120], "keyword": kw, "risk_points": pts, "source": src}
            for s, kw, pts, src in keyword_hits
        ],
        "iocs": iocs,
        "obfuscation_detected": obfuscation_hits,
        "risk_score": score,
        "risk_level": label,
        "recommendation": (
            "Submit to sandbox for dynamic analysis and check hashes on VirusTotal."
            if label in ("HIGH", "CRITICAL") else "No immediate action required."
        ),
    }
    if structural is not None:
        report["pdf_structure"] = {
            "page_count": structural.get("page_count"),
            "stream_count": structural.get("stream_count"),
            "metadata": structural.get("metadata", {}),
            "structural_findings": [
                {"name": f["name"], "where": f["where"], "weight": f["weight"], "floor_band": f["floor"]}
                for f in structural.get("findings", [])
            ],
            "decoded_js_snippet_count": len(structural.get("decoded_js", [])),
            "high_entropy_unfiltered_streams": structural.get("high_entropy_unfiltered_streams", []),
        }
    return report


# ── entry point ───────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PDF static analysis / triage tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="Path to the PDF file to analyse")
    parser.add_argument("--json", action="store_true", help="Export results as JSON")
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to FILE (implies --json)")
    parser.add_argument("--password", metavar="PW", default="", help="Password, if the PDF is encrypted")
    return parser.parse_args()


def main():
    args = parse_args()
    file_path = args.file

    data = read_file(file_path)
    if data is None:
        sys.exit(1)

    file_type = detect_file_type(file_path, data)
    hashes = compute_hashes(data)
    whole_file_entropy = shannon_entropy(data)

    mode = "structural"
    mode_note = ""
    structural = None
    keyword_hits: list = []
    iocs: dict = {}
    obfuscation_hits: list = []
    score = 0
    label, colour = "CLEAN", "green"

    if not HAS_PIKEPDF:
        mode = "raw_fallback"
        mode_note = "pikepdf not installed — structural parsing unavailable, confidence capped at MEDIUM"
    else:
        try:
            pdf = pikepdf.Pdf.open(file_path, password=args.password or "")
        except pikepdf.PasswordError:
            mode = "raw_fallback"
            mode_note = "PDF is encrypted and no/incorrect password was supplied — structural parsing unavailable, confidence capped at MEDIUM"
            pdf = None
        except Exception as e:
            mode = "raw_fallback"
            mode_note = f"could not parse PDF structure ({e}) — confidence capped at MEDIUM"
            pdf = None

        if mode == "structural":
            structural = analyze_structural(pdf, file_path)
            keyword_hits = scan_keywords(structural["content_pool"])
            iocs = extract_iocs(structural["content_pool"])
            obfuscation_hits = detect_obfuscation(structural["content_pool"])
            score, label, colour = compute_risk_score_structural(structural, keyword_hits, obfuscation_hits, iocs)

    if mode == "raw_fallback":
        fb = raw_fallback_scan(data)
        keyword_hits, obfuscation_hits, iocs = fb["keyword_hits"], fb["obfuscation_hits"], fb["iocs"]
        score, label, colour = fb["score"], fb["label"], fb["colour"]

    print_header(file_path, mode, mode_note)
    print_file_info(file_path, file_type, hashes, whole_file_entropy)
    if structural is not None:
        print_structural(structural)
    elif mode_note:
        console.print(f"  [yellow]{mode_note}[/yellow]\n")
    print_keyword_hits(keyword_hits)
    print_iocs(iocs)
    print_obfuscation(obfuscation_hits)
    print_verdict(score, label, colour, keyword_hits, iocs, obfuscation_hits, mode)

    if args.json or args.output:
        report = build_json_report(file_path, file_type, hashes, whole_file_entropy,
                                    mode, mode_note, structural, keyword_hits, iocs,
                                    obfuscation_hits, score, label)
        out_path = args.output or Path(file_path).stem + "_analysis.json"
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green][+] JSON report saved → {out_path}[/green]\n")


if __name__ == "__main__":
    main()
