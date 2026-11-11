"""logmine core — exact, local analysis of large text log files.

Three tools:

``log_summarize``  Mine the file into recurring message *templates* (so
                   ``User 12345 failed`` and ``User 67890 failed`` collapse into
                   one pattern ``User <NUM> failed`` with a count), plus a log-level
                   histogram and the detected time span. This is the part a prompt
                   cannot do over a file that does not fit in context.
``log_grep``       Regex search with line numbers and optional surrounding context
                   lines (like ``grep -C``).
``log_timeline``   Exact event counts per time bucket (minute / hour / day) from
                   detected timestamps, to find spikes.

Standard library only (``re``, ``datetime``, ``collections``, ``os``, ``json``).
No network, no credentials, no background work, no self-update. The only side
effect is reading the file path the caller supplies, read-only.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from datetime import datetime
from typing import Any, Optional

# --- Bounds that keep one call cheap and its output readable ----------------------
SCAN_LINE_CAP = 5_000_000       # stop after this many lines; flagged in the result
MAX_LINE_CHARS = 100_000        # truncate a single over-long line before matching
MAX_TEMPLATES = 50_000          # cap distinct templates held in memory
MAX_TIME_BUCKETS = 2_000        # cap timeline buckets returned
DEFAULT_MAX_PATTERNS = 20
HARD_PATTERN_CAP = 200
DEFAULT_GREP_MAX = 100
HARD_GREP_CAP = 1_000

# --- Level detection --------------------------------------------------------------
_LEVELS = ("CRITICAL", "FATAL", "ERROR", "ERR", "WARNING", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE")
_LEVEL_CANON = {"ERR": "ERROR", "WARNING": "WARN"}
_LEVEL_RX = re.compile(r"\b(" + "|".join(_LEVELS) + r")\b", re.IGNORECASE)

# --- Timestamp detection ----------------------------------------------------------
# ISO-ish: 2026-11-11T13:04:11(.ms)?(tz)?  or with a space separator.
_ISO_RX = re.compile(
    r"(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})[ T](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
# slash date: 2026/11/11 13:04:11
_SLASH_RX = re.compile(
    r"(?P<y>\d{4})/(?P<mo>\d{2})/(?P<d>\d{2})[ T](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
_MON_ALT = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
# Apache/nginx common-log: 11/Nov/2026:13:04:11
_CLF_RX = re.compile(
    r"(?P<d>\d{1,2})/(?P<mon>" + _MON_ALT + r")/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
)
# syslog: "Nov 11 13:04:11" (no year).
_SYSLOG_RX = re.compile(
    r"\b(?P<mon>" + _MON_ALT + r")\s+(?P<d>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\b"
)
_DEFAULT_SYSLOG_YEAR = 1900  # deterministic; syslog carries no year


def _detect_timestamp(line: str) -> Optional[datetime]:
    m = _ISO_RX.search(line) or _SLASH_RX.search(line)
    if m:
        try:
            return datetime(int(m["y"]), int(m["mo"]), int(m["d"]),
                            int(m["h"]), int(m["mi"]), int(m["s"]))
        except ValueError:
            return None
    m = _CLF_RX.search(line)
    if m:
        try:
            return datetime(int(m["y"]), _MONTHS[m["mon"]], int(m["d"]),
                            int(m["h"]), int(m["mi"]), int(m["s"]))
        except (ValueError, KeyError):
            return None
    m = _SYSLOG_RX.search(line)
    if m:
        try:
            return datetime(_DEFAULT_SYSLOG_YEAR, _MONTHS[m["mon"]],
                            int(m["d"]), int(m["h"]), int(m["mi"]), int(m["s"]))
        except (ValueError, KeyError):
            return None
    return None


def _detect_level(line: str) -> str:
    m = _LEVEL_RX.search(line)
    if not m:
        return "UNKNOWN"
    token = m.group(1).upper()
    return _LEVEL_CANON.get(token, token)


# --- Template normalization (the core of the plugin) ------------------------------
# Order matters: specific shapes are masked before the generic number mask.
_MASKS = [
    (_ISO_RX, "<TS>"),
    (_SLASH_RX, "<TS>"),
    (_CLF_RX, "<TS>"),
    (_SYSLOG_RX, "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{32,64}\b"), "<HEX>"),       # md5/sha1/sha256-style
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<STR>"),
    (re.compile(r"-?\b\d[\d.,]*\b"), "<NUM>"),
]
_WS_RX = re.compile(r"\s+")


def _normalize_template(line: str) -> str:
    out = line
    for rx, repl in _MASKS:
        out = rx.sub(repl, out)
    return _WS_RX.sub(" ", out).strip()


# --- IO ---------------------------------------------------------------------------
def _resolve(path: Any) -> str:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("No file path provided")
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        raise ValueError(f"File not found: {path}")
    if os.path.isdir(path):
        raise ValueError(f"Path is a directory, not a file: {path}")
    return path


def _iter_lines(path: str):
    # Default (universal) newline mode normalises \r\n and lone \r to \n, so no
    # stray carriage return reaches the regex on CRLF logs.
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, start=1):
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
            yield lineno, line.rstrip("\n")


def _err(message: str, **extra: Any) -> str:
    return json.dumps({"ok": False, "error": message, **extra})


# --- Schemas ----------------------------------------------------------------------
LOG_SUMMARIZE = {
    "name": "log_summarize",
    "description": (
        "Mine a local log file into its recurring message patterns. Variable parts "
        "(numbers, IPs, UUIDs, hashes, quoted strings, timestamps) are masked so near-"
        "identical lines collapse into one template with an exact count — turning a "
        "huge noisy log into a short ranked list of what actually happened. Also returns "
        "a log-level histogram and the detected time span. Use this to understand or "
        "triage a log that is too large to read."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the local log file."},
            "max_patterns": {
                "type": "integer",
                "description": f"Top-N patterns to return. Default {DEFAULT_MAX_PATTERNS}, capped at {HARD_PATTERN_CAP}.",
            },
            "level": {
                "type": "string",
                "description": "Only consider lines at this level (e.g. ERROR, WARN). Omit for all lines.",
            },
        },
        "required": ["path"],
    },
}

LOG_GREP = {
    "name": "log_grep",
    "description": (
        "Search a local log file with a Python regular expression and return matching "
        "lines with their 1-based line numbers, optionally with surrounding context "
        "lines (like grep -C). Exhaustive and exact over large files."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the local log file."},
            "pattern": {"type": "string", "description": "Python regular expression to match."},
            "context": {
                "type": "integer",
                "description": "Lines of context to show before and after each match (grep -C). Default 0.",
            },
            "ignore_case": {"type": "boolean", "description": "Case-insensitive match. Default false."},
            "max_matches": {
                "type": "integer",
                "description": f"Max matches to return. Default {DEFAULT_GREP_MAX}, capped at {HARD_GREP_CAP}.",
            },
        },
        "required": ["path", "pattern"],
    },
}

LOG_TIMELINE = {
    "name": "log_timeline",
    "description": (
        "Bucket a local log file's events by time (minute, hour, or day) from the "
        "timestamps it detects, returning an exact count per bucket. Use this to find "
        "when activity or errors spiked."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the local log file."},
            "bucket": {
                "type": "string",
                "description": "Bucket size: 'minute', 'hour' (default) or 'day'.",
            },
            "level": {
                "type": "string",
                "description": "Only count lines at this level (e.g. ERROR). Omit for all lines.",
            },
        },
        "required": ["path"],
    },
}


# --- Handlers (always return a JSON string) ---------------------------------------
def log_summarize(args: dict, **kwargs) -> str:
    try:
        path = _resolve(args.get("path"))
    except ValueError as exc:
        return _err(str(exc))

    want_level = args.get("level")
    want_level = want_level.upper() if isinstance(want_level, str) and want_level.strip() else None
    max_patterns = args.get("max_patterns", DEFAULT_MAX_PATTERNS)
    if not isinstance(max_patterns, int) or max_patterns <= 0:
        max_patterns = DEFAULT_MAX_PATTERNS
    max_patterns = min(max_patterns, HARD_PATTERN_CAP)

    counts: Counter = Counter()
    examples: dict[str, str] = {}
    first_line: dict[str, int] = {}
    last_line: dict[str, int] = {}
    level_hist: Counter = Counter()
    total = scanned = considered = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    scan_truncated = templates_capped = False

    try:
        for lineno, text in _iter_lines(path):
            scanned += 1
            if scanned > SCAN_LINE_CAP:
                scan_truncated = True
                break
            total += 1
            lvl = _detect_level(text)
            level_hist[lvl] += 1
            if want_level and lvl != want_level:
                continue
            considered += 1
            ts = _detect_timestamp(text)
            if ts is not None:
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts
            tmpl = _normalize_template(text)
            if tmpl not in counts and len(counts) >= MAX_TEMPLATES:
                templates_capped = True
                continue
            counts[tmpl] += 1
            if tmpl not in examples:
                examples[tmpl] = text[:300]
                first_line[tmpl] = lineno
            last_line[tmpl] = lineno
    except OSError as exc:
        return _err(f"Could not read file: {exc}")

    top = [
        {
            "template": t,
            "count": c,
            "example": examples[t],
            "first_line": first_line[t],
            "last_line": last_line[t],
        }
        for t, c in counts.most_common(max_patterns)
    ]
    return json.dumps({
        "ok": True,
        "file": path,
        "total_lines": total,
        "considered_lines": considered,
        "level_filter": want_level,
        "distinct_patterns": len(counts),
        "level_histogram": dict(level_hist.most_common()),
        "time_span": {
            "first": first_ts.isoformat() if first_ts else None,
            "last": last_ts.isoformat() if last_ts else None,
        },
        "top_patterns": top,
        "scan_truncated": scan_truncated,
        "templates_capped": templates_capped,
    })


def log_grep(args: dict, **kwargs) -> str:
    try:
        path = _resolve(args.get("path"))
    except ValueError as exc:
        return _err(str(exc))
    pattern = args.get("pattern")
    if not isinstance(pattern, str) or pattern == "":
        return _err("No regex pattern provided")
    flags = re.IGNORECASE if bool(args.get("ignore_case")) else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as exc:
        return _err(f"Invalid regular expression: {exc}")

    context = args.get("context", 0)
    if not isinstance(context, int) or context < 0:
        context = 0
    context = min(context, 50)
    max_matches = args.get("max_matches", DEFAULT_GREP_MAX)
    if not isinstance(max_matches, int) or max_matches <= 0:
        max_matches = DEFAULT_GREP_MAX
    max_matches = min(max_matches, HARD_GREP_CAP)

    total = scanned = 0
    results: list[dict] = []
    scan_truncated = False
    try:
        if context == 0:
            for lineno, text in _iter_lines(path):
                scanned += 1
                if scanned > SCAN_LINE_CAP:
                    scan_truncated = True
                    break
                if rx.search(text):
                    total += 1
                    if len(results) < max_matches:
                        results.append({"line": lineno, "text": text[:500]})
        else:
            # Context mode needs a sliding window of recent lines.
            window: list[tuple[int, str]] = []
            pending_after = 0
            current: Optional[dict] = None
            for lineno, text in _iter_lines(path):
                scanned += 1
                if scanned > SCAN_LINE_CAP:
                    scan_truncated = True
                    break
                window.append((lineno, text))
                if len(window) > context + 1:
                    window.pop(0)
                if pending_after and current is not None:
                    current["after"].append({"line": lineno, "text": text[:500]})
                    pending_after -= 1
                    if pending_after == 0:
                        current = None
                if rx.search(text):
                    total += 1
                    if len(results) < max_matches:
                        before = [{"line": ln, "text": tx[:500]} for ln, tx in window[:-1]]
                        current = {"line": lineno, "text": text[:500], "before": before, "after": []}
                        results.append(current)
                        pending_after = context
    except OSError as exc:
        return _err(f"Could not read file: {exc}")

    return json.dumps({
        "ok": True,
        "file": path,
        "pattern": rx.pattern,
        "context": context,
        "total_matches": total,
        "returned": len(results),
        "truncated": len(results) < total,
        "scan_truncated": scan_truncated,
        "matches": results,
    })


def log_timeline(args: dict, **kwargs) -> str:
    try:
        path = _resolve(args.get("path"))
    except ValueError as exc:
        return _err(str(exc))
    bucket = args.get("bucket", "hour")
    if bucket not in ("minute", "hour", "day"):
        bucket = "hour"
    want_level = args.get("level")
    want_level = want_level.upper() if isinstance(want_level, str) and want_level.strip() else None

    def _key(ts: datetime) -> str:
        if bucket == "minute":
            return ts.replace(second=0, microsecond=0).isoformat()
        if bucket == "day":
            return ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        return ts.replace(minute=0, second=0, microsecond=0).isoformat()

    buckets: Counter = Counter()
    scanned = timestamped = 0
    scan_truncated = False
    try:
        for _lineno, text in _iter_lines(path):
            scanned += 1
            if scanned > SCAN_LINE_CAP:
                scan_truncated = True
                break
            if want_level and _detect_level(text) != want_level:
                continue
            ts = _detect_timestamp(text)
            if ts is None:
                continue
            timestamped += 1
            buckets[_key(ts)] += 1
    except OSError as exc:
        return _err(f"Could not read file: {exc}")

    ordered = sorted(buckets.items())
    truncated = len(ordered) > MAX_TIME_BUCKETS
    if truncated:
        ordered = ordered[:MAX_TIME_BUCKETS]
    series = [{"bucket": k, "count": v} for k, v in ordered]
    peak = max(series, key=lambda b: b["count"]) if series else None
    return json.dumps({
        "ok": True,
        "file": path,
        "bucket": bucket,
        "level_filter": want_level,
        "timestamped_lines": timestamped,
        "buckets_returned": len(series),
        "buckets_truncated": truncated,
        "peak": peak,
        "series": series,
        "scan_truncated": scan_truncated,
    })
