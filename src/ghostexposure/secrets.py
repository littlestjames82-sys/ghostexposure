"""Secret-shaped literal detection and redaction.

Findings are recorded as path + line + type only. The literal value is
never written to any manifest, report, or log by this module.

Shape parity with GhostSlice's guard (ghostslice/secrets_scan.py) was
audited in the Oct 14, 2026 seam-fix round; see SEAM_FIX_REPORT.md for
the per-shape record. Known-shape patterns below mirror Slice's
canonical regexes for the shapes both tools detect. Exposure-only
shapes (bearer_token, long_hex_assignment) are extra coverage, and the
heuristic assignment layer (generic_assignment) deliberately stays
stricter than Slice's sensitive-assignment rule: this module REWRITES
exported evidence text, so it requires a quoted value of 12+ chars
under a sensitive name, where Slice's reporting scan can afford to
flag looser candidates without destroying anything.
"""
import re

# (type_id, regex with one capture group for the literal value)
_PATTERNS = [
    # Canonical Slice form: AKIA (long-lived) and ASIA (temporary
    # session) prefixes. Was AKIA-only before the seam fix, which let
    # ASIA temporary keys ship unredacted.
    ("aws_access_key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    # Canonical Slice form: the token body class includes "_"; without
    # it a token containing an underscore matched only partially (or not
    # at all), leaving the tail unredacted.
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b")),
    # Canonical Slice form: optional ant-/proj- prefix, 16+ body chars
    # (was a flat 20+ with no prefix handling).
    ("openai_style_key", re.compile(
        r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,})\b")),
    # Canonical Slice shape, missing from Exposure before the seam fix.
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b")),
    # Canonical Slice shape, missing before the seam fix. Group 1 is
    # the password only, so redaction keeps the URL's shape visible.
    ("password_in_url", re.compile(r"://[^/\s:@'\"]+:([^/\s:@'\"]{3,})@")),
    # Exposure-only extra shape (Slice has no bearer pattern).
    ("bearer_token", re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})")),
    ("generic_assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)"
        r"\s*[=:]\s*[\"']([^\"'\s]{12,})[\"']")),
    ("private_key_header", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("long_hex_assignment", re.compile(
        r"(?i)(?:key|secret|token)\s*[=:]\s*[\"']([0-9a-f]{32,})[\"']")),
]

# Canonical Slice aws-secret-key rule: a bare 40-char base64-ish value
# is only treated as a secret when its line also names something
# AWS-secret-like. Handled as a special case in find_literals, exactly
# as Slice handles it outside its pattern list.
_AWS_SECRET_CONTEXT = re.compile(r"aws.{0,20}secret|secret.{0,20}aws",
                                 re.IGNORECASE)
_BARE_40 = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")

_PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")

REDACTED = "***REDACTED***"


def _pem_block_last_line(lines, start):
    """0-based index of the last line of the PEM block whose BEGIN
    header is on lines[start]: through the END line when present, else
    over the following bare-base64 body lines (a file can be cut before
    its END line; the body is the secret material either way). Mirrors
    GhostSlice's _pem_block."""
    for j in range(start + 1, len(lines)):
        if _PEM_END_RE.search(lines[j]):
            return j
    last = start
    for j in range(start + 1, len(lines)):
        if _PEM_BODY_RE.fullmatch(lines[j].strip()):
            last = j
        else:
            break
    return last


def find_literals(text):
    """Return list of (line_no, type_id, start, end) for literal spans."""
    found = []
    seen = set()
    lines = text.splitlines()
    line_starts = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line) + 1
    block_spans = []

    def add(lineno, type_id, span):
        if span in seen:
            return
        if any(s <= span[0] and span[1] <= e for s, e in block_spans):
            return  # already inside a redacted private-key block
        seen.add(span)
        found.append({"line": lineno, "type": type_id,
                      "start": span[0], "end": span[1]})

    for lineno, line in enumerate(lines, 1):
        base = line_starts[lineno - 1]
        for type_id, rx in _PATTERNS:
            for m in rx.finditer(line):
                span = (base + m.start(1), base + m.end(1))
                if type_id == "private_key_header":
                    # Slice redacts the whole key block, not just the
                    # header line: extend the span to the block's last
                    # line so the base64 body cannot ship behind a
                    # redacted header. Any finding already recorded
                    # inside the block is subsumed by it.
                    last = _pem_block_last_line(lines, lineno - 1)
                    span = (span[0],
                            line_starts[last] + len(lines[last]))
                    found[:] = [f for f in found
                                if not (span[0] <= f["start"]
                                        and f["end"] <= span[1])]
                    add(lineno, type_id, span)
                    block_spans.append(span)
                    continue
                add(lineno, type_id, span)
        if _AWS_SECRET_CONTEXT.search(line):
            for m in _BARE_40.finditer(line):
                add(lineno, "aws_secret_key",
                    (base + m.start(), base + m.end()))
    return sorted(found, key=lambda f: f["start"])


def redact_text(text, findings):
    """Replace each finding span with the redaction marker."""
    out = text
    for f in sorted(findings, key=lambda x: x["start"], reverse=True):
        out = out[:f["start"]] + REDACTED + out[f["end"]:]
    return out
