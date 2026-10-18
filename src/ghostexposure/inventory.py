"""Full-tree inventory: every file accounted for exactly once."""
import hashlib
import os
from pathlib import Path

DEFAULT_IGNORE_DIRS = {".git", "__pycache__", ".tox", ".venv", "venv",
                       "node_modules", "dist", "build", ".ghostexposure-cache"}
MAX_TEXT_BYTES = 2_000_000


def _gitignore_patterns(root):
    pats = []
    gi = root / ".gitignore"
    if gi.exists():
        for raw in gi.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                pats.append(line.strip("/"))
    return pats


def _ignored(rel, pats):
    import fnmatch
    parts = rel.split("/")
    for pat in pats:
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
            return True
        for i in range(len(parts)):
            if fnmatch.fnmatch("/".join(parts[:i + 1]), pat):
                return True
    return False


def is_text_bytes(data):
    return b"\x00" not in data[:4096]


def build_inventory(root):
    """Return list of dicts: path, size, sha256, is_text, text (or None)."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError(f"project is not a directory: {root}")
    pats = _gitignore_patterns(root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in DEFAULT_IGNORE_DIRS)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if _ignored(rel, pats):
                continue
            data = full.read_bytes()
            is_text = is_text_bytes(data) and len(data) <= MAX_TEXT_BYTES
            entries.append({
                "path": rel,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "is_text": bool(is_text),
                "text": data.decode("utf-8", errors="replace") if is_text else None,
            })
    return sorted(entries, key=lambda e: e["path"])


def inventory_hash(entries):
    h = hashlib.sha256()
    for e in entries:
        h.update(f"{e['path']}\0{e['sha256']}\n".encode("utf-8"))
    return h.hexdigest()


def estimate_tokens(text, path=None):
    """Token estimate for inventory/partition records.

    Delegates to ghostexposure.tokens, which prefers GhostSlice's
    estimator (per-file language) so figures recorded here match the
    manifest figures GhostSlice's checker recomputes. Imported here
    (not at module top) to keep the inventory module importable on
    its own."""
    from .tokens import estimate_tokens as _estimate
    return _estimate(text, path)
