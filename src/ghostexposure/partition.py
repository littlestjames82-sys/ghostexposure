"""Partition an inventory into surface / context / out / conflict.

Every inventory file gets exactly one decision. Reason codes record which
rule fired. Conflicts (surface match + user pin-out) are never resolved
silently: the decision is 'conflict' until a human changes a pin or uses
an explicit, recorded override at export time.
"""
import ast
import fnmatch
import re

from .inventory import estimate_tokens


def load_profile_pins(project):
    """Read .ghostslice.json exposure section, if present."""
    import json
    from pathlib import Path
    pins = {"pinned_in": [], "pinned_out": [], "surface": None}
    prof = Path(project) / ".ghostslice.json"
    if prof.exists():
        try:
            data = json.loads(prof.read_text(encoding="utf-8"))
        except Exception:
            return pins
        exp = data.get("exposure") or {}
        if isinstance(exp, dict):
            # Accept both pinned_in/pinned_out and pin_in/pin_out spellings.
            pins["pinned_in"] = list(
                exp.get("pinned_in") or exp.get("pin_in") or [])
            pins["pinned_out"] = list(
                exp.get("pinned_out") or exp.get("pin_out") or [])
            pins["surface"] = exp.get("surface")
    return pins


def _glob_hit(rel, pat):
    return (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, "*/" + pat)
            or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], pat))


def _pattern_hits(entry, pack):
    hits = []
    text = entry.get("text") or ""
    for pat in pack["patterns"]:
        kind, needle = pat["kind"], pat["pattern"]
        fired = False
        if kind == "glob":
            fired = _glob_hit(entry["path"], needle)
        elif kind in ("symbol", "import", "data"):
            if text:
                try:
                    fired = re.search(needle, text) is not None
                except re.error:
                    fired = needle in text
        if fired:
            hits.append({"code": kind, "pattern_id": pat["id"],
                         "reason": pat["reason"]})
    return hits


def _imports_of(entry):
    """Module names a file references (Python ast, else regex import lines)."""
    text = entry.get("text") or ""
    mods = set()
    if entry["path"].endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        mods.add(a.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        mods.add(node.module)
                        for a in node.names:
                            mods.add(f"{node.module}.{a.name}")
            return mods
    for m in re.finditer(r"(?m)^\s*(?:import|from)\s+([\w\.]+)", text):
        mods.add(m.group(1))
    for m in re.finditer(r"""(?:require\(|from\s+)['"]([^'"]+)['"]""", text):
        mods.add(m.group(1))
    return mods


def _module_to_paths(entries):
    mapping = {}
    for e in entries:
        p = e["path"]
        if p.endswith(".py"):
            mod = p[:-3].replace("/", ".")
            if mod.endswith(".__init__"):
                mod = mod[:-9]
            mapping[mod] = p
            mapping[p.rsplit("/", 1)[-1][:-3]] = p
        elif p.rsplit("/", 1)[-1].count(".") >= 1:
            mapping[p.rsplit("/", 1)[-1].rsplit(".", 1)[0]] = p
    return mapping


def build_partition(entries, pack, pins):
    """Return partition list, one dict per inventory entry."""
    by_path = {e["path"]: e for e in entries}
    # First pass: surface matches and pins
    prelim = {}
    for e in entries:
        rel = e["path"]
        hits = _pattern_hits(e, pack)
        pin_in = any(_glob_hit(rel, g) for g in pins.get("pinned_in", []))
        pin_out = any(_glob_hit(rel, g) for g in pins.get("pinned_out", []))
        reasons = list(hits)
        if pin_in:
            reasons.append({"code": "user-pinned-in", "pattern_id": None,
                            "reason": "Pinned in by user profile."})
        if pin_out:
            reasons.append({"code": "user-pinned-out", "pattern_id": None,
                            "reason": "Pinned out by user profile."})
        if hits and pin_out:
            decision = "conflict"
        elif hits or pin_in:
            decision = "surface"
        elif pin_out:
            decision = "out"
        else:
            decision = "out"
        prelim[rel] = {"path": rel, "decision": decision, "reasons": reasons,
                       "sha256": e["sha256"], "size": e["size"],
                       "estimated_tokens": estimate_tokens(e.get("text"),
                                                         e["path"])}
    # Second pass: graph context = files that call into the surface
    # (distance-1 callers: they import a surface file). Files the surface
    # itself imports are not pulled in by this rule; a surface file's own
    # imports do not by themselves put a helper in the bundle.
    surface_paths = {p for p, d in prelim.items() if d["decision"] == "surface"}
    if surface_paths:
        modmap = _module_to_paths(entries)
        for e in entries:
            rel = e["path"]
            if rel in surface_paths or prelim[rel]["decision"] == "conflict":
                continue
            imports_surface = any(
                (modmap.get(m) or modmap.get(m.split(".")[-1])) in surface_paths
                for m in _imports_of(e))
            if imports_surface:
                if prelim[rel]["decision"] == "out" and not any(
                        r["code"] == "user-pinned-out"
                        for r in prelim[rel]["reasons"]):
                    prelim[rel]["decision"] = "context"
                    prelim[rel]["reasons"].append({
                        "code": "graph-neighbour", "pattern_id": None,
                        "reason": "Calls into a surface file (imports it), "
                                  "distance-1 graph context."})
    return [prelim[p] for p in sorted(prelim)]


def partition_counts(partition):
    counts = {"surface": 0, "context": 0, "out": 0, "conflict": 0, "total": 0}
    for d in partition:
        counts[d["decision"]] = counts.get(d["decision"], 0) + 1
        counts["total"] += 1
    return counts
