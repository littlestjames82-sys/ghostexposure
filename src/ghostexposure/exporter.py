"""Bundle export and verification.

Bundle layout:
  files/<rel>     exported copies (surface full, context signatures for Python)
  manifest.json   Slice-style per-file manifest (mode, tokens, sha256)
  exposure.json   partition, inventory hash, surface pack, redactions, limits
  EXPOSURE.md     human-readable hand-off document
  PROMPT.md       concatenated exported files
Transforms happen in the exported copy only. The source tree is never altered.
"""
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import CANNOT_PROVE_STATEMENT, COVERAGE_STATEMENT, __version__
from .inventory import build_inventory, estimate_tokens, inventory_hash
from .partition import build_partition, load_profile_pins, partition_counts
from .secrets import find_literals, redact_text
from .tokens import METHOD as TOKEN_METHOD
from .tokens import language_for


class ExportError(ValueError):
    pass


def signatures_source(text):
    """Python signatures mode: imports, signatures, first docstring line."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    out = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out.append(ast.unparse(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node)
            sig = f"def {node.name}({ast.unparse(node.args)}):"
            if node.returns is not None:
                sig = sig[:-1] + f" -> {ast.unparse(node.returns)}:"
            out.append(sig)
            if doc:
                out.append(f'    """{doc.splitlines()[0]}"""')
            out.append("    ...")
        elif isinstance(node, ast.ClassDef):
            out.append(f"class {node.name}:")
            doc = ast.get_docstring(node)
            if doc:
                out.append(f'    """{doc.splitlines()[0]}"""')
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append(f"    def {sub.name}({ast.unparse(sub.args)}): ...")
            out.append("    ...")
        elif isinstance(node, ast.Assign):
            try:
                out.append(ast.unparse(node).split("=")[0].strip() + " = ...")
            except Exception:
                pass
    return "\n".join(out) + "\n"


def _sha(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()


def export_bundle(project, out_dir, pack, allow_unredacted=False,
                  exclude_conflicts=False, pins=None):
    project = Path(project).resolve()
    out = Path(out_dir).resolve()
    pins = pins if pins is not None else load_profile_pins(project)
    entries = build_inventory(project)
    # Exclude the output folder itself if it lives inside the project
    try:
        out_rel = out.relative_to(project).as_posix()
        entries = [e for e in entries
                   if not (e["path"] == out_rel or e["path"].startswith(out_rel + "/"))]
    except ValueError:
        pass
    partition = build_partition(entries, pack, pins)
    counts = partition_counts(partition)
    conflicts = [d for d in partition if d["decision"] == "conflict"]
    if conflicts and not exclude_conflicts:
        names = ", ".join(d["path"] for d in conflicts)
        raise ExportError(
            f"unresolved conflicts (surface match + user pin-out): {names}. "
            "Change the pin or the pack, or re-run with --exclude-conflicts "
            "to record an explicit decision to leave them out.")
    by_path = {e["path"]: e for e in entries}
    if out.exists() and any(out.iterdir()):
        raise ExportError(f"output folder exists and is not empty: {out}")
    (out / "files").mkdir(parents=True, exist_ok=True)

    manifest_files = []
    redactions = []
    prompt_parts = []
    total_in_tokens = 0
    total_original_tokens = 0
    for d in partition:
        if d["decision"] not in ("surface", "context"):
            continue
        entry = by_path[d["path"]]
        text = entry.get("text")
        mode = "full" if d["decision"] == "surface" else "signatures"
        if text is None:
            # Binary surface/context files are carried verbatim under
            # files/, but they are not sliced text: GhostSlice excludes
            # binaries from its bundles, so the GhostSlice-shaped
            # record for one is mode "exclude" with sliced_tokens 0
            # (the mode GhostSlice's checker skips, and the only one
            # that validates for a payload whose bytes are not UTF-8
            # slice text). The Exposure-side record keeps the raw
            # sha256 above, so verify_bundle still hashes the exact
            # carried bytes; "binary"/"carried_verbatim" say why the
            # mode reads "exclude" for a file that is present.
            raw = (project / d["path"]).read_bytes()
            dest = out / "files" / d["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            manifest_files.append({
                "path": d["path"], "mode": "exclude", "decision": d["decision"],
                "language": language_for(d["path"]), "package": "",
                "binary": True, "carried_verbatim": True,
                "reasons": d["reasons"],
                "original_tokens": 0, "sliced_tokens": 0,
                "original_estimated_tokens": 0,
                "exported_estimated_tokens": 0, "sha256": _sha(raw)})
            continue
        if mode == "signatures" and d["path"].endswith(".py"):
            exported_text = signatures_source(text)
        elif mode == "signatures":
            exported_text = text
            mode = "full"
        else:
            exported_text = text
        findings = find_literals(exported_text)
        file_redactions = []
        if findings and not allow_unredacted:
            exported_text = redact_text(exported_text, findings)
            for f in findings:
                file_redactions.append({"path": d["path"], "line": f["line"],
                                        "type": f["type"]})
        elif findings and allow_unredacted:
            for f in findings:
                file_redactions.append({"path": d["path"], "line": f["line"],
                                        "type": f["type"],
                                        "unredacted_by_explicit_flag": True})
        redactions.extend(file_redactions)
        data = exported_text.encode("utf-8")
        dest = out / "files" / d["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        exp_tokens = estimate_tokens(exported_text, d["path"])
        total_in_tokens += exp_tokens
        total_original_tokens += d["estimated_tokens"]
        manifest_files.append({
            "path": d["path"], "mode": mode, "decision": d["decision"],
            "language": language_for(d["path"]), "package": "",
            "reasons": d["reasons"],
            # GhostSlice bundle schema (ghostslice/exporter.py): the
            # per-file token fields and totals below are what
            # `ghostslice check` validates, recomputing sliced_tokens
            # from the exported text with GhostSlice's estimator.
            "original_tokens": d["estimated_tokens"],
            "sliced_tokens": exp_tokens,
            # GhostExposure's original field names, kept so existing
            # readers of this manifest keep working.
            "original_estimated_tokens": d["estimated_tokens"],
            "exported_estimated_tokens": exp_tokens, "sha256": _sha(data)})
        prompt_parts.append(f"\n\n===== {d['path']} ({mode}) =====\n{exported_text}")

    inv_hash = inventory_hash(entries)
    manifest = {"tool": "ghostexposure", "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "root": str(project),
                "token_method": TOKEN_METHOD,
                "files": manifest_files,
                # GhostSlice totals schema: top-level integers that
                # `ghostslice check` requires and recomputes against.
                "total_original_tokens": total_original_tokens,
                "total_sliced_tokens": total_in_tokens,
                "total_saved_tokens": total_original_tokens - total_in_tokens,
                "totals": {"files_in_bundle": len(manifest_files),
                           "original_tokens": total_original_tokens,
                           "sliced_tokens": total_in_tokens,
                           "exported_estimated_tokens": total_in_tokens}}
    exposure = {
        "tool": "ghostexposure", "version": __version__,
        "surface_pack": {"id": pack["id"], "version": pack["version"],
                         "date": pack["date"],
                         "patterns": pack["patterns"]},
        "inventory_hash": inv_hash,
        "inventory_sha256": inv_hash,
        "inventory_file_count": len(entries),
        "surface": {"id": pack["id"], "version": pack["version"],
                    "date": pack["date"]},
        "files": partition,
        "partition": partition,
        "counts": counts,
        "redactions": redactions,
        "allow_unredacted": bool(allow_unredacted),
        "conflicts_excluded_by_explicit_flag": bool(conflicts and exclude_conflicts),
        "coverage_limits": pack.get("coverage_limits", []),
        "coverage_statement": COVERAGE_STATEMENT,
        "cannot_prove_statement": CANNOT_PROVE_STATEMENT,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",
                                       encoding="utf-8")
    (out / "exposure.json").write_text(json.dumps(exposure, indent=2) + "\n",
                                       encoding="utf-8")
    (out / "PROMPT.md").write_text(
        "# GhostExposure bundle\n" + "".join(prompt_parts) + "\n",
        encoding="utf-8")
    (out / "EXPOSURE.md").write_text(
        render_exposure_md(exposure, manifest), encoding="utf-8")
    return {"out": str(out), "counts": counts, "redactions": redactions,
            "manifest": manifest, "exposure": exposure}


def render_exposure_md(exposure, manifest):
    sp = exposure["surface_pack"]
    lines = [
        "# GhostExposure bundle",
        "",
        "This document describes a bundle of files prepared for review. "
        "It records what the bundle contains and what it does not contain. "
        "It makes no statement about the quality of the code in the bundle.",
        "",
        "## Surface definition used",
        f"- Pack: {sp['id']} version {sp['version']} dated {sp['date']}",
        "- Patterns (id, kind, pattern, reason):",
    ]
    for p in sp["patterns"]:
        lines.append(f"  - {p['id']} | {p['kind']} | `{p['pattern']}` | {p['reason']}")
    c = exposure["counts"]
    lines += [
        "",
        "## Counts (from the recorded partition)",
        f"- Files in the source tree inventory: {exposure['inventory_file_count']}",
        f"- Files in bundle: {c['surface']} surface + {c['context']} context "
        f"= {c['surface'] + c['context']}",
        f"- Files not in bundle: {c['out']}",
        f"- Conflicts recorded: {c['conflict']}",
        f"- Exported total: {manifest['totals']['exported_estimated_tokens']} "
        "estimated tokens (estimate from bundle text length, not a measured count)",
        f"- Inventory hash: {exposure['inventory_hash']}",
        f"- Redactions recorded: {len(exposure['redactions'])}"
        + (" (explicit --allow-unredacted was used and is recorded)"
           if exposure["allow_unredacted"] else
           " (secret-shaped literals replaced in exported copies by default)"),
        "",
        "## Coverage limits",
        exposure["coverage_statement"],
    ]
    for item in exposure.get("coverage_limits", []):
        lines.append(f"- {item}")
    lines += [
        "",
        "## What verification proves, and what it does not",
        exposure["cannot_prove_statement"],
        "",
        "## How a receiver verifies this bundle",
        "Run, with GhostExposure installed and no network access needed:",
        "",
        "    ghostexposure verify <this-bundle-folder>",
        "",
        "Verification re-reads manifest.json and exposure.json, checks every "
        "exported file hash, checks that the files on disk are exactly the "
        "files recorded as in the bundle, and checks that every file in the "
        "recorded inventory appears exactly once in the partition.",
        "",
    ]
    return "\n".join(lines)


def verify_bundle(bundle_dir):
    """Return (ok, problems, notes). Names every discrepancy found."""
    bundle = Path(bundle_dir).resolve()
    problems, notes = [], []
    for name in ("manifest.json", "exposure.json", "EXPOSURE.md"):
        if not (bundle / name).exists():
            problems.append(f"missing bundle file: {name}")
    if problems:
        return False, problems, notes
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    exposure = json.loads((bundle / "exposure.json").read_text(encoding="utf-8"))
    md = (bundle / "EXPOSURE.md").read_text(encoding="utf-8")
    if COVERAGE_STATEMENT.split(":")[0] not in md:
        problems.append("EXPOSURE.md is missing the coverage-limits statement")
    if "cannot prove" not in md:
        problems.append("EXPOSURE.md is missing the cannot-prove statement")
    # Partition completeness: every inventory path exactly once
    partition = exposure.get("partition", [])
    seen = {}
    for d in partition:
        seen[d["path"]] = seen.get(d["path"], 0) + 1
    for path, n in seen.items():
        if n != 1:
            problems.append(f"partition lists {path} {n} times")
    if len(partition) != exposure.get("inventory_file_count"):
        problems.append(
            f"partition has {len(partition)} entries, inventory count is "
            f"{exposure.get('inventory_file_count')}")
    # Inventory hash over recorded partition source hashes
    fake = [{"path": d["path"], "sha256": d["sha256"]}
            for d in sorted(partition, key=lambda x: x["path"])]
    if inventory_hash(fake) != exposure.get("inventory_hash"):
        problems.append("inventory hash does not match the recorded partition")
    # Files on disk under files/ must equal manifest set, hashes must match
    files_root = bundle / "files"
    on_disk = set()
    if files_root.exists():
        for p in files_root.rglob("*"):
            if p.is_file():
                on_disk.add(p.relative_to(files_root).as_posix())
    manifest_by_path = {f["path"]: f for f in manifest.get("files", [])}
    for path in sorted(set(manifest_by_path) - on_disk):
        problems.append(f"recorded in bundle but missing on disk: {path}")
    for path in sorted(on_disk - set(manifest_by_path)):
        problems.append(f"present on disk but not recorded in bundle: {path}")
    for path, f in manifest_by_path.items():
        p = files_root / path
        if p.exists() and _sha(p.read_bytes()) != f["sha256"]:
            problems.append(f"hash mismatch for bundled file: {path}")
    # Partition in-set must equal manifest set
    in_set = {d["path"] for d in partition
              if d["decision"] in ("surface", "context")}
    if in_set != set(manifest_by_path):
        for path in sorted(in_set.symmetric_difference(set(manifest_by_path))):
            problems.append(f"partition/manifest disagreement for: {path}")
    notes.append(CANNOT_PROVE_STATEMENT)
    notes.append(COVERAGE_STATEMENT)
    return (not problems), problems, notes
