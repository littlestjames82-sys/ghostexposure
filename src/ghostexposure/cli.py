"""GhostExposure CLI: scan / export / verify / packs."""
import argparse
import json
import sys
from pathlib import Path

from . import CANNOT_PROVE_STATEMENT, COVERAGE_STATEMENT, __version__
from .exporter import ExportError, export_bundle, verify_bundle
from .inventory import build_inventory, inventory_hash
from .partition import build_partition, load_profile_pins, partition_counts
from .surface import SurfaceError, load_pack, pack_summary


def _load(args):
    return load_pack(getattr(args, "surface", None))


def cmd_scan(args):
    pack = _load(args)
    project = Path(args.project)
    pins = load_profile_pins(project)
    entries = build_inventory(project)
    partition = build_partition(entries, pack, pins)
    counts = partition_counts(partition)
    if args.json:
        print(json.dumps({
            "surface_pack": pack_summary(pack),
            "inventory_hash": inventory_hash(entries),
            "counts": counts, "partition": partition,
            "coverage_statement": COVERAGE_STATEMENT,
            "coverage_limits": pack.get("coverage_limits", []),
        }, indent=2))
    else:
        print(f"GhostExposure scan: {project}")
        print(f"Surface pack: {pack['id']} {pack['version']} ({pack['date']})")
        for d in partition:
            codes = ",".join(r["code"] for r in d["reasons"]) or "-"
            print(f"  {d['decision']:9} {d['path']}  [{codes}]")
            for r in d["reasons"]:
                print(f"              {r['code']}: {r['reason']}")
        print(f"Counts: {counts}")
        print(COVERAGE_STATEMENT)
        for item in pack.get("coverage_limits", []):
            print(f"  - {item}")
        if counts["conflict"]:
            print("Conflicts are listed above as 'conflict'. They require a "
                  "human decision: change the pin or the pack. They are not "
                  "resolved by this tool.")
    return 1 if counts["conflict"] else 0


def cmd_export(args):
    pack = _load(args)
    try:
        result = export_bundle(
            args.project, args.output, pack,
            allow_unredacted=args.allow_unredacted,
            exclude_conflicts=args.exclude_conflicts)
    except ExportError as e:
        print(f"export stopped: {e}", file=sys.stderr)
        return 2
    c = result["counts"]
    print(f"Bundle written to {result['out']}")
    print(f"Files in bundle: {c['surface']} surface + {c['context']} context; "
          f"not in bundle: {c['out']}; conflicts: {c['conflict']}")
    if result["redactions"]:
        print(f"Redactions recorded: {len(result['redactions'])} "
              "(path + line + type in exposure.json, values never recorded)")
        for r in result["redactions"]:
            print(f"  {r['path']}:{r['line']} {r['type']}")
    print(COVERAGE_STATEMENT)
    return 0


def cmd_verify(args):
    ok, problems, notes = verify_bundle(args.bundle)
    if args.json:
        print(json.dumps({"matches_manifest": ok, "problems": problems,
                          "notes": notes}, indent=2))
    else:
        if ok:
            print("Bundle on disk matches its manifest and partition.")
        else:
            print("Bundle does NOT match its manifest:")
            for p in problems:
                print(f"  - {p}")
        for n in notes:
            print(n)
    return 0 if ok else 1


def cmd_packs(args):
    pack = _load(args)
    print(json.dumps(pack_summary(pack), indent=2))
    for p in pack["patterns"]:
        print(f"  {p['id']} | {p['kind']} | {p['pattern']} | {p['reason']}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ghostexposure",
        description="Prepare a scoped bundle of a sensitive surface, with a "
                    "recorded partition of what is in the bundle and what is not.")
    ap.add_argument("--version", action="version",
                    version=f"ghostexposure {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "export"):
        p = sub.add_parser(name)
        p.add_argument("project")
        p.add_argument("--surface", default=None,
                       help="path to a surface pack JSON (default: starter pack)")
        if name == "scan":
            p.add_argument("--json", action="store_true")
            p.set_defaults(fn=cmd_scan)
        else:
            p.add_argument("-o", "--output", required=True)
            p.add_argument("--allow-unredacted", action="store_true",
                           help="export secret-shaped literals as-is; this "
                                "choice is recorded in exposure.json")
            p.add_argument("--exclude-conflicts", action="store_true",
                           help="leave conflicted files out, with the decision "
                                "recorded in exposure.json")
            p.set_defaults(fn=cmd_export)
    p = sub.add_parser("verify")
    p.add_argument("bundle")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("packs")
    p.add_argument("--surface", default=None)
    p.set_defaults(fn=cmd_packs)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (SurfaceError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
