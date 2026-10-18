"""Surface pack loading and validation. Surface definitions are data."""
import json
from pathlib import Path

VALID_KINDS = {"glob", "symbol", "import", "data"}
REQUIRED_PACK_FIELDS = {"id", "version", "date", "description", "patterns",
                        "coverage_limits"}


class SurfaceError(ValueError):
    pass


def default_pack_path():
    # src/ghostexposure/../../surfaces/starter.json relative to package root
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "surfaces" / "starter.json",
        here.parents[1] / "surfaces" / "starter.json",
        Path.cwd() / "surfaces" / "starter.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


def load_pack(path=None):
    p = Path(path) if path else default_pack_path()
    if not p.exists():
        raise SurfaceError(f"surface pack not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SurfaceError(f"surface pack is not valid JSON: {p}: {e}") from e
    # Accept 'dated' as the date field name and a plain string for
    # coverage_limits; normalise both to the canonical shape.
    if "date" not in data and "dated" in data:
        data["date"] = data["dated"]
    if isinstance(data.get("coverage_limits"), str):
        data["coverage_limits"] = [data["coverage_limits"]]
    missing = REQUIRED_PACK_FIELDS - set(data)
    if missing:
        raise SurfaceError(f"surface pack {p} missing fields: {sorted(missing)}")
    if data.get("kind", "surface") != "surface":
        raise SurfaceError("surface pack kind must be 'surface'")
    for pat in data["patterns"]:
        for field in ("id", "kind", "pattern", "reason"):
            if field not in pat:
                raise SurfaceError(f"pattern in {p} missing field: {field}")
        if pat["kind"] not in VALID_KINDS:
            raise SurfaceError(
                f"pattern {pat['id']} has unknown kind: {pat['kind']}")
    data["_path"] = str(p)
    return data


def pack_summary(pack):
    return {"id": pack["id"], "version": pack["version"],
            "date": pack["date"], "description": pack["description"],
            "pattern_count": len(pack["patterns"])}
