# GhostExposure examples

Everything here is invented sample material. No real code, no real data.

| File | What it is |
|---|---|
| `starter-surface.example.json` | A starter surface pack (auth, payments, config/secrets, personal-data shapes). Copy it and edit it for a real project. |
| `mini_project/` | A tiny project with one auth file and one unrelated helper, small enough to follow by hand. |
| `sample_EXPOSURE.md` | What the `EXPOSURE.md` in an exported bundle looks like, including both limit statements the plan requires. |

## Try the shape of it (once the core is built)

```bash
ghostexposure scan examples/mini_project --surface examples/starter-surface.example.json
ghostexposure export examples/mini_project --surface examples/starter-surface.example.json -o /tmp/mini-bundle
ghostexposure verify /tmp/mini-bundle
```

Expected shape of the result: `auth/login.py` is in the bundle as surface
(it matches the `auth/**` glob), `util/format.py` is accounted for as out,
and the bundle folder contains `files/`, `manifest.json`, `exposure.json`,
and an `EXPOSURE.md` like the sample.
