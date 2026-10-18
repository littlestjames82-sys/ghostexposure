# GhostExposure

**Build a review bundle of only a sensitive surface, with a manifest that accounts for every other file in the tree.**

By Ghost Developer Studio. Working name, v0.1 design per `PLAN.md`. MIT core pattern, local-only, no network calls.

GhostExposure prepares evidence for a code review hand-off. You define the sensitive surface (auth, payments, secrets handling, personal-data paths) as a readable surface pack. GhostExposure scans the whole project, decides for every file whether it is in the bundle or not, records the reason for each decision, and exports a bundle a receiver can verify against its manifest without trusting you.

It stays in evidence language on purpose: *contained, accounted for, verified against the manifest.* It does not use assurance language, because it cannot offer assurance.

## What this tool is not

- It is **not a security audit**, and it **does not certify** anything. It prepares and proves a bundle. Reviewers review.
- It does not scan for vulnerabilities, look up CVEs, or grade code.
- It does not prove a project is safe, compliant, or certified compliant.
- It cannot prove a sender did not share other files by another channel. It proves what is in this artifact, checked against its manifest, and nothing about what happened in the world outside the artifact.

Coverage limit, stated plainly: a surface pack only matches the signals it lists. GhostExposure does not detect sensitive logic in files with no matching signals. A bundle is "the files this surface pack matched, plus their direct graph context", never "everything sensitive in this project".

---

## For senders

You are preparing a bundle for an outside reviewer, a contractor, or an agent.

### 1. Write or pick a surface pack

A surface pack is a JSON file you can read top to bottom. Each pattern has an id, a kind, a pattern, and a plain-words reason. Kinds: `glob` (paths), `symbol` (function/class names), `import` (dependencies such as a payments SDK), `data` (field names shaped like personal identifiers).

See `examples/starter-surface.example.json` for a starter pack covering auth, payments, config/secrets handling, and personal-data shapes. Copy it, edit it, version it. The exact pack you used is written into every export, so the receiver can read the same definition you used.

You can also pin files in or out in the project's `.ghostslice.json`:

```json
{"exposure": {"surface": "starter-auth-payments-data",
              "pinned_in": [],
              "pinned_out": ["docs/internal-notes.md"]}}
```

If a file matches a sensitive pattern **and** a pin-out, that is a **conflict**. GhostExposure lists it as a conflict requiring your decision. It never resolves a conflict silently in either direction.

### 2. Scan before you export

```bash
ghostexposure scan <project> --surface <pack.json>
```

Scan prints every file in the tree with its proposed decision and the reason codes that fired (`glob`, `symbol`, `import`, `data`, `graph-neighbour`, `user-pinned-in`, `user-pinned-out`), lists any conflicts, and prints what the pack does not cover.

### 3. Export

```bash
ghostexposure export <project> --surface <pack.json> -o <bundle-folder>
```

The bundle contains:

| File | What it is |
|---|---|
| `files/` | Surface files in full, direct graph context (callers/callees) at signatures. Nothing else. |
| `manifest.json` | GhostSlice bundle manifest: per file, mode, token estimate, sha256. Validates with `ghostslice check`. |
| `exposure.json` | Per-file in/out decision with reason codes, the tree inventory hash, the surface pack used, tool versions, and any redaction records. |
| `EXPOSURE.md` | Human summary: the surface definition in full, counts, estimated token totals, the coverage limits statement, and receiver verification instructions. |

Token totals are **estimates** from GhostSlice's estimator and its local, dated price table. They are not billed amounts.

### Redaction: on by default

If a surface file contains a secret-shaped literal, the export warns, and **by default** replaces that value with a redaction marker in the exported copy only. Your source project is never altered. Each redaction is recorded in the manifest (file and finding type, never the value).

Exporting a literal unredacted requires the explicit flag `--allow-unredacted`, and using that flag is also recorded in the manifest. There is no quiet path that ships a live-looking key. Treat any key that has ever been in a shared bundle as exposed and rotate it; redaction in the copy is a guardrail, not a time machine.

### 4. Send the bundle folder

Send the whole folder, including `exposure.json` and `EXPOSURE.md`. The receiver's steps are below, and they do not require trusting you or this README.

---

## For receivers

You received a bundle. Your job is to check that what you have is what the manifest says you have.

### 1. Verify the bundle

```bash
ghostexposure verify <bundle-folder>
```

Verify re-runs the GhostSlice bundle check, confirms the inventory hash and the in/out partition in `exposure.json` match the bundle contents, and confirms every file in the sender's tree inventory is accounted for in the partition (in, or out, no third state). If a file was added to the bundle, or a listed file is missing, verify fails and names the file.

Verify also prints its own limit, every time: it cannot prove a sender did not share other files by another channel, and it cannot prove the surface pack was the right definition. It proves the bundle matches its manifest.

### 2. Read `EXPOSURE.md` before the code

It contains the full surface pack that was used (every pattern and its reason), the counts (files in tree, files in bundle, surface vs context), and what the pack does not cover. Judge the review scope from that, not from the folder alone: code outside the patterns was not in the tree view either side used, and sensitive logic in a file with no matching signal would not have been included.

### 3. Work only from the bundle

Files marked `context` are present at signatures so you can judge the surface's callers and callees. Files marked as surface are in full. Everything else was accounted for as out, and is listed by name in `exposure.json`, so you can ask the sender about a specific excluded file instead of guessing.

---

## Commands

| Command | What it does |
|---|---|
| `ghostexposure scan <project> --surface <pack>` | Full inventory, per-file in/out proposal with reason codes, conflicts, coverage limits |
| `ghostexposure export <project> --surface <pack> -o <folder>` | Write the bundle (`files/`, `manifest.json`, `exposure.json`, `EXPOSURE.md`) |
| `ghostexposure verify <bundle-folder>` | Check a received bundle against its manifest and partition, naming any discrepancy |

All three run locally. No command makes a network call.

## Honest limits

- Pattern-bound detection will miss novel sensitive code. The coverage statement is in every export so this limit travels with the artifact.
- The in/out partition proves accounting against the inventory the sender's scan produced. Verify checks that partition against the bundle, not against a tree you do not have.
- Graph context is static analysis. For Python it uses GhostSlice's call graph; for other languages it is import and outline level, and `EXPOSURE.md` says which.
- Estimates are estimates: token counts and costs come from a local estimator and a dated price table.

## Layout of this repo

```
PLAN.md        the v0.1 plan and verification bar
README.md      this file, written for senders and receivers
src/           the tool (Agent A)
surfaces/      starter surface packs (Agent A)
tests/         the verification-bar tests and fixtures (Agent B)
examples/      a mini project, an example surface pack, and a sample EXPOSURE.md
```
