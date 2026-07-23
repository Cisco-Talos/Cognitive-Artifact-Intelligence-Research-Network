---
name: run-cairn
description: Run, test, build, or smoke-test the CAIRN CLI tool. Use when asked to run cairn, start cairn, test cairn, verify cairn works, or execute any cairn command.
---

CAIRN is a CLI research toolkit (Python, `cairn` entry point). It has no GUI. The driver is a smoke script that runs all offline commands in sequence and reports pass/fail. API-touching commands (`pull`, `refresh`, `pivot`) are not in the smoke script — run them manually with the VT key present.

All paths below are relative to the repo root (`/home/ryan/CAIRN`).

## Prerequisites

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pip install numpy   # required by tests/test_embed.py; not in pyproject.toml dev extras
```

The `.env` file must exist with `VIRUSTOTAL_API_KEY` set for API commands. Copy from `.env.example`:

```bash
cp .env.example .env
# edit .env — set VIRUSTOTAL_API_KEY
```

## Run (agent path) — smoke script

Exercises all offline commands (no API calls):

```bash
source .venv/bin/activate
bash .claude/skills/run-cairn/smoke.sh
```

Expected output:

```
PASS: filters
PASS: validate-rules
PASS: summary (samples=0)
PASS: validate-seeds
PASS: rescan (rescanned=0)
PASS: report

All smoke checks passed.
```

Each line asserts the JSON response has the expected shape. Exit code 0 = all pass.

## Common individual commands

```bash
source .venv/bin/activate

cairn filters                          # list configured VT channels + key status
cairn validate-rules                   # parse YARA rules, report tier counts
cairn summary                          # corpus stats (sample count, rule hits)
cairn rescan                           # re-run YARA against cached corpus — zero API calls
cairn validate-seeds                   # expected-rule validation against known seeds
cairn report                           # export CSV + markdown to outputs/

# API-touching (requires VT key):
cairn pull --filter llmgate-hunt --limit 10 --deep
cairn refresh --sha256 <sha256> --behaviours
cairn pivot-urls <sha256>
```

## Tests

```bash
source .venv/bin/activate
python -m pytest tests/ --ignore=tests/test_embed.py -v
```

6 tests, all pass. `test_embed.py` requires `sentence-transformers` (not installed by default — use `pip install -e ".[embed]"`).

## Gotchas

- **`test_embed.py` fails on `import numpy`** — `numpy` is not in `[dev]` extras. Fix: `pip install numpy` or `pip install -e ".[embed]"`. The other 6 tests are unaffected.
- **`cairn summary` shows 0 samples** on a fresh instance — the SQLite corpus at `data/cairn.sqlite` is gitignored and not distributed. This is expected; populate with `cairn pull`.
- **`cairn report` writes to `outputs/`** — this directory is gitignored. The files are created fresh each run; check `outputs/cairn_findings.md` and `outputs/rule_yield.csv` after running.
- **VT key check** — `cairn filters` reports `"vt_key_configured": true/false`. If false, `pull` and `refresh` commands will fail with a missing-key error. Set `VIRUSTOTAL_API_KEY` in `.env`.
- **Rate limit defaults are conservative** — `.env.example` sets `CAIRN_RATE_LIMIT_PER_MINUTE=4` and `CAIRN_DAILY_LIMIT=500`. Do not increase without checking VT entitlement.
