#!/usr/bin/env bash
# Smoke test for CAIRN CLI — runs offline commands only, no API calls.
# All commands verified working 2026-06-08.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO"

# Activate venv if not already active
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  source .venv/bin/activate
fi

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

# 1. filters — lists configured VT acquisition channels, confirms key configured
out=$(cairn filters 2>&1)
echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['vt_key_configured'], 'VT key not configured'" \
  && pass "filters" || fail "filters: $out"

# 2. validate-rules — parses YARA rule file, checks tier counts
out=$(cairn validate-rules 2>&1)
echo "$out" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['valid'], 'rules invalid'
assert d['rule_count'] >= 17, f\"rule_count={d['rule_count']}\"
assert d['tiers']['T3'] >= 5, f\"T3 count={d['tiers']['T3']}\"
" && pass "validate-rules" || fail "validate-rules: $out"

# 3. summary — corpus stats (may be empty on fresh instance)
out=$(cairn summary 2>&1)
echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'samples' in d" \
  && pass "summary (samples=$(echo "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin)["samples"])'))" \
  || fail "summary: $out"

# 4. validate-seeds — expected-rule validation (pass/fail counts)
out=$(cairn validate-seeds 2>&1)
echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'summary' in d" \
  && pass "validate-seeds" || fail "validate-seeds: $out"

# 5. rescan — re-runs YARA against cached corpus, zero API calls
out=$(cairn rescan 2>&1)
echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'rescanned' in d" \
  && pass "rescan (rescanned=$(echo "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin)["rescanned"])'))" \
  || fail "rescan: $out"

# 6. report — exports CSV and markdown (creates outputs/ files)
out=$(cairn report 2>&1)
echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'csv' in d and 'markdown' in d" \
  && pass "report" || fail "report: $out"

echo ""
echo "All smoke checks passed."
