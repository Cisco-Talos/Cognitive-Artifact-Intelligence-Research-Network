# Contributing to CAIRN

Contributions are welcome. CAIRN is a research toolkit, so the most valuable contributions are new YARA rules, family reports for newly confirmed AI-malware families, and improvements to the acquisition filters or corpus tooling.

## Prerequisites

- Python 3.11+
- A [VirusTotal Intelligence](https://www.virustotal.com/gui/my-apikey) API key (required for `pull`, `refresh`, and `pivot` commands; not required for offline development)

## Development Setup

```bash
git clone https://github.com/fetterm4n/CAIRN.git
cd CAIRN
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Edit .env — set VIRUSTOTAL_API_KEY
```

Verify the install:

```bash
cairn validate-rules   # should report 44 rules, valid: true
cairn filters          # should list all channels
```

For embedding-based clustering:

```bash
pip install -e ".[embed]"
```

## Contributing YARA Rules

Rules live in `config/yara_rules.yar`. The three-tier structure is strict:

| Tier | Purpose | Requirements |
|---|---|---|
| T1 | Primitive artifact — a single cognitive artifact string or pattern | High recall expected; FPs acceptable |
| T2 | Behavioral context — co-occurrence of two or more T1-level signals | Must represent an operationally meaningful combination |
| T3 | Family attribution | Must be anchored to at least one confirmed seed hash via `cairn seed-add` |

**After any rule edit:**

```bash
cairn validate-rules     # syntax check and tier count
cairn rescan             # re-run all rules against corpus — zero API calls
cairn validate-seeds     # confirm known seeds still fire expected rules
```

All three must pass before opening a PR.

Rule naming convention: `T<tier>-<FAMILY>_<Short_Description>` — e.g. `T3-TEAMPCP_Backdoored_LiteLLM_Proxy`.

## Contributing Family Reports

Family reports live in `docs/families/<FAMILY>.md`. The family designation is ALL_CAPS.

Before writing a report:

1. Confirm the family with at least one seed hash: `cairn seed-add --sha256 <sha256> --family <NAME> --expect <T3-RULE>`
2. Verify the seed fires: `cairn validate-seeds`
3. Follow the template structure (see any existing report for reference)

After writing a report, review `docs/SOA.md` to determine whether the family introduces a new archetype, extends an existing one, or only confirms a known pattern. Update the archetype table if needed.

## Contributing Acquisition Filters

Filters live in `config/acquisition_filters.yaml`. Each filter is a named VT Intelligence query with a slug, category, minimum detection threshold, and optional description. Add filters for new hunt hypotheses; disable rather than delete filters that are temporarily inactive.

## Running Tests

```bash
source .venv/bin/activate
python -m pytest tests/ --ignore=tests/test_embed.py -v
```

`test_embed.py` requires `sentence-transformers`: `pip install -e ".[embed]"`.

## Pull Request Requirements

Before opening a PR:

- [ ] `cairn validate-rules` passes
- [ ] `cairn validate-seeds` passes
- [ ] `python -m pytest tests/ --ignore=tests/test_embed.py` passes
- [ ] New T3 rules have at least one registered seed hash
- [ ] New family reports include an **Assessment → Archetype** subsection
- [ ] `docs/SOA.md` updated if a new archetype was introduced

## Safety Boundaries

CAIRN is designed to operate without touching malware directly. Contributions must not:

- Download binary samples
- Upload files to VirusTotal
- Submit URLs for scanning
- Add scheduled or automatic pulls
- Store raw binary content in the corpus

## Code Style

CAIRN has no enforced formatter. Follow the conventions of the surrounding code. Keep changes focused — a rule addition does not need surrounding refactors.
