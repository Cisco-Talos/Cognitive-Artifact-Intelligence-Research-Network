# CAIRN — Standard Operating Procedures

**Toolkit:** CAIRN (Cognitive Artifact Intelligence Research Network)
**CLI entry point:** `cairn` (installed via miniconda — do NOT use `python -m cairn`)
**Config:** `.env` — requires `VT_API_KEY`; optional `PROMPTINTEL_API_KEY`
**Rate limits:** 4 req/min, 500 req/day (configurable in `.env`)

---

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add VT_API_KEY (required), PROMPTINTEL_API_KEY (optional)
```

---

## 1. Acquisition — Filter-Based

Pulls samples from VT Intelligence using named keyword filters. Results are stored in the SQLite corpus with YARA run automatically on import.

```bash
# Check when each filter was last pulled and what date window was used
cairn pull-status

# List all configured filters and their enabled status
cairn filters

# First-ever pull of a filter (no date clause — reach full VT history)
cairn pull --filter broad-discovery --limit 100

# Subsequent pulls — always constrain to close the gap since last run
cairn pull --filter broad-discovery --limit 50 --date-clause "fs:30d+"
cairn pull --filter llmgate-hunt --limit 50 --date-clause "fs:7d+"

# Deep pull: per-hash file report + sandbox behaviours (costs 2 API calls per sample)
cairn pull --filter provider-api-integration --limit 20 --deep

# Snippets pull: fetch content-match hex fragments from VTGrep (1 extra API call per sample with a snippet ID)
# Use on broad content: filters (local-llm-runtime, provider-api-integration, etc.) to
# confirm the AI string actually appears in the binary and give YARA rules real text to match.
cairn pull --filter local-llm-runtime --limit 50 --snippets

# Pull all enabled filters (add --date-clause for routine freshness runs)
cairn pull-enabled --limit 50
cairn pull-enabled --limit 50 --date-clause "fs:30d+"
```

**Pull discipline:** Before any hunt session, run `cairn pull-status` to see what was last pulled and when. For filters never pulled (no entry), do a full backfill run without `--date-clause`. For filters with a prior run, pass `--date-clause "fs:<N>d+"` to cover only the gap — this avoids re-fetching samples already in the corpus and conserves daily API quota (500 req/day).

| Scenario | Command |
|---|---|
| First pull of a filter | `cairn pull --filter <slug> --limit 100` |
| Routine weekly freshness | `cairn pull --filter <slug> --limit 50 --date-clause "fs:7d+"` |
| Catch-up after a gap | `cairn pull --filter <slug> --limit 100 --date-clause "fs:<days>d+"` |
| Targeted family watch | `cairn pull --filter llmgate-hunt --limit 50 --date-clause "fs:30d+"` |

**Available filters (17 total):**

| Slug | Category | File Types | Min Det | Notes |
|---|---|---|---|---|
| `broad-discovery` | discovery | peexe/pedll | 5 | High-recall AI string sweep |
| `prompt-residue` | prompt | peexe/pedll | 5 | Role markers, jailbreak residue |
| `agentic-tooling` | agentic | peexe/pedll/ps1/py/js | 5 | Framework names, tool_call syntax |
| `local-llm-runtime` | runtime | peexe/pedll | 5 | Ollama, llama.cpp, GGUF, etc. |
| `provider-api-integration` | api | peexe/pedll | 5 | Provider API endpoints |
| `ai-analysis-evasion` | evasion | peexe/pedll | 5 | Prompt-injection evasion strings |
| `offensive-co-occurrence` | offensive | peexe/pedll | 5 | AI + offensive term co-occurrence |
| `powershell-ai-scripts` | script | ps1 | 3 | PS1 with LLM API or prompt strings |
| `python-ai-scripts` | script | tag:python | 3 | Python AI/LLM imports |
| `codegen-residue` | prompt | peexe/pedll/ps1 | 3 | LLM refusal phrases as artifacts |
| `llmgate-hunt` | hunt | peexe | 3 | LLMGATE Gen1/2: TechSoft/AceSoft, sysupdsvc, ip.sb |
| `llmgate-gen3-hunt` | hunt | peexe | 3 | LLMGATE Gen3: rotated cover names sysmntsvc/wupdmgr/svchost |
| `promptlock-hunt` | hunt | peexe/pedll/lua | 3 | target_file_list.log, SPECK 128bit |
| `local-model-hunt` | hunt | peexe | 2 | Local model binaries (GGUF loaders, Ollama server, llama.cpp) |
| `vozdyhan-hunt` | hunt | peexe | 2 | vozdyhan C2, telemetrysystem path |
| `honestcue-hunt` | hunt | peexe/pedll | 3 | HONESTCUE .NET LLM probe loader |
| `sangfor-lure-watch` | hunt | peexe | 3 | **disabled** — passive watch only |

---

## 2. Acquisition — Pivot-Based

Starts from a known seed (SHA256, domain, or IP) and walks VT relationship edges to discover related samples. Imported samples get full YARA treatment; provenance is tracked in the `pivot_edges` table.

```bash
# Pivot from a file hash — defaults to similar_files
cairn pivot a6e8e005e597961b571e9b279ec2a80979126b6e2013e930cfcfb034e10f06aa

# Multiple relationships in one run
cairn pivot a6e8e005... --rel similar_files --rel communicating_files

# Pivot from a domain (defaults to communicating_files)
cairn pivot vozdyhan.up.railway.app

# Pivot from an IP
cairn pivot 66.33.22.142

# Control depth and noise
cairn pivot a6e8e005... --rel similar_files --limit 40 --min-detections 3

# With full sandbox behaviours per discovered sample
cairn pivot a6e8e005... --rel dropped_files --deep
```

**Seed type is auto-detected:**
- 64 hex chars → file (SHA256)
- Four dot-separated octets → IP
- Anything else → domain

**Available relationships per seed type:**

| Seed type | Relationship | What it finds |
|---|---|---|
| file | `similar_files` | Structurally similar PE files (same vhash cluster) |
| file | `communicating_files` | Files that contacted the same network IOCs |
| file | `dropped_files` | Files observed dropped by this sample in sandbox |
| file | `bundled_files` | Files embedded/contained in this sample |
| file | `execution_parents` | Files that executed this sample |
| domain | `communicating_files` | Files that contacted this domain in sandbox |
| ip | `communicating_files` | Files that contacted this IP in sandbox |

**Note:** VT does not track loopback (127.0.0.1) sandbox traffic — `communicating_files` on a loopback URL object returns 0. This is a platform limitation.

---

## 3. Refresh — Update Stored Samples

Re-fetches VT data for samples already in the corpus. Updates `raw_json` and re-runs YARA. Use this to backfill behavioural data or pick up new detections.

```bash
# Re-fetch and re-scan a specific hash
cairn refresh --sha256 <sha256>

# Multiple hashes
cairn refresh --sha256 <sha256> --sha256 <sha256>

# Also pull sandbox behavioural data (one extra API call per hash)
cairn refresh --sha256 <sha256> --behaviours
```

---

## 4. Rule Management

```bash
# Validate the YARA rule file (parse + tier check, no API calls)
cairn validate-rules

# Re-run YARA against all stored raw_json — zero API calls
# Run this after every rule change instead of re-pulling from VT
cairn rescan
```

**Rule tiers:**
- **T1** — Primitive artifacts (API endpoints, prompt residue, local runtimes, codegen phrases) — 8 rules
- **T2** — Behavioral context (shell co-occurrence, Discord C2, agentic+offensive, local inference persistence) — 5 rules
- **T3** — Operational families (LLMGATE, PROMPTLOCK, HONESTCUE, FRUITSHELL, XENORAT, SUPERAGENT, …) — 17 rules

---

## 5. Seeds and Validation

Seeds are known ground-truth samples used to validate rule recall. Expected matches are checked on every `validate-seeds` run.

```bash
# Add a known seed with an expected rule match
cairn seed-add --sha256 <sha256> --family LLMGATE \
  --source-url https://... \
  --expect T3-LLMGATE_Go_Backdoor_Fake_UpdateService

# Add a FRUITSHELL seed from a SHA256
cairn seed-fruitshell --sha256 <sha256> --notes "variant with port 4444"

# Run expected-rule validation against all stored seeds
cairn validate-seeds
```

---

## 6. Corpus Inspection

```bash
# Print corpus summary: sample count, rule hit counts, filter yield, recent runs
cairn summary

# Resolve all embedded_url relationship objects for a stored sample
# (read-only — does not import anything)
cairn pivot-urls <sha256>
```

---

## 7. Embeddings, Clustering, and Projection

Semantic similarity pipeline over scan_text. Requires `pip install cairn[embed]` for sentence-transformers and HDBSCAN.

```bash
# Encode all stored samples into embeddings
cairn embed

# Re-encode samples that already have embeddings
cairn embed --reembed

# Skip samples with very short scan_text (default 200 chars)
cairn embed --min-chars 400

# Cluster stored embeddings with HDBSCAN
cairn cluster --min-cluster-size 3

# Project embeddings to 2D for visualization in the Explorer
# Uses UMAP if umap-learn is installed, otherwise falls back to t-SNE (sklearn)
cairn project
cairn project --method tsne      # force t-SNE
cairn project --method umap      # force UMAP (requires: pip install umap-learn)

# Find nearest neighbours for a given hash
cairn near <sha256> --top 10
```

**Note:** Clustering only operates on samples already in the corpus. Samples not matching any acquisition filter or pivot chain are never seen. Use `cairn pivot` to bring in confirmed-related samples before clustering to improve label density.

Run `cairn project` once after `cairn cluster` to populate the UMAP view in the Explorer. Re-run whenever new samples are embedded.

---

## 8. Explorer

Interactive local web UI for exploring the relationship graph and embedding cluster space.

```bash
# Launch (opens browser automatically)
cairn explorer

# Custom port, no browser auto-open
cairn explorer --port 8422 --no-browser
```

The Explorer has two views:

- **Graph view** (default) — force-directed relationship graph showing samples, YARA rules, acquisition filters, imphashes, domains, certs, and submitters as nodes. Family hull overlays, T3-only filter, 3D mode.
- **UMAP view** (UMAP button) — 2D scatter plot with node positions from the latest `cairn project` run. Semantic proximity = visual proximity. Known families shown in family color with labeled hulls; unknown clusters in muted tones; noise (-1) in near-black. Hover for sha256/family/cluster_id. Requires `cairn project` to have been run first.

---

## 9. Corpus Maintenance — Threads and Submitters

```bash
# List all open threads from THREADS.md (JSON or formatted)
cairn threads
cairn threads --json

# Backfill VT submission source_keys for corpus samples
# Enriches the Explorer submitter graph and enables attribution analysis
cairn fetch-submitters
cairn fetch-submitters --limit 500   # cap API calls (default: all unenriched)
```

`fetch-submitters` requires a VirusTotal Intelligence subscription. Coverage is tracked as a fraction of corpus samples with at least one submitter key. Re-run periodically to improve coverage as new samples are added.

---

## 10. Reporting and Export

```bash
# Export summary CSV and markdown findings draft
cairn report

# Export to specific paths
cairn report --csv outputs/reports/findings.csv --markdown outputs/reports/findings.md

# Export relationship graph JSON
cairn graph
cairn graph --output outputs/graphs/cairn_graph.json
```

---

## 11. PromptIntel Feed

```bash
# Sync PromptIntel IOC feed — reports new binary-relevant records
cairn sync-promptintel

# Print all stored IOCs (not just new ones)
cairn sync-promptintel --all
```

Binary-relevant heuristic: reference URLs present AND abuse category AND at least one binary-signal threat type (Malware generation, AI driven attack enablement, Supply Chain Abuse, Agentic Misuse, etc.).

---

## 12. Corpus Maintenance — Exclusions and Pruning

False positives (reclassified-legitimate or dead-end samples with no analytical value) should be removed from the corpus. Keeping them adds noise to `cairn summary`, inflates rule hit counts, and creates misleading edges in the Explorer graph. The investigation record is preserved in `docs/families/<FAMILY>.md` or `docs/SOA.md` progression notes — the corpus itself only needs the threat samples.

### Design

**`config/exclusions.yaml`** is the source of truth. It maps SHA256 → reason/date/analyst. Two effects:

1. **Pull-time skip** — `cairn pull` and `cairn pivot` silently skip any hash present in the exclusion list. A sample excluded today will never re-enter the corpus on a future pull of the same filter.
2. **`cairn prune`** — retroactively removes already-ingested excluded hashes from the DB, cascading to `rule_matches`, `sample_filters`, `pivot_edges`, `artifact_embeddings`, and `artifact_clusters`.

### Workflow

When a thread closes as reclassified-legitimate or dead-end:

```bash
# 1. Add the SHA256(s) to config/exclusions.yaml with reason, date, analyst

# 2. Dry-run first to confirm what will be removed
cairn prune --dry-run

# 3. Prune the corpus
cairn prune

# 4. Verify seeds are unaffected
cairn validate-seeds
```

### Adding an exclusion entry

```yaml
# config/exclusions.yaml
exclusions:
  <sha256>:
    reason: One-line reason — what it actually is or why it was closed
    reclassified_as: Optional — the legitimate product or tool (if applicable)
    date: "YYYY-MM-DD"
    analyst: Name or initials
```

The `reason` field is what future analysts will read when they wonder why a hash is blocked. Be specific: name the product, the cert pivot, or the investigation note.

### Seed conflict guard

`cairn prune` reports any excluded hash that also appears in `known_seeds`. This should never happen — a known-malicious seed should not be in the exclusion list. If it is, remove it from one list before pruning.

### When NOT to exclude

- Samples that hit T3 rules and are genuinely malicious — even if low confidence, keep them in the corpus.
- Samples you haven't investigated yet — the exclusion list is for closed, investigated FPs only.
- Samples shared across multiple filter hits where only some detections are FPs — investigate the full picture first.

---

## Research Loops

### Hunt Workflow (full loop)

The standard sequence for a filter-based hunt session:

1. **Pull** — `cairn pull --filter <slug> --limit 25`
2. **Triage** — `cairn summary`, review rule hits; manually inspect interesting samples
3. **Write threads** — Before investigating any single sample, add every promising lead to `THREADS.md`. Each entry needs: status, source hunt + date, sample hashes, what we know, and pivot leads. This step is mandatory — threads written now prevent promising leads from being lost when a single sample expands into a multi-hour investigation.
4. **Investigate** — Pull on threads one at a time. For each thread: run `cairn pivot` / `cairn refresh --behaviours`, review sandbox data, draft the T3 rule.
5. **Report** — When a thread has enough evidence for attribution: scaffold a family report (`/new-family-report`), register the seed (`cairn seed-add`), validate (`cairn validate-seeds`), update `docs/SOA.md`.
6. **Close the thread** — Once a thread results in a family report OR is determined to be uninteresting/duplicate, **remove it from `THREADS.md`**. A thread should not remain in `THREADS.md` after it has a corresponding `docs/families/<FAMILY>.md`.

**`THREADS.md` is a working list of open, uninvestigated leads only.** Closed threads live in the family report. If a lead is closed without a report (dead end, duplicate), remove the entry and note the reason in a single commit message line — no need to preserve it elsewhere.

---

### Filter-first (discovery)

Use when looking for new families or building out a fresh topic area.

```bash
cairn pull --filter <slug> --limit 25
cairn summary                          # check yield and rule hits
# tune rules in config/yara_rules.yar
cairn rescan                           # re-run rules — no API calls
cairn pull --filter <slug> --limit 25 --deep   # go deeper on a promising filter
cairn seed-add --sha256 <sha256> --family <NAME> --expect <RULE>
cairn validate-seeds
```

### Pivot-first (investigation)

Use when you have a confirmed interesting sample and want to map its campaign.

```bash
# Start from a seed — find variants
cairn pivot <sha256> --rel similar_files

# Map campaign infrastructure
cairn pivot <sha256> --rel communicating_files
cairn pivot <domain>
cairn pivot <ip>

# Go deep on discovered samples
cairn refresh --sha256 <sha256> --behaviours

# Resolve embedded URLs on a specific sample
cairn pivot-urls <sha256>

# Check corpus after pivoting
cairn summary
```

### Rule development

```bash
# Edit config/yara_rules.yar
cairn validate-rules                   # check syntax and tier structure
cairn rescan                           # apply to corpus — no API calls
cairn validate-seeds                   # confirm known samples still fire
```

### Semantic clustering

```bash
# After building up a labeled corpus via filters + pivots:
cairn embed
cairn cluster --min-cluster-size 3
cairn project                          # generate 2D coords for Explorer UMAP view
cairn near <known_seed_sha256> --top 10
cairn explorer                         # open UMAP view to inspect clusters visually
```

---

## Safety Boundaries

- No binary downloads
- No file uploads to VT
- No URL submissions or scans
- No scheduled automatic pulls
- Store only: metadata, string/content snippets, hashes, VT links, relationships, analyst notes

---

## Key Paths

| Path | Contents |
|---|---|
| `config/acquisition_filters.yaml` | Named VT acquisition channels (17 filters) |
| `config/exclusions.yaml` | SHA256 blocklist — skipped on pull/pivot, removed by `cairn prune` |
| `config/yara_rules.yar` | YARA rule definitions (T1/T2/T3; 30 rules) |
| `data/cairn.sqlite` | SQLite corpus (gitignored) |
| `outputs/` | Graph and report exports (gitignored) |
| `docs/SOA.md` | AI-malware archetype taxonomy and YARA ontology reference |
| `docs/families/` | Per-family technical reports |
| `docs/SOP.md` | This file |
| `cairn/explorer.py` | Explorer HTTP server and API endpoints |
| `cairn/explorer_ui.py` | Explorer UI — force graph + UMAP cluster view |
| `.env` | API keys (gitignored) |
