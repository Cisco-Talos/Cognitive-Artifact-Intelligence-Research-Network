# CAIRN

CAIRN (Cognitive Artifact Intelligence Research Network) is a malware research toolkit that identifies, attributes, clusters, and tracks AI-related artifacts embedded in malware — using only VirusTotal metadata. No binary downloads, no detonation, no active scanning.

**Entry point:** `cairn` CLI (requires `source .venv/bin/activate`)
**Corpus:** `data/cairn.sqlite` (gitignored — populated via `cairn pull`)
**Config:** `.env` — requires `VT_API_KEY`

Full command reference: `docs/SOP.md`

---

## Key Documents

| File | Purpose |
|---|---|
| `docs/SOP.md` | All CLI commands, research loops, safety boundaries |
| `docs/SOA.md` | State of the Art — AI-malware archetype taxonomy (A1–A9), YARA ontology reference |
| `PLAN.md` | Research questions with current status and answers |
| `THREADS.md` | Open investigation leads — working list only |
| `docs/families/<FAMILY>.md` | Per-family technical reports (LLMGATE, VOZDYHAN, WURM, TEAMPCP, SUPERO, PANDORA, …) |

---

## Skills

Use these via `/skill-name` in Claude Code:

| Skill | When to use |
|---|---|
| `/new-family-report` | Scaffold a `docs/families/<FAMILY>.md` for a newly confirmed family |
| `/rule-tuning` | Add, edit, or validate YARA rules |
| `/vt-pivot` | Pivot investigation from a seed hash, domain, or IP |
| `/run-cairn` | Run, smoke-test, or verify the CLI |

---

## Behavioral Rules

These apply in every session. Do not wait to be asked.

### Hunt workflow

The standard sequence for a filter-based hunt session:

1. `cairn pull --filter <slug> --limit 25`
2. Triage rule hits via `cairn summary`; inspect interesting samples
3. **Before investigating any single sample:** write every promising lead into `THREADS.md` — status, source hunt + date, sample hashes, what we know, pivot leads
4. Investigate threads one at a time
5. When a thread reaches attribution: run `/new-family-report`, register seed (`cairn seed-add`), validate (`cairn validate-seeds`)
6. **Close the thread:** remove it from `THREADS.md` once a `docs/families/<FAMILY>.md` exists for it

### THREADS.md discipline

- `THREADS.md` contains **open, uninvestigated leads only**
- A thread with a corresponding `docs/families/<FAMILY>.md` must be removed from `THREADS.md`
- A dead-end thread is also removed — a commit message note is sufficient record
- Never let `THREADS.md` accumulate resolved or reported threads

### SOA review

After every family report is created or materially updated:

1. Open `docs/SOA.md`
2. Determine whether the family introduces a new archetype, extends an existing one (add it to the Families column), or only confirms a known pattern
3. If new: add a row to the archetype table (next ID), write a progression note, update the T3 table row with the Archetypes column
4. State the verdict explicitly in the report's **Assessment → Archetype** subsection

### Rule changes

After any edit to `config/yara_rules.yar`:
1. `cairn validate-rules` — confirm syntax and tier counts
2. `cairn rescan` — re-run against corpus (no API calls)
3. `cairn validate-seeds` — confirm known seeds still fire

### Naming conventions

- Family designations: ALL_CAPS (`LLMGATE`, `TEAMPCP`, `WURM`)
- Rule names: `T<tier>-<FAMILY>_<Short_Description>` (`T3-TEAMPCP_Backdoored_LiteLLM_Proxy`)
- Report files: `docs/families/<FAMILY>.md`

---

## Safety Boundaries

- No binary downloads
- No file uploads to VirusTotal
- No URL submissions or active scans
- No scheduled automatic pulls
- Store only: metadata, string/content snippets, hashes, VT links, relationships, analyst notes
