---
name: new-family-report
description: Create a new family report for a newly confirmed malware family. Use when asked to start a report, scaffold a report, document a new family, or create a new family doc.
---

Creates a new `docs/<FAMILYNAME>.md` from the canonical report template. Run this at the point where a family is confirmed — when you have at least a seed hash, a name, and a preliminary understanding of what it does.

All paths are relative to the repo root (`/home/ryan/CAIRN`).

## Usage

```bash
# Replace FAMILYNAME with the all-caps research designation (e.g. LLMGATE, VOZDYHAN, HONESTCUE)
FAMILY=FAMILYNAME

# Confirm the file doesn't already exist
ls docs/${FAMILY}.md 2>/dev/null && echo "EXISTS — check before overwriting"

# Write the scaffold
bash .claude/skills/new-family-report/scaffold.sh $FAMILY
```

The script writes `docs/<FAMILYNAME>.md` and prints the path. Open it and fill in the placeholders.

## Template structure

The scaffold produces all sections used across LLMGATE.md and VOZDYHAN.md. Required sections are always present; optional ones are marked — delete them if not applicable.

| Section | Required | Notes |
|---|---|---|
| Header metadata | yes | Family name, author, dates, variants, platform, CAIRN rules, related reports |
| Summary | yes | 2–4 paragraph overview; ends with "No public analyst coverage" line if confirmed |
| Discovery | yes | How CAIRN surfaced it — filter slug, pivot type, acquisition path |
| `<COMPONENT>.exe` — Component Analysis | yes, repeat per component | One section per distinct binary in the family; see sub-sections below |
| Infection Chain | yes | How all components connect — what lands on the victim and in what order |
| Actor Timeline | yes | Chronological table: date, sha256, binary, component, C2, notes |
| Architecture | yes | Component table: component, binary, language, role, C2 |
| Infrastructure IOCs | yes | Domains, IPs, certificates, exfil channels |
| Assessment | yes | Archetype, APT vs FIN, inferred use case, attribution signals, open questions |
| CAIRN Rules | yes | YARA rule blocks for all T3 rules added for this family |
| Update Log | yes | Append-only; one row per analysis session |
| Predecessors | optional | Pre-campaign binaries if identified |
| Relationship to `<OTHER FAMILY>` | optional | Cross-family attribution section if co-deployment confirmed |

### Component Analysis sub-sections

Each component section (`## <component>.exe — <Role>`) should cover:

- **Binary Characteristics** — file type, compiler, version fields, import hash
- **Code-Signing Certificate** — if present; note self-signed vs trusted CA
- **PE Resource Strings** — CompanyName, FileDescription, OriginalFileName
- **Embedded URL Infrastructure** — all resolved URL relationship objects
- **Sandbox Behavior and Detection** — AV detection count, sandbox tags, what actually runs vs stalls
- **Variants** — SHA256 table with detections, first-seen, notable differences
- **VT Submission Source Keys** — per-variant submitter identity table
- **Static Analysis** — only if deep reverse work was done; include offsets, cipher details, config layout

### Infection Chain section

This is the canonical place to document how the actor gets from zero to fully deployed toolset on a victim machine. It should answer:

1. **Initial access** — how the operator reaches the victim (known/unknown/inferred)
2. **Deployment sequence** — what gets dropped/injected and in what order, with timing
3. **Component dependencies** — which components require others to be running (e.g. sysupdsvc requires stager on :7778)
4. **Persistence mechanisms** — how each persistent component survives reboot
5. **Operator command path** — how the operator issues commands after deployment
6. **Key custody** — if credentials/keys are passed between components, document the flow

Use a numbered sequence for the happy path, then call out gaps explicitly. Example from LLMGATE:

```
1. Operator gains access to victim via unknown initial vector
2. Operator drops sysupdsvc.exe and runs it (likely via CS post-exploitation file-write
   after step 4, or pre-staged before loader run — order unconfirmed)
3. Operator runs loader_full.exe
4. Loader passes evasion checks → SPECK-decrypts stager shellcode → injects via CreateRemoteThread
5. Stager does AMSI/ETW/WDAC bypass → HTTP GET to TS (T+10-24s)
6. TS delivers second-layer encrypted payload → stager ARX-decrypts → API keys + C2 URL now in memory
7. Stager binds 127.0.0.1:7778
8. sysupdsvc POSTs to :7778/register → receives LLM API keys
9. CS beacon (Stage 3) delivered by TS → operator has interactive shell via Aggressor
10. sysupdsvc routes LLM inference through victim IP; operator drives shell/SOCKS/file ops via CS

Gap: step 2 order relative to step 3 is unconfirmed. Step 1 initial vector unknown.
```

If the infection chain is entirely unknown, say so — but document what IS known (e.g. "all VT submissions are single-submitter manual-deploy — not phishing/drive-by").

## After scaffolding

1. Fill in the header metadata (dates, variant count, platform, CAIRN rules)
2. Write the Summary from what you know at time of creation — it will be updated
3. Fill in Discovery with the filter/pivot that surfaced the family
4. Add the first seed hash to the Variants table
5. Add a first Update Log entry
6. Run `cairn seed-add` to register the seed: `cairn seed-add --sha256 <sha256> --family <NAME> --expect <T3-RULE>`
7. Run `cairn validate-seeds` to confirm the rule fires

## SOA review (mandatory — runs after every new or updated family report)

After the report is written or materially updated, open `docs/SOA.md` and assess the family against the archetype taxonomy:

1. **Does the family instantiate an existing archetype?** — Add it to the `Families` column of the matching archetype row(s).
2. **Does the family represent a new archetype not in the table?** — Add a new row with the next ID (A10, A11, …), description, first-confirmed date, and family name. Write a progression note entry.
3. **Does the family only confirm a known pattern?** — No table change needed; add a progression note if it marks a new "first seen" date or notable variant.
4. **Update the Tier 3 table** — add or update the row for the family's T3 rule(s), including the Archetypes column.

Answer the question explicitly in the report's Assessment → Archetype subsection: *"This is a new archetype / extends archetype A\_ / confirms a known pattern."*

If the family is a pure VOZDYHAN-style case (no LLM integration at all, just AI-adjacent infrastructure), set the Archetypes column to `—` and note it in the Assessment.
