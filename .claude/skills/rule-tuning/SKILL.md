---
name: rule-tuning
description: Edit, validate, and test CAIRN YARA rules. Use when asked to add a rule, tune a rule, write a YARA rule, fix a rule, improve detection, check rule recall, or validate rules.
---

CAIRN uses a custom YARA parser (`cairn/rules.py`) — no `yara-python` dependency. Rules run against structured scan text derived from VT metadata, not raw binary content. This means matches fire on strings that appear in AV detections, sandbox DNS/HTTP logs, PE resource strings, embedded URL objects, and behavioral signatures — not in the binary bytes themselves.

All paths relative to repo root (`/home/ryan/CAIRN`). Rules live at `config/yara_rules.yar`.

## The tuning cycle

Every rule change follows this sequence — no exceptions:

```bash
source .venv/bin/activate

# 1. Edit the rule
# $EDITOR config/yara_rules.yar

# 2. Validate syntax and tier structure
cairn validate-rules

# 3. Apply to corpus — zero API calls
cairn rescan

# 4. Confirm known seeds still fire
cairn validate-seeds

# 5. Review yield to check for false positives
cairn summary
```

Running `rescan` after every edit is cheap (no API calls) and catches regression immediately. Never skip `validate-seeds` after touching a T3 rule — that's the only automated recall check.

---

## Tier structure

| Tier | Purpose | Confidence |
|---|---|---|
| T1 | Primitive artifacts — individual strings (API endpoints, prompt residue, model names) | Low — strings appear in many contexts |
| T2 | Behavioral context — co-occurrence of offensive + AI signals, specific behavioral patterns | Medium |
| T3 | Operational families — named, confirmed families with high-confidence discriminating strings | High |

Rules must be tagged with `tier = "T1"` / `"T2"` / `"T3"` in the `meta:` block. `cairn validate-rules` checks this and reports counts per tier. A rule with the wrong tier or missing tier field is a parse error.

---

## Scan text sources

Rules match against VT-derived structured text, not binary content. Strings that appear in the scan text include:

- File names, tags, type description
- Signature / cert info, context attributes
- Sandbox verdicts, popular threat classification
- Crowdsourced YARA hit names
- ExifTool PE resource strings (FileDescription, CompanyName, ProductName)
- PE imports, exports
- AV detection strings
- Embedded URL relationship objects
- Behavioral sandbox data: DNS lookups, HTTP conversations, memory pattern URLs, processes created, files dropped, sandbox signature match strings

**Implication:** A rule that matches on `"sysupdsvc"` fires if that string appears in any of the above fields — not necessarily in the binary's PE resources. Check which scan-text field the match is actually coming from when debugging unexpected hits or misses.

---

## Writing a new T3 family rule

1. Identify strings that are **unique to this family** and appear in VT scan text for confirmed samples. Good candidates:
   - C2 domain or URL path (appears in sandbox DNS/HTTP or embedded URL objects)
   - Actor-specific file path or registry key (appears in dropped_files or behavioral signatures)
   - Unique PE resource string (CompanyName, OriginalFileName)
   - Unique process name or service name impersonation that is distinctive to this actor
   
2. Prefer **specificity over recall** at T3. A T3 rule that fires on 5 confirmed samples with 0 false positives is better than one that fires on 50 samples including noise.

3. Use `nocase` on strings that may appear in mixed case across sandbox environments.

4. Test the condition logic manually: `$a or $b` vs `$a and $b` — for infrastructure strings (C2 domain), `or` is usually right. For behavioral patterns that need co-occurrence, `and` is appropriate.

5. Add the rule to the report's `## CAIRN Rules` section with a note on which samples it fires on and via which scan-text source.

---

## Common failure modes

- **Rule doesn't fire on a known sample:** the string isn't in VT scan text for that sample. Run `cairn refresh --sha256 <sha256>` to update `raw_json`, then `cairn rescan`. If still no hit, the string may only appear in binary bytes (which CAIRN doesn't index) or only in the live sandbox environment (not persisted to VT metadata).
- **Rule fires on too many unrelated samples:** the string is too common in VT scan text. Add a second condition (e.g. `$c2_domain and $persist_path`) or increase specificity.
- **`validate-rules` reports a parse error:** check the `meta:` block — `tier`, `family`, `confidence`, `description` fields must be present and quoted. The custom parser is strict about this format.
- **`validate-seeds` shows a miss after a rule edit:** you changed a condition in a way that dropped recall on a confirmed sample. The diff in `yara_rules.yar` will show what changed — restore the condition or add an alternative.

---

## Adding a hunt filter for a new family

After writing a T3 rule, add a corresponding acquisition filter to `config/acquisition_filters.yaml`. The filter should use the same discriminating strings as the rule but formatted as VT Intelligence query terms:

```yaml
- slug: myfamily-hunt
  name: MyFamily Hunt
  category: hunt
  enabled: true
  min_detections: 2
  default_limit: 100
  query_terms:
    - 'content:"discriminating-string-1"'
    - 'content:"discriminating-string-2"'
  file_types:
    - peexe
```

Run `cairn filters` to confirm it appears in the list. Run `cairn pull --filter myfamily-hunt --limit 10` to test yield.
