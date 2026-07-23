# PROMPTLOCK — Research Report

**Family designation:** PROMPTLOCK (AV consensus: `Trojan.Ransom.PromptLock`, `Filecoder.PromptLock`, `Ransom.Win64.PROMPTLOCK`; ESET: `WinGo/Filecoder.PromptLock.A`)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-08-25 (all three corpus samples, same day)
**Last seen:** 2025-08-25
**Variants:** 3 confirmed (two ~7 MB builds, one ~10 MB build)
**Platform:** Win64 PE32+ (console), Go-compiled
**CAIRN rules:** `T3-PromptLock_LLM_Lua_Ransomware`
**Related report:** None confirmed

---

## Summary

PROMPTLOCK is a Go-compiled ransomware family that uses a hard-coded LLM prompt at runtime to generate Lua-based file encryption logic. The LLM produces Lua code implementing a SPECK 128-bit ECB cipher; the malware executes this generated code to encrypt files on the victim system. The ransomware writes a `target_file_list.log` artifact during operation. AV labels across 40+ vendors are unanimous on family attribution.

PROMPTLOCK is the earliest confirmed A1 (LLM-Directed Payload Generation) family in the CAIRN corpus, first observed August 25, 2025 — nine months before the VOZDYHAN campaign that shares the same primary submitter identity.

---

## Discovery

PROMPTLOCK was surfaced via the `T3-PromptLock_LLM_Lua_Ransomware` rule, which fires on AV detection name consensus strings (`Filecoder.PromptLock`, `Ransom.PromptLock`, `Ransom.Win64.PROMPTLOCK`) and the combination of `target_file_list.log` + `SPECK 128bit`. The YARA rule reference cites ESET attribution and PromptIntel API as the original discovery signal. The three corpus samples all appeared on VT on the same day (2025-08-25), submitted via a shared set of submitter keys including the Vozdyhan operator `7a4d5f37` (DE).

---

## PromptLock.exe — LLM-Directed Ransomware

### Binary Characteristics

| Field | Value |
|---|---|
| File type | Win64 PE32+ (console), Go-compiled |
| Primary names | `Windows/PromptLock.exe`, `PromptLock.exe`, `llm_windows.exe`, `llm_windows_newport.exe` |
| Size | 7,118,848 bytes (`7bbb0647`, `1458b6dc`) / 10,327,552 bytes (`e24fe0dd`) |
| Detections | 53 / 53 / 43 |
| First seen | 2025-08-25 (all three) |
| Code-signing | None |
| Rich PE header hash | None (stripped) |
| Imphash | `d42595b695fc008ef2c56aabd8efd68e` (both 7 MB builds identical) |
| Sandbox behavior | No behavior reports in corpus (VT sandbox did not execute or report) |

The two 7 MB builds (`7bbb0647`, `1458b6dc`) share identical imphash and PE section layout — same binary, different hashes likely due to minor compile-time or packing differences. The 10 MB build (`e24fe0dd`) has a different section layout (additional unnamed COFF sections `/4`, `/19`, `/32`) and is likely a later build with embedded resources or debug symbols.

### PE Section Layout

| Section | `7bbb0647` / `1458b6dc` | `e24fe0dd` |
|---|---|---|
| `.text` | 3,279,697 | 3,279,697 |
| `.rdata` | 3,378,384 / 3,378,352 | 3,378,384 |
| `.data` | 675,760 | 675,760 |
| `.pdata` | 73,032 | 73,032 |
| `.xdata` | 180 | 180 |
| `.idata` | 1,342 | 1,342 |
| `.reloc` | 59,940 | 59,940 |
| `.symtab` | 4 | 4 |
| `/19` | — | 584,183 |
| `/32` | — | 118,070 |

The additional ~700 KB in `/19` and `/32` in the larger build suggests embedded data or extended debug output.

### Operational Logic

Based on ESET attribution and rule construction:

1. **LLM prompt at runtime.** The binary contains a hard-coded prompt instructing a hosted LLM to generate Lua code implementing a SPECK 128-bit ECB cipher for file encryption. The LLM is a code factory — not a C2, not a command channel. Each run may generate a unique Lua encryption routine depending on LLM output variation.

2. **Lua execution.** The generated Lua code is executed within the Go binary (likely via an embedded Lua interpreter). Files are encrypted using the SPECK algorithm as generated.

3. **Target enumeration.** The ransomware writes `target_file_list.log` during operation — a unique artifact identifying the file targeting phase.

No embedded URL relationships, LLM provider endpoints, C2 domains, or ransom note strings are recoverable from VT metadata alone. Behavioral reports are absent from the corpus.

### Submission Name Artifacts

| SHA256 | Submission name artifact | Significance |
|---|---|---|
| `7bbb0647` | `Windows/PromptLock.exe`, `llm_windows.exe` | Path prefix suggests Windows-targeted build from a multi-platform repo |
| `1458b6dc` | `llm_windows_newport.exe` | `newport` suffix — possible build variant name or target environment |
| `e24fe0dd` | `llm_windows.exe`, `analysis/promptlock/...` | Analyst path confirms family known at submission time |

The `llm_windows.exe` naming across all three builds and the `Windows/` path prefix on the primary sample are consistent with a build system generating platform-specific ransomware binaries — a `windows`, potentially `linux`, and `mac` target set.

### AV Label Consensus

All three samples carry strong, consistent AV labels across 40+ vendors:
- `WinGo/Filecoder.PromptLock.A` (ESET)
- `Trojan.Ransom.PromptLock` (AhnLab, ALYac, Bitdefender)
- `Ransom.Win64.PROMPTLOCK.THBBDBF` (TrendMicro)
- `Trojan-Ransom.Win64.PromptLock.b/c` (Kaspersky)
- `W32/Filecoder_PromptLock.A!tr` (Fortinet)
- `Generic.Ransom.PromptLock.A.48837827` (BitDefender GravityZone)

The ESET `WinGo/` prefix confirms Go compilation. No disagreement across vendors on family identification.

---

## Submitter Attribution

Three submitter keys appear across all three samples — the core submitter set:

| Key | Country | Present in | Notes |
|---|---|---|---|
| `7a4d5f37` | DE | 3/3 | Malware researcher/collector ("petik") — not an operator signal; see note below |
| `b32d639c` | NL | 3/3 | Malware researcher/collector — also appears on `8effbb7f` (Nov 2025, confirmed petik automated feed copy) |
| `3d9e5170` | — | 3/3 | Unknown |

The remaining ~20 keys appear on 1–2 samples and are consistent with researcher/scanner distribution (multiple analyst paths in submission names, e.g. `/home/petik/ss/malware/2025-08-28_...`).

**Note on `7a4d5f37` and `b32d639c`:** Both keys are malware researcher/collector accounts, not operator identities. `7a4d5f37` appears across 29 corpus samples spanning 6+ unrelated families; VT submission paths confirm a researcher workstation (`/home/petik/ss/malware/`) and C2 research lab (`localhostc2-main/realc2/`). `b32d639c` co-submits with `7a4d5f37` and is confirmed as part of the same petik automated collection feed. No cross-family operator attribution can be drawn from these keys.

---

## Assessment

### Archetype

**PROMPTLOCK is archetype A1 — LLM-Directed Payload Generation.** Confirmed. First seen 2025-08-25.

The defining characteristic: a hard-coded LLM prompt embedded at build time instructs a hosted LLM at runtime to generate Lua-based SPECK cipher code. The LLM functions as a code factory — the ransomware encryption logic is not static but generated fresh each execution from the LLM's output. This matches the A1 archetype exactly. PROMPTLOCK and HONESTCUE are the two confirmed A1 families in the SOA.

**Archetype column:** A1.

### Assessment

PROMPTLOCK is a Go-compiled ransomware family distinguished by its use of a live LLM call to generate the encryption implementation at runtime. The SPECK 128-bit cipher is not compiled in — it is produced by the LLM on demand and executed via an embedded Lua interpreter. This architecture has two operational implications: the encryption logic varies per run (complicating static detection), and the malware requires live LLM API access to encrypt files.

The `llm_windows.exe` naming convention across all builds suggests a multi-platform development approach, though only Windows builds have been confirmed in the corpus. The `newport` build variant name on `1458b6dc` suggests active development with named iteration stages.

No cross-family operator attribution has been established for PROMPTLOCK. The three samples appeared on the same day (2025-08-25) across a set of submitters that are all consistent with researcher/collector accounts.

**Confidence:** High (A1 archetype confirmed; AV label consensus across 40+ vendors; ESET `WinGo/Filecoder.PromptLock.A` label and rule reference confirm Go + LLM + Lua + SPECK architecture; `target_file_list.log` artifact is unique to this family).

### Open Questions

- **LLM provider:** Which LLM API does PROMPTLOCK call at runtime? The provider, endpoint, and any hardcoded API key are not recoverable from VT metadata. The fact that `7bbb0647` is named `Windows/PromptLock.exe` in a path (`C:\Users\user\AppData\Local\Temp\ortopz4y.rzu\Windows\PromptLock.exe`) suggests extraction from a multi-file archive — a Linux or macOS sibling binary may exist.
- **Ransom note:** No ransom note strings or contact mechanisms are recoverable from metadata.
- **Campaign scope:** Three samples on one day. Whether this was a targeted deployment, a test, or the visible surface of a wider campaign is unknown. No victims have been reported in available public sources.
- **Operator identity unknown.** No submitter keys on PROMPTLOCK samples are operator-attributable — all are consistent with researcher/collector feeds. The PROMPTLOCK operator is unidentified.

---

## CAIRN Rules

```yara
rule T3-PromptLock_LLM_Lua_Ransomware
{
    meta:
        description = "Detects PromptLock ransomware — hard-coded LLM prompt for Lua-based file encryption via SPECK ECB cipher; target_file_list.log is a unique binary artifact"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "orchestration_logic"
        tier = "T3"
        confidence = "high"
        family = "PromptLock"
        reference = "Discovered via PromptIntel API; ESET attribution; embedded LLM prompt drives AI-generated Lua SPECK encryption at runtime"

    strings:
        $filecoder_pl  = "Filecoder.PromptLock"    nocase
        $filecoder_pl2 = "Filecoder/PromptLock"    nocase
        $ransom_pl     = "Ransom.PromptLock"       nocase
        $ransom64_pl   = "Ransom.Win64.PROMPTLOCK"  nocase
        $tfl           = "target_file_list.log"    nocase
        $speck         = "SPECK 128bit"            nocase

    condition:
        $filecoder_pl or $filecoder_pl2 or $ransom_pl or $ransom64_pl or ($tfl and $speck)
}
```

Fires on:
- Any sample carrying an AV label in the PromptLock family consensus (`Filecoder.PromptLock`, `Filecoder/PromptLock`, `Ransom.PromptLock`, `Ransom.Win64.PROMPTLOCK`)
- Any sample combining the `target_file_list.log` artifact with the `SPECK 128bit` cipher string

---

## Indicators of Compromise

**Registered seeds:** `7bbb0647`, `1458b6dc`, `e24fe0dd`, `8effbb7f`

| SHA256 | Filenames | Size | Detections | First Seen (UTC) | Notes |
|---|---|---|---|---|---|
| `7bbb06479a2e554e450beb2875ea19237068aa1055a4d56215f4e9a2317f8ce6` | `Windows/PromptLock.exe`, `PromptLock.exe`, `llm_windows.exe` | 7,118,848 | 53 | 2025-08-25 | Primary named build; seed |
| `1458b6dc98a878f237bfb3c3f354ea6e12d76e340cefe55d6a1c9c7eb64c9aee` | `llm_windows_newport.exe` | 7,118,848 | 53 | 2025-08-25 | `newport` variant; identical imphash to `7bbb0647`; seed |
| `e24fe0dd0bf8d3943d9c4282f172746af6b0787539b371e6626bdb86605ccd70` | `llm_windows.exe` | 10,327,552 | 43 | 2025-08-25 | Larger build; additional COFF sections; seed |
| `8effbb7f069c7d9d9b1feba8aed10c93bc86eb753a05dfde685d38823402f6a6` | (hash-named path) | 7,483,396 | 50 | 2025-11-07 | Petik automated collection copy (`b32d639c` + `223274c1`); same imphash as Aug cluster; NOT a new operator build — rule validation seed only |

No C2 infrastructure or network IOCs recoverable from VT metadata.

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-22 | Initial report — 3 corpus samples confirmed; A1 archetype confirmed |
| 2026-07-02 | `8effbb7f` (Nov 2025, 50 det) added to IOC table as rule-validation seed. Confirmed as petik automated-feed copy of an existing Aug 2025 build — not a new operator build. |
| 2026-07-03 | **Attribution correction:** `7a4d5f37` and `b32d639c` reclassified as malware researcher/collector keys (petik). Cross-family VOZDYHAN operator link retracted — both signals were researcher coincidence, not operator overlap. PROMPTLOCK operator remains unidentified. |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-07-02. Author: Ryan Fetterman (https://fetterm4n.github.io)*
