# PROMPTLOCK — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `WinGo/Filecoder.PromptLock.A` (ESET) · `Trojan.Ransom.PromptLock` (Bitdefender, AhnLab, ALYac) · `Ransom.Win64.PROMPTLOCK` (TrendMicro) · `Trojan-Ransom.Win64.PromptLock` (Kaspersky)
**First seen:** 2025-08-25
**Last seen:** 2025-08-25 (operator builds); 2025-11-07 (collector re-submission)
**Platform:** Windows x86-64 (PE32+ console), Go-compiled
**Archetype:** A1 — LLM-Directed Payload Generation
**TLP:** TLP:AMBER

---

## Summary

PROMPTLOCK is a Go-compiled ransomware family whose **file-encryption implementation does not exist in the binary**. Instead, the executable carries a hard-coded prompt that instructs a hosted LLM, at runtime, to generate Lua source code implementing a **SPECK 128-bit ECB cipher**. The malware then executes that generated Lua through an embedded interpreter to encrypt victim files.

This inverts the normal relationship between a ransomware binary and its cryptography. The cipher is not a compiled routine to be located and signatured — it is model output, regenerated on each execution and free to vary in structure, variable naming, and loop form between runs while remaining functionally identical. The LLM here is a **code factory, not a command channel**: it does not receive victim data or issue tasking, and it is not a C2.

PROMPTLOCK is the earliest confirmed instance of this technique observed in the wild, establishing the A1 archetype. It is also the clearest demonstration of the archetype's operational cost: a ransomware build that **cannot encrypt anything without live LLM API access**. Loss of that access — through key revocation, provider-side abuse enforcement, network egress filtering, or simple outage — is a total capability failure, not a degraded mode.

Three operator builds appeared on VirusTotal on a single day, 2025-08-25. AV coverage is unusually unanimous: 40+ vendors agree on family attribution with no dissent, and ESET's `WinGo/` prefix independently confirms Go compilation.

---

## Architecture

| Stage | Component | Location | Role |
|---|---|---|---|
| 1 | Go executable | On disk (`PromptLock.exe`) | Host process, file enumeration, LLM call |
| 2 | Embedded prompt | Static, in binary | Instructs the model to emit Lua SPECK-128 ECB code |
| 3 | Hosted LLM | Remote (provider unidentified) | Generates the encryption implementation |
| 4 | Lua interpreter | Embedded in the Go binary | Executes the model-generated cipher |
| 5 | `target_file_list.log` | Written to disk | Enumeration output — the family's clearest host artifact |

The consequence for defenders: **static analysis of the binary will not recover a cipher**, because none is present. What is present is the prompt describing one.

---

## Samples

| SHA256 | Filenames | Size | Detections | First Seen (UTC) | Notes |
|---|---|---|---|---|---|
| `7bbb06479a2e554e450beb2875ea19237068aa1055a4d56215f4e9a2317f8ce6` | `Windows/PromptLock.exe`, `PromptLock.exe`, `llm_windows.exe` | 7,118,848 | 53 | 2025-08-25 | Primary named build |
| `1458b6dc98a878f237bfb3c3f354ea6e12d76e340cefe55d6a1c9c7eb64c9aee` | `llm_windows_newport.exe` | 7,118,848 | 53 | 2025-08-25 | `newport` build variant; imphash-identical to `7bbb0647` |
| `e24fe0dd0bf8d3943d9c4282f172746af6b0787539b371e6626bdb86605ccd70` | `llm_windows.exe` | 10,327,552 | 43 | 2025-08-25 | Larger build; extra COFF sections `/4`, `/19`, `/32` |
| `8effbb7f069c7d9d9b1feba8aed10c93bc86eb753a05dfde685d38823402f6a6` | (hash-named) | 7,483,396 | 50 | 2025-11-07 | Researcher-collection copy of an August build — **not** a new operator build |

The two 7 MB builds share an identical imphash (`d42595b695fc008ef2c56aabd8efd68e`) and PE section layout. The 10 MB build carries roughly 700 KB of additional data in unnamed COFF sections, consistent with embedded resources or retained debug output from a later build.

---

## Binary Details

| Field | Value |
|---|---|
| File type | Win64 PE32+ (console), Go-compiled |
| Imphash (7 MB builds) | `d42595b695fc008ef2c56aabd8efd68e` |
| Code signing | None |
| Rich PE header | Stripped |
| Sandbox execution | No behavioral report available — the samples did not run to completion under automated analysis |

### PE Section Layout

| Section | 7 MB builds | 10 MB build |
|---|---|---|
| `.text` | 3,279,697 | 3,279,697 |
| `.rdata` | 3,378,384 | 3,378,384 |
| `.data` | 675,760 | 675,760 |
| `.pdata` | 73,032 | 73,032 |
| `.xdata` | 180 | 180 |
| `.idata` | 1,342 | 1,342 |
| `.reloc` | 59,940 | 59,940 |
| `.symtab` | 4 | 4 |
| `/19` | — | 584,183 |
| `/32` | — | 118,070 |

The identical `.text` size across both build sizes indicates the same code with additional non-code data appended, rather than an expanded feature set.

---

## Build Pipeline Indicators

Submission filenames expose the operator's build layout:

| Artifact | Reading |
|---|---|
| `llm_windows.exe` (all three builds) | Platform-suffixed naming implies a **multi-target build system** — `llm_linux` / `llm_darwin` siblings are plausible but unobserved |
| `Windows/` path prefix | The Windows build was one directory in a multi-platform tree |
| `llm_windows_newport.exe` | Named iteration stage — indicates active, versioned development |
| `C:\Users\user\AppData\Local\Temp\ortopz4y.rzu\Windows\PromptLock.exe` | Extraction from a multi-file archive at analysis time |

No Linux or macOS sibling has been recovered.

---

## Detection

### YARA

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

Two independent arms: AV-label consensus, or the co-occurrence of the `target_file_list.log` artifact with the `SPECK 128bit` cipher string.

### Host Indicators

| Indicator | Type | Notes |
|---|---|---|
| `target_file_list.log` | File artifact | Written during enumeration; unique to this family |
| Go binary issuing outbound LLM API requests | Behavioral | An unsigned Go console executable calling a hosted inference endpoint is the highest-value signal |
| Lua interpreter activity inside a Go process | Behavioral | Uncommon combination outside game and embedded-scripting software |

### Detection Guidance

Signature strategies keyed on the encryption routine will fail by design — the routine is generated after execution begins. Two approaches remain reliable:

1. **Network-layer.** The binary is inert without reaching an inference provider. Egress control and monitoring of LLM API endpoints from non-developer hosts breaks the family's core capability, not merely its detection.
2. **Behavioral.** The sequence *unsigned Go executable → outbound inference request → dynamic script execution → mass file writes* is a strong composite indicator regardless of what the model emits.

---

## Open Questions

1. **Which LLM provider is called?** The endpoint, provider, and any embedded API credential are not recoverable without binary-level analysis of the prompt-handling code. This is the single most valuable outstanding gap — the provider determines both the takedown path and the attribution surface.
2. **Do non-Windows builds exist?** The `llm_windows.exe` convention strongly implies siblings. None has surfaced.
3. **Ransom note and payment channel.** No ransom-note text, contact address, or payment mechanism has been recovered. It is unresolved whether the note is also model-generated.
4. **Campaign scope.** Three builds, one day, no confirmed victim in public reporting. Whether this represents a live deployment, an operator test, or the visible edge of a broader campaign is undetermined.
5. **Operator identity.** Unknown. Every submitter key on these samples traces to malware-researcher collection feeds rather than operator infrastructure, so submission metadata yields no attribution here.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
