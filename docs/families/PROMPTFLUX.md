# PROMPTFLUX — Research Report

**Family designation:** PROMPTFLUX (TrendMicro `Trojan.VBS.PROMPTFLUX.THBBDBF`; Microsoft `Trojan:VBS/PromptFlux.GVA!MTB`)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-05-10 (earliest VT submission in corpus)
**Last seen:** 2025-05-10 (single corpus sample)
**Variants:** 1 confirmed seed; 1 corpus hit
**Platform:** VBScript (.vbs) — heavy obfuscation, ~4.4 MB
**CAIRN rules:** `T3-PROMPTFLUX_VBS_Dropper`
**Related report:** N/A

---

## Summary

PROMPTFLUX is a heavily obfuscated VBScript dropper (~4.4 MB) that stages and executes a chunked, base64-encoded PE payload. The script assembles the PE from an `ExeDataParts` array of base64 chunks, decodes and writes the PE to disk, then executes it. The filename `crypted_pw-free-online (4).vbs` is a social engineering lure presenting as a password recovery or credential dump tool.

PROMPTFLUX instantiates **A1 (LLM-Directed Payload Generation)** with a self-mutation sub-pattern: the delivered payload holds a hardcoded Gemini API key and sends the payload's own source to the model at runtime, requesting rewritten obfuscated/evasion variants. The LLM output replaces the payload on disk for persistence. This distinguishes PROMPTFLUX from other A1 families (PromptLock generates encryption logic; HONESTCUE generates a C# stage2 loader) — PROMPTFLUX uses the LLM as a self-rewriting obfuscation engine. Because the hash changes on every LLM rewrite cycle, corpus sample count is likely an undercount of true deployment scale.

---

## Discovery

PROMPTFLUX was added to the CAIRN corpus as a seed sample. The T3 rule fires on AV label consensus (TrendMicro and Microsoft both name the `PROMPTFLUX`/`PromptFlux` family) and on the `ExeDataParts` array name, which is a distinctive string from the dropper's chunked PE assembly logic. VT metadata does not surface the VBScript body content, so AI-interaction strings from the dropped PE are not recoverable from corpus metadata alone.

---

## crypted_pw-free-online (4).vbs — VBS Dropper

### Binary Characteristics

| Field | Value |
|---|---|
| File type | VBScript (`.vbs`) |
| Filename | `crypted_pw-free-online (4).vbs` |
| Size | ~4,302 KB (4.4 MB) |
| First seen | 2025-05-10 |
| Detections | 34 |
| Tags | `base64-string`, `long-sleeps`, `write-file`, `create-ole`, `run-file`, `vba`, `anti-analysis`, `obfuscated`, `run-dll`, `spreader` |
| Code-signing | None |
| Provider references | None recovered in corpus metadata |

The 4.4 MB size is characteristic of a base64-encoded PE embedded inside the VBScript body — a common dropper technique for bypassing file-type filters on email gateways or web proxies.

### Dropper Mechanism

PROMPTFLUX uses a chunked base64 PE assembly pattern:

1. **Payload storage.** The PE binary is base64-encoded and split into an `ExeDataParts` array of string literals in the VBScript body. At 4.4 MB, the encoded PE occupies virtually the entire script.

2. **Reconstruction.** The script joins the array elements, base64-decodes the result, and writes the decoded PE to disk via `WriteFile` / `CreateObject("Scripting.FileSystemObject")`.

3. **Execution.** The dropped PE is executed via `Shell` or `WScript.Shell.Run`.

4. **Anti-analysis.** The `long-sleeps` tag indicates the dropper includes sleep delays to defeat sandbox timeout-based analysis. The `anti-analysis` and `obfuscated` tags confirm additional evasion layers.

### Lure

The filename `crypted_pw-free-online (4).vbs` is a social engineering lure targeting users searching for free password recovery or credential extraction tools. The `(4)` suffix suggests the file was distributed as the fourth in a series of downloads from a fake tool website or file sharing platform.

### Crowdsourced YARA Hit

VT's crowdsourced YARA engine fired `Base64_Encoded_URL` on this sample — confirming at least one base64-encoded URL is present in the script body. This is consistent with the dropper encoding a callback URL or C2 address alongside the PE payload.

---

## Operator Infrastructure

No C2 domains, IPs, or delivered payload URLs were recovered from VT metadata for the dropper script. The dropped PE contains the LLM-related infrastructure; without access to the delivered binary, operator C2 is unknown.

**C2AE (C2 Attribute Enricher) verdict:** Undetected — the dropper's network activity did not produce confirmed C2 endpoints in VT's C2AE pipeline.

---

## Assessment

### Archetype

**A1 — LLM-Directed Payload Generation (self-mutation sub-pattern)**

The delivered payload holds a hardcoded Gemini API key. At runtime it sends its own source code to the Gemini API requesting an obfuscated/evasion rewrite, then replaces itself on disk with the LLM's output. The LLM is a self-rewriting obfuscation engine — not a code factory for a separate stage. This is a novel A1 variant:

| Family | LLM Role |
|---|---|
| PromptLock | LLM generates Lua SPECK encryption logic at runtime |
| HONESTCUE | LLM generates a C# stage2 reflective loader |
| **PROMPTFLUX** | **LLM rewrites the payload's own source for obfuscation/persistence** |

Because the hash changes on every rewrite cycle, VT corpus sample count is a significant undercount of true deployment scale. The dropper (VBS, `ExeDataParts` chunked base64) is the stable artifact that CAIRN detects; the delivered PE is ephemeral by design.

### Assessment

PROMPTFLUX is a 4.4 MB obfuscated VBScript dropper using chunked base64 PE assembly, targeting users seeking free password tools. The dropper pattern is conventional; the CAIRN interest is in the delivered PE, which carries the `PROMPTFLUX` family attribution from two major AV engines. Without access to the dropped binary, the payload's AI-related behavior cannot be characterized from metadata alone.

**Confidence:** High for A1 archetype assignment (confirmed via external reporting: hardcoded Gemini key, LLM-driven self-rewriting obfuscation, persistence via hash-cycling). Low for variant count — corpus undercount is expected by design.

### Open Questions

- **Distribution campaign:** Is `crypted_pw-free-online (4).vbs` part of a broader fake-tool distribution campaign? The "(4)" suffix and lure filename suggest an active series. Hard to track via hash due to self-mutation.
- **Payload capabilities beyond obfuscation:** Does the dropped PE have a primary payload (stealer, RAT, ransomware) beyond the LLM self-rewrite loop, or is the rewrite loop the entirety of the operation?
- **Gemini model/key rotation:** Is a single hardcoded Gemini key reused across all variants, or does the key rotate? A burnt key would suppress the rewrite capability without affecting dropper delivery.

---

## CAIRN Rules

```yara
rule T3-PROMPTFLUX_VBS_Dropper
{
    meta:
        description = "Detects PROMPTFLUX VBS dropper — 4.4MB heavily obfuscated script staging chunked base64 PE payload via ExeDataParts array; Kaspersky/Microsoft consensus on PROMPTFLUX family"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "orchestration_logic"
        tier = "T3"
        confidence = "high"
        family = "PROMPTFLUX"

    strings:
        $av_kav  = "Trojan.VBS.PROMPTFLUX"  nocase
        $av_ms   = "PromptFlux.GVA"         nocase
        $vbs_arr = "ExeDataParts"           nocase

    condition:
        $av_kav or $av_ms or $vbs_arr
}
```

Fires on:
- Samples carrying `Trojan.VBS.PROMPTFLUX` (TrendMicro) or `PromptFlux.GVA` (Microsoft) detection labels
- Samples containing the `ExeDataParts` array name from the chunked PE assembly pattern

1 corpus sample confirmed.

---

## Indicators of Compromise

**Registered seed:** `eb0687daed29f3651c61b0a2aa4a0cdcf2049a1ebae2e15e2dd9326471d318a1`

| SHA256 | Filename | Detections | First Seen (UTC) |
|---|---|---|---|
| `eb0687daed29f3651c61b0a2aa4a0cdcf2049a1ebae2e15e2dd9326471d318a1` | `crypted_pw-free-online (4).vbs` | 34 | 2025-05-10 |

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial report — 1 corpus sample confirmed; dropper mechanism documented; archetype classification pending payload analysis; seed registered |
| 2026-06-24 | Archetype confirmed A1 (self-mutation sub-pattern) via external reporting: hardcoded Gemini key, LLM rewrites payload source for obfuscation/persistence, hash-cycling by design. A1 first-confirmed date in SOA.md updated to 2025-05-10. |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-12. Author: Ryan Fetterman (https://fetterm4n.github.io)*
