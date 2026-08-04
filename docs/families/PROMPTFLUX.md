# PROMPTFLUX — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `Trojan.VBS.PROMPTFLUX.THBBDBF` (TrendMicro) · `Trojan:VBS/PromptFlux.GVA!MTB` (Microsoft)
**First seen:** 2025-05-10
**Platform:** VBScript dropper → Windows PE payload
**Archetype:** A1 — LLM-Directed Payload Generation (self-mutation sub-pattern)
**LLM provider:** Google Gemini (hardcoded API key in payload)
**TLP:** TLP:AMBER

---

## Summary

PROMPTFLUX uses a language model as a **self-rewriting obfuscation engine**. The delivered payload carries a hardcoded Google Gemini API key, submits **its own source code** to the model at runtime with a request for an obfuscated, evasion-hardened rewrite, then overwrites itself on disk with the model's output.

This makes hash-based tracking structurally unreliable. Each rewrite cycle produces a new file hash for functionally equivalent malware, and the mutation rate is bounded only by API quota rather than by operator effort. Where conventional polymorphism requires an operator to build and maintain a mutation engine, here the engine is a commercial API — no development cost, no maintenance, and output diversity beyond what most hand-written packers achieve.

The practical consequence for defenders: **any sample count for this family is a floor, not an estimate.** The stable, detectable artifact is the delivery stage — a ~4.4 MB obfuscated VBScript dropper that assembles a base64-chunked PE from an `ExeDataParts` array. The payload it drops is ephemeral by design.

Within the A1 archetype, PROMPTFLUX occupies a distinct position:

| Family | What the model generates |
|---|---|
| PROMPTLOCK | Lua code implementing a SPECK cipher |
| HONESTCUE | A C# second-stage loader |
| **PROMPTFLUX** | **A rewritten copy of the malware's own source** |

The first two use the model to produce capability. PROMPTFLUX uses it to produce *variation* — the model is applied to survival rather than function.

---

## Architecture

| Stage | Component | Role |
|---|---|---|
| 1 | `crypted_pw-free-online (4).vbs` | ~4.4 MB obfuscated VBScript; assembles and drops the PE |
| 2 | Dropped Windows PE | Primary payload; holds the hardcoded Gemini key |
| 3 | Gemini API | Rewrites stage 2's source on request |
| 4 | Rewritten stage 2 | Replaces the on-disk payload — new hash, same behavior |

Stage 4 loops back into stage 3. Persistence is achieved through continuous mutation rather than through a registry key or scheduled task, so the artifact defenders would normally pivot on keeps changing while the foothold remains.

---

## Samples

| SHA256 | Filename | Size | Detections | First Seen (UTC) |
|---|---|---|---|---|
| `eb0687daed29f3651c61b0a2aa4a0cdcf2049a1ebae2e15e2dd9326471d318a1` | `crypted_pw-free-online (4).vbs` | ~4,302 KB | 34 | 2025-05-10 |

One dropper sample is confirmed. Given the self-mutation design, the payload population is expected to be substantially larger and largely invisible to hash-based collection.

---

## Dropper Details

| Field | Value |
|---|---|
| File type | VBScript (`.vbs`) |
| Size | ~4.4 MB |
| Detections | 34 |
| Code signing | None |
| Tags | `base64-string`, `long-sleeps`, `write-file`, `create-ole`, `run-file`, `vba`, `anti-analysis`, `obfuscated`, `run-dll`, `spreader` |

### Delivery Chain

1. **Storage.** The PE payload is base64-encoded and split across an `ExeDataParts` array of string literals. At 4.4 MB the encoded PE is effectively the entire script.
2. **Reconstruction.** Array elements are joined, base64-decoded, and written to disk through `Scripting.FileSystemObject`.
3. **Execution.** The dropped PE is launched via `WScript.Shell.Run`.
4. **Anti-analysis.** Long sleep delays target sandbox timeouts; additional obfuscation layers are present.

The 4.4 MB size is itself characteristic — a script this large exists to smuggle a PE past file-type filtering on mail gateways and web proxies.

### Social Engineering

The filename `crypted_pw-free-online (4).vbs` targets users searching for free password-recovery or credential-extraction tooling. The `(4)` suffix is consistent with distribution as one item in a numbered series from a fake tool site or file-sharing page.

VirusTotal's crowdsourced YARA flagged `Base64_Encoded_URL`, confirming at least one base64-encoded URL in the script body alongside the PE payload.

---

## Detection

### YARA

```yara
rule T3-PROMPTFLUX_VBS_Dropper
{
    meta:
        description = "Detects PROMPTFLUX VBS dropper — 4.4MB heavily obfuscated script staging chunked base64 PE payload via ExeDataParts array"
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

`ExeDataParts` is the durable anchor — it is the dropper's own array identifier and survives payload mutation entirely, because the dropper is not what mutates.

### Detection Guidance

**Detect the dropper, not the payload.** The delivery stage is stable and signaturable; the payload's hash has a lifetime measured in rewrite cycles. Every hash-based control — blocklists, reputation lookups, retrospective hunting — degrades against stage 2 and holds firm against stage 1.

Recommended controls:

| Control | Rationale |
|---|---|
| Block / alert on multi-megabyte `.vbs` files at the gateway | A 4.4 MB script has no legitimate use case |
| Restrict `wscript.exe` / `cscript.exe` execution from user-writable paths | Removes the delivery mechanism entirely |
| Monitor outbound traffic to generative-AI endpoints from non-developer hosts | The rewrite loop is a hard external dependency |
| Alert on an executable overwriting its own image on disk | Self-replacement is the family's defining behavior and is rare in legitimate software |

The last row is the most specific available signal. It is also mutation-proof: however the model rewrites the code, the rewritten copy must still replace the original for persistence to work.

**Denying model access breaks the mutation loop.** It does not remove the foothold — the payload remains resident and functional — but it freezes the payload at a known hash, which restores every hash-based control that the design was built to defeat.

---

## Open Questions

1. **What is the payload's primary function?** Whether stage 2 carries a stealer, RAT, or ransomware capability in addition to the rewrite loop — or whether the rewrite loop is the whole operation — is unresolved. This is the most consequential gap: it separates a self-obfuscating tool from a self-obfuscating *implant*.
2. **Is the Gemini key shared or rotated?** A single hardcoded key across all variants would be a decisive intervention point; revocation would halt mutation family-wide. Per-variant keys would not.
3. **Campaign breadth.** The `(4)` suffix and lure theme suggest an active fake-tool distribution series. Hash-based tracking cannot measure it; only the dropper pattern can.
4. **Rewrite fidelity and drift.** Whether the model's rewrites preserve functionality reliably over many generations, or degrade, is unknown. Accumulated drift would be a meaningful weakness in the design.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
