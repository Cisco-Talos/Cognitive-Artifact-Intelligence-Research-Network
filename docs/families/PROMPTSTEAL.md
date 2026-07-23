# PROMPTSTEAL — Research Report

**Family designation:** PROMPTSTEAL (ESET `Python/TrojanDownloader.Agent.ARS`; Avast/AVG `Win32:LAMEHUG-A [Pws]`)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-07-11 (earliest VT submission in corpus)
**Last seen:** 2025-07-11 (single corpus sample)
**Variants:** 1 confirmed seed; 1 corpus hit
**Platform:** Windows PE32+ (PyInstaller-packed Python); 10.4 MB
**CAIRN rules:** `T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer`
**Related report:** `LAMEHUG.md` (bare Python variant of the same family)

---

## Summary

PROMPTSTEAL is a PyInstaller-packed Windows executable that implements the LAMEHUG credential theft and recon operation in a self-contained Win64 binary. It targets LLM API credentials and document files, harvesting them to `C:\ProgramData\info\`, and uses `router.huggingface.co` for DNS-based C2 beaconing or API interaction. The sample uses a Ukrainian-language homoglyph filename (`Додаток.pif` — "Application.pif") as a social engineering lure.

PROMPTSTEAL is assessed as a PyInstaller-packed delivery form of LAMEHUG based on shared AV labeling (`Win32:LAMEHUG-A`) and the HuggingFace router domain. It adds a document harvesting stage not confirmed in the bare Python LAMEHUG variant.

---

## Discovery

PROMPTSTEAL was added to the CAIRN corpus as a seed sample. The T3 rule fires on the `ProgramData\info\info.txt` harvest path and the ESET downloader label. After the ImTip false positive incident (2026-06-12), `router.huggingface.co` alone was removed as a standalone T3 condition — the domain is shared with the legitimate ImTip AI input tool. The rule was tightened to require either the `info_dir` path or the ESET AV label as primary conditions.

---

## Додаток.pif — PyInstaller AI Credential Stealer

### Binary Characteristics

| Field | Value |
|---|---|
| File type | PE32+ executable (console) x86-64 (PyInstaller bundle) |
| Filename | `Додаток.pif` (Ukrainian: "Application.pif") |
| Size | ~10,430 KB (10.4 MB — consistent with PyInstaller bundle including Python runtime) |
| First seen | 2025-07-11 |
| Detections | 46 |
| Tags | `checks-bios`, `checks-network-adapters`, `overlay`, `detect-debug-environment`, `peexe`, `calls-wmi`, `64bits` |
| Code-signing | None |
| Crowdsourced YARA | `PyInstaller` |
| Provider references | `HuggingFace` (via memory_pattern_domains: `router.huggingface.co`) |

The 10.4 MB size is characteristic of a PyInstaller bundle — the Python interpreter and all imported modules are bundled into the PE overlay. Crowdsourced YARA confirms PyInstaller packing.

### Lure and Targeting

The filename `Додаток.pif` is a Ukrainian-language homoglyph lure. The Sigma rule `Homoglyph Attack Using Lookalike Characters in Filename` confirmed on this sample — the Cyrillic characters (`Д`, `о`, `д`, `а`, `т`, `о`, `к`) are visually similar to Latin characters in some contexts, and the `.pif` extension is associated with Program Information Files that Windows can execute. The combination targets Ukrainian-speaking users or organizations.

**Targeting hypothesis:** Ukrainian-language lure + BIOS/network adapter checks + WMI calls is consistent with targeted credential theft in the Ukrainian tech or developer ecosystem.

### Behavioral Indicators (Sigma)

| Sigma Rule | Significance |
|---|---|
| `Python Image Load By Non-Python Process` | PyInstaller PE loading Python DLLs — confirms Python runtime bundle |
| `Potential Python DLL SideLoading` | Python DLL loaded outside the standard Python install directory |
| `Homoglyph Attack Using Lookalike Characters in Filename` | Cyrillic characters in filename used as a lure |
| `WMIC Loading Scripting Libraries` | WMI-based system recon (BIOS, network adapters) |
| `Suspicious Copy From/To System Directory` | File operations in system paths — consistent with harvest drop to `C:\ProgramData\` |
| `Non Interactive PowerShell Process Spawned` | PowerShell invoked non-interactively — post-harvest scripting or exfil |
| `Python:LAMEHUG / Win32:LAMEHUG` (AV) | Cross-variant attribution to LAMEHUG family by Avast/AVG |

### Harvest Path

The string `Programdata\info\info.txt` (matched via T3 rule string `$info_dir`) indicates PROMPTSTEAL harvests data to `C:\ProgramData\info\`. This is a persistent staging directory rather than a temp path — documents and credentials are written here before exfiltration.

The `checks-bios` and `checks-network-adapters` VT tags confirm VM/sandbox evasion checks are performed before the primary payload activates.

### HuggingFace Router Interaction

`router.huggingface.co` appears in memory pattern domains — consistent with LAMEHUG's HuggingFace token rotation and Hyperbolic provider query pattern. Whether PROMPTSTEAL uses the same 400+ hardcoded `hf_` token pool as the bare Python variant is unknown without decompiling the PyInstaller bundle.

---

## Embedded URLs

20 embedded URL hashes were identified in VT relationship data. These likely correspond to the HuggingFace inference router, the operator's webhook or SSH exfil endpoint, and potentially download URLs for secondary payloads. Specific URLs within the 20-hash set were not fully enumerated in the corpus.

---

## Operator Infrastructure

| IOC | Type | Notes |
|---|---|---|
| `router.huggingface.co` | Domain | HuggingFace inference router — confirmed in memory patterns |
| `C:\ProgramData\info\info.txt` | Path | Document/credential harvest staging path |
| (20 embedded URL hashes) | URLs | Not fully enumerated — likely includes exfil endpoints |

---

## Assessment

### Archetype

**PROMPTSTEAL is archetype A6 — AI Credential Harvester.** Confirmed (shared with LAMEHUG).

PROMPTSTEAL is a delivery variant of LAMEHUG that adds document harvesting. The LAMEHUG family label from Avast/AVG (`Win32:LAMEHUG-A`) and the HuggingFace router domain confirm shared lineage. Both variants target AI credentials (`hf_` tokens) and use AI infrastructure for recon.

The document harvest stage (`ProgramData\info\`) is an additional data theft objective not confirmed in the bare Python variant. This may reflect a targeting-specific payload modification: the Ukrainian lure and document harvest suggest a targeted deployment against a specific individual or organization, rather than the broad credential burn pattern of the bare script.

**Archetype column:** A6 (see LAMEHUG).

### Assessment

PROMPTSTEAL is a hardened deployment form of the LAMEHUG family: PyInstaller-packed for easier delivery, homoglyph-lured for targeted victims, and extended with a document harvest stage. The combination of AI credential theft, BIOS/adapter evasion checks, and a Ukrainian-language lure is consistent with a targeted credential theft operation against a Ukrainian developer or AI practitioner.

**Confidence:** High (AV label cross-references to LAMEHUG; HuggingFace router domain confirmed; harvest path confirmed; PyInstaller confirmed; behavioral indicators consistent with the described operation).

### Open Questions

- **Token pool:** Does PROMPTSTEAL embed the same 400+ hardcoded `hf_` tokens as the bare Python LAMEHUG script? Or does it retrieve a fresh pool dynamically? Cannot determine from metadata — requires PyInstaller decompression.
- **Document harvest scope:** What file types are collected to `C:\ProgramData\info\`? API key files, `.env` configs, documents, source code? Unknown without binary analysis.
- **Exfil endpoint:** The 20 embedded URL hashes include the exfil destination. The specific URLs were not fully enumerated.
- **Ukrainian targeting:** Is this a targeted deployment against a known individual/organization, or is the Ukrainian lure a broad phishing campaign targeting Ukrainian developers?

---

## CAIRN Rules

```yara
rule T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer
{
    meta:
        description = "Detects PROMPTSTEAL — PyInstaller Python stealer targeting LLM API credentials and documents; harvests docs to C:\\ProgramData\\info\\; DNS beacon to router.huggingface.co. NOTE: router.huggingface.co alone removed as standalone condition — legitimate AI aggregator tools embed it as a provider config string; use $info_dir or AV label as primary anchors"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "api_key_pattern"
        tier = "T3"
        confidence = "high"
        family = "PROMPTSTEAL"

    strings:
        $hf_dns   = "router.huggingface.co"              nocase
        $info_dir = "Programdata\\info\\info.txt"        nocase
        $av_eset  = "Python/TrojanDownloader.Agent.ARS"  nocase

    condition:
        $info_dir or $av_eset or ($hf_dns and $info_dir)
}
```

**Rule tuning note (2026-06-12):** `router.huggingface.co` was initially a standalone T3 condition but was removed after the ImTip false positive (`77f4e241...` — github.com/aardio/ImTip open-source AI input assistant). ImTip includes the HuggingFace router as a provider config string. The current rule requires `$info_dir` (harvest path) or the ESET downloader label as primary anchors; `$hf_dns` is retained only as a co-occurrence amplifier.

Fires on:
- Samples containing the `ProgramData\info\info.txt` harvest staging path
- Samples carrying ESET's `Python/TrojanDownloader.Agent.ARS` label
- Samples combining both the HuggingFace router domain and the harvest path

---

## Indicators of Compromise

**Registered seed:** `766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777`

| SHA256 | Filename | Detections | First Seen (UTC) |
|---|---|---|---|
| `766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777` | `Додаток.pif` (Ukrainian homoglyph lure) | 46 | 2025-07-11 |

**Infrastructure:**

| IOC | Type |
|---|---|
| `router.huggingface.co` | LLM inference router (HuggingFace) |
| `C:\ProgramData\info\info.txt` | Credential/document harvest staging path |

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial report — 1 corpus sample confirmed; A6 archetype confirmed; harvest path and Ukrainian lure documented; T3 rule tightened after ImTip FP; cross-referenced to LAMEHUG |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-12. Author: Ryan Fetterman (https://fetterm4n.github.io)*
