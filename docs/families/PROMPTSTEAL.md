# PROMPTSTEAL — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `Python/TrojanDownloader.Agent.ARS` (ESET) · `Win32:LAMEHUG-A [Pws]` (Avast/AVG)
**First seen:** 2025-07-11
**Platform:** Windows x86-64 (PE32+, PyInstaller-packed Python), 10.4 MB
**Archetype:** A6 — AI Credential Harvester
**Related:** [LAMEHUG](LAMEHUG.md) — the bare-script form of the same family
**TLP:** TLP:AMBER

---

## Summary

PROMPTSTEAL is the **weaponized delivery form of LAMEHUG**: the same AI-credential-theft and LLM-directed reconnaissance operation, packed into a self-contained 10.4 MB Windows executable, fitted with a Ukrainian-language homoglyph lure, and extended with a document-harvesting stage that the bare script does not have.

Three changes distinguish it from the script variant, and all three point the same direction — from opportunistic to targeted:

1. **PyInstaller packaging.** No Python installation required on the victim host; the interpreter and every dependency ship inside the PE overlay. This converts a script that only runs on a developer machine into one that runs anywhere.
2. **Ukrainian homoglyph lure.** The filename `Додаток.pif` ("Application.pif") uses Cyrillic characters and the executable `.pif` extension. This is language-specific victim selection, not broad spray.
3. **Document harvesting.** Files are staged to `C:\ProgramData\info\` — a persistent directory, not a temp path — indicating an intent to collect and hold victim documents alongside credentials.

The family shares AV attribution (`Win32:LAMEHUG-A`) and the `router.huggingface.co` inference path with LAMEHUG, establishing common lineage. The combination of a Ukrainian lure, sandbox-evasion checks, and document theft is consistent with a targeted operation against Ukrainian developers or AI practitioners rather than the indiscriminate credential burn the bare script performs.

---

## Samples

| SHA256 | Filename | Size | Detections | First Seen (UTC) |
|---|---|---|---|---|
| `766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777` | `Додаток.pif` | ~10,430 KB | 46 | 2025-07-11 |

---

## Binary Details

| Field | Value |
|---|---|
| File type | PE32+ executable (console), x86-64 — PyInstaller bundle |
| Size | ~10.4 MB (Python runtime + dependencies in overlay) |
| Detections | 46 |
| Code signing | None |
| Crowdsourced YARA | `PyInstaller` |
| VT tags | `checks-bios`, `checks-network-adapters`, `overlay`, `detect-debug-environment`, `calls-wmi`, `64bits` |
| Provider reference | `router.huggingface.co` (observed in process memory) |

### The Lure

`Додаток.pif` is Ukrainian for "Application" written in Cyrillic. Two mechanisms combine:

| Element | Effect |
|---|---|
| Cyrillic characters | Visually resemble Latin equivalents in many fonts; defeats casual filename inspection and simple string blocklists |
| `.pif` extension | A legacy Program Information File type that Windows will **execute**, while reading as a benign document type to most users |

A Ukrainian-language filename presupposes a Ukrainian-reading victim. This is targeting, and it should be read as intelligence about victim selection rather than as incidental packaging.

### Anti-Analysis

The `checks-bios` and `checks-network-adapters` tags, together with WMI usage, confirm environment checks executed **before** the primary payload activates. Automated analysis in a virtualized sandbox may therefore observe only benign behavior — absence of malicious activity in a sandbox report is not evidence of a benign sample here.

### Observed Behavior

| Indicator | Significance |
|---|---|
| Python image loaded by non-Python process | PyInstaller bundle unpacking its runtime |
| Potential Python DLL sideloading | Python DLL loaded outside a standard install path |
| Homoglyph attack in filename | Cyrillic lure confirmed |
| WMIC loading scripting libraries | WMI-based recon (BIOS, network adapters) |
| Suspicious copy from/to system directory | Consistent with the `C:\ProgramData\` harvest drop |
| Non-interactive PowerShell spawned | Post-harvest scripting or exfiltration |

### Harvest Staging

Collected data is written to **`C:\ProgramData\info\info.txt`**. The choice of `ProgramData` over a temp path is deliberate: the directory is world-writable, survives reboots, and is excluded from many user-profile-focused monitoring configurations. Data accumulates there pending exfiltration.

---

## Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `router.huggingface.co` | Domain | HuggingFace inference router — observed in process memory |
| `C:\ProgramData\info\info.txt` | File path | Credential and document harvest staging |
| 20 embedded URL references | URLs | Not fully enumerated; expected to include exfiltration endpoints |

Whether PROMPTSTEAL carries the same 400+ stolen `hf_` token pool as the bare LAMEHUG script is unconfirmed — resolving it requires unpacking the PyInstaller bundle.

---

## Detection

### YARA

```yara
rule T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer
{
    meta:
        description = "Detects PROMPTSTEAL — PyInstaller Python stealer targeting LLM API credentials and documents; harvests to C:\\ProgramData\\info\\; router.huggingface.co is NOT a standalone condition (legitimate AI tools embed it as provider config)"
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

**Rule design note.** `router.huggingface.co` was removed as a standalone condition after it produced a false positive against a legitimate open-source AI input assistant that embeds the router as provider configuration. The lesson generalizes: **a legitimate AI provider endpoint is never sufficient evidence of malice.** The harvest path and AV label are the anchors; the domain only amplifies.

### Detection Guidance

| Control | Rationale |
|---|---|
| Alert on any file creation under `C:\ProgramData\info\` | Family-specific and highly reliable |
| Flag executable extensions (`.pif`, `.scr`, `.com`) carrying non-ASCII filenames | Catches the homoglyph lure class generally, not just this family |
| Monitor `wmic.exe` invoked by an unsigned single-file executable | The recon stage |
| Treat inbound `.pif` attachments as executable | Many gateways do not classify `.pif` as executable — a longstanding gap this family exploits |

The homoglyph rule is worth generalizing. Non-ASCII characters in an executable filename have almost no legitimate use in most environments and reliably indicate a lure.

---

## Open Questions

1. **Does it carry the same token pool?** Whether the 400+ stolen `hf_` tokens from the bare script are embedded here, or a fresh pool is fetched at runtime, is unresolved. A dynamic pool would imply supporting operator infrastructure not otherwise observed.
2. **What documents are collected?** The file types written to `C:\ProgramData\info\` are unconfirmed. `.env` files, API-key stores, source code, and office documents are all plausible; the answer defines the actual victim impact.
3. **Exfiltration endpoint.** Present among the 20 embedded URL references but not individually identified. This is the highest-value outstanding IOC.
4. **Targeting specificity.** Whether the Ukrainian lure indicates a specific named target or a broad phishing campaign against Ukrainian developers is undetermined. One sample cannot distinguish these.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
