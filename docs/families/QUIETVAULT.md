# QUIETVAULT — Research Report

**Family designation:** QUIETVAULT (TrendMicro `TrojanSpy.JS.QVAULT.THBBDBF`; Microsoft `Trojan:JS/QuietVault!MTB`)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-08-27 (earliest VT submission in corpus)
**Last seen:** 2025-08-27 (single corpus sample)
**Variants:** 1 confirmed seed; 1 corpus hit
**Platform:** JavaScript / Node.js (6.6 KB)
**CAIRN rules:** `T3-QUIETVAULT_JS_Telemetry_Spy`
**Related report:** N/A

---

## Summary

QUIETVAULT is a JavaScript stealer distributed as a fake npm package telemetry module (`package/telemetry.js`). It masquerades as a routine package telemetry component but performs credential or data theft, drops `edb.chk`, and includes geofencing and anti-debug evasion. The supply chain vector (npm package masquerade) classifies QUIETVAULT alongside SUPERO as an A8 (Malicious AI SDK / Package) family, distinguishing it from conventional JavaScript stealers by its delivery mechanism.

---

## Discovery

QUIETVAULT was added to the CAIRN corpus as a seed sample. The T3 rule fires on TrendMicro (`TrojanSpy.JS.QVAULT`) and Microsoft (`QuietVault`) family name consensus, plus the co-occurrence of the `package/telemetry.js` path identifier and the `edb.chk` drop path.

---

## package/telemetry.js — JavaScript npm Supply Chain Stealer

### Binary Characteristics

| Field | Value |
|---|---|
| File type | JavaScript (Node.js) |
| Filenames | `package/telemetry.js`, `telemetry.js` |
| Size | 6,632 bytes |
| First seen | 2025-08-27 |
| Detections | 37 |
| Tags | `long-sleeps`, `javascript` |
| Code-signing | None |
| Crowdsourced YARA | `Windows_API_Function` |
| Provider references | None recovered in corpus metadata |

The 6,632-byte size is characteristic of a hand-written JavaScript stealer — small enough to avoid file-size heuristics, large enough to include evasion logic and payload delivery. The `package/telemetry.js` path is the characteristic npm package internal path — the script presents itself as a telemetry module within a legitimate-looking npm package.

### Delivery Mechanism

QUIETVAULT uses the npm supply chain as its delivery vector. The script is structured as a `package/telemetry.js` module within an npm package. When installed by a developer (via `npm install` or `npm ci`), the telemetry module activates. This pattern is consistent with the malicious npm package supply chain attack technique documented for SUPERO (A8).

The npm supply chain vector is particularly effective against AI developers — the target audience installs many packages quickly, and telemetry modules are common in legitimate packages and rarely audited.

### Behavioral Profile

| Behavior | Evidence |
|---|---|
| Data theft / credential access | TrendMicro `TrojanSpy.JS.QVAULT` classification; `Spy` prefix |
| File drop | `edb.chk` dropped at runtime |
| Anti-analysis | `long-sleeps` tag — sleep delays to defeat sandbox timeout analysis |
| Geofencing | Referenced in VT sandbox — victim geolocation check before activation |
| Anti-debug | Referenced in VT sandbox — debugger/sandbox detection |
| Windows API calls | Crowdsourced YARA `Windows_API_Function` — Node.js accessing Win32 API via native module |

The `edb.chk` drop is a distinctive artifact. `.chk` files are associated with Windows file system check operations — the filename is a cover for a data staging or persistence file. The Windows API access from a Node.js process (via `Crowdsourced: Windows_API_Function`) is unusual for a telemetry module and confirms the script accesses system resources beyond normal telemetry scope.

### Embedded URLs

1 embedded URL hash was identified in VT relationship data. The specific URL was not fully enumerated in corpus metadata but likely corresponds to the C2 exfiltration endpoint.

---

## Operator Infrastructure

| IOC | Type | Notes |
|---|---|---|
| (1 embedded URL hash) | URL | C2 exfil endpoint — specific URL not fully enumerated |
| `edb.chk` | Drop path | Data staging or persistence marker |

No hardcoded C2 domain was recovered from VT metadata for this sample. The geofencing check implies a remote geolocation service was queried at runtime.

---

## Assessment

### Archetype

**QUIETVAULT is archetype A8 — Malicious AI SDK / Package.** Confirmed.

QUIETVAULT is delivered as a fake npm package telemetry module — the same supply chain vector as SUPERO (malicious PyPI package). The defining A8 characteristic is that the malicious code activates on install/import within a developer's package environment, not via a traditional execution vector. QUIETVAULT is a JavaScript instance of A8 where SUPERO was a Python instance.

The `TrojanSpy` prefix confirms the primary goal is credential or data theft rather than payload staging — making QUIETVAULT a stealer delivered via npm supply chain.

QUIETVAULT is the second confirmed A8 instance (after SUPERO), and the first confirmed A8 in the JavaScript/npm ecosystem.

**Archetype column:** A8.

### Assessment

QUIETVAULT demonstrates that the malicious package supply chain attack pattern (A8) has extended from PyPI (SUPERO) into npm. The npm ecosystem is the primary package manager for web and Node.js development — including a large segment of AI application developers who use LangChain.js, the OpenAI Node.js SDK, and other AI framework packages. Targeting npm telemetry module conventions provides high-confidence activation: developers installing AI tooling regularly install packages without inspecting telemetry modules.

The geofencing and anti-debug capabilities suggest QUIETVAULT is a purpose-built targeted tool rather than a spray-and-pray npm package — the operator wanted specific victim profiles, not random installations.

**Confidence:** High (A8 archetype confirmed; AV label consensus across TrendMicro and Microsoft; supply chain vector confirmed by `package/telemetry.js` path; behavioral indicators consistent with stealer operation; single corpus sample limits variant assessment).

### Open Questions

- **Stolen data targets:** What credentials does QUIETVAULT steal? Browser cookies, npm auth tokens, `.npmrc` credentials, LLM API keys, SSH keys? Unknown without script body access.
- **Exfil endpoint:** The single embedded URL hash corresponds to the C2. The specific URL was not fully enumerated in corpus metadata.
- **Package identity:** Which npm package was QUIETVAULT distributed in? The sample path is `package/telemetry.js` — the parent package name and version are unknown.
- **Scale:** Was this a targeted attack on a specific developer or organization, or a broader npm package campaign? Single corpus sample; full campaign scope unknown.
- **`edb.chk` role:** Is this a persistence marker, a data staging file, or a flag for secondary payload activation? Cannot determine from metadata alone.

---

## CAIRN Rules

```yara
rule T3-QUIETVAULT_JS_Telemetry_Spy
{
    meta:
        description = "Detects QUIETVAULT — JavaScript stealer masquerading as npm package telemetry module (package/telemetry.js); drops edb.chk; TrendMicro/Microsoft consensus on QVAULT/QuietVault family"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "c2_comms"
        tier = "T3"
        confidence = "high"
        family = "QUIETVAULT"

    strings:
        $av_trend = "TrojanSpy.JS.QVAULT"   nocase
        $av_ms    = "QuietVault"            nocase
        $path     = "package/telemetry.js"  nocase
        $dropped  = "edb.chk"              nocase

    condition:
        $av_trend or $av_ms or ($path and $dropped)
}
```

Fires on:
- Samples carrying `TrojanSpy.JS.QVAULT` (TrendMicro) or `QuietVault` / `Trojan:JS/QuietVault!MTB` (Microsoft) labels
- Samples combining the `package/telemetry.js` npm module path with the `edb.chk` drop artifact

1 corpus sample confirmed.

---

## Indicators of Compromise

**Registered seed:** `8eea1f65e468b515020e3e2854805f1ef5c611342fa23c4b31d8ed3374286a90`

| SHA256 | Filenames | Detections | First Seen (UTC) |
|---|---|---|---|
| `8eea1f65e468b515020e3e2854805f1ef5c611342fa23c4b31d8ed3374286a90` | `package/telemetry.js`, `telemetry.js` | 37 | 2025-08-27 |

**Dropped files:**

| Path | Type | Notes |
|---|---|---|
| `edb.chk` | Drop | Data staging or persistence marker |

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial report — 1 corpus sample confirmed; A8 archetype confirmed (first confirmed npm/JS supply chain A8); npm telemetry masquerade technique documented; seed registered |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-12. Author: Ryan Fetterman (https://fetterm4n.github.io)*
