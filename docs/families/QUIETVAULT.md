# QUIETVAULT — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `TrojanSpy.JS.QVAULT.THBBDBF` (TrendMicro) · `Trojan:JS/QuietVault!MTB` (Microsoft)
**First seen:** 2025-08-27
**Platform:** JavaScript / Node.js (6.6 KB)
**Archetype:** A8 — Malicious AI SDK / Package (with A6 credential-theft objective)
**TLP:** TLP:AMBER

---

## Summary

QUIETVAULT is a JavaScript credential stealer that ships inside an npm package disguised as a **telemetry module** (`package/telemetry.js`). It activates in the developer's own environment during dependency installation, steals credentials, drops a file named `edb.chk`, and gates execution behind geolocation and anti-debug checks.

The choice of disguise is the notable part. Telemetry modules are ubiquitous in legitimate npm packages, are expected to make outbound network requests, and are almost never read during code review. A malicious telemetry module is therefore *pre-justified*: the two behaviors that would otherwise draw attention — network egress and system enumeration — are exactly what the file's name says it does.

The victim profile follows from the delivery mechanism. npm is the primary package ecosystem for Node.js and web development, which now includes a large population of AI application developers using LangChain.js, the OpenAI Node SDK, and similar tooling. Those developers install dependencies rapidly and in volume, and their machines hold precisely the high-value secrets a stealer wants: inference API keys, npm publish tokens, cloud credentials, and SSH keys. A single compromised developer with publish rights also opens the path to further supply-chain propagation.

The presence of **geofencing and anti-debug logic** argues against an indiscriminate campaign. An operator who wanted maximum installations would not add code that suppresses execution for most of them. This is victim selection, which implies a specific intended target set.

---

## Delivery

| Step | Mechanism |
|---|---|
| 1 | Malicious package published to npm containing `package/telemetry.js` |
| 2 | Developer runs `npm install` / `npm ci` — directly or via a transitive dependency |
| 3 | Telemetry module executes in the developer's environment |
| 4 | Geolocation and anti-debug checks gate the payload |
| 5 | On a passing check: credential theft, `edb.chk` drop, exfiltration |

Step 2 is what makes this class of attack effective — a developer may never have chosen this package. Transitive dependencies are installed silently and reviewed by nobody.

---

## Samples

| SHA256 | Filenames | Size | Detections | First Seen (UTC) |
|---|---|---|---|---|
| `8eea1f65e468b515020e3e2854805f1ef5c611342fa23c4b31d8ed3374286a90` | `package/telemetry.js`, `telemetry.js` | 6,632 | 37 | 2025-08-27 |

---

## Script Details

| Field | Value |
|---|---|
| File type | JavaScript (Node.js) |
| Size | 6,632 bytes |
| Detections | 37 |
| Code signing | None |
| Crowdsourced YARA | `Windows_API_Function` |
| VT tags | `long-sleeps`, `javascript` |

At 6,632 bytes this is hand-written rather than bundled or minified — compact enough to read as a plausible telemetry helper, large enough to carry evasion logic and exfiltration.

### Behavior

| Behavior | Evidence |
|---|---|
| Credential / data theft | `TrojanSpy` classification across vendors |
| File drop | `edb.chk` written at runtime |
| Sandbox evasion | `long-sleeps` — delays intended to exceed sandbox analysis windows |
| Geofencing | Victim geolocation checked before activation |
| Anti-debug | Debugger and analysis-environment detection |
| Win32 API access | `Windows_API_Function` YARA match — native API reach from Node.js |

Two of these deserve emphasis:

**Win32 API access from a telemetry module** has no legitimate justification. Genuine telemetry collects application metrics through Node's own APIs; reaching into the Windows API indicates access to system resources far outside any telemetry scope.

**`edb.chk` as a filename** is deliberate camouflage. Real `edb.chk` files are Extensible Storage Engine checkpoint files associated with Windows database components — a name chosen to survive a casual look at a directory listing.

---

## Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `edb.chk` | Dropped file | Data staging or persistence marker |
| 1 embedded URL reference | URL | Exfiltration endpoint — not individually enumerated |

No hardcoded C2 domain was recovered. The geofencing behavior implies a geolocation service is queried at runtime, which may be a separate endpoint from the exfiltration target.

---

## Detection

### YARA

```yara
rule T3-QUIETVAULT_JS_Telemetry_Spy
{
    meta:
        description = "Detects QUIETVAULT — JavaScript stealer masquerading as npm package telemetry module (package/telemetry.js); drops edb.chk"
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

Note that `package/telemetry.js` is required to co-occur with `edb.chk` — the path alone appears in countless legitimate packages and is worthless as a standalone signal.

### Detection Guidance

Supply-chain attacks of this shape are best addressed before execution, since by the time the payload runs it is already inside a trusted developer environment.

| Control | Effect |
|---|---|
| `npm install --ignore-scripts` in CI, with an explicit allowlist | Blocks install-time execution, the primary activation path |
| Lockfile pinning + review of dependency *additions*, not just direct deps | Transitive dependencies are the realistic delivery route |
| Alert on `node.exe` performing Win32 API calls or writing outside the project tree | Catches the payload behavior regardless of the package name |
| Alert on creation of `edb.chk` outside legitimate ESE database directories | Family-specific and low-noise |
| Scope developer credentials: short-lived tokens, no long-lived cloud keys on workstations | Limits the yield when prevention fails |

The final row matters most. Every control above can be bypassed; reducing what a compromised developer machine can surrender is the durable mitigation.

---

## Open Questions

1. **Which npm package carried it?** The sample path is only `package/telemetry.js` — the parent package name and version are unidentified. Without them, downstream victim scope cannot be assessed and affected consumers cannot be notified. This is the most important open question.
2. **What credentials are targeted?** Browser cookies, `.npmrc` tokens, LLM API keys, SSH keys, cloud credentials — undetermined without full script analysis. It defines the actual impact.
3. **What is the exfiltration endpoint?** Present as a single embedded URL reference but not individually resolved.
4. **What is `edb.chk` for?** Persistence marker, staged data, or an activation flag for a second stage — unresolved.
5. **What does the geofence select for?** The geographic criterion would be direct evidence of intended targeting. Not recoverable from available metadata.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
