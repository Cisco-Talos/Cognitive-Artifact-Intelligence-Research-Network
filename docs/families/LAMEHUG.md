# LAMEHUG — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `Python:LAMEHUG-A [Pws]` (Avast/AVG) · `Trojan.Python.LAMEHUBLOADER` (TrendMicro) · `Win32:LAMEHUG-A [Pws]` (Avast/AVG, packed variant) · `Python/TrojanDownloader.Agent.ARS` (ESET, packed variant)
**First seen:** 2025-07-10
**Platform:** Python script (bare form); Windows x86-64 PE (PyInstaller-packed form, 10.4 MB)
**Archetype:** A6/A7 — see *Archetype Divergence* below
**LLM provider:** Hyperbolic, reached via the HuggingFace inference router
**TLP:** TLP:AMBER

---

## Summary

LAMEHUG is a Python infostealer that runs its reconnaissance on **stolen inference credentials**. The script embeds a pool of **400+ compromised HuggingFace API tokens** (`hf_` prefix) and rotates through them to query `router.huggingface.co/hyperbolic/v1/chat/completions`, using the Hyperbolic model to generate Windows reconnaissance commands. Results are exfiltrated over SSH to a VPS and mirrored to a `webhook.site` collection URL.

The economics are the point. The operator pays nothing for inference — the cost lands on the victims whose HuggingFace accounts were compromised earlier — and needs no infrastructure of their own for collection. There is no registered domain, no TLS certificate, and no dedicated C2 server: a free webhook aggregator handles collection, and the LLM traffic terminates at `router.huggingface.co`, a legitimate high-reputation endpoint that blends cleanly into normal AI-developer activity.

The family exists in two forms. The **bare script** (LAMEHUG proper) is a 19,827-byte Python file with the token pool embedded as source. The **packed variant** (internally called PROMPTSTEAL) wraps the same payload in a 10.4 MB PyInstaller PE, adds a Ukrainian-language homoglyph lure, a BIOS/VM environment check, and a document-harvesting stage that collects victim files to `C:\ProgramData\info\`. The packed variant is the operationally deployed form; the script is likely a development or test artifact.

A second, non-essential code path in the bare script generates NSFW images through a HuggingFace image provider. This appears to be either operational cover or a side revenue channel; it is unrelated to the reconnaissance function.

---

## Archetype Divergence

The two variants of this family sit in **different archetypes**, and the reason is worth stating because it is easy to get backwards.

Both run the same LLM-directed recon workflow, and both carry the same pool of pre-stolen HuggingFace tokens. Neither of those facts makes a family an AI credential harvester: a pre-stolen pool that ships *with* the malware is an operating cost the attacker has already paid elsewhere. The victim is not the source. On that basis the bare script — which only ever spends its token pool — is classified **A7 (LLM-Augmented Offensive Tool)**.

The packed variant adds the thing that changes the answer: **collection from the victim host**, staged to `C:\ProgramData\info\`. That makes the victim a credential source, which is what **A6 (AI Credential Harvester)** describes.

> **Caveat.** That the `C:\ProgramData\info\` staging directory receives *AI credentials specifically*, rather than only documents and browser data, is inferred from the harvest path string and the accompanying WMI/BIOS reconnaissance behavior — it has not been confirmed by decompiling the PyInstaller bundle. If the directory turns out to hold only generic stolen data, the packed variant is an ordinary stealer with an LLM recon stage and the A6 label does not hold. Treat A6 as well-supported but not settled; A7 is confirmed.

---

## Architecture

| Phase | Mechanism | Notes |
|---|---|---|
| 1 — Credential rotation | Iterate the embedded `hf_` token pool against the HF router | Fails open with `No valid authorization tokens found` on exhaustion |
| 2 — LLM-directed recon | `LLM_QUERY_EX` prompts Hyperbolic for Windows recon commands | The model supplies the tradecraft, not the operator |
| 3 — Document harvest | Write files to `C:\ProgramData\info\info.txt` | **Packed variant only.** ProgramData survives reboots and is excluded from many user-profile monitors |
| 4 — Exfiltration | `ssh_send` to operator VPS + POST to `webhook.site` | Dual-path: synchronous and asynchronous |
| 5 — Cover / side channel | NSFW image generation via HF image provider | **Bare script only.** Non-essential; images named `image_generated_at_<timestamp>` |

Phase 2 is the defining behavior — a conventional infostealer workflow with one LLM call bolted into its recon stage. Phase 1 is a **credential burn pattern**: a pool of 400+ tokens rotated until depletion, treating tokens as consumables the operator expects to lose to revocation.

The exhaustion sentinel (`No valid authorization tokens found`) is a useful artifact: it confirms the operator anticipated running the pool dry and handled it explicitly, which in turn confirms the tokens are stolen rather than purchased-and-owned.

---

## Samples

| SHA256 | Filename | Form | Size | Detections | First Seen (UTC) |
|---|---|---|---|---|---|
| `384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715` | `image.py`, `81cd20319c8f0b2ce499f9253ce0a6a8.bin` | Bare Python script | 19,827 B | 36 | 2025-07-10 |
| `766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777` | `Додаток.pif` | PyInstaller PE (packed) | ~10,430 KB | 46 | 2025-07-11 |

---

## Script Details (bare form)

| Field | Value |
|---|---|
| File type | Python script (`.py` / `.bin`) |
| Size | 19,827 bytes |
| Code signing | None |
| Direct provider calls | HuggingFace router only — no direct OpenAI or Anthropic endpoints |

### Key Strings

| String | Significance |
|---|---|
| `router.huggingface.co/hyperbolic/v1/chat/completions` | Primary inference target — Hyperbolic via HF routing |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | Operator collection endpoint |
| `LLM_QUERY_EX` | Recon query function |
| `ssh_send` | SSH exfiltration function |
| `No valid authorization tokens found` | Token-pool exhaustion sentinel |
| `image_generated_at_` | Image-generation cover path |

---

## Binary Details (packed form — `Додаток.pif`)

| Field | Value |
|---|---|
| File type | PE32+ executable (console), x86-64 — PyInstaller bundle |
| Size | ~10.4 MB (Python runtime + dependencies in overlay) |
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

### Harvest Staging

Collected data is written to **`C:\ProgramData\info\info.txt`**. The choice of `ProgramData` over a temp path is deliberate: the directory is world-writable, survives reboots, and is excluded from many user-profile-focused monitoring configurations. Data accumulates there pending exfiltration.

---

## Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `router.huggingface.co` | Domain | Legitimate HuggingFace inference router — abused, not operator-controlled |
| `router.huggingface.co/hyperbolic/v1/chat/completions` | URL | Hyperbolic provider through the HF routing layer |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | URL | Operator webhook C2 — free service, ephemeral |
| `144.126.202.227` | IPv4 | SSH exfiltration VPS |
| `C:\ProgramData\info\info.txt` | File path | Credential and document harvest staging (packed variant) |

The infrastructure profile is deliberately minimal. Blocking `router.huggingface.co` outright is impractical in most developer environments, and `webhook.site` is trivially replaced. The SSH VPS (`144.126.202.227`) is the only durable operator-controlled asset and the only sound blocking target.

---

## Detection

### YARA

```yara
rule T3-LAMEHUG_Python_HuggingFace_Abuser
{
    meta:
        description = "Detects LAMEHUG Python infostealer — abuses pool of stolen hf_ tokens to query HuggingFace router for Windows recon command generation; exfiltrates via SSH and webhook.site"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "api_key_pattern"
        tier = "T3"
        confidence = "high"
        family = "LAMEHUG"

    strings:
        $av_label    = "Python:LAMEHUG-A"                              nocase
        $av_label2   = "Trojan.Python.LAMEHUBLOADER"                   nocase
        $fn_llm      = "LLM_QUERY_EX"                                  nocase
        $fn_ssh      = "ssh_send"                                      nocase
        $hf_route    = "router.huggingface.co/hyperbolic/v1"           nocase
        $no_tokens   = "No valid authorization tokens found"           nocase
        $img_name    = "image_generated_at_"                           nocase
        $webhook_c2  = "webhook.site/b3e30c61-c8a3-4a8f-9489"

    condition:
        $av_label or $av_label2 or
        ($fn_llm and $fn_ssh) or
        ($hf_route and $no_tokens) or
        ($img_name and $webhook_c2)
}

rule T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer
{
    meta:
        description = "Detects LAMEHUG packed variant (PROMPTSTEAL) — PyInstaller Python stealer targeting LLM API credentials and documents; harvests to C:\\ProgramData\\info\\; router.huggingface.co is NOT a standalone condition (legitimate AI tools embed it as provider config)"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "api_key_pattern"
        tier = "T3"
        confidence = "high"
        family = "LAMEHUG"

    strings:
        $hf_dns   = "router.huggingface.co"              nocase
        $info_dir = "Programdata\\info\\info.txt"        nocase
        $av_eset  = "Python/TrojanDownloader.Agent.ARS"  nocase

    condition:
        $info_dir or $av_eset or ($hf_dns and $info_dir)
}
```

**Important:** `router.huggingface.co` is deliberately **not** a standalone condition in either rule. Legitimate AI tooling embeds that domain as provider configuration, and matching on it alone produces false positives against benign software.

### Detection Guidance

| Signal | Where it fires | Variant |
|---|---|---|
| A single host presenting **many distinct** `hf_` bearer tokens in sequence | Proxy logs — the rotation pattern is highly distinctive | Both |
| Outbound `hf_`-authenticated requests from a host with no HuggingFace-using software | Network / proxy logs | Both |
| `webhook.site` traffic from a server or workstation | Network — near-zero legitimate enterprise use | Bare script |
| Outbound SSH to an unrecognized VPS following inference-API activity | Network flow correlation | Bare script |
| Any file creation under `C:\ProgramData\info\` | Endpoint — family-specific and highly reliable | Packed variant |
| Executable extensions (`.pif`, `.scr`, `.com`) carrying non-ASCII filenames | Endpoint / email gateway | Packed variant |
| `wmic.exe` invoked by an unsigned single-file executable | Endpoint | Packed variant |

The token-rotation pattern is the strongest available detection across both forms. Legitimate clients use one credential; presenting dozens or hundreds of distinct bearer tokens from one source in one session has no benign explanation.

### For AI Platform Operators

This family monetizes credential theft through inference abuse. Rate-limiting or anomaly detection keyed on *token diversity per source IP* — rather than per-token volume — directly counters the rotation pattern, since each individual token stays under its own quota while the aggregate does not.

---

## Open Questions

1. **Where did the 400+ tokens come from?** A prior harvesting campaign, a marketplace purchase, or scraped from public repositories. The answer determines whether LAMEHUG is one link in a larger operation or an opportunistic consumer of someone else's theft.
2. **What are the recon prompts?** `LLM_QUERY_EX` requests Windows reconnaissance commands, but the exact prompt chain is not recoverable without full script access. This reveals how much of the operator's tradecraft is delegated to the model.
3. **What documents does the packed variant collect?** The file types written to `C:\ProgramData\info\` are unconfirmed. The answer defines the actual victim impact and settles the A6 classification question.
4. **Exfiltration endpoint (packed variant).** Present among the 20 embedded URL references but not individually identified. This is the highest-value outstanding IOC.
5. **Does the packed variant carry the same token pool?** Whether the 400+ stolen `hf_` tokens are embedded in the PE or fetched at runtime is unresolved. A dynamic pool would imply supporting operator infrastructure not otherwise observed.
6. **Campaign scale.** One bare-script sample plus one packed variant. Whether these represent a single operator or a shared kit in wider circulation is unknown.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-07.*
