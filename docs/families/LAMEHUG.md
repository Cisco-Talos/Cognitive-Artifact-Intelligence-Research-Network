# LAMEHUG — Research Report

**Family designation:** LAMEHUG (Avast/AVG `Python:LAMEHUG-A [Pws]`; TrendMicro `Trojan.Python.LAMEHUBLOADER`)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-07-10 (earliest VT submission in corpus)
**Last seen:** 2025-07-11 (PROMPTSTEAL variant)
**Variants:** 2 confirmed (bare Python script + PyInstaller-packed loader)
**Platform:** Python script; Windows PE32+ (PyInstaller-packed variant)
**CAIRN rules:** `T3-LAMEHUG_Python_HuggingFace_Abuser`, `T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer`
**Related report:** `PROMPTSTEAL.md` (PyInstaller-packed variant of this family)

---

## Summary

LAMEHUG is a Python infostealer that abuses a large pool of stolen HuggingFace API tokens (`hf_` credentials) to query the HuggingFace router inference endpoint at `router.huggingface.co/hyperbolic/v1/chat/completions`. The script rotates through 400+ hardcoded tokens, generating Windows reconnaissance commands via the Hyperbolic LLM provider, and exfiltrates results via SSH to a VPS and via `webhook.site` for asynchronous collection. As cover, it also generates NSFW images using a secondary HuggingFace image provider.

LAMEHUG is an A6 (AI Credential Harvester) family — it steals and operationally burns HuggingFace API credentials. A PyInstaller-packed variant (tracked separately as PROMPTSTEAL) adds a document harvesting stage and uses a Ukrainian lure filename.

---

## Discovery

LAMEHUG was discovered in the CAIRN corpus via the `python-ai-scripts` filter, entering via the `router.huggingface.co` embedded URL relationship. The T3 rule fires on the combination of the Avast/AVG family label, the HuggingFace router path with the hyperbolic provider, and the operational function names (`LLM_QUERY_EX`, `ssh_send`). The webhook.site C2 URL is a high-confidence indicator when present.

---

## image.py — Python HuggingFace Token Abuser

### Binary Characteristics

| Field | Value |
|---|---|
| File type | Python script (`.py` / `.bin`) |
| Filenames | `81cd20319c8f0b2ce499f9253ce0a6a8.bin`, `image.py` |
| Size | 19,827 bytes |
| First seen | 2025-07-10 |
| Detections | 36 |
| Provider references | `HuggingFace` (via embedded URL); no direct OpenAI calls confirmed |
| Code-signing | None |

The bare Python script is 19,827 bytes. At this size the script body almost certainly contains the full token pool — 400+ `hf_` tokens embedded as Python list literals occupy the majority of the file size.

### Operational Flow

LAMEHUG implements a three-phase operation:

1. **Token rotation.** The script maintains a large pool of hardcoded `hf_` tokens. It iterates through them attempting authenticated API calls to `router.huggingface.co/hyperbolic/v1/chat/completions`. On exhaustion it reports "No valid authorization tokens found" and exits. This is a credential burn pattern — the operator pre-loaded stolen HuggingFace tokens and uses them until they expire or are revoked.

2. **LLM-directed recon.** The core function `LLM_QUERY_EX` sends prompts to the Hyperbolic inference provider via the HuggingFace router. Responses are expected to be Windows reconnaissance commands or output. The script includes `ssh_send` for exfiltration, confirming that LLM-generated output is forwarded to the operator's VPS.

3. **NSFW image generation cover.** A secondary code path generates NSFW images via a HuggingFace image provider as operational cover or side income. Images are named `image_generated_at_<timestamp>`. This component is non-essential to the recon functionality and may be a revenue side-channel.

4. **Webhook C2.** Results are also sent to `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` — a free webhook aggregation service used for asynchronous operator collection. This C2 pattern requires no dedicated infrastructure.

### Key Strings

| String | Location | Significance |
|---|---|---|
| `router.huggingface.co/hyperbolic/v1/chat/completions` | Embedded URL (memory_pattern_domains) | Primary API target — Hyperbolic LLM via HF router |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | Embedded URL | Operator C2 collection endpoint |
| `LLM_QUERY_EX` | Script function name | Primary recon query function |
| `ssh_send` | Script function name | SSH exfiltration function |
| `No valid authorization tokens found` | Script error string | Token exhaustion sentinel |
| `image_generated_at_` | Image naming prefix | NSFW image generation cover |

---

## Operator Infrastructure

| IOC | Type | Notes |
|---|---|---|
| `router.huggingface.co` | Domain | HuggingFace inference router — legitimate service abused |
| `router.huggingface.co/hyperbolic/v1/chat/completions` | URL | Hyperbolic LLM provider via HF routing layer |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | URL | Operator webhook C2 — free service, ephemeral |
| `144.126.202.227` | IPv4 | SSH exfiltration target VPS (from reference metadata) |

The use of `webhook.site` as C2 is consistent with a low-infrastructure operator: no domain registration, no dedicated server, no SSL cert required. The HuggingFace router adds a further layer of indirection — traffic to `router.huggingface.co` blends with legitimate AI developer activity.

---

## Assessment

### Archetype

**LAMEHUG is archetype A6 — AI Credential Harvester.** Confirmed.

LAMEHUG steals and burns HuggingFace `hf_` tokens — tokens stolen from legitimate users — to fund its own LLM inference without paying. The pool rotation pattern (400+ tokens, fail-open with a sentinel message) is the defining behavioral characteristic. The LLM is used operationally for recon command generation, but the primary criminal value is the credential theft and abuse: the operator offloads API costs onto victims whose credentials were previously compromised.

This is distinct from A4 (LLM-tasked C2 where the operator authors prompts interactively) and from A2 (routing victim traffic). The defining property of A6 as instantiated by LAMEHUG is pre-loaded credential pools consumed operationally.

**Archetype column:** A6.

### Assessment

LAMEHUG demonstrates that stolen HuggingFace tokens have operational value beyond resale — they can fund an active recon loop. The 400+ token pool implies either a prior credential harvesting campaign or purchase from a marketplace. The webhook.site C2 and absence of dedicated infrastructure point to a low-sophistication operator comfortable with service abuse.

The PyInstaller-packed variant (PROMPTSTEAL) adds a document harvesting stage, suggesting LAMEHUG is a modular kit with delivery options.

**Confidence:** High (A6 archetype confirmed; AV label consensus across Avast/AVG and TrendMicro; HuggingFace router URL and webhook C2 recovered from embedded URL metadata; function names consistent with described operation; PyInstaller-packed variant independently confirmed).

### Open Questions

- **Token source:** Where were the 400+ HuggingFace tokens stolen from? Prior credential harvesting campaign, marketplace purchase, or a combination? Unknown.
- **LLM recon prompts:** What specific prompts does `LLM_QUERY_EX` send? Windows recon command generation, but the exact prompt chain and output structure are unknown without script body access.
- **NSFW image revenue:** Is the image generation component monetized (selling generated images) or purely a cover? Unknown from metadata alone.
- **Campaign scale:** One corpus sample. Whether this represents a single deployment or a wider campaign with multiple operators using the same script is unknown.

---

## CAIRN Rules

```yara
rule T3-LAMEHUG_Python_HuggingFace_Abuser
{
    meta:
        description = "Detects LAMEHUG Python infostealer — abuses pool of stolen hf_ tokens to query HuggingFace router for Windows recon command generation; exfiltrates via SSH and webhook.site; generates NSFW images as cover"
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
```

Fires on:
- Samples carrying `Python:LAMEHUG-A` (Avast/AVG) or `Trojan.Python.LAMEHUBLOADER` (TrendMicro) labels
- Samples combining the `LLM_QUERY_EX` recon function with SSH exfiltration (`ssh_send`)
- Samples combining the HuggingFace/Hyperbolic router path with the token exhaustion sentinel
- Samples combining the image naming prefix with the operator's webhook.site C2

See also `T3-PROMPTSTEAL_PyInstaller_AI_Credential_Stealer` for the PyInstaller-packed variant.

---

## Indicators of Compromise

**Registered seed:** `384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715`

| SHA256 | Filenames | Detections | First Seen (UTC) |
|---|---|---|---|
| `384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715` | `81cd20319c8f0b2ce499f9253ce0a6a8.bin`, `image.py` | 36 | 2025-07-10 |

**Infrastructure:**

| IOC | Type |
|---|---|
| `router.huggingface.co/hyperbolic/v1/chat/completions` | LLM API target |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | C2 webhook |
| `144.126.202.227` | SSH exfil VPS |

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial report — 1 corpus sample confirmed; A6 archetype confirmed; token rotation and webhook C2 pattern documented; PyInstaller variant cross-referenced to PROMPTSTEAL |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-12. Author: Ryan Fetterman (https://fetterm4n.github.io)*
