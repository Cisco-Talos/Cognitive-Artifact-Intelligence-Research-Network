# LAMEHUG — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `Python:LAMEHUG-A [Pws]` (Avast/AVG) · `Trojan.Python.LAMEHUBLOADER` (TrendMicro)
**First seen:** 2025-07-10
**Platform:** Python script (bare); see [PROMPTSTEAL](PROMPTSTEAL.md) for the PyInstaller-packed variant
**Archetype:** A6 — AI Credential Harvester
**LLM provider:** Hyperbolic, reached via the HuggingFace inference router
**TLP:** TLP:AMBER

---

## Summary

LAMEHUG is a Python infostealer that runs its reconnaissance on **stolen inference credentials**. The script embeds a pool of **400+ compromised HuggingFace API tokens** (`hf_` prefix) and rotates through them to query `router.huggingface.co/hyperbolic/v1/chat/completions`, using the Hyperbolic model to generate Windows reconnaissance commands. Results are exfiltrated over SSH to a VPS and mirrored to a `webhook.site` collection URL.

The economics are the point. The operator pays nothing for inference — the cost lands on the victims whose HuggingFace accounts were compromised earlier — and needs no infrastructure of their own for collection. There is no registered domain, no TLS certificate, and no dedicated C2 server: a free webhook aggregator handles collection, and the LLM traffic terminates at `router.huggingface.co`, a legitimate high-reputation endpoint that blends cleanly into normal AI-developer activity.

A second, non-essential code path generates NSFW images through a HuggingFace image provider. This appears to be either operational cover or a side revenue channel; it is unrelated to the reconnaissance function.

At 19,827 bytes for a script of this modest functionality, the file is dominated by the embedded token list — the stolen credentials are physically most of the malware.

---

## Architecture

| Phase | Mechanism | Notes |
|---|---|---|
| 1 — Credential rotation | Iterate the embedded `hf_` token pool against the HF router | Fails open with `No valid authorization tokens found` on exhaustion |
| 2 — LLM-directed recon | `LLM_QUERY_EX` prompts Hyperbolic for Windows recon commands | The model supplies the tradecraft, not the operator |
| 3 — Exfiltration | `ssh_send` to operator VPS + POST to `webhook.site` | Dual-path: synchronous and asynchronous |
| 4 — Cover / side channel | NSFW image generation via HF image provider | Non-essential; images named `image_generated_at_<timestamp>` |

Phase 1 is the defining behavior. A pool of 400+ tokens rotated until depletion is a **credential burn pattern**: the tokens are consumables, not assets, and the operator expects to lose them to revocation.

---

## Samples

| SHA256 | Filenames | Size | Detections | First Seen (UTC) |
|---|---|---|---|---|
| `384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715` | `image.py`, `81cd20319c8f0b2ce499f9253ce0a6a8.bin` | 19,827 | 36 | 2025-07-10 |

A PyInstaller-packed variant of the same family, carrying a Ukrainian-language lure and an added document-harvest stage, is documented separately as **[PROMPTSTEAL](PROMPTSTEAL.md)**.

---

## Script Details

| Field | Value |
|---|---|
| File type | Python script (`.py` / `.bin`) |
| Size | 19,827 bytes |
| Detections | 36 |
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

The exhaustion sentinel is a useful artifact: it confirms the operator anticipated running the pool dry and handled it explicitly, which in turn confirms the tokens are stolen rather than purchased-and-owned.

---

## Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `router.huggingface.co` | Domain | Legitimate HuggingFace inference router — abused, not operator-controlled |
| `router.huggingface.co/hyperbolic/v1/chat/completions` | URL | Hyperbolic provider through the HF routing layer |
| `webhook.site/b3e30c61-c8a3-4a8f-9489-5b862585a9a7` | URL | Operator webhook C2 — free service, ephemeral |
| `144.126.202.227` | IPv4 | SSH exfiltration VPS |

The infrastructure profile is deliberately minimal. Blocking `router.huggingface.co` outright is impractical in most developer environments, and `webhook.site` is trivially replaced. The SSH VPS is the only durable operator-controlled asset and the only sound blocking target.

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
```

**Important:** `router.huggingface.co` is deliberately **not** a standalone condition. Legitimate AI tooling embeds that domain as provider configuration, and matching on it alone produces false positives against benign software. Every arm above requires a second, family-specific signal.

### Detection Guidance

| Signal | Where it fires |
|---|---|
| Outbound `hf_`-authenticated requests from a host with no HuggingFace-using software | Network / proxy logs |
| A single host presenting **many distinct** `hf_` bearer tokens in sequence | Proxy logs — the rotation pattern is highly distinctive |
| `webhook.site` traffic from a server or workstation | Network — near-zero legitimate enterprise use |
| Outbound SSH to an unrecognized VPS following inference-API activity | Network flow correlation |

The token-rotation pattern is the strongest available detection. Legitimate clients use one credential; presenting dozens or hundreds of distinct bearer tokens from one source in one session has no benign explanation.

### For AI Platform Operators

This family monetizes credential theft through inference abuse. Rate-limiting or anomaly detection keyed on *token diversity per source IP* — rather than per-token volume — directly counters the rotation pattern, since each individual token stays under its own quota while the aggregate does not.

---

## Open Questions

1. **Where did the 400+ tokens come from?** A prior harvesting campaign, a marketplace purchase, or scraped from public code repositories. The answer determines whether LAMEHUG is one link in a larger operation or an opportunistic consumer of someone else's theft.
2. **What are the recon prompts?** `LLM_QUERY_EX` requests Windows reconnaissance commands, but the prompt chain and expected output structure are not recoverable without full script access. This matters because it reveals how much of the operator's tradecraft is delegated to the model.
3. **Is the image generation monetized?** Cover, revenue stream, or personal use — undetermined from available evidence.
4. **Campaign scale.** One bare-script sample plus one packed variant. Whether these represent a single operator or a shared kit in wider circulation is unknown.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
