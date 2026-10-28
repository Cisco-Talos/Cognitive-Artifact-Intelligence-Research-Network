# PANDORA

**Author:** Ryan Fetterman
**Aliases:** HTML:Defacement-AH [PUP] (Avast/AVG — most specific label); PY/Agent.AM (ESET); Trojan.Script.Malgent (Bitdefender); Malicious score: 99 (Trellix)
**First seen:** 2025-07-08
**Last seen:** 2025-07-08 (three variants submitted within 27 minutes; campaign status unknown)
**Platform:** Windows/Linux; Python 3 script
**Archetype:** A7 — LLM-Augmented Offensive Tool
**TLP:** AMBER

---

## Summary

PANDORA is a Python web defacement and OSINT tool with integrated OpenAI API capability, authored by the actor operating under the handle **MrSanZz** (GitHub: `github.com/MrSanZz`, Telegram: `t.me/MrSanZzXe`). The tool combines web defacement (posting to `fuck.you/index.php`), victim OSINT scraping via ThatsThem with social media enumeration across 9gag, LinkedIn, and WhatsApp, multimedia payload delivery from an actor-controlled CDN (`kosred.com`), and LLM queries through both the legacy GPT-3.5 completions endpoint and the current `chat/completions` API.

The LLM component serves as an automated content generation engine — producing defacement content or processing OSINT results — integrated alongside conventional attack tooling. The simultaneous submission of three near-identical variants within 27 minutes indicates the actor was iterating and testing live. PANDORA is classified as a script kiddie-tier offensive toolkit with AI augmentation; the `InsomniaGPT` WormGPT-style jailbreak reference embedded in the script confirms awareness of bypass techniques.

A persistent typo in the OSINT scraping variable — `{victm_mails}` (missing the 'i') — is present across all three variants and serves as a reliable cross-variant fingerprint.

---

## pandora.py — Defacement and OSINT Tool

### Characteristics

| Field | Value |
|---|---|
| File type | Python script, UTF-8, ~5,304 lines |
| Actor handle | MrSanZz; JogjaXploit (associated group) — Indonesian origin |
| AI integration | OpenAI GPT-3.5 (legacy) + `chat/completions`; `InsomniaGPT` jailbreak reference |
| API key cracker | Brute-force `sk-` key tester embedded in the tool |
| CDN | `kosred.com` — actor-controlled multimedia payload delivery (audio, video, images) |
| Typo fingerprint | `{victm_mails}` — present in all 3 variants |

### Capabilities

| Capability | Implementation |
|---|---|
| Web defacement | Posts to `fuck.you/index.php?id=` |
| OSINT — email | `thatsthem.com/email/{victm_mails}` (typo fingerprint) |
| OSINT — name | `thatsthem.com/name/` |
| Social media enumeration | 9gag, LinkedIn, WhatsApp |
| Multimedia lures | `kosred.com` CDN (MP3, JPEG, MP4 assets) |
| OpenAI LLM | `api.openai.com/v1/engines/gpt-3.5-turbo/completions` (legacy) + `api.openai.com/v1/chat/completions` |
| API key brute-force | In-tool `sk-` key tester |

### Sandbox Behavior

- v1 (`8f90ed03`): Zenbox `harmless` 99% — tool requires interactive operator input to activate offensive functions; sandbox stalls at interactive menu.
- v2 (`5e47efec`): `detect-debug-environment` tag — script checks for analysis environments.
- v3 (`6cdc576a`): `idle` in sandbox — same interactive-menu stall pattern.

---

## Samples

| SHA256 | Det | First Seen (UTC) | Notes |
|---|---|---|---|
| `5e47efecba759c032b55a91fac744a3e64b56e43bf46ccc488ef308a04bceb22` | 7 | 2025-07-08 09:46 | v2; `detect-debug-environment`; submission path `pandora 2/pandora.py` |
| `8f90ed037479cb110e0a57063f93f1d172a62dc0bdf2392aa0cb0ba7b8305e24` | 8 | 2025-07-08 09:48 | v1; seed; ESET `PY/Agent.AM` |
| `6cdc576a4146000310380bdc1549a5da569cd2053800191c932d842f92b0183d` | 7 | 2025-07-08 10:13 | v3; 27 min after v1 |

All three variants share identical embedded URL sets.

---

## Infrastructure

**Actor identity:**
- `github.com/MrSanZz` — actor GitHub
- `t.me/MrSanZzXe` — actor Telegram

**Actor CDN (`kosred.com`):**
- `https://kosred.com/a/gavwen.mp3`, `/a/wudeyr.jpeg`, `/a/oanknh.mp4` — multimedia lures/payloads
- (9 total assets hosted at this domain)

**Defacement endpoint:**
- `https://fuck.you/index.php?id=`

**OSINT targets:**
- `https://thatsthem.com/email/{victm_mails}` — email-to-identity lookup
- `https://9gag.com/u/`, `https://www.linkedin.com/in/`, `https://api.whatsapp.com/send?phone=`

**LLM endpoints:**
- `https://api.openai.com/v1/engines/gpt-3.5-turbo/completions` (legacy)
- `https://api.openai.com/v1/chat/completions`

---

## Detection

### YARA

```yara
rule PANDORA_Defacement_OpenAI_Tool
{
    meta:
        description = "Detects PANDORA web defacement and OSINT tool with OpenAI integration — actor MrSanZz; kosred.com multimedia CDN; thatsthem.com OSINT scraping with typo variable {victm_mails}; both GPT-3.5 legacy and chat/completions endpoints"
        author = "CAIRN"
        tier = "T3"
        confidence = "high"

    strings:
        $cdn         = "kosred.com"           nocase
        $typo_var    = "{victm_mails}"
        $actor_gh    = "github.com/MrSanZz"   nocase
        $actor_tg    = "t.me/MrSanZzXe"       nocase
        $defacement  = "fuck.you/index.php"   nocase
        $av_label    = "Defacement-AH"        nocase

    condition:
        $cdn or $typo_var or $actor_gh or $actor_tg or $defacement or $av_label
}
```

### Detection Guidance

- **Network:** outbound requests to `kosred.com` (multimedia CDN) combined with `thatsthem.com` queries
- **File:** Python script with `{victm_mails}` variable name (typo fingerprint present in all variants)
- **Attribution:** actor handle strings `MrSanZz` or `MrSanZzXe` in script content

---

## Open Questions

- Whether `kosred.com` CDN assets remain live
- True deployment scope — three variants submitted within 27 minutes suggests active development rather than a mature campaign
- Full extent of the `InsomniaGPT` jailbreak integration in the LLM call path

---

*Last updated 2026-09-30.*
