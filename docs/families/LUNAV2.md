# LUNAV2

**Author:** Ryan Fetterman
**Aliases:** trojan.msil/cassiopeia (multiple engines — dropper); various Go RAT labels; Trojan.MSIL (generic)
**First seen:** 2025-08-06 (dropper); 2025-06-24 (Go RAT payload, predates dropper by 43 days)
**Last seen:** 2026-07-26 (dropper last submission)
**Platform:** Windows; VB.NET (dropper), Go 1.22.7 x86-64 (RAT), .NET x86 (second stage)
**Archetype:** A0 — No AI Content
**TLP:** AMBER

---

## Summary

LUNAV2 is a three-component Windows malware family. A 20.7 MB VB.NET dropper (`LunaV2.exe`) carries two GZip-compressed payloads in a single .NET managed resource: a 45 MB Go/garble Telegram-C2 RAT (also named `LunaV2.exe`) and a 328 KB control-flow-flattened .NET second stage (`svchost.exe`). The dropper writes both to `%Temp%`, registers a Windows Defender path exclusion via hidden PowerShell, sets an `HKCU\...\Run` persistence value, and executes both payloads.

**The AI integration is inactive, not absent.** The Go RAT statically links EinStack Glide v1.0.0 — a legitimate open-source LLM gateway with seven provider clients (OpenAI, Anthropic, Cohere, Bedrock, AzureOpenAI, OctoML, Ollama). All seven provider base URLs, Glide's default system prompt, its config struct tags, and its embedded Swagger spec are compiled into the binary. None of this code is reachable. The Go module metadata reveals why: the main module path is `myproject (devel)` with a `replace => ../glide-develop` directive — the operator built the RAT inside a local checkout of the Glide repository and imported the package without using it. Glide and its 100 transitive dependencies inflate a ~50 KB RAT into a 45 MB binary.

The archetype is **A0** — no LLM call site is reachable in this build, and the Telegram C2, Defender exclusion, and persistence mechanisms are entirely independent of Glide. A0 records that the AI axis was examined and came back empty at runtime; it does not soften the malicious verdict, and it does not imply the family will remain A0 indefinitely: an operator who adds `--config glide.yaml` and ships a routing config has a working multi-provider LLM gateway with no code change.

The dropper is a packaging vehicle for a widely-circulated payload. The Go RAT has **510 unique sources and 598 submissions**, predating the dropper's first VT appearance by 43 days. Delivery is via fake game cheats — a Russian-language masquerade: `ВИРУС НЕ ОТКРЫВАТЬ` ("VIRUS DO NOT OPEN").

---

## Components

### `LunaV2.exe` (dropper) — VB.NET Dropper

| Field | Value |
|---|---|
| SHA256 | `6302d6b848024752eff5baa7f249d0e257d71ef9109ee55c8abfc9e7999f4d85` |
| Compiler | VB.NET (Microsoft.VisualBasic) |
| Size | 20,743,680 bytes |
| Detections | 43/77 |
| Threat label | `trojan.msil/cassiopeia` |
| PE timestamp | 2025-07-19 08:25:57 UTC |
| Mutex | `Pj5r8hhohV62XVYnE` |

**Dropper logic:** acquires mutex, iterates a pipe-delimited config list, decompresses each GZip payload, writes to `%Temp%`, optionally applies `Hidden` attribute and Defender exclusion, sets `HKCU\Run` persistence for `svchost.exe`, then executes both payloads. The Defender exclusion is applied silently: `powershell.exe -ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '<path>'` with `WindowStyle = Hidden`.

### `LunaV2.exe` (dropped) — Go Telegram-C2 RAT

| Field | Value |
|---|---|
| SHA256 | `28d47ea07a0db73948d8dca67e2911654b16e37411c960e060852e51a76f392e` |
| Go version | 1.22.7; garble obfuscation |
| Main module | `myproject (devel)` with `replace => ../glide-develop` |
| Size | 44,996,608 bytes (inflated by Glide + 100 transitive dependencies) |
| Unique sources | 510; 598 submissions |
| C2 | `api.telegram.org/bot%s/getUpdates` / `sendMessage` |

The RAT communicates via Telegram. Glide is a dead import — `main.main` calls `glide.Run`, which dead-ends in a `cobra` usage message because Glide's `--config` flag is required and no `--config` argument is provided anywhere in the binary.

### `svchost.exe` (dropped) — .NET Second Stage

| Field | Value |
|---|---|
| SHA256 | `b5675f9f85b8d79857f841e3725698d9618b009e03bc67525dd26c2819f78db1` |
| Type | .NET x86, control-flow-flattened |
| Size | 328,704 bytes |

---

## Glide Activation Canary

The following strings are **byte-absent from every build seen to date**. A detection hit on any of these combined with Glide-linked fingerprints means the gateway may no longer be dormant:

- `glide.yaml` — Glide config file path
- `routers:` — Glide routing config key
- `weighted-round-robin` — Glide load-balancing strategy

---

## Samples

| SHA256 | Component | Det | First Seen | Notes |
|---|---|---|---|---|
| `6302d6b848024752eff5baa7f249d0e257d71ef9109ee55c8abfc9e7999f4d85` | Dropper (VB.NET) | 43 | 2025-08-06 | `LunaV2.exe`; 3 unique sources; `Pj5r8hhohV62XVYnE` mutex |
| `28d47ea07a0db73948d8dca67e2911654b16e37411c960e060852e51a76f392e` | Go RAT | — | 2025-06-24 | `LunaV2.exe` (dropped); 510 unique sources; Telegram C2 + Glide (inactive) |
| `b5675f9f85b8d79857f841e3725698d9618b009e03bc67525dd26c2819f78db1` | .NET second stage | — | 2025-08-06 | `svchost.exe` (dropped); control-flow-flattened |

---

## Infrastructure

**Telegram C2:**
- `api.telegram.org` — C2 channel via bot API (`bot%s/getUpdates`, `bot%s/sendMessage`)

**Glide provider URLs (compiled in, unreachable):**
- `api.openai.com/v1` (merged form: `api.openai.com/v1azure` — Go string table artifact)
- `api.anthropic.com`, `api.cohere.ai/v1`, `text.octoai.run/v1octoml`, `github.com/EinStack/glide`

---

## Detection

### YARA

```yara
rule LUNAV2_Glide_Linked_Telegram_RAT
{
    meta:
        description = "Detects LUNAV2 — VB.NET dropper delivering a Go Telegram-C2 RAT that statically links EinStack Glide v1.0.0 as an unused dependency; Defender exclusion via hidden PowerShell; HKCU\\Run persistence. A0: Glide is compiled in but unreachable. Activation canary: $act_* strings are byte-absent in all known builds — a hit means the gateway may be active."
        author = "CAIRN"
        tier = "T3"
        confidence = "high"

    strings:
        $glide_azure   = "api.openai.com/v1azure"        nocase
        $glide_octoml  = "text.octoai.run/v1octoml"      nocase
        $glide_repo    = "github.com/EinStack/glide"      nocase
        $glide_cohere  = "api.cohere.ai/v1"               nocase
        $name_luna     = "LunaV2"                         ascii
        $name_lunaalt  = "LunaV2alt.exe"                  ascii
        $name_myproj   = "myproject.exe"                  ascii
        $res_dropper   = "kungvzfgscr"                    ascii
        $tg_send       = "api.telegram.org/bot%25s/sendMessage" nocase
        $tg_send2      = "api.telegram.org/bot%s/sendMessage"   nocase
        $wd_excl       = "Add-MpPreference -ExclusionPath"       nocase
        $wd_temp_svc   = "AppData\\Local\\Temp\\svchost.exe"     nocase
        // Activation canary — byte-absent in all known builds
        $act_config    = "glide.yaml"             nocase
        $act_routers   = "routers:"               ascii
        $act_strategy  = "weighted-round-robin"   nocase

    condition:
        $res_dropper or
        (1 of ($name_lunaalt, $name_myproj)) or
        ($glide_repo and 1 of ($name_luna, $tg_send, $tg_send2)) or
        (2 of ($glide_azure, $glide_octoml, $glide_repo, $glide_cohere)) or
        ($glide_azure and 1 of ($name_luna, $tg_send, $tg_send2)) or
        ($name_luna and 1 of ($tg_send, $tg_send2)) or
        ($name_luna and $wd_excl and $wd_temp_svc) or
        (1 of ($act_config, $act_routers, $act_strategy) and 2 of ($glide_azure, $glide_octoml, $glide_repo, $glide_cohere))
}
```

### Detection Guidance

- **Behavioral:** hidden PowerShell `Add-MpPreference -ExclusionPath` for a `%Temp%` path followed by execution of both `LunaV2.exe` and `svchost.exe` from `%Temp%`
- **Process:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value pointing to `%Temp%\svchost.exe`
- **Network:** Telegram bot API traffic (`api.telegram.org/bot.../getUpdates`) from a non-browser process; Telegram is also used by legitimate applications — require the `LunaV2` name artifact or the Glide string fingerprint for high-confidence attribution
- **Activation canary:** if any of `glide.yaml`, `routers:`, or `weighted-round-robin` appear alongside Glide provider strings (`api.openai.com/v1azure`, `EinStack/glide`), the LLM gateway may be active — re-evaluate the A0 determination immediately

---

*Last updated 2026-09-30.*
