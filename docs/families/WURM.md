# WURM

**Author:** Ryan Fetterman
**Aliases:** Trojan:Python/Reldein.A (Microsoft — both variants); Python/Agent.BEL (ESET); Trojan.Generic (Bitdefender)
**First seen:** 2026-03-25
**Last seen:** 2026-03-28
**Platform:** Windows/Linux; Python 3 script
**Archetype:** A7 · A9 (developmental)
**TLP:** AMBER

---

## Summary

WURM is a **developmental offensive toolkit** — a Python script with staged but non-functional AI and worm capabilities. The code is unambiguously malicious in intent: the OpenAI call site instructs the model to *"Generate undetectable PowerShell code for C2"*, and the reachable `main()` path implements sandbox evasion, `/24` network scanning, and three persistence mechanisms (WMI event subscription, service DLL hijacking, NTFS ADS). A companion CVE-2023-32046 MSHTML exploit (`do not run.txt`) was co-hosted on the actor's CDN (`legit-cdn.com`), confirming the worm is part of a broader access toolkit.

**Why "developmental":** The AI component (`polymorphic_payload`) is never called from `main()` and carries no API key or Authorization header — an unauthenticated POST would return HTTP 401. The Impacket propagation code imports seven submodules that do not exist in any Impacket release (`eternalblue`, `proxyshell`, `log4shell`, `petitpotam`, `proxynotshell`, `printnightmare`, `mshtml`), raising `ImportError` before any other line executes. Of 63 defined functions, 43 are unreachable from `main()`, including every distinctive offensive capability. German-language code comments (`schädliche Datei` = "malicious file"; `Führe den Wurm aus` = "Run the worm") confirm the author's intent.

**Deploy-time configuration model.** Operational parameters are template strings rather than hardcoded values: `http://C2/payload.bin`, `hooks.slack.com/your-webhook`, `mainnet.infura.io/v3/YOUR_KEY`. This suggests WURM is a framework distributed to operators who substitute their own infrastructure at deployment, not a ready-to-deploy weapon.

Two variants were submitted three days apart — plain text and an obfuscated equivalent.

---

## Capability Analysis

### Reachable from `main()` (20 of 63 functions)

| Capability | Implementation |
|---|---|
| Sandbox evasion | `is_sandbox()` — exits if analysis environment detected |
| Network scanning | `infect_local_network()` / `scan_and_infect()` — `/24` sweep, threaded per host per port |
| Persistence (WMI) | `set_wmi_event_subscription()` — fires 5 min after every boot |
| Persistence (DLL hijack) | `set_service_dll_hijacking()` — targets `%TEMP%\Update.exe` |
| Persistence (NTFS ADS) | `set_ntfs_ads_persistence()` |
| Registry autostart | `copy_file_and_set_autostart()` — `REG_PATH`/`REG_NAME` |
| C2 listener | `app.run(host='0.0.0.0', port=443, ssl_context='adhoc')` |

### Unreachable (43 of 63 functions — staged offensive capability)

The following functions are defined but never transitively reachable from `main()`: the OpenAI `polymorphic_payload` call, `generate_ai_payload`, `send_slack_message`, `fetch_blockchain_c2`, `lateral_movement`, `bypass_edr`, `bypass_amsi`, `reflective_injection`, `atom_bombing`, `process_doppelganging`, and 33 additional exploit and evasion functions. Several are bare `pass` stubs; others reference undefined names and would raise `NameError` if called.

### AI Component

The single OpenAI call site (`polymorphic_payload()`, unreachable):

```python
gpt4_payload = requests.post(
    "https://api.openai.com/v1/chat/completions",
    json={"model": "gpt-4", "messages": [{"role": "user", "content": "Generate undetectable PowerShell code for C2"}]}
).json()
```

No API key exists anywhere in the file. The prompt's content — evasion-optimised C2 generation — is unambiguously malicious, placing the AI component in A7 (tool augmentation) with A2 elements (LLM-directed payload generation). Both archetypes are staged, not deployed.

---

## Samples

| SHA256 | Det | First Seen (UTC) | Notes |
|---|---|---|---|
| `ed6660a9029d54c335bc574ee6cc3dbdda85eb9840c0f1c04dd77ddb37277432` | 11 | 2026-03-25 | `wurm.py` — plain text; seed |
| `e51cf070e26ab8c3d6a8df9dba3be5888498ee5cb0138d87e75a1d2c0660ad8f` | 14 | 2026-03-28 | `wurmobfuscated.py` — obfuscated version |

---

## Infrastructure

**Actor CDN:**
- `legit-cdn.com/payload.bin` — payload hosting; co-hosts CVE-2023-32046 exploit (`do not run.txt`)

**Configured but placeholder (template values):**
- `http://C2/payload.bin` — operator-substituted C2 at deploy time
- `hooks.slack.com/your-webhook` — Slack C2/exfiltration webhook (placeholder)
- `mainnet.infura.io/v3/YOUR_KEY` — Ethereum RPC (placeholder)
- `api.openai.com/v1/chat/completions` — LLM endpoint (no key present)

---

## Detection

### YARA

```yara
rule WURM_Python_Impacket_LLM_Worm
{
    meta:
        description = "Detects WURM Python worm — Impacket-based network propagation with OpenAI LLM tasking, Slack webhook C2, and Ethereum/Infura blockchain component; template config vars (C2, your-webhook) suggest deploy-time substitution"
        author = "CAIRN"
        tier = "T3"
        confidence = "high"

    strings:
        $ms_label    = "Trojan:Python/Reldein.A"    nocase
        $cdn_payload = "legit-cdn.com/payload.bin"  nocase
        $slack_c2    = "hooks.slack.com"             nocase
        $infura      = "mainnet.infura.io"           nocase
        $c2_template = "http://C2/payload.bin"       nocase

    condition:
        $ms_label or $cdn_payload or $c2_template or
        ($slack_c2 and $infura)
}
```

### Detection Guidance

- **Network:** outbound DNS queries to `legit-cdn.com` from Python interpreter processes
- **File:** Python scripts containing all three of: Impacket imports, `api.openai.com`, `hooks.slack.com`; German comments (`schädliche Datei`, `Führe den Wurm aus`) alongside English code
- **AV label:** Microsoft `Trojan:Python/Reldein.A` is the highest-fidelity label available for this family

---

## Open Questions

- Whether WURM is CanisterWorm — the self-propagating worm component of the TeamPCP campaign — is an open question; the two share first-seen date, a submission path artifact, and a propagating-worm architecture, but no code-level linkage has been confirmed
- No operator infrastructure (filled-in C2, webhook, Infura key) has been recovered
- Whether the co-hosted CVE-2023-32046 exploit (`do not run.txt`) belongs to the same actor or shares CDN infrastructure by coincidence

---

*Last updated 2026-09-30.*
