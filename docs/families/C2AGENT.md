# C2AGENT

**Author:** CAIRN (coverage assessment); primary analysis by Unit42 / Palo Alto Networks
**Aliases:** C2Agent (Unit42)
**First seen:** 2026-09-10 (v0) · **Last seen:** 2026-10-08 (v2.4)
**Platform:** Windows x86-64 · Go
**Archetype:** A7 — LLM-Augmented Offensive Tool
**TLP:** TLP:AMBER

> Full technical analysis, IOC lists, and timeline are in the Unit42 disclosure. This document is a CAIRN coverage summary and detection reference.
>
> **Primary source:** https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-09-C2Agent-malware.txt

---

## Summary

C2AGENT is a Go-based Windows implant where an LLM drives all post-exploitation operations on the infected host. The operator sends a natural-language goal; the agent builds a system prompt, calls the model for a tool selection, executes it, feeds the result back, and repeats — up to 40 steps by default. The LLM is not a one-shot code generator; it is the decision engine for the entire engagement.

Eight major versions shipped in 29 days (v0 on 2026-09-10 through v2.4 on 2026-10-08). v2.4 added a Cobalt Strike Beacon Object File loader and self-upgrade, placing it in the same capability tier as purpose-built adversary simulation frameworks.

---

## Architecture

**Delivery:** Two-stage. A stager downloads the agent binary from `agent.x90[.]dev/data/copilot.txt` and injects it into a host process (`sihost.exe`, `RuntimeBroker.exe`, and others).

**Agentic loop:** The agent receives a goal from the C2, constructs a prompt (LLM role, tool list, host context, loaded skills), calls the model, executes the returned tool invocation, and iterates on the result until the goal is complete or the step cap is hit.

**LLM routing:** Model traffic is proxied through `agent.x90[.]dev` — the agent never contacts an inference provider directly.

**MCP:** The agent embeds an MCP client with Firecrawl (`mcp.firecrawl[.]dev/v2/mcp`) as the default server. The C2 can push additional MCP servers at runtime.

---

## Samples

CAIRN holds 21 of the 32 samples in the Unit42 disclosure (19 agents, 2 stagers). Full hash lists are in the Unit42 report. Selected builds:

| SHA256 | Version | First seen | Role |
|---|---|---|---|
| `35fc649622dfea297cb2a37ce2b6a9f89733546a22a5d13410c96ff904126e92` | v0 | 2026-09-10 | Agent |
| `14d7dee40dbe0fd62a9b0fb68b71b58616664bad620d32efeafe127ab599030d` | v1 | 2026-09-18 | Agent |
| `aaea58096313c877495ab0c07de3217cefdf1bc9bd9d08df06b44881fe9b90a9` | v2.1 | 2026-09-30 | Agent |
| `376cacae394932b14e23257d2e5a166f1a7ceb68a6135ba265c06c201cda731a` | v2.2 | 2026-10-01 | Agent |
| `e6ad79c9c792c0337c7d19ad5e6c9e9d94b6355a45460bef2c72000fc3197292` | v2.4 | 2026-10-08 | Agent |
| `215efb8405e32c9b59a95b560363fb4c51a6471e8c067938d67a464e33facd3c` | v7 | 2026-09-27 | Stager |

---

## Infrastructure

| Indicator | Role |
|---|---|
| `agent.x90[.]dev` | C2, LLM proxy, PTY shell, pivot |
| `agent.x90[.]dev/data/copilot.txt` | Stage 2 payload delivery URL |
| `mcp.firecrawl[.]dev/v2/mcp` | Default MCP server (legitimate service, abused) |

**Host artifacts:** persistence copy at `%LOCALAPPDATA%\<random>\<random>.exe`; startup LNK; scheduled task `/sc onlogon`; runtime keypair at `%TEMP%\iris-kp-*`; BOF loader helpers at `%TEMP%\iris-bof-*.coff` (v2.4+).

---

## Detection

```yara
rule T3-C2AGENT_Go_LLM_Operated_Agentic_Implant
{
    meta:
        description = "C2AGENT — Go Windows LLM-operated agentic implant. Anchors: actor C2 domain and hardcoded default MCP server URL."
        reference   = "https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-09-C2Agent-malware.txt"

    strings:
        $c2  = "agent.x90.dev"            nocase
        $mcp = "mcp.firecrawl.dev/v2/mcp" nocase

    condition:
        $c2 or $mcp
}
```

**Detection guidance:** The `$c2` anchor covers both agent and stager; `$mcp` covers agent builds that change the C2 domain but retain the default MCP server. The two anchors have 0 FP across a 5,580-sample corpus. Network: block or alert on outbound connections to `agent.x90[.]dev` and `mcp.firecrawl.dev` from non-browser processes.

---

## CAIRN Coverage Note

CAIRN holds 21 of 32 disclosed samples. The 11 missing builds were not acquired because C2AGENT proxies all LLM traffic through `agent.x90[.]dev` — no direct inference-provider contact means no provider-API filter fires. Samples entered the corpus via VT domain-relationship pivots from `agent.x90.dev`, not through a filter sweep. The `T2-MCP_Client_Endpoint_PE` rule (added 2026-10-13) independently covers agent builds via the Firecrawl MCP endpoint.

---

*Based on Unit42 / Palo Alto Networks disclosure, 2026-10-09. CAIRN coverage assessed 2026-10-13.*
