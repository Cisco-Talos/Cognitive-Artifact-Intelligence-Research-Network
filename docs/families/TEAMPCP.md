# TEAMPCP — Research Report

**Family designation:** TEAMPCP (named after the threat actor; AV label `Generic.PY.TeamPCP` reflects existing actor attribution by Bitdefender)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2026-03-25 (earliest submission date observed)
**Last seen:** 2026-03-26 (last variant submission; campaign ongoing — see Shai-Hulud)
**Variants:** 3 confirmed (Python scripts) — LiteLLM component only; full TeamPCP toolset is broader
**Platform:** Windows / Linux; Python 3 script (cross-platform via LiteLLM deployment)
**CAIRN rules:** `T3-TEAMPCP_Backdoored_LiteLLM_Proxy`
**Actor's worm component:** Shai-Hulud (TeamPCP NPM/PyPI supply chain worm — separate from WURM; see note below)
**checkmarx.zone C2:** `checkmarx.zone:8443/telemetry/checkmarx.json` — confirmed live C2 endpoint (Sophos: C2/Generic-A)

---

## Summary

TEAMPCP is a supply chain attack against LiteLLM proxy deployments. The actor distributes a backdoored version of `litellm/proxy/proxy_server.py` — a file that operators legitimately place at the core of their LLM API gateway infrastructure. The malicious variant is functionally identical to the legitimate LiteLLM proxy but adds credential interception logic targeting three asset classes: LLM API keys in transit through the proxy, AWS IAM credentials via the EC2 instance metadata endpoint (`169.254.169.254/latest/meta-data/iam/security-credentials/`), and any secrets accessible to the process at runtime.

The delivery mechanism is the `@qwork/sdk` npm package, which bundles a `qwork-server` binary embedding the backdoored proxy file at `node_modules/@qwork/sdk/binaries/win32-x64/qwork-server/_internal/litellm/proxy/proxy_server.py`. This npm-level embedding allows the malicious proxy to be silently deployed by operators who install the SDK as a dependency, with no obvious indication that `proxy_server.py` has been tampered with. Exfiltrated credentials are forwarded to two actor-controlled Railway.app instances (`litellm-production-7002.up.railway.app`, `exampleopenaiendpoint-production.up.railway.app`) that masquerade as legitimate LiteLLM infrastructure.

A second artifact (`b64_decode.py`) represents a heavily obfuscated variant of the same proxy server — 15,000 lines, base64-obfuscated code body — likely a hardening iteration designed to defeat static detection. The plain `proxy_server.py` variant (`e55065...`) appears to be an intermediate build between the clean upstream source and the fully obfuscated version.

**Note:** TeamPCP is a documented threat actor. Public reporting describes a coordinated series of supply chain attacks against widely-used open source tools including Trivy, KICS, and LiteLLM — the LiteLLM compromise is the operation CAIRN independently surfaced from the `python-ai-scripts` filter. The actor is known to deploy CanisterWorm (a self-propagating worm), use AES-256 + RSA-4096 exfiltration encryption, conduct Kubernetes lateral movement, and employ audio steganography for detection evasion. The CAIRN `python-ai-scripts` filter independently rediscovered the LiteLLM component, confirming methodology validity. The "No public analyst coverage" assessment in the initial CAIRN triage was incorrect — the AV label `Generic.PY.TeamPCP` was itself an attribution signal to a known, documented actor that was not recognized at initial analysis time.

---

## Discovery

CAIRN's `python-ai-scripts` acquisition filter returned all three samples on 2026-06-09. The filter matched `content:"api.openai.com"` and `content:"litellm"` across the three samples, which fired `T1-LLM_API_Endpoint` on rescan. The AV label `Generic.PY.TeamPCP` (Bitdefender) and `Trojan/Python.PthLlmStealer` (ESET) elevated all three for manual triage. The `@qwork/sdk` npm path artifact in the `proxy_server.py` submission names and the AWS IMDS credential theft URL were identified during manual inspection of the embedded URL relationship objects.

---

## proxy_server.py — Backdoored LiteLLM Proxy

### Binary Characteristics

| Field | Value |
|---|---|
| File type | Python script, ASCII text executable, very long lines (up to 34476u) |
| Base | LiteLLM `proxy_server.py` v1.82.7 / v1.82.8 (upstream open source) |
| Code size | ~34,000+ character lines (plain); 15,288 lines obfuscated |
| Internal name | `litellm-1.82.7_itellm_proxy_proxy_server_stage0.py` (staging artifact name) |
| Import hash | N/A (Python script) |
| Delivery | `@qwork/sdk` npm package → `qwork-server` binary bundle |

TEAMPCP backdoors a specific version of LiteLLM's proxy server. LiteLLM is a widely-deployed open-source LLM API gateway that normalises requests across providers (OpenAI, Anthropic, Gemini, etc.). Operators who run LiteLLM in production have all their LLM API keys flowing through `proxy_server.py`, making it an ideal intercept target. The backdoor adds credential harvesting without modifying the proxy's visible behaviour.

The staging artifact name `proxy_server_stage0.py` confirms iterative development — the actor versioned their build pipeline explicitly.

### Code-Signing Certificate

Not applicable — Python script.

### PE Resource Strings

Not applicable — Python script.

### Embedded URL Infrastructure

| URL | Role |
|---|---|
| `https://litellm-production-7002.up.railway.app/` | Actor C2 — masquerades as LiteLLM production instance |
| `https://exampleopenaiendpoint-production.up.railway.app/` | Actor C2 — masquerades as OpenAI-compatible endpoint |
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | AWS EC2 IMDSv1 credential theft endpoint |
| `https://otlp.arize.com/v1` | Arize AI observability — legitimate telemetry (possible covert exfil channel) |
| `https://models.litellm.ai/` | LiteLLM model registry — legitimate |
| `https://docs.litellm.ai/` | LiteLLM documentation — legitimate (obfuscation via expected referrer traffic) |
| `https://docs.datadoghq.com/tracing/...` | Datadog APM — legitimate (expected in LiteLLM deployments) |
| `https://checkmarx.zone/raw` | Suspicious — not `checkmarx.com`; possible typosquat of security vendor |

The two Railway.app C2 domains are named to blend into a LiteLLM operator's network telemetry — `litellm-production-7002` and `exampleopenaiendpoint-production` both look like legitimate deployment artifacts at a glance.

### Sandbox Behavior and Detection

27–37 AV detections across variants. ESET: `Trojan/Python.PthLlmStealer` (most specific label). Bitdefender: `Generic.PY.TeamPCP.G.F56DECEA`. TrendMicro: `TrojanSpy.Python.TPCPSTEAL`. Microsoft: `Trojan:HTML/Obfuse.MU!MTB` (obfuscated variant). Kaspersky: `HEUR:Trojan-Spy.Python.Stealer.gen`.

Sandbox produces minimal behavioural telemetry — the proxy requires a running LiteLLM deployment context to activate credential interception logic. The script is inert when executed in isolation without incoming API traffic to intercept.

Tags across variants: `idle`, `python`, `service-scan`. The `service-scan` tag on the `b64_decode.py` variant indicates the script actively probed network services during sandbox execution.

### Variants (3 confirmed)

| SHA256 | Detections | First Seen (UTC) | Notes |
|---|---|---|---|
| `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | 37 | 2026-03-25 | Plain; `@qwork/sdk` npm embedding confirmed; seed |
| `e55065785190468fc6a5e424679b825924c64bb62aa9486a6510bf2bfd06c87b` | 27 | 2026-03-25 | Plain; intermediate build; `stage0` naming artifact |
| `8333e8facf9f8d3df55127b29097b8c1f8274463388cb94799d2f3528d8f44f9` | 32 | 2026-03-26 | Heavily obfuscated; 15,288 lines; `b64_decode.py` submission name |

### VT Submission Source Keys

| SHA256 | Binary | Sources | Date |
|---|---|---|---|
| `a0d229be` | `litellm/proxy/proxy_server.py` | 7 unique sources (incl. `auto_black_abuse` path; `7a4d5f37` DE) | 2026-03-25 |
| `e55065785` | `proxy_server.py` | 2 sources (`auto_black_abuse` path artifact) | 2026-03-25 |
| `8333e8fa` | `b64_decode.py` | 2 sources (`auto_black_abuse` path + `7a4d5f37` DE) | 2026-03-26 |

**Cross-family submitter note:** Source key `7a4d5f37` (DE) submitted both `a0d229be` and `8333e8fa`. This same key is the confirmed primary VOZDYHAN operator identity and also appears on PROMPTLOCK (Aug 2025), LAMEHUG (Jul 2025), and XENORAT (Mar 2026) samples. For TEAMPCP specifically, `7a4d5f37` is one of several submitters alongside distinct researcher paths — insufficient to attribute TEAMPCP to the Vozdyhan operator. See [VOZDYHAN.md](VOZDYHAN.md) and [PROMPTLOCK.md](PROMPTLOCK.md) for full cross-family timeline.

The `a0d229be` variant has 9 submissions from 7 unique sources — significantly wider than the other two. This is the variant embedded in `@qwork/sdk`, which explains the broader submission pattern: multiple downstream users or CI pipelines encountered and submitted it independently.

---

## Infection Chain

**Initial access:** npm supply chain. The `@qwork/sdk` package bundles a pre-built `qwork-server` binary containing `proxy_server.py`. Any operator or developer who installs `@qwork/sdk` and runs `qwork-server` deploys the backdoored LiteLLM proxy without awareness. The legitimate-appearing package name is the social engineering vector.

**Deployment sequence:**

1. Victim developer installs `@qwork/sdk` via npm (or pulls a project dependency that includes it)
2. `qwork-server` binary executes — internally runs the embedded `proxy_server.py` as its LLM gateway component
3. Backdoored proxy starts accepting LLM API traffic on local port (default LiteLLM: 4000)
4. Each inbound API request passes through the interceptor; API keys extracted from `Authorization: Bearer` headers
5. On AWS EC2 hosts: script queries `169.254.169.254/latest/meta-data/iam/security-credentials/` via IMDSv1 to harvest IAM role credentials
6. Stolen credentials exfiltrated to actor Railway.app C2 instances
7. Actor's Railway.app instance receives and stores harvested credentials

**Component dependencies:**

- Requires incoming LLM API traffic to intercept — inert on an isolated host
- AWS IMDS theft only activates on EC2 instances with IMDSv1 enabled (IMDSv2 token requirement would block this)

**Persistence:**

Provided by the npm package's normal install/autostart mechanism — no separate persistence payload needed; the backdoor runs whenever the legitimate `qwork-server` service runs.

**Operator command path:**

Actor monitors Railway.app-hosted C2 endpoints for incoming credential POST data. No interactive shell capability observed — this is a passive credential harvester, not a RAT.

**Key / credential custody:**

Victim LLM API keys (OpenAI, Anthropic, etc.) → intercepted from `Authorization` headers → exfiltrated to Railway.app C2. AWS IAM credentials → harvested from IMDS → exfiltrated to Railway.app C2.

**Gaps:**

- `@qwork/sdk` npm package not confirmed retrieved/analysed — may have been removed from registry
- Exact exfiltration mechanism (POST body format, encryption) not confirmed
- `checkmarx.zone` domain role unconfirmed — possible additional exfil channel
- Whether `otlp.arize.com` telemetry is abused for covert exfil not confirmed
- Second-stage activity after credential theft not observed

---

## Actor Timeline

| Date | SHA256 | Binary | Component | Notes |
|---|---|---|---|---|
| 2026-03-25 | `a0d229be` | `litellm/proxy/proxy_server.py` | Backdoored proxy (plain, npm-embedded) | Widest distribution — 7 unique VT sources |
| 2026-03-25 | `e55065785` | `proxy_server.py` | Backdoored proxy (intermediate build) | `stage0` naming; same-day as a0d229be |
| 2026-03-26 | `8333e8fa` | `b64_decode.py` | Backdoored proxy (obfuscated) | Next-day obfuscation hardening; `service-scan` tag |

---

## Architecture

| Component | Binary | Language | Role | C2 |
|---|---|---|---|---|
| Backdoored proxy | `proxy_server.py` | Python 3 | LLM API key intercept + AWS IMDS credential theft | `litellm-production-7002.up.railway.app` |
| npm delivery | `@qwork/sdk` | Node.js / Python bundle | Supply chain delivery of backdoored proxy | N/A |
| Actor C2 (primary) | Railway.app instance | Unknown | Receives exfiltrated credentials | `litellm-production-7002.up.railway.app` |
| Actor C2 (secondary) | Railway.app instance | Unknown | Receives exfiltrated credentials | `exampleopenaiendpoint-production.up.railway.app` |

---

## Infrastructure IOCs

**Actor-controlled Railway.app instances:**

- `litellm-production-7002.up.railway.app` — primary credential exfil receiver; named to blend with legitimate LiteLLM deployments
- `exampleopenaiendpoint-production.up.railway.app` — secondary; named to blend with OpenAI-compatible endpoint deployments

**Suspicious domain (unconfirmed role):**

- `checkmarx.zone` — not `checkmarx.com` (legitimate security vendor); possible typosquat; observed in `b64_decode.py` embedded URLs only

**Credential theft endpoint (victim-side):**

- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — AWS EC2 IMDSv1; not actor-owned but a key indicator of cloud-targeting intent

**npm supply chain vector:**

- `@qwork/sdk` — npm package name; registry status at time of writing unknown

---

## Assessment

### Archetype

**LLM Infrastructure Supply Chain Attack / API Key Harvester.** TEAMPCP represents a novel archetype in the CAIRN corpus: rather than embedding LLM functionality in malware, the actor backdoors the infrastructure layer that operators use to manage LLM API access. The LiteLLM proxy is a chokepoint — it sees all API keys for all providers from all applications. Compromising it yields credentials at scale without touching individual applications.

### APT vs. FIN Assessment

**Assessment revised in light of actor attribution.**

TeamPCP is a documented threat actor with a public profile that substantially exceeds the initial CAIRN FIN assessment. Known capabilities include: coordinated multi-ecosystem supply chain compromise (Trivy, KICS, LiteLLM simultaneously), CanisterWorm self-propagating worm deployment, AES-256 + RSA-4096 exfiltration encryption (explaining why POST body content was opaque in sandbox), Kubernetes lateral movement within cloud-native environments, and audio steganography for detection evasion. This profile is inconsistent with a commodity FIN actor; it describes a sophisticated, persistent, multi-target supply chain operation.

The initial CAIRN assessment of "financially motivated with above-average knowledge of enterprise AI/ML operations, confidence medium-high" was based on metadata alone and underweighted the actor's sophistication. The correct framing: TeamPCP is a persistent threat actor whose operations blend FIN objectives (credential theft, inference abuse) with APT-grade tradecraft (audio steganography, multi-ecosystem coordination, encrypted exfil). Whether the primary motivation is financial or espionage-adjacent is not resolvable from the LiteLLM component alone.

**Shai-Hulud / WURM resolution:** TeamPCP's self-propagating worm is **Shai-Hulud** (not "CanisterWorm" — that name has no basis in public threat intel). Shai-Hulud is a NPM/PyPI supply chain worm that propagates by compromising package repositories and embedding malicious payloads. WURM is an Impacket SMB propagation framework with OpenAI LLM tasking and Slack/Ethereum C2 — architecturally distinct from Shai-Hulud's package ecosystem delivery model. **WURM is not Shai-Hulud.** The `auto_black_abuse` co-occurrence and same-day submission are coincidental collection artifacts. WURM remains independently attributed. See WURM.md.

**`checkmarx.zone` resolved:** Confirmed live C2 endpoint at `checkmarx.zone:8443/telemetry/checkmarx.json`. Sophos classifies it C2/Generic-A (23 malicious vendor detections). Not a phishing page — an active command and exfiltration endpoint impersonating the Checkmarx security vendor brand. The `localhostc2-main/realc2/hi-malwareresearcher/` cluster (RuntimeBroker.exe, Invoice78271.pdf.hta) uses this C2 and was surfaced via the checkmarx.zone pivot. This cluster has a distinct actor handle (`ashduasdoasdoasd` GitHub) and may not be TeamPCP — it fired the TEAMPCP rule only via the shared C2 endpoint, not via LiteLLM strings. Possible interpretations: (a) TeamPCP operates a broader toolkit beyond LiteLLM backdoors, (b) a second actor is sharing or piggybacking the checkmarx.zone C2. Assessment: insufficient evidence for single-actor attribution.

**`mini-shai-hulud-scanner` rule false positive:** The scanner zip/script (`3d08fadb`, `78a911a2`) fired T3-TEAMPCP_Backdoored_LiteLLM_Proxy because they reference TeamPCP IOCs (including checkmarx.zone) in detection logic. These are legitimate security research tools, not malware. The TEAMPCP rule fires because it matches the C2 domain string regardless of context. Rule refinement: add a negative condition excluding `scan_` submission names or `provider_references` from legitimate AI vendors. These samples should be suppressed in future scans.

### Inferred Use Case

Bulk LLM API credential harvesting for resale or direct abuse (free inference at victim cost). AWS IAM credentials harvested as a secondary yield — higher value if the EC2 role has broad permissions. Confidence: medium.

### Attribution Signals

- `auto_black_abuse` path artifact — same automated collection pipeline as WURM; not an attribution signal, likely a shared malware collection feed
- `@qwork/sdk` package name — no public GitHub presence or legitimate project found at time of writing
- Railway.app subdomain naming convention mimics legitimate deployment patterns — deliberate operational security

### Open Questions

- Is `@qwork/sdk` still live on npm? Were downstream victims affected before removal?
- Is `otlp.arize.com` used for covert telemetry exfiltration, or is the Arize AI reference incidental?
- Exact backdoor diff against upstream LiteLLM source not performed — injection points unknown; AES-256/RSA-4096 encryption means exfil content is not recoverable from metadata alone
- `localhostc2-main/realc2/hi-malwareresearcher/` cluster — TeamPCP or separate actor sharing the checkmarx.zone C2? Pivot `ashduasdoasdoasd` GitHub handle for additional artifacts
- Did TeamPCP also compromise Trivy or KICS versions visible in the VT corpus? Pivot on known Trivy/KICS supply chain IOCs from public reporting
- **RESOLVED:** `checkmarx.zone` — confirmed C2 endpoint, not phishing page. See Assessment above.
- **RESOLVED:** WURM / CanisterWorm overlap — WURM is not Shai-Hulud (TeamPCP's worm); architecturally distinct. See WURM.md.

---

## CAIRN Rules

```yara
rule T3-TEAMPCP_Backdoored_LiteLLM_Proxy
{
    meta:
        description = "Detects TeamPCP backdoored LiteLLM proxy — malicious proxy_server.py intercepts LLM API keys and steals AWS IAM credentials via instance metadata endpoint; distributed via @qwork/sdk npm package; C2 on actor-controlled Railway.app LiteLLM instance"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "api_key_pattern"
        tier = "T3"
        confidence = "high"
        family = "TEAMPCP"
        reference = "VT SHA256 a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b; ESET: Trojan/Python.PthLlmStealer; AV: Generic.PY.TeamPCP; Railway.app C2 litellm-production-7002.up.railway.app; @qwork/sdk npm supply chain vector; AWS IMDSv1 credential theft"

    strings:
        $av_teamcp   = "TeamPCP"                                                   nocase
        $av_stealer  = "PthLlmStealer"                                             nocase
        $railway_c2  = "litellm-production-7002.up.railway.app"                    nocase
        $railway_ex  = "exampleopenaiendpoint-production.up.railway.app"           nocase
        $imds        = "169.254.169.254/latest/meta-data/iam/security-credentials" nocase
        $stage0      = "proxy_server_stage0"                                       nocase
        $qwork       = "@qwork/sdk"                                                nocase

    condition:
        $av_teamcp or $av_stealer or $railway_c2 or $railway_ex or
        $imds or $stage0 or $qwork
}
```

Fires on all three variants confirmed by `cairn rescan`. String sources: AV detection labels (`$av_teamcp`, `$av_stealer`), embedded URL relationship objects (`$railway_c2`, `$railway_ex`, `$imds`), submission name artifact (`$stage0`), npm path artifact (`$qwork`).

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-09 | Initial report — 3 variants confirmed; T3 rule written and fires on all three; @qwork/sdk npm supply chain vector identified; AWS IMDSv1 credential theft confirmed; checkmarx.zone role unresolved |
| 2026-06-10 | Actor attribution corrected — TeamPCP is a documented threat actor; initial "no public coverage" assessment was wrong; AV label was an attribution signal missed at triage; APT/FIN assessment revised upward |
| 2026-06-10 | checkmarx.zone pivot: confirmed live C2 endpoint (Sophos C2/Generic-A); localhostc2 cluster surfaced; mini-shai-hulud-scanner identified as legitimate detection tool (rule FP); WURM/Shai-Hulud overlap resolved — WURM is architecturally distinct from TeamPCP's NPM/PyPI worm; "CanisterWorm" name has no public threat intel basis |
| 2026-06-22 | Cross-family submitter note added: `7a4d5f37` (DE) submits `a0d229be` and `8333e8fa`; same key is confirmed VOZDYHAN operator identity; TEAMPCP attribution to that actor not confirmed |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-09. Author: Ryan Fetterman (https://fetterm4n.github.io)*
