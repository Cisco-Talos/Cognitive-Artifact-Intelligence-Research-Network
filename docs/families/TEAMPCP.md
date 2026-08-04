# TEAMPCP — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** `Generic.PY.TeamPCP` (Bitdefender) · `Trojan/Python.PthLlmStealer` (ESET) · `TrojanSpy.Python.TPCPSTEAL` (TrendMicro) · `HEUR:Trojan-Spy.Python.Stealer.gen` (Kaspersky)
**First seen:** 2026-03-25
**Last seen:** 2026-03-26 (LiteLLM component; actor activity ongoing)
**Platform:** Python 3 — Windows / Linux, wherever LiteLLM deploys
**Archetype:** A5 — LLM Infrastructure Supply Chain
**Actor:** TeamPCP — a documented, multi-ecosystem supply chain threat actor
**TLP:** TLP:AMBER

---

## Summary

TEAMPCP is a supply-chain compromise of **LiteLLM**, the widely deployed open-source LLM API gateway. The actor distributes a backdoored `litellm/proxy/proxy_server.py` — functionally identical to the upstream file, with added credential interception.

The target selection is the sophisticated part. LiteLLM exists to normalize API calls across providers, which means an organization running it has routed **every LLM API key, from every application, for every provider, through this one file**. It is the designed chokepoint of the AI stack. Backdooring it harvests credentials at organizational scale without touching a single application, and the harvest arrives pre-aggregated.

Three asset classes are stolen:

| Target | Method |
|---|---|
| LLM API keys (OpenAI, Anthropic, Gemini, …) | Extracted from `Authorization: Bearer` headers in transit through the proxy |
| AWS IAM role credentials | Queried from the EC2 instance metadata endpoint (`169.254.169.254`, IMDSv1) |
| Runtime-accessible secrets | Whatever the proxy process can reach |

Delivery is one layer deeper still. The backdoored Python file is embedded inside the **`@qwork/sdk` npm package**, at `node_modules/@qwork/sdk/binaries/win32-x64/qwork-server/_internal/litellm/proxy/proxy_server.py`. An operator installing an npm SDK deploys a backdoored Python LLM gateway, with nothing in the npm dependency tree indicating that a Python file several directories down has been altered. Cross-ecosystem embedding of this kind defeats per-ecosystem auditing: npm tooling does not inspect bundled Python, and Python tooling never sees the package.

Exfiltration goes to two actor-controlled Railway.app instances named to disappear into a LiteLLM operator's own telemetry: `litellm-production-7002.up.railway.app` and `exampleopenaiendpoint-production.up.railway.app`.

TeamPCP is a documented actor with a track record of coordinated supply-chain attacks against widely used open-source security and infrastructure tooling — Trivy, KICS, and LiteLLM among them. Reported capabilities include the **Shai-Hulud** self-propagating npm/PyPI worm, AES-256 + RSA-4096 exfiltration encryption, Kubernetes lateral movement, and audio steganography for evasion. This profile is not commodity crimeware; it blends financially motivated credential theft with tradecraft normally associated with state-adjacent operations.

---

## Architecture

| Component | Artifact | Language | Role | C2 |
|---|---|---|---|---|
| Backdoored proxy | `proxy_server.py` | Python 3 | API key intercept + AWS IMDS theft | `litellm-production-7002.up.railway.app` |
| Delivery vehicle | `@qwork/sdk` | npm (bundling Python) | Cross-ecosystem supply-chain delivery | — |
| Primary collector | Railway.app instance | Unknown | Receives exfiltrated credentials | `litellm-production-7002.up.railway.app` |
| Secondary collector | Railway.app instance | Unknown | Receives exfiltrated credentials | `exampleopenaiendpoint-production.up.railway.app` |

---

## Samples

| SHA256 | Detections | First Seen (UTC) | Notes |
|---|---|---|---|
| `a0d229be8efcb2f9135e2ad55ba275b76ddcfeb55fa4370e0a522a5bdee0120b` | 37 | 2026-03-25 | Plain source; `@qwork/sdk` npm embedding confirmed; widest distribution (7 unique VT sources) |
| `e55065785190468fc6a5e424679b825924c64bb62aa9486a6510bf2bfd06c87b` | 27 | 2026-03-25 | Intermediate build; `proxy_server_stage0.py` naming artifact |
| `8333e8facf9f8d3df55127b29097b8c1f8274463388cb94799d2f3528d8f44f9` | 32 | 2026-03-26 | Heavily obfuscated — 15,288 lines, base64 body; submitted as `b64_decode.py` |

The three samples capture the actor's hardening cycle within 48 hours: a `stage0` intermediate, the npm-embedded production build, and next-day base64 obfuscation. The staging artifact name confirms an explicitly versioned build pipeline rather than ad-hoc modification.

The wider submission footprint on `a0d229be` — 9 submissions from 7 unique sources — is consistent with the npm-embedded build being encountered independently by multiple downstream consumers and CI pipelines.

---

## Component Details

| Field | Value |
|---|---|
| Base | LiteLLM `proxy_server.py` v1.82.7 / v1.82.8 (upstream open source) |
| File type | Python 3 source; very long lines (up to ~34,000 characters) |
| Obfuscated variant | 15,288 lines, base64-encoded body |
| Internal name artifact | `litellm-1.82.7_itellm_proxy_proxy_server_stage0.py` |
| Delivery | `@qwork/sdk` npm package → `qwork-server` binary bundle |

### Infection Chain

1. Developer or operator installs `@qwork/sdk` — directly, or through a project dependency
2. `qwork-server` runs, launching the embedded `proxy_server.py` as its LLM gateway
3. The backdoored proxy begins accepting LLM API traffic (LiteLLM default port 4000)
4. Each inbound request passes the interceptor; keys extracted from `Authorization: Bearer` headers
5. On EC2 hosts, the script queries IMDSv1 at `169.254.169.254/latest/meta-data/iam/security-credentials/` for IAM role credentials
6. Harvested credentials are exfiltrated to the Railway.app collectors

Persistence requires no separate payload: the backdoor runs whenever the legitimate `qwork-server` service runs.

### Operational Constraints

Two properties limit exposure and explain why sandbox analysis of these samples yields almost nothing:

| Constraint | Consequence |
|---|---|
| Requires live inbound LLM API traffic | **Inert in isolation** — a sandbox with no proxy traffic sees no malicious behavior |
| AWS theft requires IMDSv1 | **IMDSv2's token requirement blocks it outright** |

The second is directly actionable: enforcing IMDSv2 eliminates the cloud-credential half of this attack.

This is a **passive harvester, not a RAT**. No interactive shell capability was observed. The operator monitors the collectors for inbound credential POSTs.

---

## Infrastructure IOCs

### Actor-Controlled

| Indicator | Role |
|---|---|
| `litellm-production-7002.up.railway.app` | Primary credential exfiltration receiver |
| `exampleopenaiendpoint-production.up.railway.app` | Secondary receiver |
| `checkmarx.zone:8443/telemetry/checkmarx.json` | Confirmed live C2 — impersonates the Checkmarx security vendor brand (23 vendor detections; Sophos: `C2/Generic-A`) |
| `@qwork/sdk` | npm delivery package |

Both Railway.app names are chosen to survive a glance at network telemetry: `litellm-production-7002` and `exampleopenaiendpoint-production` read as ordinary deployment artifacts in exactly the environment being attacked. `checkmarx.zone` is not `checkmarx.com` — it is a brand-impersonating typosquat of a security vendor, and it is live infrastructure rather than a phishing page.

### Victim-Side Indicator

| Indicator | Significance |
|---|---|
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Not actor-owned, but any outbound reference to it from a proxy process indicates cloud-credential targeting |

### Legitimate Endpoints Present in the File

Inherited from upstream LiteLLM and useful for reducing false positives: `models.litellm.ai`, `docs.litellm.ai`, `docs.datadoghq.com`, `otlp.arize.com`. Their presence is expected in any genuine LiteLLM deployment and is not evidence of compromise.

---

## Detection

### YARA

```yara
rule T3-TEAMPCP_Backdoored_LiteLLM_Proxy
{
    meta:
        description = "Detects TeamPCP backdoored LiteLLM proxy — malicious proxy_server.py intercepts LLM API keys and steals AWS IAM credentials via instance metadata endpoint; distributed via @qwork/sdk npm package"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "api_key_pattern"
        tier = "T3"
        confidence = "high"
        family = "TEAMPCP"

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

**Known false-positive class.** This rule matches IOC strings wherever they appear — including inside **legitimate detection tooling**. Security scanners that reference TeamPCP indicators (for instance `mini-shai-hulud-scanner`) will match on the C2 domain alone. Any hit should be checked for whether the sample *uses* the indicator or merely *catalogs* it; detection content and malware are not distinguishable by string presence.

### Detection and Mitigation Guidance

Ordered by effectiveness:

| Control | Effect |
|---|---|
| **Enforce IMDSv2** on all EC2 instances | Eliminates the AWS credential theft path entirely |
| **Verify `proxy_server.py` against upstream LiteLLM** by hash for the deployed version | Directly detects the backdoor; the file should match upstream exactly |
| **Alert on outbound traffic from LLM gateway hosts to `*.up.railway.app`** | Catches exfiltration; a production gateway has no reason to reach an unknown PaaS instance |
| **Audit npm packages that bundle non-JavaScript executables or interpreters** | Addresses the cross-ecosystem delivery pattern generally |
| **Treat inference API keys as rotatable secrets with short lifetimes** | Limits the value of a successful harvest |

The second row is the highest-confidence check available. LiteLLM is open source, so the correct content of `proxy_server.py` for any given version is publicly verifiable — a hash comparison is definitive, requires no signatures, and works even against a variant that defeats every string-based rule above.

---

## Open Questions

1. **Is `@qwork/sdk` still available on npm, and who consumed it?** The downstream victim population is unquantified. This is the most urgent gap — every affected operator has had their entire multi-provider key inventory exposed.
2. **Where exactly is the backdoor injected?** No diff against upstream LiteLLM has been performed, so the injection points are unmapped. Because exfiltration is reportedly AES-256 + RSA-4096 encrypted, captured traffic will not reveal content — source comparison is the only path.
3. **Is `otlp.arize.com` abused as a covert channel?** The Arize observability endpoint is legitimate in a LiteLLM deployment, which makes it an attractive exfiltration cover. Unconfirmed either way.
4. **Are Trivy or KICS compromised builds also in circulation?** Public reporting places those tools in the same actor's campaign; corresponding samples have not been examined here.
5. **Is the `checkmarx.zone` C2 exclusive to TeamPCP?** A separate cluster (distinct actor handle, unrelated tooling) shares this endpoint. Either the actor's toolkit is broader than the LiteLLM component, or a second party is sharing the infrastructure. Current evidence does not settle it — and a shared C2 alone is not sufficient grounds for single-actor attribution.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
