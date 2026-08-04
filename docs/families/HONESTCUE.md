# HONESTCUE — Threat Intelligence Report

**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**Aliases:** HONESTCUE (Mandiant GTIG, September 2025) · `trojan.agentb/cryp` (VT suggested label)
**First seen:** 2025-07-22
**Last seen:** 2025-08-01
**Platform:** Windows x86-64 (PE32+ console), .NET
**Archetype:** A1 — LLM-Directed Payload Generation
**LLM provider:** Google Gemini (`generativelanguage.googleapis.com`)
**TLP:** TLP:AMBER

---

## Summary

HONESTCUE is a Windows .NET loader that treats the **Google Gemini API as its payload server**. The binary embeds a hard-coded prompt instructing Gemini to generate a C# class — named `AITask` or `Stage2` — then compiles the model's response at runtime with `CSharpCodeProvider` (which spawns the real `csc.exe` compiler) and executes the resulting assembly in-process.

The second stage therefore **has no static existence**. It is not packed, not encrypted, and not downloaded from operator-controlled infrastructure; it does not exist until the model writes it. This defeats payload extraction as an analysis technique and removes the operator's need to host anything: there is no staging server to seize, no CDN link to block, and no payload hash to blocklist. Google's own infrastructure serves the malicious code.

41 samples were submitted in a tight 11-day window. Every one carries the filename `ConsoleApplication1.exe` — the untouched Visual Studio default. Two imphash clusters account for 32 of the 41, indicating two stable build configurations rather than two campaigns.

Mandiant GTIG published attribution for this family in September 2025.

---

## Architecture

| Stage | Mechanism | Artifact left behind |
|---|---|---|
| 1 | Embedded prompt → HTTPS POST to Gemini | Outbound request to `generativelanguage.googleapis.com` |
| 2 | `CSharpCodeProvider` compiles the response | `csc.exe` child process; transient `.cs` / `.dll` in a temp path |
| 3 | Compiled assembly loaded and run in-process | None persistent |

Stage 3 behavior is not fixed across executions. Because the model generates the source each run, two executions of the identical binary can produce functionally different payloads — meaning **a single sandbox capture is not necessarily representative of the family**.

---

## Samples

All 41 samples: filename `ConsoleApplication1.exe`, PE32+ x86-64 console, unsigned, no version strings.

### Primary build — imphash `a63661caccd7017c284e41d9db93d8d4` (22 samples)

| SHA256 | Detections | First Seen (UTC) |
|---|---|---|
| `5c70dd5ad4d34cd25cceab4421a73686e4ae3c3a3e6ffa61916f245ca9f7697c` | 42 | 2025-07-22 |
| `fb72accfbde0c8628140c4ee2e6866efcfcf45f0a65e25ec89177cfbe63ec2a3` | 45 | 2025-07-22 |
| `513a7a0daa03a6591a18b2d850af5ed6ebc6d5e1d04080214ebd3047f2ba70be` | 26 | 2025-07-22 |
| `8d656e2672bfb08872d919d5b7cb3a5acd333bc7bf3f5769d14abfcac99dcd70` | 23 | 2025-07-23 |
| `af25b1c3b36a97262206842679dc2baef0d654726976330e433547920094abbc` | 20 | 2025-07-23 |
| `97da665a133d5ada32e0c2705cea6eb4f9b00e6d4506ab1771d70f7c99105b6b` | 27 | 2025-07-23 |
| `de501b275d50622023a44489d23bf78a0157f883eaf970c9a3c2d95c52ac5de0` | 27 | 2025-07-23 |
| `e73ae1e1eca6be4f96d91e802dfa8a9b1ed29732cc0fb6378ab8d91c9bb0feba` | 25 | 2025-07-23 |
| `6371e212b87bca591d3a52eee0c8af63d67c2345492ceb3bfd63f42967f359b1` | 27 | 2025-07-23 |
| `183bc69ea1f39eeacbc6ee934d2c054878821ae32213de50cfd272546ff04774` | 30 | 2025-07-23 |
| `c1168c5bd39dd20873bc73ee2bd27bd960d53e665f1d74990be373f83527f10b` | 30 | 2025-07-23 |
| `51de550577469f56a7ffd7cb1a1ec1f6ddacfe635e6d20c339873cec6f056521` | 32 | 2025-07-23 |
| `cec9d4e4bd217de80fd55f1b055c7919ed7ee68d04850bd6651f184a0833695e` | 27 | 2025-07-23 |
| `a689f599d45421c0509f12e0da9155fdc4f332bfb0234f1a31f5df9df3f14349` | 31 | 2025-07-23 |
| `0539fbf0e37dd623cd068a357cc876cac68ccf272a8c6e0b361c63e9d6e980bd` | 34 | 2025-07-23 |
| `618a4f0d6cb47bdde07a9e1e3dc107ae090d867e3cf728428ce7aeecb4f43296` | 29 | 2025-07-24 |
| `8a4ae1f830ccf116ee5d92069e98b08a13ef1d77004c7f31a896765b4466313f` | 30 | 2025-07-24 |
| `959c8d65bd8b7acda2c09c0cf2e981ffb675c138cb67fea1d9fdb5f923908b9a` | 28 | 2025-07-26 |
| `3f14baee32fc0a43bb1270ed987c91bcfeca0ff6be558eb80d9ccade06c2b219` | 35 | 2025-07-26 |
| `db43fa07fba044cd4a8f0df6ec7e4536e8af42b13a6428f8f732b4671ebe6a53` | 37 | 2025-07-26 |
| `cd8afec1a9164f5bcfea9b3bd62894cb360ac1e175d305daa3c5f6b4f6acb2dd` | 38 | 2025-07-27 |
| `7c7017a52c787a08772f42614b670f7b6e5ba472e6db88427945c1310c15b2c0` | 36 | 2025-08-01 |

### Secondary build — imphash `df407d359c3abfab25011d2a0d9ec42a` (10 samples)

| SHA256 | Detections | First Seen (UTC) |
|---|---|---|
| `5c929c8cc12504b1b3a164284a6b83ff32e15defe54c9dbae81b0e37e65fe1be` | 19 | 2025-07-22 |
| `3481106ad452f684e0d5ccfa6e7c185663480f6c7fa757caef384415140136ba` | 12 | 2025-07-23 |
| `c3e80d2f7953592e0e0ba7e04303b8b2ea3e519959aa72ece25eccac45476648` | 14 | 2025-07-23 |
| `e5ae65729a7af8f71300aacba0eade5c320cfd0ce89c56c57ec71d7eb914a951` | 13 | 2025-07-23 |
| `780754c3300ae9e3ed22b4abbb5ddbf590767a6c2a2328410e482bb0392d69d3` | 16 | 2025-07-23 |
| `3b4737d4378bfbe94a22ec6cbbec1996eb7672b8a7c242c021eb7cb3bb533493` | 15 | 2025-07-23 |
| `2816f350bbcb35c731817608f5d434dd031ab772eaaef9fe6dccd6335038ab59` | 22 | 2025-07-23 |
| `2f831be1bcd62d67c187a1111bd36d04c1e07e23962f64e0c9f11ea31871ce85` | 24 | 2025-07-23 |
| `b3379bea18d40b3eb33d7626965f5b7424b958bd78290e4b1efbc3f360be94f9` | 29 | 2025-07-23 |
| `5b58365f174fb44c8b56f7ac354f65b888578a9ae6b56f651066bc926b966152` | 28 | 2025-07-24 |

### Outlier / early builds — singleton imphashes (9 samples)

| SHA256 | Detections | First Seen (UTC) |
|---|---|---|
| `03a29678b78f390dc4bbb4f485e4905b640b82cfa99ad976b475c1114d69146e` | 37 | 2025-07-24 |
| `de48ed56bcf188e538d298777f29105c9d4cf7ed68571e2129865e981707e90a` | 33 | 2025-07-24 |
| `a5cc95fa6d8e28f563cda46b9f5a8e5d9ed41bb96dca5f2a43e6c33e5a3fc6a1` | 30 | 2025-07-26 |
| `7f6e02f7dfe64bcce460a241fdd5c41d39e43f0b0bec169372ebe3488b7bd9fd` | 29 | 2025-07-26 |
| `f0041ce7a604bcc466cd4cda5cafec35493e07e65b435a0417ac8b88a11b4a44` | 36 | 2025-07-26 |
| `d583f60cdbd0909965d3e8f14fe6f3d663b93dd6850c7c2e5734954053d0e33d` | 31 | 2025-07-26 |
| `2beb652cdf326670d04da2a5bb75acfe12f6610ca26cf1b4c355de527c56f8e9` | 36 | 2025-07-26 |
| `80690dcc5b7779ca26ff7b981e101ddb74e5e3bd10edcec343de0325cdfe835a` | 34 | 2025-07-27 |
| `6994b8b2b870f4e920b969b9efca6bdce9fca8dce2f4a782dfae1e7af2b20a77` | 37 | 2025-07-27 |

The two dominant clusters share the same submission window and filename; the imphash split reflects a recompilation with different linked assemblies (a .NET framework or dependency change), not two distinct tools.

---

## Binary Details

| Field | Value |
|---|---|
| File type | PE32+ executable (console), x86-64 |
| Filename | `ConsoleApplication1.exe` (41/41) |
| Code signing | None |
| PE resources | Single `RT_MANIFEST` (entropy ~4.91) — standard app manifest, **no embedded payload** |
| CompanyName / ProductName / FileDescription | All null |
| Detection range | 12–45 |

The default project name plus fully stripped version metadata indicates a build pipeline that was never hardened for deployment — either operator carelessness or a deliberate refusal to supply cover naming that would itself be a signature.

---

## Behavioral Indicators

Observed across 41 samples under automated analysis:

| Detection | Hits | Coverage | Significance |
|---|---|---|---|
| Dynamic .NET compilation via `csc.exe` | 33/41 | 80% | Direct confirmation of the runtime-compilation model |
| .NET compiler compiling from a suspicious location | 31/41 | 76% | Compilation input in a temp / non-standard path |
| Dynamic C# compile artifact written | 31/41 | 76% | Transient `.cs` / `.dll` during compilation |
| Stdin contents read via `cmd.exe` | 2/41 | 5% | Possible piping of the model response |
| DNS query to malware-hosting / shortener services | 2/41 | 5% | Candidate secondary delivery path |
| Python image loaded by non-Python process | 2/41 | 5% | Stage 3 may involve a Python runtime |
| Non-interactive PowerShell spawned | 1/41 | 2% | Post-compilation tasking candidate |
| DNS query to IP-lookup service API | 1/41 | 2% | Victim geolocation profiling |

The top three form one tight cluster present in ~80% of samples — this is the family's defining behavior, not a sandbox artifact. The low-frequency hits appear on 1–2 samples each and should be treated as leads rather than family traits.

---

## Infrastructure

**LLM endpoint:** `generativelanguage.googleapis.com` (Google Gemini).

**No operator C2 has been identified** — no command-and-control domain, IP, or pre-staged payload URL. This is a structural property of the design rather than a gap in collection: with the model generating stage 2 on demand, the operator has nothing to host.

The absence of attacker-controlled infrastructure is the family's most significant defensive implication. Conventional blocking — sinkholes, domain takedowns, payload hash blocklists — has no target. The only chokepoint is the inference provider itself.

---

## Detection

### YARA

```yara
rule T3-HONESTCUE_LLM_Probe_Loader
{
    meta:
        description = "Detects HONESTCUE downloader — hard-coded Gemini API prompts embedded as binary string literals; probe prompt contains 'class named AITask'; stage2 prompts reference Stage2 class and CSharpCodeProvider for fileless in-memory C# compilation"
        author = "CAIRN"
        artifact_class = "llm_api_backdoor"
        artifact_type = "downloader"
        tier = "T3"
        confidence = "high"
        family = "HONESTCUE"
        reference = "Mandiant GTIG blog Sep 2025"

    strings:
        $aitask_prompt  = "class named AITask"                nocase
        $stage2_prompt  = "class named 'Stage2'"              nocase
        $csharp_compile = "CSharpCodeProvider"                nocase
        $gemini_api     = "generativelanguage.googleapis.com" nocase
        $honestcue      = "HONESTCUE"                         nocase

    condition:
        $honestcue or $aitask_prompt or $stage2_prompt or
        ($csharp_compile and $gemini_api)
}
```

### Detection Guidance

The prompt strings are the durable anchor — they are functional requirements of the design, not incidental strings, and cannot be removed without breaking the loader. They can, however, be obfuscated; the behavioral chain cannot.

**Highest-value composite signal:** an unsigned .NET console executable that issues an outbound request to a generative-AI endpoint and then invokes `csc.exe`. Legitimate software that compiles C# at runtime exists, but almost none of it sources the source code from an LLM API moments earlier.

Practical controls:

1. **Alert on `csc.exe` spawned by a non-developer process**, particularly where the compilation input sits in a temp path.
2. **Treat outbound inference-API traffic from non-developer endpoints as anomalous.** For this family it is a hard dependency: no model access means no payload.
3. **Do not rely on payload-based detection.** There is no payload to detect until after the model responds, and it may differ every run.

---

## Open Questions

1. **What does the generated stage 2 actually do?** Unresolved, and structurally hard to resolve — the code is fileless, model-generated, and potentially different on each execution. Capturing the Gemini response, not the binary, is the only path to an answer.
2. **How is the Gemini API key supplied?** Whether it is embedded in the binary or fetched at runtime is undetermined. This matters materially: an embedded key is both a takedown lever and an attribution artifact.
3. **Is Python part of stage 3?** Two samples loaded a Python image into a non-Python process. At 2/41 this is a lead, not a family characteristic.
4. **One operator or a shared kit?** The 11-day window and two-cluster build structure are consistent with a single operator, but do not exclude multiple deployments of a shared loader.
5. **Post-August 2025 activity.** The observation window closes 2025-08-01. Whether the operator retooled, changed provider, or stopped is unknown.

---

*SHA256 hashes truncated to 8 characters in narrative; full hashes in tables. Last updated 2026-08-04.*
