# HONESTCUE — Research Report

**Family designation:** HONESTCUE (Mandiant GTIG attribution; confirmed `popular_threat_name` on VT)
**Author:** Ryan Fetterman (https://fetterm4n.github.io)
**First seen:** 2025-07-22 (earliest VT submission in corpus)
**Last seen:** 2025-08-01 (latest submission in tight 11-day window)
**Variants:** 41 confirmed (all `ConsoleApplication1.exe`; two dominant build variants by imphash)
**Platform:** Windows x86-64; PE32+ console executable
**CAIRN rules:** `T3-HONESTCUE_LLM_Probe_Loader`
**Related report:** N/A

---

## Summary

HONESTCUE is a Windows PE loader that uses the Google Gemini API as a live code factory. Stage 1 embeds a hard-coded prompt instructing Gemini to generate a C# class (`AITask` or `Stage2`); it receives the generated code, compiles it in-memory using `CSharpCodeProvider` (invoking `csc.exe` at runtime), and executes the resulting assembly without writing a persistent file to disk. The stage2 payload is therefore never statically present in the binary and cannot be recovered from VT metadata alone.

All 41 corpus samples share the filename `ConsoleApplication1.exe` — the default Visual Studio project output name, indicating either development/testing build artifacts or a deliberate omission of cover naming. The full corpus was submitted to VirusTotal in an 11-day window (2025-07-22 to 2025-08-01). Two dominant imphash clusters account for 32 of 41 samples, indicating two stable compiled variants; 8 singleton imphashes represent outlier or early builds.

HONESTCUE was publicly attributed by Mandiant GTIG in September 2025. No actor identity or campaign targeting has been confirmed from VT metadata alone.

---

## Discovery

HONESTCUE was imported into the CAIRN corpus via the Mandiant GTIG report (September 2025) and VT `popular_threat_name` attribution. The YARA rule `T3-HONESTCUE_LLM_Probe_Loader` was written against the published indicators and fires on four independent signals: the Mandiant family label string, the hard-coded Gemini probe prompt (`class named AITask`), the in-memory C# compilation string (`CSharpCodeProvider`), and the Gemini API endpoint (`generativelanguage.googleapis.com`). Forty-one corpus samples confirmed.

---

## ConsoleApplication1.exe — LLM-Directed Loader

### Binary Characteristics

| Field | Value |
|---|---|
| File type | PE32+ executable (console) x86-64 |
| Filename | `ConsoleApplication1.exe` (all 41 samples — default VS project name) |
| Code-signing | None (no Authenticode signature) |
| PE resources | Single RT_MANIFEST (entropy ~4.91) — standard application manifest; no embedded payloads |
| CompanyName / ProductName / FileDescription | All null — stripped / default build |
| Detection range | 12–45 across corpus |
| Provider references | None recovered in CAIRN metadata |

The absence of version strings and the default Visual Studio output name together point to a development or test build pipeline that was not hardened for deployment. Either the operator left the default project settings intact, or the naming omission is deliberate obfuscation.

### Imphash Clusters

Two stable compiled variants dominate the corpus. Imphash differences indicate distinct import tables, consistent with different .NET runtime linking or dependency configurations between the two builds.

| Imphash | Sample count | Notes |
|---|---|---|
| `a63661caccd7017c284e41d9db93d8d4` | 22 | Primary build; largest cluster |
| `df407d359c3abfab25011d2a0d9ec42a` | 10 | Secondary build |
| (8 singleton imphashes) | 8 (1 each) | Outlier or early builds; pre-stable compilation |
| **Total** | **41** | |

The two dominant clusters share the same submission window and filename, indicating two parallel or sequential build configurations rather than separate campaigns.

### Execution Flow

HONESTCUE implements a three-stage LLM-as-code-factory pattern:

1. **Stage 1 — Gemini API probe.** The PE contains a hard-coded prompt string embedded as a binary string literal. At runtime it sends an HTTP POST to `generativelanguage.googleapis.com` (Google Gemini API) with a prompt instructing the model to generate a C# class named `AITask` or `Stage2`. The prompt is structurally a code-generation request, not a C2 command channel.

2. **Stage 2 — In-memory compilation.** The loader receives the LLM-generated C# source from the API response. It invokes `CSharpCodeProvider` to compile the source code at runtime, spawning `csc.exe` as a child process and writing intermediate compile artifacts to a temporary or suspicious-path location (confirmed by Sigma). The compiled assembly is loaded into memory directly.

3. **Stage 3 — Fileless execution.** The compiled assembly executes in-process. No persistent PE is written to a standard location. Stage3 payload content is unknown — it is generated fresh by the LLM at execution time and is not present in any static artifact observable via VT metadata. Two samples loaded a Python DLL from a non-Python process (`Python Image Load By Non-Python Process` sigma hit), suggesting stage3 may use Python as a runtime or that a separate Python-based tool executes co-resident.

**Gemini API key custody:** Whether the API key is hardcoded in the binary or retrieved dynamically is unknown without access to the string table. CAIRN safety constraints preclude binary download; this cannot be determined from metadata alone.

---

## Behavioral Indicators

All behavioral evidence is derived from sandbox Sigma rule matches across 41 corpus samples. No network-level IOCs (C2 domains, IPs) were recovered from VT metadata.

| Sigma Rule | Hits | Coverage | Significance |
|---|---|---|---|
| Dynamic .NET Compilation Via Csc.EXE | 33/41 | 80% | Direct confirmation of stage2 compilation model: `csc.exe` spawned at runtime |
| Dot net compiler compiles file from suspicious location | 31/41 | 76% | Compilation input sourced from a non-standard or temp path |
| Dynamic CSharp Compile Artefact | 31/41 | 76% | `.cs` source or compiled DLL written to temp / suspicious path during compilation |
| Read Contents From Stdin Via Cmd.EXE | 2/41 | 5% | Stdin-based data ingestion in loader stage; possible piped input from LLM response processing |
| DNS Query To Common Malware Hosting and Shortener Services | 2/41 | 5% | Queries to shortener / hosting services — payload delivery path candidate |
| Python Image Load By Non-Python Process | 2/41 | 5% | Python DLL loaded by a non-Python host process; stage3 may involve a Python runtime |
| Non Interactive PowerShell Process Spawned | 1/41 | 2% | Non-interactive PowerShell launched — post-compilation tasking candidate |
| Suspicious DNS Query for IP Lookup Service APIs | 1/41 | 2% | IP geolocation API query — victim profiling before primary function |

The three dominant Sigma hits (`csc.exe` compilation, suspicious-path source, compile artefact) form a tight behavioral cluster. Their consistency across 80% of samples confirms the dynamic compilation model is the defining characteristic of the family, not a sandbox artefact.

The low-frequency hits (stdin read, Python load, PowerShell) are present on only 2–1 samples. These may represent distinct stages of execution in a subset of samples, or sandbox-specific artefacts. They are documented here but not treated as defining family indicators.

---

## Build Comparison

The two dominant imphash clusters are structurally distinct compiled outputs. No behavioral differentiation between clusters is confirmed from available metadata — all Sigma-attributed behavioral data is aggregated across the full corpus and does not resolve to specific imphash groups.

| Attribute | Primary build (`a63661ca…`) | Secondary build (`df407d35…`) |
|---|---|---|
| Sample count | 22 | 10 |
| Imphash | `a63661caccd7017c284e41d9db93d8d4` | `df407d359c3abfab25011d2a0d9ec42a` |
| Filename | `ConsoleApplication1.exe` | `ConsoleApplication1.exe` |
| Platform | PE32+ x86-64 | PE32+ x86-64 |
| Code-signing | None | None |
| Behavioral differentiation | Not confirmed from metadata | Not confirmed from metadata |
| Notes | Dominant build; majority of corpus | Secondary configuration; different import table |

Both clusters share the same submission window and identical file naming. The imphash difference indicates a recompilation with different import dependencies — possibly a .NET framework version change, a different set of linked assemblies, or a minor code change that altered the import table.

---

## Infrastructure

**LLM provider endpoint:** `generativelanguage.googleapis.com` — Google Gemini API. The stage1 loader sends code-generation prompts to this endpoint at runtime.

**No operator C2 identified.** No command-and-control domains, IPs, or hardcoded stage2 delivery URLs were recovered from VT metadata. Stage2 is generated by the Gemini API at execution time; there is no pre-staged binary payload to host.

**`popular_threat_label`:** `suggested_threat_label: trojan.agentb/cryp`. `popular_threat_name` entries: `agentb` (2), `cryp` (2), `honestcue` (2). The `honestcue` name appears on multiple samples, confirming AV engine attribution consistent with the Mandiant family designation.

---

## Assessment

### Archetype

**HONESTCUE is archetype A1 — LLM-Directed Payload Generation.** Confirmed.

The family instantiates A1 directly: the loader embeds a hard-coded prompt at build time, sends it to Google Gemini at runtime, receives executable C# source code in response, and compiles and executes it in-memory via `CSharpCodeProvider`. The LLM is a code factory — it is not a C2 channel, not a credential target, and not a routing layer. The generated stage2 is the payload; the LLM generates it fresh per execution.

This is distinct from A2 (LLMGATE — LLM traffic routing through victim egress), A4 (WURM — LLM as live tasking channel), and A6 (credential harvesters). The definining property of A1 is that **the LLM output is executable code that runs immediately**, not instructions to the operator or routed traffic.

PromptLock was the first confirmed A1 instance (2025-08-25 corpus entry; Lua script generating SPECK-based encryption via an LLM). HONESTCUE is the second confirmed A1 instance; it extends the archetype into the C# / .NET compilation domain and substitutes Google Gemini for PromptLock's provider. Both families share the core A1 pattern: prompt embedded at build time → LLM generates code → code executes immediately → no static payload artifact.

**Archetypes column:** A1.

### Assessment

HONESTCUE demonstrates that the A1 LLM-Directed Payload Generation pattern is not limited to a single provider, language, or compilation model. PromptLock used a Lua-scripted LLM prompt to generate encryption logic; HONESTCUE uses a .NET/C# compilation pipeline with Google Gemini. The Mandiant GTIG public attribution in September 2025 confirms external analyst visibility. The tight 11-day submission window (2025-07-22 to 2025-08-01) and two-cluster imphash structure are consistent with a concentrated test or deployment period followed by cessation or retooling.

No actor identity, targeting sector, or initial access vector is confirmed from VT metadata.

**Confidence:** High (A1 archetype confirmed; behavioral indicators consistent across 80% of corpus; Mandiant attribution corroborated by VT `popular_threat_name`).

### Open Questions

- **Gemini API key custody:** Hardcoded binary string or retrieved dynamically? Cannot determine without string table access (binary not downloadable under CAIRN safety constraints).
- **Stage2 payload content:** What does the Gemini-generated C# code actually do? Unknown. The fileless execution model leaves no recoverable artifact in VT metadata. The generated code changes per execution and may vary across samples or over time.
- **Python Image Load hits (2 samples):** Is stage2 launching a Python runtime as a sub-component? Or is a separate Python-based tool co-executing alongside the loader? The 2/41 hit rate does not confirm this as a family-wide behavior.
- **Single operator or kit?** Do all 41 samples represent one operator's deployment, or multiple independent deployments of a shared loader kit? The tight submission window and two-cluster structure are consistent with a single operator, but VT submission source key analysis was not performed.
- **Post-August 2025 activity:** The corpus window closes 2025-08-01. No subsequent variants have been confirmed. Whether the operator retooled, shifted provider, or ceased operations is unknown.
- **Stage2 variability:** Because stage2 is LLM-generated at execution time, the actual payload behavior may differ across executions even for the same binary. Sandbox captures may not be representative.

---

## CAIRN Rules

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
        reference = "Mandiant GTIG blog Sep 2025; Gemini API generates C# stage2 downloader/reflective loader compiled in-memory via CSharpCodeProvider; Discord CDN payload delivery"

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

Fires on:
- Samples carrying the `HONESTCUE` AV/Mandiant detection label string
- Samples with the hard-coded Gemini code-generation prompt (`class named AITask` or `class named 'Stage2'`)
- Samples combining in-memory C# compilation with the Gemini API endpoint (`CSharpCodeProvider` AND `generativelanguage.googleapis.com`)

All 41 corpus samples confirmed against this rule via `cairn rescan`.

---

## Indicators of Compromise

**Registered seed:** `eb0687daed29f3651c61b0a2aa4a0cdcf2049a1ebae2e15e2dd9326471d318a1` (status: not_tested — hash not yet in corpus at time of report)

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

---

## Update Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial report — 41 samples confirmed; two-cluster imphash structure documented; behavioral indicators from Sigma corpus; A1 archetype confirmed; seed registered (not_tested) |

---

*Discovered using CAIRN v0.1.0. Report last updated 2026-06-12. Author: Ryan Fetterman (https://fetterm4n.github.io)*
