#!/usr/bin/env bash
# Scaffolds a new family report at docs/<FAMILYNAME>.md
# Usage: bash .claude/skills/new-family-report/scaffold.sh FAMILYNAME
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
FAMILY="${1:-}"

if [[ -z "$FAMILY" ]]; then
  echo "Usage: $0 FAMILYNAME" >&2
  exit 1
fi

OUT="$REPO/docs/${FAMILY}.md"

if [[ -f "$OUT" ]]; then
  echo "ERROR: $OUT already exists. Delete it first if you want to regenerate." >&2
  exit 1
fi

TODAY="$(date +%Y-%m-%d)"
AUTHOR="Ryan Fetterman (rfetterman@cisco.com)"

cat > "$OUT" << TEMPLATE
# ${FAMILY} — Research Report

**Family designation:** ${FAMILY} (CAIRN research name; no public attribution at time of writing)
**Author:** ${AUTHOR}
**First seen:** <!-- YYYY-MM-DD -->
**Last seen:** <!-- YYYY-MM-DD (campaign active / inactive) -->
**Variants:** <!-- N binaries (language/toolchain) -->
**Platform:** <!-- Windows x86-64 / Linux / macOS; language -->
**CAIRN rules:** \`<!-- T3-RULE_NAME -->\`
**Related report:** <!-- [OTHER.md](OTHER.md) — co-deployed family (brief description) --> N/A

---

## Summary

<!-- 2–4 paragraphs. Cover: what it is, what makes it distinctive, co-deployment if any,
     known operator signals. End with the standard coverage line below. -->

<!-- PLACEHOLDER: Brief description of what ${FAMILY} is and does. -->

No public analyst coverage was found at any point during the investigation.

---

## Discovery

<!-- How CAIRN surfaced this family. Which filter slug returned the first sample,
     what string in the binary caused the hit, what pivot recovered additional variants.
     Be specific — filter slug, acquisition query, relationship type used. -->

CAIRN's \`<!-- filter-slug -->\` acquisition filter returned \`<!-- sha256[:8] -->\` on <!-- date -->.
<!-- Describe what string or signal caused the hit. -->

<!-- Optional: pivot chain that recovered additional variants. -->

---

## <!-- COMPONENT_NAME -->.exe — <!-- Role (e.g. LLM Gateway and RAT, Loader, WebRAT Agent) -->

### Binary Characteristics

| Field | Value |
|---|---|
| File type | <!-- PE32+ executable (console/GUI) x86-64 --> |
| Compiler | <!-- Go / MinGW-w64 C / MSVC / Node.js pkg / PyInstaller / Java --> |
| Version | <!-- e.g. go1.26.2 / v3.2.1.0 --> |
| Code size | <!-- ~N MB (packed/unpacked) --> |
| Internal name | <!-- from PE resource strings --> |
| Import hash | <!-- md5 of import table --> |
| Module / package | <!-- e.g. svc (Go main package at svc/main.go) --> |

<!-- Describe notable characteristics: framework, capabilities confirmed from source paths,
     any unusual compilation flags or obfuscation. -->

### Code-Signing Certificate

<!-- If present. Note: self-signed vs trusted CA, issuing entity, cert date vs first-seen date.
     If absent: "Variants are unsigned." -->

| Field | Value |
|---|---|
| Subject | <!-- CompanyName, CN --> |
| Issuer | <!-- self-signed / trusted CA --> |
| Serial | <!-- hex --> |
| SHA1 thumbprint | <!-- for sigcheck pivots --> |
| Valid from / to | <!-- dates --> |

### PE Resource Strings

| Field | Value |
|---|---|
| FileDescription | |
| CompanyName | |
| ProductName | |
| InternalName / OriginalFileName | |

### Embedded URL Infrastructure

<!-- All URLs from VT embedded_url relationship objects, resolved with cairn pivot-urls.
     Table: URL | Role/Origin -->

| URL | Role |
|---|---|
| <!-- url --> | <!-- role --> |

<!-- Note if any are toolchain artifacts (Go dev pages, npm packages) vs operational infrastructure. -->

### Sandbox Behavior and Detection

<!-- AV detection count, notable AV family names, sandbox behavioral tags.
     What the binary actually does vs what it stalls on.
     If it requires a co-resident component, say so explicitly — this explains sandbox inertness. -->

### Variants (N confirmed)

| SHA256 | Detections | First Seen (UTC) | Notes |
|---|---|---|---|
| \`<!-- sha256 -->\` | <!-- N --> | <!-- YYYY-MM-DD HH:MM --> | <!-- seed; notable features --> |

### VT Submission Source Keys

All samples \`times_submitted=1\`, \`unique_sources=1\`:

| SHA256 | Binary | Source Key | CC | Date |
|---|---|---|---|---|
| \`<!-- sha256[:8] -->\` | <!-- name --> | \`<!-- key -->\` | <!-- CC --> | <!-- date --> |

<!-- Key observations: which source key is the primary submitter, any shared keys across families. -->

---

<!-- Repeat the above component section for each distinct binary in the family.
     e.g. ## loader_full.exe — Loader / Dropper  -->

---

## Infection Chain

<!-- How the operator goes from zero to fully deployed on a victim machine.
     Use a numbered sequence for the happy path. Call out gaps explicitly.

     Cover:
     1. Initial access — how the operator reaches the victim (known / unknown / inferred)
     2. Deployment sequence — what gets dropped or injected, in what order, with timing where known
     3. Component dependencies — which components require others to be present/running
     4. Persistence mechanisms — how each persistent component survives reboot
     5. Operator command path — how the operator issues commands post-deployment
     6. Key / credential custody — if credentials pass between components, document the flow

     Example structure:
     1. [Initial access — unknown / inferred / confirmed mechanism]
     2. [First artifact dropped or run]
     3. [Second artifact — dependency on step 2 if any]
     ...
     N. [Operator has full access via C2]

     Gap: [list what is unconfirmed or unknown]
-->

**Initial access:** <!-- unknown / inferred: credential stuffing, exposed service, phishing, etc. -->

**Deployment sequence:**

1. <!-- Step 1 -->
2. <!-- Step 2 -->
3. <!-- Step 3 -->

**Component dependencies:**

- <!-- e.g. ComponentA requires ComponentB to be running on :PORT -->

**Persistence:**

- <!-- e.g. Scheduled task, registry Run key, WMI subscription, service install -->

**Operator command path:**

<!-- How does the operator issue commands after deployment? e.g. CS Aggressor → TS → beacon polling,
     direct C2 HTTP transport, etc. -->

**Key / credential custody:**

<!-- If any component receives credentials from another (e.g. API keys, tokens), document the flow.
     e.g. TS → stager (ARX decrypt) → sysupdsvc (via :7778 registration response) -->

**Gaps:**

- <!-- e.g. Initial access vector unknown -->
- <!-- e.g. Order of component deployment unconfirmed -->

---

## Actor Timeline

| Date | SHA256 | Binary | Component | Notes |
|---|---|---|---|---|
| <!-- YYYY-MM-DD --> | \`<!-- sha256[:8] -->\` | <!-- name --> | <!-- component label --> | <!-- notes --> |

---

## Architecture

| Component | Binary | Language | Role | C2 |
|---|---|---|---|---|
| <!-- label --> | <!-- filename --> | <!-- language --> | <!-- role --> | <!-- C2 address or local port --> |

---

## Infrastructure IOCs

<!-- Domains, IPs, certificates, exfil channels (webhooks, cloud storage, social handles).
     Group by actor-linked cluster vs unconfirmed. Note hosting provider for each IP. -->

**Actor-linked domain cluster:**

- \`<!-- domain -->\` — <!-- registrar, NS, registration date -->
  - \`<!-- subdomain -->\` → \`<!-- IP -->\` (<!-- provider -->) — <!-- role -->

**Certificates:**

- <!-- cert thumbprint, issuer, issued date, domain -->

**Exfil / social channels:**

- <!-- Discord webhook ID, GoFile, ImgBB username, etc. -->

---

## Assessment

### Archetype

<!-- Where does this family fit in the AI-malware taxonomy? Use the table from LLMGATE.md
     as reference. If it represents a new archetype, propose a designation. -->

### APT vs. FIN Assessment

**FIN indicators:**
- <!-- e.g. commodity stealer co-deployed, crimeware infrastructure, etc. -->

**APT indicators:**
- <!-- e.g. long infrastructure preparation, novel watermark, targeted deployment, etc. -->

**Assessment:** <!-- One-paragraph conclusion with confidence level. -->

### Inferred Use Case

<!-- What is the operator actually using this for? What does the evidence constrain?
     Be explicit about what is confirmed vs inferred vs speculative.
     Confidence: high / medium / medium-low / low -->

### Attribution Signals

<!-- Specific, evidence-backed signals. Operator handles, infrastructure overlaps,
     toolchain fingerprints, language indicators. -->

### Open Questions

- <!-- e.g. C2 URL not recovered -->
- <!-- e.g. Initial access vector unknown -->
- <!-- e.g. Component X role unresolved -->

---

## CAIRN Rules

\`\`\`yara
rule T3-${FAMILY}_<!-- descriptor -->
{
    meta:
        tier = "T3"  family = "${FAMILY}"  confidence = "<!-- high/medium -->"
        description = "<!-- one-line description of what this fires on -->"
    strings:
        \$s1 = "<!-- string 1 -->" nocase
        \$s2 = "<!-- string 2 -->" nocase
    condition:
        \$s1 or \$s2
}
\`\`\`

<!-- Note: which cluster members this rule fires on and via which scan-text source
     (sandbox DNS, embedded URL objects, AV detection strings, PE resource strings). -->

---

## Update Log

| Date | Change |
|---|---|
| ${TODAY} | Initial scaffold — <!-- brief summary of what is known at creation time --> |

---

*Discovered using CAIRN v0.1.0. Report last updated ${TODAY}. Author: ${AUTHOR}*
TEMPLATE

echo "Created: $OUT"
