# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Evidence-provenance audit for rule matches.

Codifies the fourteenth and sixteenth methodological lessons (docs/SOA.md):
a string recovered from VT sandbox **memory** proves only that the sample
*assembled* it at runtime, never that it was *embedded* in the file. Four
retractions (SCRIBESIPHON, ZAPRETCORE, JACKALCLIENT, and the SUPERO/RIFTLOADER
pair) each rested in part on reading a sandbox observation as a static one.

The classic shape of the error, from JACKALCLIENT: five LLM provider domains
appeared in `memory_pattern_urls` and were reported as "hardcoded in the
binary." Static RE proved them absent from the file in every encoding — the
program built the URLs at runtime for a bring-your-own-key user chat feature.

`memory_pattern_urls`/`_domains`/`_ips` come from Zenbox and friends dumping
process memory *after* execution, so they capture format-string output,
decrypted config, and library-assembled request URLs indiscriminately. Every
other scan_text source (exiftool, pe_info, content snippets, submission names)
is a static property of the file.

This module answers one question per rule match: **does this hit survive if
sandbox-memory evidence is removed?** A hit that does not is not necessarily
wrong — JOBRADAR is a confirmed family whose T3 rule is memory-only — but it
is a hit whose report must say "observed in sandbox memory," not "embedded."

**Surviving this filter is necessary, not sufficient** (eighteenth lesson,
CLOSEDQUORUM). "Static" means *present in the file*; it does not mean *authored
by the program*. An embedded third-party data blob — a CA bundle, an X.509
certificate, a vendored asset — is statically present and semantically
irrelevant, and nothing here can tell the two apart. CLOSEDQUORUM's four Stripe
hostnames sat in `relationships/embedded_urls`, passed this audit, and were
SAN/CN entries inside certificate material Go's TLS stack had pulled in; 59 of
the same sample's 65 memory URLs were CA CRL/OCSP endpoints. Two checks this
module does not perform, worth running by hand on any surviving hit: does the
extracted set *exactly reproduce a published list* (an allowlist, a CA bundle,
a default config), and is it *dominated by one third party's infrastructure*?
Either answer being yes means the strings belong to the blob, not the malware.

Also note `embedded_urls` splices adjacent Go string-table entries with no
terminator (`https://api.deepseek.com/v1/chat/completions\\Microsoft\\Edge\\User`),
so adjacency in it carries no semantics — the same defect as the memory fields.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any

# VT behaviour keys populated from a post-execution process-memory dump.
# A string present ONLY under these keys was assembled at runtime.
MEMORY_PATTERN_KEYS = frozenset(
    {
        "memory_pattern_urls",
        "memory_pattern_domains",
        "memory_pattern_ips",
    }
)


@dataclass(frozen=True)
class ProvenanceFinding:
    """One rule match whose evidence is wholly or partly sandbox-memory."""

    sha256: str
    rule: str
    tier: str
    provenance: str  # "memory_only" | "mixed"
    memory_only_patterns: list[str] = field(default_factory=list)
    static_patterns: list[str] = field(default_factory=list)
    corpus_frequency: dict[str, int] = field(default_factory=dict)

    @property
    def is_memory_only(self) -> bool:
        return self.provenance == "memory_only"

    @property
    def reading(self) -> str:
        """Which way a memory-only hit points, per the fourteenth lesson.

        A sandbox-only string **unique to one sample** points *into* the binary — it is
        evidence of runtime construction and a reason to hunt for the decoder (LLMGATE's
        `192.168.3.55`, 1 of 4829 samples, which static RE then recovered from six
        runtime-concatenated `.data` fragments). A sandbox-only string **shared across
        unrelated samples** is environmental — sandbox NAT, telemetry, library
        boilerplate — and carries no attribution weight.

        Only the unique case is decidable from metadata alone. Distinguishing "shared
        because these samples are one family" from "shared because the string is
        boilerplate" needs a relatedness signal independent of the rule that fired —
        embedding cluster, imphash, submitter, infrastructure overlap — which this
        module deliberately does not guess at. For shared strings it reports the count
        and says so.
        """
        if self.provenance != "memory_only" or not self.corpus_frequency:
            return "n/a"
        if max(self.corpus_frequency.values()) <= 1:
            return "sample_unique — likely runtime-constructed; look for the decoder"
        return (
            "shared — needs an independent relatedness check (cluster/imphash/submitter) "
            "to tell a real family cluster from boilerplate"
        )


def strip_memory_patterns(node: Any) -> Any:
    """Return `node` with every memory_pattern_* key removed, recursively."""
    if isinstance(node, dict):
        return {k: strip_memory_patterns(v) for k, v in node.items() if k not in MEMORY_PATTERN_KEYS}
    if isinstance(node, list):
        return [strip_memory_patterns(item) for item in node]
    return node


def has_memory_patterns(raw: dict[str, Any]) -> bool:
    """Cheap pre-check: does this sample carry any memory_pattern_* evidence?"""
    behaviours = raw.get("behaviours")
    if not behaviours:
        return False
    return "memory_pattern" in json.dumps(behaviours)


def audit_sample(sha256: str, raw: dict[str, Any], rules: list[Any]) -> list[ProvenanceFinding]:
    """Classify each rule match on one sample by evidence provenance.

    Re-runs the rules twice — once on full scan_text, once with memory_pattern_*
    stripped — and diffs. A rule that stops matching is memory-only; a rule that
    still matches but loses patterns is mixed.
    """
    from cairn.rules import run_yara_rules
    from cairn.vt import VTRow, scan_text_from_vt_row

    if not has_memory_patterns(raw):
        return []

    def matches_for(payload: dict[str, Any]) -> dict[str, Any]:
        row = VTRow(
            object_id=sha256,
            attributes=payload.get("attributes") or {},
            relationships=payload.get("relationships") or {},
            raw=payload,
        )
        return {m.rule: m for m in run_yara_rules(scan_text_from_vt_row(row), rules)}

    full = matches_for(raw)
    stripped_raw = copy.deepcopy(raw)
    stripped_raw["behaviours"] = strip_memory_patterns(raw.get("behaviours"))
    stripped = matches_for(stripped_raw)

    findings: list[ProvenanceFinding] = []
    for rule_name, match in full.items():
        full_pats = {hit.pattern for hit in match.matched_strings}
        if rule_name not in stripped:
            findings.append(
                ProvenanceFinding(
                    sha256=sha256,
                    rule=rule_name,
                    tier=match.tier,
                    provenance="memory_only",
                    memory_only_patterns=sorted(full_pats),
                )
            )
            continue
        static_pats = {hit.pattern for hit in stripped[rule_name].matched_strings}
        lost = full_pats - static_pats
        if lost:
            findings.append(
                ProvenanceFinding(
                    sha256=sha256,
                    rule=rule_name,
                    tier=match.tier,
                    provenance="mixed",
                    memory_only_patterns=sorted(lost),
                    static_patterns=sorted(static_pats),
                )
            )
    return findings


def _corpus_frequency(patterns: list[str], rows: list[tuple[str, str]]) -> dict[str, int]:
    """Count how many samples in the corpus contain each pattern.

    Implements the decidable half of the fourteenth lesson: a memory-only string unique
    to one sample was probably built by that sample. A count above 1 is reported as-is —
    telling "shared because one family" from "shared because boilerplate" needs a
    relatedness signal this module does not have. See `ProvenanceFinding.reading`.
    """
    counts = {p: 0 for p in patterns}
    lowered = {p: p.lower() for p in patterns}
    for _sha256, raw_json in rows:
        blob = (raw_json or "").lower()
        for pattern, needle in lowered.items():
            if needle in blob:
                counts[pattern] += 1
    return counts


def audit_corpus(
    rows: list[tuple[str, str]],
    rules_text: str,
    *,
    min_tier: str = "T1",
    with_frequency: bool = True,
) -> dict[str, Any]:
    """Audit provenance across `rows` of (sha256, raw_json).

    Returns findings plus counts. `min_tier` filters output — T3 hits matter most,
    since a T3 rule is a family-attribution claim. `with_frequency` adds the
    corpus-wide uniqueness measure that tells you which way a memory-only hit points.
    """
    from cairn.rules import parse_yara_rules

    rules, errors = parse_yara_rules(rules_text)
    if not rules or errors:
        raise ValueError(f"Rule validation failed: {errors}")

    tier_floor = {"T1": 1, "T2": 2, "T3": 3}.get(min_tier.upper(), 1)
    findings: list[ProvenanceFinding] = []
    audited = 0

    for sha256, raw_json in rows:
        try:
            raw = json.loads(raw_json or "{}")
        except json.JSONDecodeError:
            continue
        if not has_memory_patterns(raw):
            continue
        audited += 1
        for finding in audit_sample(sha256, raw, rules):
            rank = {"T1": 1, "T2": 2, "T3": 3}.get(finding.tier, 1)
            if rank >= tier_floor:
                findings.append(finding)

    if with_frequency and findings:
        # one pass over the corpus for the union of flagged patterns, not one per finding
        union = sorted({p for f in findings if f.is_memory_only for p in f.memory_only_patterns})
        freq = _corpus_frequency(union, rows) if union else {}
        findings = [
            ProvenanceFinding(
                sha256=f.sha256,
                rule=f.rule,
                tier=f.tier,
                provenance=f.provenance,
                memory_only_patterns=f.memory_only_patterns,
                static_patterns=f.static_patterns,
                corpus_frequency={p: freq[p] for p in f.memory_only_patterns if p in freq},
            )
            for f in findings
        ]

    findings.sort(key=lambda f: ({"T3": 0, "T2": 1, "T1": 2}.get(f.tier, 3), f.rule, f.sha256))
    memory_only = [f for f in findings if f.is_memory_only]

    by_rule: dict[str, int] = {}
    for finding in memory_only:
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1

    return {
        "samples_with_memory_patterns": audited,
        "memory_only_hits": len(memory_only),
        "mixed_hits": len(findings) - len(memory_only),
        "memory_only_samples": len({f.sha256 for f in memory_only}),
        "memory_only_by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        "findings": [
            {
                "sha256": f.sha256,
                "rule": f.rule,
                "tier": f.tier,
                "provenance": f.provenance,
                "memory_only_patterns": f.memory_only_patterns,
                "static_patterns": f.static_patterns,
                "corpus_frequency": f.corpus_frequency,
                "reading": f.reading,
            }
            for f in findings
        ],
    }
