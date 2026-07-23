from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cairn.config import load_rules_text, settings
from cairn.corpus import Corpus
from cairn.models import VTRow
from cairn.rules import parse_yara_rules, run_yara_rules
from cairn.vt import scan_text_from_vt_row

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

FRUITSHELL_LABELS = {
    "family": "fruitshell",
    "source": "public_poc",
    "artifact": "ai_analysis_evasion",
    "behavior": "powershell_reverse_shell",
    "validation": "yara_positive_seed",
}

FRUITSHELL_EXPECTATIONS = [
    {
        "rule_name": "T3-FRUITSHELL_PowerShell_AI_Decoy_ReverseShell",
        "expected_result": "should_match",
        "expectation_type": "positive_seed",
    },
    {
        "rule_name": "T2-AI_Decoy_Prompt_In_Malware",
        "expected_result": "should_match",
        "expectation_type": "positive_seed",
    },
    {
        "rule_name": "T1-Prompt_Residue",
        "expected_result": "should_match",
        "expectation_type": "positive_seed",
    },
    {
        "rule_name": "T2-Shell_Execution_Cooccurrence",
        "expected_result": "should_match",
        "expectation_type": "positive_seed",
    },
]


def add_seed(
    sha256: str,
    *,
    family_name: str,
    source_name: str = "",
    source_url: str = "",
    description: str = "",
    notes: str = "",
    labels: dict[str, str] | None = None,
    expectations: list[dict[str, str]] | None = None,
    database_path: Path | None = None,
) -> dict[str, Any]:
    normalized = sha256.lower().strip()
    if not SHA256_RE.match(normalized):
        raise ValueError("Seed must be a SHA256 hash.")
    corpus = Corpus(database_path or settings().database_path)
    corpus.upsert_seed(
        sha256=normalized,
        family_name=family_name,
        source_name=source_name,
        source_url=source_url,
        description=description,
        notes=notes,
        labels=labels or {},
        expectations=expectations or [],
    )
    return {"updated": True, "sha256": normalized, "family_name": family_name}


def add_fruitshell_seed(
    sha256: str,
    *,
    source_name: str = "Google Threat Intelligence Group",
    source_url: str = "https://cloud.google.com/blog/topics/threat-intelligence/",
    notes: str = "",
    database_path: Path | None = None,
) -> dict[str, Any]:
    return add_seed(
        sha256,
        family_name="FRUITSHELL",
        source_name=source_name,
        source_url=source_url,
        description="FRUITSHELL-style AI-analysis decoy and PowerShell reverse-shell seed.",
        notes=notes,
        labels=FRUITSHELL_LABELS,
        expectations=FRUITSHELL_EXPECTATIONS,
        database_path=database_path,
    )


def run_seed_validation(*, database_path: Path | None = None, rules_path: Path | None = None) -> dict[str, Any]:
    corpus = Corpus(database_path or settings().database_path)
    rules, errors = parse_yara_rules(load_rules_text(rules_path))
    if not rules or errors:
        raise ValueError(f"Rule validation failed: {errors}")
    inputs = corpus.validation_inputs()
    samples_by_hash = {row["sha256"].lower(): row for row in inputs["samples"]}
    expectations_by_seed: dict[str, list[dict[str, Any]]] = {}
    for expectation in inputs["expectations"]:
        expectations_by_seed.setdefault(expectation["seed_sha256"].lower(), []).append(expectation)

    summary = {"pass": 0, "fail": 0, "warning": 0, "not_tested": 0}
    details: list[dict[str, Any]] = []
    for seed in inputs["seeds"]:
        sha256 = seed["sha256"].lower()
        sample = samples_by_hash.get(sha256)
        observed = {}
        if sample:
            raw = json.loads(sample["raw_json"])
            row = VTRow(
                object_id=sha256,
                attributes=raw.get("attributes") if isinstance(raw.get("attributes"), dict) else {},
                relationships=raw.get("relationships") if isinstance(raw.get("relationships"), dict) else {},
                raw=raw,
            )
            observed = {match.rule: match for match in run_yara_rules(scan_text_from_vt_row(row), rules)}

        expectations = expectations_by_seed.get(sha256, [])
        if not sample:
            for expectation in expectations:
                corpus.store_validation_result(
                    seed_sha256=sha256,
                    rule_name=expectation["rule_name"],
                    observed_match=False,
                    expected_result=expectation["expected_result"],
                    validation_status="not_tested",
                    matched_strings=[],
                )
                summary["not_tested"] += 1
            details.append({"sha256": sha256, "family_name": seed["family_name"], "status": "not_tested"})
            continue

        seed_statuses = []
        for expectation in expectations:
            rule_name = expectation["rule_name"]
            observed_match = rule_name in observed
            expected_result = expectation["expected_result"]
            status = _validation_status(expected_result, observed_match)
            match = observed.get(rule_name)
            matched_strings = [hit.__dict__ for hit in (match.matched_strings if match else [])[:20]]
            corpus.store_validation_result(
                seed_sha256=sha256,
                rule_name=rule_name,
                observed_match=observed_match,
                expected_result=expected_result,
                validation_status=status,
                matched_strings=matched_strings,
            )
            summary[status] += 1
            seed_statuses.append(status)
        details.append(
            {
                "sha256": sha256,
                "family_name": seed["family_name"],
                "status": "fail" if "fail" in seed_statuses else "pass" if seed_statuses else "warning",
                "observed_rules": sorted(observed),
            }
        )
    return {"summary": summary, "details": details}


def _validation_status(expected_result: str, observed_match: bool) -> str:
    if expected_result == "should_match":
        return "pass" if observed_match else "fail"
    if expected_result == "should_not_match":
        return "fail" if observed_match else "pass"
    return "warning" if observed_match else "not_tested"

