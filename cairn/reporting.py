from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from cairn.config import PROJECT_ROOT, settings
from cairn.corpus import Corpus


def summary(*, database_path: Path | None = None) -> dict[str, Any]:
    return Corpus(database_path or settings().database_path).summary()


def export_summary_csv(path: Path | None = None, *, database_path: Path | None = None) -> Path:
    output_path = path or PROJECT_ROOT / "outputs" / "rule_yield.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = summary(database_path=database_path)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["rule_name", "tier", "samples"])
        writer.writeheader()
        for row in payload["samples_by_rule"]:
            writer.writerow(row)
    return output_path


def export_markdown(path: Path | None = None, *, database_path: Path | None = None) -> Path:
    output_path = path or PROJECT_ROOT / "outputs" / "cairn_findings.md"
    payload = summary(database_path=database_path)
    lines = [
        "# CAIRN Findings Draft",
        "",
        f"- Samples in corpus: {payload['samples']}",
        f"- Rule matches: {payload['rule_matches']}",
        "",
        "## Rule Yield",
        "",
    ]
    for row in payload["samples_by_rule"]:
        lines.append(f"- `{row['rule_name']}` ({row['tier']}): {row['samples']} samples")
    lines.extend(["", "## Acquisition Channels", ""])
    for row in payload["samples_by_filter"]:
        lines.append(f"- {row['filter_name']}: {row['samples']} distinct samples")
    lines.extend(["", "## Recent Runs", "", "```json", json.dumps(payload["recent_runs"], indent=2), "```", ""])
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path

