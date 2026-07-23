from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cairn.config import PROJECT_ROOT, settings
from cairn.corpus import Corpus


def build_graph(*, database_path: Path | None = None) -> dict[str, list[dict[str, Any]]]:
    corpus = Corpus(database_path or settings().database_path)
    rows = corpus.graph_rows()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def node(node_id: str, label: str, node_type: str, **attrs: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "label": label, "type": node_type, **attrs})

    for sample in rows["samples"]:
        sample_id = f"sample:{sample['sha256']}"
        tags = _json(sample.get("tags_json"), [])
        raw = _json(sample.get("raw_json"), {})
        node(
            sample_id,
            sample.get("name") or sample["sha256"][:12],
            "sample",
            sha256=sample["sha256"],
            detections=sample.get("detections") or 0,
            file_type=sample.get("file_type"),
            first_seen=sample.get("first_seen"),
            vt_url=sample.get("vt_url"),
            tags=tags,
        )
        for provider in ((raw.get("cairn") or {}).get("provider_references") or []):
            provider_id = f"provider:{provider}"
            node(provider_id, provider, "provider")
            edges.append(
                {
                    "source": sample_id,
                    "target": provider_id,
                    "type": "references_provider",
                    "weight": 1,
                    "evidence": provider,
                }
            )

    for item in rows["filters"]:
        filter_id = f"filter:{item['filter_slug']}"
        sample_id = f"sample:{item['sample_sha256']}"
        node(filter_id, item["filter_name"], "acquisition_filter", slug=item["filter_slug"])
        edges.append(
            {
                "source": sample_id,
                "target": filter_id,
                "type": "acquired_by",
                "weight": item.get("times_seen") or 1,
                "evidence": f"{item['filter_name']} matched sample",
            }
        )

    for match in rows["matches"]:
        rule_id = f"rule:{match['rule_name']}"
        sample_id = f"sample:{match['sample_sha256']}"
        node(
            rule_id,
            match["rule_name"],
            "yara_rule",
            tier=match["tier"],
            artifact_class=match["artifact_class"],
            confidence=match["confidence"],
        )
        edges.append(
            {
                "source": sample_id,
                "target": rule_id,
                "type": "matched_rule",
                "weight": max(1, int(match.get("confidence") or 50) // 20),
                "evidence": match.get("description") or match["rule_name"],
            }
        )

    return {"nodes": list(nodes.values()), "edges": edges}


def export_graph(path: Path | None = None, *, database_path: Path | None = None) -> Path:
    output_path = path or PROJECT_ROOT / "outputs" / "graphs" / "cairn_graph.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(build_graph(database_path=database_path), indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def _json(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default

