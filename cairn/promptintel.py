"""PromptIntel IOC feed sync — fetches the novahunting.ai prompt IOC catalogue
and stores new/updated records in the local corpus.

Binary-relevant heuristic: a record is flagged when the prompt is likely
embedded in a malware binary rather than being a runtime jailbreak.
Signals: `abuse` category + a high-signal threat type (malware generation,
AI-driven attack enablement, supply-chain abuse, agentic misuse, harmful
automation) OR the presence of reference URLs with known malware tags.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

PROMPTINTEL_BASE = "https://api.promptintel.novahunting.ai/api/v1"
PROMPTS_URL = f"{PROMPTINTEL_BASE}/prompts"

# Threats that indicate the prompt is embedded inside a malware artifact
_BINARY_THREAT_SIGNALS = {
    "Malware generation",
    "AI driven attack enablement",
    "Supply Chain Abuse (package-level prompts)",
    "Agentic Misuse (tool/agent loops)",
    "Harmful Automation Guidance",
    "Automation for crime",
}


def _is_binary_relevant(record: dict[str, Any]) -> bool:
    categories = set(record.get("categories") or [])
    threats = set(record.get("threats") or [])
    refs = record.get("reference_urls") or []

    if not refs:
        return False

    if "abuse" not in categories:
        return False

    return bool(threats & _BINARY_THREAT_SIGNALS)


async def fetch_all_prompts(api_key: str) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(PROMPTS_URL, headers=headers, params={"limit": 100})
        response.raise_for_status()
        data = response.json()

    records = data.get("data") or []
    pagination = data.get("pagination") or {}
    total = pagination.get("total", len(records))

    # If there are more pages, fetch them
    page = 2
    while len(records) < total:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                PROMPTS_URL, headers=headers, params={"limit": 100, "page": page}
            )
            response.raise_for_status()
            batch = response.json().get("data") or []
        if not batch:
            break
        records.extend(batch)
        page += 1

    return records


async def sync_promptintel(api_key: str, *, database_path: Any = None) -> dict[str, Any]:
    from cairn.config import settings
    from cairn.corpus import Corpus

    corpus = Corpus(database_path or settings().database_path)
    records = await fetch_all_prompts(api_key)

    now = datetime.now(timezone.utc).isoformat()
    new_count = 0
    updated_count = 0
    binary_relevant_new: list[dict[str, Any]] = []

    for record in records:
        binary_relevant = _is_binary_relevant(record)
        was_new = corpus.upsert_promptintel_ioc(record, binary_relevant=binary_relevant, synced_at=now)
        if was_new:
            new_count += 1
            if binary_relevant:
                binary_relevant_new.append({
                    "id": record.get("id"),
                    "title": record.get("title"),
                    "severity": record.get("severity"),
                    "categories": record.get("categories"),
                    "threats": record.get("threats"),
                    "tags": record.get("tags"),
                    "has_nova_rule": bool(record.get("nova_rule")),
                    "reference_urls": record.get("reference_urls") or [],
                    "is_new": True,
                })
        else:
            updated_count += 1

    return {
        "fetched": len(records),
        "new": new_count,
        "updated": updated_count,
        "binary_relevant_new": len(binary_relevant_new),
        "binary_relevant_records": binary_relevant_new,
    }
