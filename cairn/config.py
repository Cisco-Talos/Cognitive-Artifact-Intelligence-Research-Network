from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from cairn.models import AcquisitionFilter

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    vt_api_key: str
    promptintel_api_key: str
    database_path: Path
    rate_limit_per_minute: int
    daily_limit: int


def load_dotenv(path: Path | None = None) -> None:
    env_path = path or PROJECT_ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def settings() -> Settings:
    load_dotenv()
    db_path = Path(os.getenv("CAIRN_DATABASE_PATH", str(PROJECT_ROOT / "data" / "cairn.sqlite")))
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path
    return Settings(
        vt_api_key=os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY") or "",
        promptintel_api_key=os.getenv("PROMPTINTEL_API_KEY") or "",
        database_path=db_path,
        rate_limit_per_minute=int(os.getenv("CAIRN_RATE_LIMIT_PER_MINUTE", "4") or 4),
        daily_limit=int(os.getenv("CAIRN_DAILY_LIMIT", "500") or 500),
    )


def load_acquisition_filters(path: Path | None = None) -> list[AcquisitionFilter]:
    filter_path = path or PROJECT_ROOT / "config" / "acquisition_filters.yaml"
    payload = yaml.safe_load(filter_path.read_text(encoding="utf-8")) or {}
    rows = payload.get("filters") or []
    filters: list[AcquisitionFilter] = []
    for row in rows:
        filters.append(
            AcquisitionFilter(
                name=str(row["name"]),
                slug=str(row["slug"]),
                category=str(row.get("category") or "discovery"),
                description=str(row.get("description") or ""),
                query_text=str(row["query_text"]).strip(),
                enabled=bool(row.get("enabled", True)),
                default_limit=max(1, min(100, int(row.get("default_limit") or 100))),
                min_detections=max(0, int(row.get("min_detections") or 0)),
            )
        )
    return filters


def load_rules_text(path: Path | None = None) -> str:
    rules_path = path or PROJECT_ROOT / "config" / "yara_rules.yar"
    return rules_path.read_text(encoding="utf-8")


def load_threads(path: Path | None = None) -> list[dict]:
    """Parse THREADS.md into a list of thread dicts."""
    threads_path = path or PROJECT_ROOT / "THREADS.md"
    if not threads_path.exists():
        return []

    text = threads_path.read_text(encoding="utf-8")
    blocks = [b.strip() for b in text.split("\n## ") if b.strip()]

    # Drop the preamble block (no bold Status field)
    results: list[dict] = []
    for block in blocks:
        if "**Status:**" not in block:
            continue
        lines = block.splitlines()
        title = lines[0].lstrip("#").strip()
        thread: dict = {"title": title, "status": "", "source": "", "date_added": "", "hashes": [], "pivot_leads": []}

        in_pivots = False
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith("**Status:**"):
                thread["status"] = stripped.removeprefix("**Status:**").strip()
            elif stripped.startswith("**Source:**"):
                thread["source"] = stripped.removeprefix("**Source:**").strip()
            elif stripped.startswith("**Date added:**"):
                thread["date_added"] = stripped.removeprefix("**Date added:**").strip()
            elif stripped.startswith("**Hash:**"):
                thread["hashes"].append(stripped.removeprefix("**Hash:**").strip())
            elif "### Open pivot leads" in stripped or "### Pivot leads" in stripped or "### Remaining pivot leads" in stripped:
                in_pivots = True
            elif in_pivots and stripped.startswith("- "):
                thread["pivot_leads"].append(stripped.lstrip("- ").strip())
            elif in_pivots and stripped.startswith("### "):
                in_pivots = False

        results.append(thread)
    return results


def load_exclusions(path: Path | None = None) -> set[str]:
    """Return the set of excluded SHA256 hashes from config/exclusions.yaml."""
    excl_path = path or PROJECT_ROOT / "config" / "exclusions.yaml"
    if not excl_path.exists():
        return set()
    payload = yaml.safe_load(excl_path.read_text(encoding="utf-8")) or {}
    rows = payload.get("exclusions") or {}
    return {sha.lower().strip() for sha in rows}

