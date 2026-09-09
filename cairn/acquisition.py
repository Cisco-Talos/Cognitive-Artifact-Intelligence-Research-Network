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

from __future__ import annotations

from pathlib import Path

from cairn.config import load_acquisition_filters, load_exclusions, load_rules_text, settings
from cairn.corpus import Corpus
from cairn.models import AcquisitionFilter, AcquisitionRunSummary
from cairn.rules import parse_yara_rules, run_yara_rules
from cairn.vt import VirusTotalClient, VirusTotalError, detect_seed_type, provider_references_from_row, row_to_sample, scan_text_from_vt_row


def get_filter(slug: str, *, config_path: Path | None = None) -> AcquisitionFilter:
    for acquisition_filter in load_acquisition_filters(config_path):
        if acquisition_filter.slug == slug:
            return acquisition_filter
    raise ValueError(f"Unknown acquisition filter: {slug}")


async def pull_filter(
    acquisition_filter: AcquisitionFilter,
    *,
    limit: int | None = None,
    date_clause: str = "",
    deep_lookup: bool = False,
    fetch_snippets: bool = False,
    database_path: Path | None = None,
    rules_path: Path | None = None,
) -> AcquisitionRunSummary:
    app_settings = settings()
    corpus = Corpus(database_path or app_settings.database_path)
    rules_text = load_rules_text(rules_path)
    rules, rule_errors = parse_yara_rules(rules_text)
    if not rules or rule_errors:
        raise ValueError(f"Rule validation failed: {rule_errors}")

    exclusions = load_exclusions()
    requested = max(1, min(100, int(limit or acquisition_filter.default_limit)))
    query = _with_date_clause(acquisition_filter.query_text, date_clause)
    run_id = corpus.start_run(acquisition_filter, requested=requested, effective_query_text=query, date_clause=date_clause)
    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )

    try:
        rows, effective_query, fallback_reason = await client.search_with_content_fallback(query, limit=requested)
    except VirusTotalError as exc:
        corpus.finish_run(
            run_id,
            status=exc.status,
            found=0,
            imported=0,
            matched_samples=0,
            rule_hits=0,
            message=exc.message,
            effective_query_text=query,
        )
        return AcquisitionRunSummary(
            filter_slug=acquisition_filter.slug,
            status=exc.status,
            requested=requested,
            found=0,
            imported=0,
            matched_samples=0,
            rule_hits=0,
            message=exc.message,
        )

    imported = 0
    matched_samples = 0
    rule_hits = 0
    for row in rows[:requested]:
        source_row = row
        sample = row_to_sample(row)
        if len(sample.sha256) != 64:
            continue
        if sample.sha256 in exclusions:
            continue
        if sample.detections < acquisition_filter.min_detections:
            continue
        if deep_lookup:
            try:
                source_row = await client.lookup_file(sample.sha256)
                sample = row_to_sample(source_row)
                behaviours = await client.lookup_behaviours(sample.sha256)
                if behaviours:
                    source_row.raw["behaviours"] = behaviours
                sub_keys = await client.fetch_submissions(sample.sha256)
                source_row.raw.setdefault("cairn", {})["submitter_keys"] = sub_keys
            except VirusTotalError:
                source_row = row
        # Fetch content-match snippet when requested, the query wasn't degraded to a
        # fallback (which strips content: modifiers), and the search result carries a
        # snippet ID in context_attributes.
        if fetch_snippets and not fallback_reason:
            ctx = row.raw.get("context_attributes")
            snippet_id = ctx.get("snippet") if isinstance(ctx, dict) else None
            if snippet_id:
                fragments = await client.fetch_snippet(snippet_id)
                if fragments:
                    source_row.raw["snippets"] = fragments
        scan_text = scan_text_from_vt_row(source_row)
        matches = run_yara_rules(scan_text, rules)
        refs = provider_references_from_row(source_row)
        if refs:
            source_row.raw.setdefault("cairn", {})["provider_references"] = refs
        # Rebuild sample from source_row so upsert_sample serializes the correct
        # raw_json (including snippets, behaviours, and cairn annotations).
        sample = row_to_sample(source_row)
        is_new = corpus.upsert_sample(sample, acquisition_filter, run_id, matches)
        imported += 1 if is_new else 0
        matched_samples += 1 if matches else 0
        rule_hits += len(matches)

    status = "success"
    message = (
        f"Pulled {len(rows)} VT rows, imported {imported} new samples, "
        f"and stored {rule_hits} rule hits."
    )
    if fallback_reason:
        message += " VT content search failed once, so CAIRN retried with content: modifiers stripped."
    corpus.finish_run(
        run_id,
        status=status,
        found=len(rows),
        imported=imported,
        matched_samples=matched_samples,
        rule_hits=rule_hits,
        message=message,
        effective_query_text=effective_query,
        fallback_reason=fallback_reason,
    )
    return AcquisitionRunSummary(
        filter_slug=acquisition_filter.slug,
        status=status,
        requested=requested,
        found=len(rows),
        imported=imported,
        matched_samples=matched_samples,
        rule_hits=rule_hits,
        message=message,
        fallback_query_used=bool(fallback_reason),
    )


async def pull_enabled(
    *,
    limit: int | None = None,
    date_clause: str = "",
    deep_lookup: bool = False,
    fetch_snippets: bool = False,
) -> list[AcquisitionRunSummary]:
    summaries: list[AcquisitionRunSummary] = []
    for acquisition_filter in load_acquisition_filters():
        if not acquisition_filter.enabled:
            continue
        summaries.append(
            await pull_filter(
                acquisition_filter,
                limit=limit,
                date_clause=date_clause,
                deep_lookup=deep_lookup,
                fetch_snippets=fetch_snippets,
            )
        )
    return summaries


async def refresh_samples(
    sha256_list: list[str],
    *,
    database_path: Path | None = None,
    rules_path: Path | None = None,
    fetch_behaviours: bool = False,
) -> list[dict]:
    """Deep-lookup a list of known sha256s, update raw_json, and re-run YARA.

    Each sha256 must already exist in the corpus. Returns one result dict per hash.
    Pass fetch_behaviours=True to also pull sandbox behavioural data (costs one extra
    API call per hash).
    """
    app_settings = settings()
    corpus = Corpus(database_path or app_settings.database_path)
    rules_text = load_rules_text(rules_path)
    rules, rule_errors = parse_yara_rules(rules_text)
    if not rules or rule_errors:
        raise ValueError(f"Rule validation failed: {rule_errors}")

    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )

    results = []
    for sha256 in sha256_list:
        entry: dict = {"sha256": sha256, "status": "ok", "rule_hits": 0, "rules": [], "message": ""}
        try:
            vt_row = await client.lookup_file(sha256)
            sample = row_to_sample(vt_row)
            if fetch_behaviours:
                behaviours = await client.lookup_behaviours(sha256)
                if behaviours:
                    vt_row.raw["behaviours"] = behaviours
            # Preserve snippet data from the existing DB record — snippets are only
            # fetched during cairn pull --snippets and are not returned by the plain
            # file lookup endpoint. Without this, a refresh would silently discard them.
            with corpus.connect() as _conn:
                _old = _conn.execute("SELECT raw_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
            if _old:
                import json as _json
                _old_raw = _json.loads(_old[0])
                if _old_raw.get("snippets"):
                    vt_row.raw.setdefault("snippets", _old_raw["snippets"])
            sub_keys = await client.fetch_submissions(sha256)
            vt_row.raw.setdefault("cairn", {})["submitter_keys"] = sub_keys
            scan_text = scan_text_from_vt_row(vt_row)
            matches = run_yara_rules(scan_text, rules)
            refs = provider_references_from_row(vt_row)
            if refs:
                vt_row.raw.setdefault("cairn", {})["provider_references"] = refs
            corpus.update_sample_raw_and_matches(sha256, vt_row.raw, matches, sample=sample)
            entry["rule_hits"] = len(matches)
            entry["rules"] = [m.rule for m in matches]
            entry["detections"] = sample.detections
            entry["name"] = sample.name
            entry["provider_references"] = refs
        except VirusTotalError as exc:
            entry["status"] = exc.status
            entry["message"] = exc.message
        results.append(entry)
    return results


async def pivot_embedded_urls(
    sha256: str,
    *,
    database_path: Path | None = None,
) -> list[dict]:
    """Look up all embedded_url relationship objects for a stored sample.

    Returns one dict per embedded URL with its VT metadata.
    """
    import json as _json

    app_settings = settings()
    corpus = Corpus(database_path or app_settings.database_path)
    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )

    with corpus.connect() as conn:
        row = conn.execute("SELECT raw_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    if not row:
        raise ValueError(f"SHA256 not found in corpus: {sha256}")

    raw = _json.loads(row["raw_json"] or "{}")
    embedded_data = raw.get("relationships", {}).get("embedded_urls", {}).get("data", [])
    url_ids = [item["id"] for item in embedded_data if isinstance(item, dict) and item.get("id")]

    results = []
    for url_id in url_ids:
        entry: dict = {"url_id": url_id, "status": "ok"}
        try:
            info = await client.lookup_url(url_id)
            entry.update(info)
        except VirusTotalError as exc:
            entry["status"] = exc.status
            entry["message"] = exc.message
        results.append(entry)
    return results


_DEFAULT_PIVOT_RELATIONSHIPS: dict[str, list[str]] = {
    "file": ["similar_files"],
    "domain": ["communicating_files"],
    "ip": ["communicating_files"],
}


async def pivot_from_seed(
    seed: str,
    *,
    relationships: list[str] | None = None,
    limit: int = 40,
    min_detections: int = 1,
    deep_lookup: bool = False,
    database_path: Path | None = None,
    rules_path: Path | None = None,
) -> dict:
    """Pivot from a seed (SHA256, domain, or IP) via VT relationship edges.

    Discovered file objects are imported into the corpus with pivot provenance
    recorded in the pivot_edges table. Returns a summary of what was found.
    """
    app_settings = settings()
    corpus = Corpus(database_path or app_settings.database_path)
    rules_text = load_rules_text(rules_path)
    rules, rule_errors = parse_yara_rules(rules_text)
    if not rules or rule_errors:
        raise ValueError(f"Rule validation failed: {rule_errors}")

    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )

    exclusions = load_exclusions()
    seed_clean = seed.strip()
    seed_type = detect_seed_type(seed_clean)
    rels = relationships or _DEFAULT_PIVOT_RELATIONSHIPS.get(seed_type, ["communicating_files"])

    total_found = 0
    total_new = 0
    total_rule_hits = 0
    results_by_rel: dict[str, list[dict]] = {}

    for rel in rels:
        try:
            rows = await client.fetch_relationship(seed_clean, seed_type, rel, limit=limit)
        except VirusTotalError as exc:
            results_by_rel[rel] = [{"error": exc.message}]
            continue

        rel_results = []
        for row in rows:
            sample = row_to_sample(row)
            if len(sample.sha256) != 64:
                continue
            if sample.sha256 in exclusions:
                continue
            if sample.detections < min_detections:
                continue
            source_row = row
            if deep_lookup:
                try:
                    source_row = await client.lookup_file(sample.sha256)
                    sample = row_to_sample(source_row)
                    behaviours = await client.lookup_behaviours(sample.sha256)
                    if behaviours:
                        source_row.raw["behaviours"] = behaviours
                    sub_keys = await client.fetch_submissions(sample.sha256)
                    source_row.raw.setdefault("cairn", {})["submitter_keys"] = sub_keys
                except VirusTotalError:
                    source_row = row
            scan_text = scan_text_from_vt_row(source_row)
            matches = run_yara_rules(scan_text, rules)
            refs = provider_references_from_row(source_row)
            if refs:
                source_row.raw.setdefault("cairn", {})["provider_references"] = refs
            is_new = corpus.record_pivot_sample(
                sample, matches,
                seed=seed_clean, seed_type=seed_type, relationship=rel,
            )
            total_found += 1
            total_new += 1 if is_new else 0
            total_rule_hits += len(matches)
            rel_results.append({
                "sha256": sample.sha256,
                "name": sample.name,
                "detections": sample.detections,
                "new": is_new,
                "rule_hits": [m.rule for m in matches],
            })
        results_by_rel[rel] = rel_results

    return {
        "seed": seed_clean,
        "seed_type": seed_type,
        "relationships": rels,
        "found": total_found,
        "new": total_new,
        "rule_hits": total_rule_hits,
        "results": results_by_rel,
    }


async def fetch_submitters(
    *,
    limit: int | None = None,
    t3_only: bool = False,
    database_path: Path | None = None,
) -> dict:
    """Backfill submission source_keys for corpus samples that don't have them yet.

    Skips samples where cairn.submitter_keys is already stored. Respects the
    configured rate limit and daily cap. Emits incremental progress to stdout.
    Returns a summary dict.
    """
    import sys

    app_settings = settings()
    corpus = Corpus(database_path or app_settings.database_path)
    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )

    sha256s = corpus.sha256s_missing_submitters(t3_only=t3_only)
    if limit:
        sha256s = sha256s[:limit]

    total = len(sha256s)
    done = 0
    errors = 0

    for sha256 in sha256s:
        try:
            keys = await client.fetch_submissions(sha256)
            corpus.store_submitter_keys(sha256, keys)
            done += 1
        except VirusTotalError as exc:
            errors += 1
            if exc.status in ("daily_limit_reached", "rate_limited"):
                print(f"\nAborted: {exc.message}", file=sys.stderr)
                break
        pct = int(done * 100 / total) if total else 100
        print(f"\r  {done}/{total} ({pct}%)  errors={errors}", end="", flush=True)

    print()
    return {"total": total, "done": done, "errors": errors}


def _with_date_clause(query: str, date_clause: str) -> str:
    cleaned = date_clause.strip()
    if not cleaned:
        return query
    return f"({query}) AND {cleaned}"
