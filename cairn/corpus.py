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

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cairn.models import AcquisitionFilter, RuleMatch, SampleRecord


def _dedup_matched_strings(matched_strings: list) -> list[dict]:
    """Return one representative hit per unique identifier, up to 50 total.

    The raw list can have dozens of hits for the same $identifier when a string
    appears many times in scan_text (e.g. $dashscope firing 12 times). Keeping
    all of them crowds out hits from other identifiers and fills the stored
    audit trail with redundant entries. We take the first hit for each identifier,
    then pad with any remaining unique-identifier hits up to the cap.
    """
    seen: set[str] = set()
    deduped: list[dict] = []
    rest: list[dict] = []
    for hit in matched_strings:
        identifier = getattr(hit, "identifier", None) or hit.__dict__.get("identifier")
        if identifier not in seen:
            seen.add(identifier)
            deduped.append(hit.__dict__)
        else:
            rest.append(hit.__dict__)
    combined = deduped + rest
    return combined[:50]


class Corpus:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS samples (
                    sha256 TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    vt_url TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    file_type TEXT,
                    detections INTEGER NOT NULL DEFAULT 0,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    raw_json TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS acquisition_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filter_slug TEXT NOT NULL,
                    filter_name TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    effective_query_text TEXT NOT NULL,
                    fallback_reason TEXT,
                    status TEXT NOT NULL,
                    requested INTEGER NOT NULL,
                    found INTEGER NOT NULL DEFAULT 0,
                    imported INTEGER NOT NULL DEFAULT 0,
                    matched_samples INTEGER NOT NULL DEFAULT 0,
                    rule_hits INTEGER NOT NULL DEFAULT 0,
                    date_clause TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL DEFAULT '',
                    started_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS sample_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
                    filter_slug TEXT NOT NULL,
                    filter_name TEXT NOT NULL,
                    acquisition_run_id INTEGER REFERENCES acquisition_runs(id) ON DELETE SET NULL,
                    first_imported_at TEXT NOT NULL,
                    last_imported_at TEXT NOT NULL,
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(sample_sha256, filter_slug)
                );

                CREATE TABLE IF NOT EXISTS rule_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sample_sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
                    rule_name TEXT NOT NULL,
                    tier TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_class TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    matched_strings_json TEXT NOT NULL,
                    matched_at TEXT NOT NULL,
                    UNIQUE(sample_sha256, rule_name)
                );

                CREATE TABLE IF NOT EXISTS known_seeds (
                    sha256 TEXT PRIMARY KEY,
                    family_name TEXT NOT NULL,
                    source_name TEXT NOT NULL DEFAULT '',
                    source_url TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    labels_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS expected_rule_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seed_sha256 TEXT NOT NULL REFERENCES known_seeds(sha256) ON DELETE CASCADE,
                    rule_name TEXT NOT NULL,
                    expected_result TEXT NOT NULL,
                    expectation_type TEXT NOT NULL DEFAULT 'positive_seed',
                    notes TEXT NOT NULL DEFAULT '',
                    UNIQUE(seed_sha256, rule_name)
                );

                CREATE TABLE IF NOT EXISTS validation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seed_sha256 TEXT NOT NULL REFERENCES known_seeds(sha256) ON DELETE CASCADE,
                    rule_name TEXT NOT NULL,
                    observed_match INTEGER NOT NULL,
                    expected_result TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    matched_strings_json TEXT NOT NULL DEFAULT '[]',
                    validated_at TEXT NOT NULL,
                    UNIQUE(seed_sha256, rule_name)
                );

                CREATE TABLE IF NOT EXISTS artifact_embeddings (
                    sha256      TEXT PRIMARY KEY REFERENCES samples(sha256) ON DELETE CASCADE,
                    model       TEXT NOT NULL,
                    embedding   BLOB NOT NULL,
                    text_len    INTEGER,
                    embedded_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS artifact_clusters (
                    sha256      TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
                    cluster_id  INTEGER NOT NULL,
                    model       TEXT NOT NULL,
                    run_id      TEXT NOT NULL,
                    PRIMARY KEY (sha256, run_id)
                );

                CREATE TABLE IF NOT EXISTS artifact_projections (
                    sha256  TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
                    run_id  TEXT NOT NULL,
                    x       REAL NOT NULL,
                    y       REAL NOT NULL,
                    PRIMARY KEY (sha256, run_id)
                );

                CREATE TABLE IF NOT EXISTS pivot_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seed TEXT NOT NULL,
                    seed_type TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    discovered_sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
                    pivoted_at TEXT NOT NULL,
                    UNIQUE(seed, relationship, discovered_sha256)
                );

                CREATE TABLE IF NOT EXISTS promptintel_iocs (
                    id                   TEXT PRIMARY KEY,
                    title                TEXT NOT NULL,
                    prompt               TEXT NOT NULL,
                    severity             TEXT NOT NULL,
                    categories_json      TEXT NOT NULL DEFAULT '[]',
                    threats_json         TEXT NOT NULL DEFAULT '[]',
                    tags_json            TEXT NOT NULL DEFAULT '[]',
                    nova_rule            TEXT,
                    reference_urls_json  TEXT NOT NULL DEFAULT '[]',
                    author               TEXT NOT NULL DEFAULT '',
                    impact_description   TEXT,
                    binary_relevant      INTEGER NOT NULL DEFAULT 0,
                    api_created_at       TEXT NOT NULL,
                    synced_at            TEXT NOT NULL,
                    updated_at           TEXT NOT NULL
                );
                """
            )
        # Migrate existing DBs that predate the date_clause column.
        with self.connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(acquisition_runs)")}
            if "date_clause" not in cols:
                conn.execute("ALTER TABLE acquisition_runs ADD COLUMN date_clause TEXT NOT NULL DEFAULT ''")

    def start_run(self, acquisition_filter: AcquisitionFilter, *, requested: int, effective_query_text: str | None = None, date_clause: str = "") -> int:
        now = _now()
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO acquisition_runs (
                    filter_slug, filter_name, query_text, effective_query_text, status,
                    requested, date_clause, started_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)
                """,
                (
                    acquisition_filter.slug,
                    acquisition_filter.name,
                    acquisition_filter.query_text,
                    effective_query_text or acquisition_filter.query_text,
                    requested,
                    date_clause,
                    now,
                ),
            )
            return int(cur.lastrowid)

    def finish_run(
        self,
        run_id: int,
        *,
        status: str,
        found: int,
        imported: int,
        matched_samples: int,
        rule_hits: int,
        message: str,
        effective_query_text: str,
        fallback_reason: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE acquisition_runs
                SET status = ?, found = ?, imported = ?, matched_samples = ?, rule_hits = ?,
                    message = ?, effective_query_text = ?, fallback_reason = ?, completed_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    found,
                    imported,
                    matched_samples,
                    rule_hits,
                    message,
                    effective_query_text,
                    fallback_reason,
                    _now(),
                    run_id,
                ),
            )

    def upsert_sample(
        self,
        sample: SampleRecord,
        acquisition_filter: AcquisitionFilter,
        run_id: int,
        matches: list[RuleMatch],
    ) -> bool:
        now = _now()
        with self.connect() as conn:
            existed = conn.execute("SELECT sha256 FROM samples WHERE sha256 = ?", (sample.sha256,)).fetchone()
            conn.execute(
                """
                INSERT INTO samples (
                    sha256, name, vt_url, first_seen, last_seen, file_type, detections,
                    tags_json, raw_json, collected_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    name = excluded.name,
                    vt_url = excluded.vt_url,
                    first_seen = COALESCE(samples.first_seen, excluded.first_seen),
                    last_seen = excluded.last_seen,
                    file_type = excluded.file_type,
                    detections = excluded.detections,
                    tags_json = excluded.tags_json,
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at
                """,
                (
                    sample.sha256,
                    sample.name,
                    sample.vt_url,
                    sample.first_seen,
                    sample.last_seen,
                    sample.file_type,
                    sample.detections,
                    json.dumps(sample.tags),
                    json.dumps(sample.raw, sort_keys=True),
                    sample.collected_at.isoformat(),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO sample_filters (
                    sample_sha256, filter_slug, filter_name, acquisition_run_id,
                    first_imported_at, last_imported_at, times_seen
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(sample_sha256, filter_slug) DO UPDATE SET
                    acquisition_run_id = excluded.acquisition_run_id,
                    last_imported_at = excluded.last_imported_at,
                    times_seen = sample_filters.times_seen + 1
                """,
                (sample.sha256, acquisition_filter.slug, acquisition_filter.name, run_id, now, now),
            )
            conn.execute("DELETE FROM rule_matches WHERE sample_sha256 = ?", (sample.sha256,))
            for match in matches:
                conn.execute(
                    """
                    INSERT INTO rule_matches (
                        sample_sha256, rule_name, tier, artifact_type, artifact_class,
                        confidence, description, matched_strings_json, matched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sample_sha256, rule_name) DO UPDATE SET
                        tier = excluded.tier,
                        artifact_type = excluded.artifact_type,
                        artifact_class = excluded.artifact_class,
                        confidence = excluded.confidence,
                        description = excluded.description,
                        matched_strings_json = excluded.matched_strings_json,
                        matched_at = excluded.matched_at
                    """,
                    (
                        sample.sha256,
                        match.rule,
                        match.tier,
                        match.artifact_type,
                        match.artifact_class,
                        match.confidence,
                        match.description,
                        json.dumps([hit.__dict__ for hit in match.matched_strings[:20]], sort_keys=True),
                        now,
                    ),
                )
        return not bool(existed)

    def rescan_samples(self, rules_text: str) -> dict[str, Any]:
        """Re-run YARA rules against all stored sample scan_text without making API calls.

        Deletes all existing rule_matches and replaces them with fresh results based on
        the current rules and the enriched scan_text (which may now include exiftool,
        pe_info, sigma_analysis_results, and relationship data stored in raw_json).
        """
        from cairn.rules import parse_yara_rules, run_yara_rules
        from cairn.vt import VTRow, scan_text_from_vt_row

        rules, errors = parse_yara_rules(rules_text)
        if not rules or errors:
            raise ValueError(f"Rule validation failed: {errors}")

        now = _now()
        rescanned = 0
        rule_hits_total = 0
        samples_matched = 0

        with self.connect() as conn:
            rows = conn.execute("SELECT sha256, raw_json FROM samples ORDER BY sha256").fetchall()
            conn.execute("DELETE FROM rule_matches")
            for row in rows:
                sha256 = row["sha256"]
                raw = json.loads(row["raw_json"] or "{}")
                vt_row = VTRow(
                    object_id=sha256,
                    attributes=raw.get("attributes", {}),
                    relationships=raw.get("relationships", {}),
                    raw=raw,
                )
                scan_text = scan_text_from_vt_row(vt_row)
                matches = run_yara_rules(scan_text, rules)
                for match in matches:
                    conn.execute(
                        """
                        INSERT INTO rule_matches (
                            sample_sha256, rule_name, tier, artifact_type, artifact_class,
                            confidence, description, matched_strings_json, matched_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            sha256,
                            match.rule,
                            match.tier,
                            match.artifact_type,
                            match.artifact_class,
                            match.confidence,
                            match.description,
                            json.dumps(_dedup_matched_strings(match.matched_strings), sort_keys=True),
                            now,
                        ),
                    )
                rescanned += 1
                rule_hits_total += len(matches)
                if matches:
                    samples_matched += 1

        return {
            "rescanned": rescanned,
            "rule_hits": rule_hits_total,
            "samples_matched": samples_matched,
        }

    def summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            sample_count = conn.execute("SELECT COUNT(*) AS count FROM samples").fetchone()["count"]
            match_count = conn.execute("SELECT COUNT(*) AS count FROM rule_matches").fetchone()["count"]
            by_filter = [dict(row) for row in conn.execute(
                """
                SELECT filter_name, filter_slug, COUNT(DISTINCT sample_sha256) AS samples
                FROM sample_filters
                GROUP BY filter_slug, filter_name
                ORDER BY samples DESC, filter_name
                """
            )]
            by_rule = [dict(row) for row in conn.execute(
                """
                SELECT rule_name, tier, COUNT(DISTINCT sample_sha256) AS samples
                FROM rule_matches
                GROUP BY rule_name, tier
                ORDER BY samples DESC, rule_name
                """
            )]
            runs = [dict(row) for row in conn.execute(
                """
                SELECT id, filter_name, status, found, imported, matched_samples, rule_hits,
                       started_at, completed_at, message
                FROM acquisition_runs
                ORDER BY id DESC
                LIMIT 10
                """
            )]
        return {
            "database": str(self.path),
            "samples": sample_count,
            "rule_matches": match_count,
            "samples_by_filter": by_filter,
            "samples_by_rule": by_rule,
            "recent_runs": runs,
        }

    def pull_status(self) -> list[dict[str, Any]]:
        """Per-filter summary: last run date, date_clause used, and import counts."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    r.filter_slug,
                    r.filter_name,
                    r.started_at        AS last_run,
                    r.date_clause,
                    r.found,
                    r.imported,
                    r.status
                FROM acquisition_runs r
                INNER JOIN (
                    SELECT filter_slug, MAX(started_at) AS max_started
                    FROM acquisition_runs
                    GROUP BY filter_slug
                ) latest ON r.filter_slug = latest.filter_slug
                         AND r.started_at = latest.max_started
                ORDER BY r.filter_slug
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def graph_rows(self) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as conn:
            samples = [dict(row) for row in conn.execute("SELECT * FROM samples")]
            filters = [dict(row) for row in conn.execute("SELECT * FROM sample_filters")]
            matches = [dict(row) for row in conn.execute("SELECT * FROM rule_matches")]
        return {"samples": samples, "filters": filters, "matches": matches}

    def upsert_seed(
        self,
        *,
        sha256: str,
        family_name: str,
        source_name: str = "",
        source_url: str = "",
        description: str = "",
        notes: str = "",
        labels: dict[str, str] | None = None,
        expectations: list[dict[str, str]] | None = None,
    ) -> None:
        now = _now()
        normalized = sha256.lower().strip()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO known_seeds (
                    sha256, family_name, source_name, source_url, description,
                    notes, labels_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    family_name = excluded.family_name,
                    source_name = excluded.source_name,
                    source_url = excluded.source_url,
                    description = excluded.description,
                    notes = excluded.notes,
                    labels_json = excluded.labels_json,
                    updated_at = excluded.updated_at
                """,
                (
                    normalized,
                    family_name,
                    source_name,
                    source_url,
                    description,
                    notes,
                    json.dumps(labels or {}, sort_keys=True),
                    now,
                    now,
                ),
            )
            for expectation in expectations or []:
                conn.execute(
                    """
                    INSERT INTO expected_rule_matches (
                        seed_sha256, rule_name, expected_result, expectation_type, notes
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(seed_sha256, rule_name) DO UPDATE SET
                        expected_result = excluded.expected_result,
                        expectation_type = excluded.expectation_type,
                        notes = excluded.notes
                    """,
                    (
                        normalized,
                        expectation["rule_name"],
                        expectation.get("expected_result", "should_match"),
                        expectation.get("expectation_type", "positive_seed"),
                        expectation.get("notes", ""),
                    ),
                )

    def validation_inputs(self) -> dict[str, list[dict[str, Any]]]:
        with self.connect() as conn:
            seeds = [dict(row) for row in conn.execute("SELECT * FROM known_seeds ORDER BY family_name, sha256")]
            expectations = [
                dict(row)
                for row in conn.execute("SELECT * FROM expected_rule_matches ORDER BY seed_sha256, rule_name")
            ]
            samples = [dict(row) for row in conn.execute("SELECT * FROM samples")]
        return {"seeds": seeds, "expectations": expectations, "samples": samples}

    def store_validation_result(
        self,
        *,
        seed_sha256: str,
        rule_name: str,
        observed_match: bool,
        expected_result: str,
        validation_status: str,
        matched_strings: list[dict[str, Any]],
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO validation_results (
                    seed_sha256, rule_name, observed_match, expected_result,
                    validation_status, matched_strings_json, validated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(seed_sha256, rule_name) DO UPDATE SET
                    observed_match = excluded.observed_match,
                    expected_result = excluded.expected_result,
                    validation_status = excluded.validation_status,
                    matched_strings_json = excluded.matched_strings_json,
                    validated_at = excluded.validated_at
                """,
                (
                    seed_sha256,
                    rule_name,
                    1 if observed_match else 0,
                    expected_result,
                    validation_status,
                    json.dumps(matched_strings, sort_keys=True),
                    _now(),
                ),
            )

    def validation_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            seeds = [dict(row) for row in conn.execute("SELECT * FROM known_seeds ORDER BY family_name, sha256")]
            results = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT seed_sha256, rule_name, observed_match, expected_result,
                           validation_status, validated_at
                    FROM validation_results
                    ORDER BY seed_sha256, rule_name
                    """
                )
            ]
        return {"seeds": seeds, "results": results}


    def record_pivot_sample(
        self,
        sample: SampleRecord,
        matches: list[RuleMatch],
        *,
        seed: str,
        seed_type: str,
        relationship: str,
    ) -> bool:
        """Upsert a pivot-discovered sample and record its provenance edge.

        Returns True if the sample is new to the corpus.
        """
        now = _now()
        with self.connect() as conn:
            existed = conn.execute("SELECT sha256 FROM samples WHERE sha256 = ?", (sample.sha256,)).fetchone()
            conn.execute(
                """
                INSERT INTO samples (
                    sha256, name, vt_url, first_seen, last_seen, file_type, detections,
                    tags_json, raw_json, collected_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    name = excluded.name,
                    vt_url = excluded.vt_url,
                    first_seen = COALESCE(samples.first_seen, excluded.first_seen),
                    last_seen = excluded.last_seen,
                    file_type = excluded.file_type,
                    detections = excluded.detections,
                    tags_json = excluded.tags_json,
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at
                """,
                (
                    sample.sha256, sample.name, sample.vt_url,
                    sample.first_seen, sample.last_seen, sample.file_type,
                    sample.detections, json.dumps(sample.tags),
                    json.dumps(sample.raw, sort_keys=True),
                    sample.collected_at.isoformat(), now,
                ),
            )
            conn.execute("DELETE FROM rule_matches WHERE sample_sha256 = ?", (sample.sha256,))
            for match in matches:
                conn.execute(
                    """
                    INSERT INTO rule_matches (
                        sample_sha256, rule_name, tier, artifact_type, artifact_class,
                        confidence, description, matched_strings_json, matched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sample_sha256, rule_name) DO UPDATE SET
                        tier = excluded.tier,
                        artifact_type = excluded.artifact_type,
                        artifact_class = excluded.artifact_class,
                        confidence = excluded.confidence,
                        description = excluded.description,
                        matched_strings_json = excluded.matched_strings_json,
                        matched_at = excluded.matched_at
                    """,
                    (
                        sample.sha256, match.rule, match.tier, match.artifact_type,
                        match.artifact_class, match.confidence, match.description,
                        json.dumps([hit.__dict__ for hit in match.matched_strings[:20]], sort_keys=True),
                        now,
                    ),
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO pivot_edges
                    (seed, seed_type, relationship, discovered_sha256, pivoted_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (seed, seed_type, relationship, sample.sha256, now),
            )
        return not bool(existed)

    def update_sample_raw_and_matches(
        self,
        sha256: str,
        raw: dict[str, Any],
        matches: list[RuleMatch],
        sample: "SampleRecord | None" = None,
    ) -> None:
        """Upsert raw_json and rule_matches for a sample.

        If the sample does not yet exist in the corpus (e.g. refreshing a seed hash
        that was never pulled), it is inserted using the provided SampleRecord.
        Passing sample=None and the row not existing raises IntegrityError as before.
        """
        now = _now()
        with self.connect() as conn:
            if sample is not None:
                conn.execute(
                    """
                    INSERT INTO samples (
                        sha256, name, vt_url, first_seen, last_seen, file_type, detections,
                        tags_json, raw_json, collected_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        name = excluded.name,
                        vt_url = excluded.vt_url,
                        last_seen = excluded.last_seen,
                        file_type = excluded.file_type,
                        detections = excluded.detections,
                        tags_json = excluded.tags_json,
                        raw_json = excluded.raw_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        sample.sha256, sample.name, sample.vt_url,
                        sample.first_seen, sample.last_seen, sample.file_type,
                        sample.detections, json.dumps(sample.tags),
                        json.dumps(raw, sort_keys=True),
                        sample.collected_at.isoformat(), now,
                    ),
                )
            else:
                conn.execute(
                    "UPDATE samples SET raw_json = ?, updated_at = ? WHERE sha256 = ?",
                    (json.dumps(raw, sort_keys=True), now, sha256),
                )
            conn.execute("DELETE FROM rule_matches WHERE sample_sha256 = ?", (sha256,))
            for match in matches:
                conn.execute(
                    """
                    INSERT INTO rule_matches (
                        sample_sha256, rule_name, tier, artifact_type, artifact_class,
                        confidence, description, matched_strings_json, matched_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sha256,
                        match.rule,
                        match.tier,
                        match.artifact_type,
                        match.artifact_class,
                        match.confidence,
                        match.description,
                        json.dumps([hit.__dict__ for hit in match.matched_strings[:20]], sort_keys=True),
                        now,
                    ),
                )

    def store_submitter_keys(self, sha256: str, source_keys: list[str]) -> None:
        """Patch cairn.submitter_keys into an existing sample's raw_json."""
        with self.connect() as conn:
            row = conn.execute("SELECT raw_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
            if not row:
                return
            raw = json.loads(row["raw_json"] or "{}")
            raw.setdefault("cairn", {})["submitter_keys"] = source_keys
            conn.execute(
                "UPDATE samples SET raw_json = ?, updated_at = ? WHERE sha256 = ?",
                (json.dumps(raw, sort_keys=True), _now(), sha256),
            )

    def sha256s_missing_submitters(self, *, t3_only: bool = False) -> list[str]:
        """Return sha256s that have no cairn.submitter_keys stored yet.

        If t3_only=True, restrict to samples with at least one T3 rule match.
        T3-matched samples are returned first regardless.
        """
        with self.connect() as conn:
            if t3_only:
                rows = conn.execute("""
                    SELECT DISTINCT s.sha256, s.raw_json
                    FROM samples s
                    INNER JOIN rule_matches rm ON s.sha256 = rm.sample_sha256
                    WHERE rm.tier = 'T3' AND s.raw_json IS NOT NULL
                """).fetchall()
            else:
                t3_shas = {
                    row[0] for row in conn.execute(
                        "SELECT DISTINCT sample_sha256 FROM rule_matches WHERE tier = 'T3'"
                    ).fetchall()
                }
                rows = conn.execute("SELECT sha256, raw_json FROM samples WHERE raw_json IS NOT NULL").fetchall()
                rows = sorted(rows, key=lambda r: 0 if r["sha256"] in t3_shas else 1)
        missing = []
        for row in rows:
            try:
                raw = json.loads(row["raw_json"])
            except (TypeError, ValueError):
                missing.append(row["sha256"])
                continue
            if "submitter_keys" not in (raw.get("cairn") or {}):
                missing.append(row["sha256"])
        return missing

    def store_embeddings(
        self,
        rows: list[tuple[str, str, Any, int]],
    ) -> None:
        """Upsert (sha256, model, float32_vector, text_len) tuples into artifact_embeddings."""
        import numpy as np

        now = _now()
        with self.connect() as conn:
            for sha256, model, vector, text_len in rows:
                blob = np.array(vector, dtype=np.float32).tobytes()
                conn.execute(
                    """
                    INSERT INTO artifact_embeddings (sha256, model, embedding, text_len, embedded_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        model = excluded.model,
                        embedding = excluded.embedding,
                        text_len = excluded.text_len,
                        embedded_at = excluded.embedded_at
                    """,
                    (sha256, model, blob, text_len, now),
                )

    def load_embeddings(self, model: str | None = None) -> list[sqlite3.Row]:
        """Return all rows from artifact_embeddings, optionally filtered by model name."""
        with self.connect() as conn:
            if model:
                return conn.execute(
                    "SELECT sha256, model, embedding, text_len FROM artifact_embeddings "
                    "WHERE model = ? ORDER BY sha256",
                    (model,),
                ).fetchall()
            return conn.execute(
                "SELECT sha256, model, embedding, text_len FROM artifact_embeddings ORDER BY sha256"
            ).fetchall()

    def store_clusters(
        self,
        run_id: str,
        rows: list[tuple[str, int, str]],
    ) -> None:
        """Insert (sha256, cluster_id, model) cluster assignments for a given run_id."""
        with self.connect() as conn:
            for sha256, cluster_id, model in rows:
                conn.execute(
                    """
                    INSERT INTO artifact_clusters (sha256, cluster_id, model, run_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(sha256, run_id) DO UPDATE SET
                        cluster_id = excluded.cluster_id,
                        model = excluded.model
                    """,
                    (sha256, cluster_id, model, run_id),
                )

    def store_projections(self, run_id: str, rows: list[tuple[str, float, float]]) -> None:
        """Insert (sha256, x, y) 2D projection coords for a given run_id."""
        with self.connect() as conn:
            for sha256, x, y in rows:
                conn.execute(
                    "INSERT INTO artifact_projections (sha256, run_id, x, y) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(sha256, run_id) DO UPDATE SET x=excluded.x, y=excluded.y",
                    (sha256, run_id, x, y),
                )

    def load_projections(self, run_id: str | None = None) -> list[dict[str, Any]]:
        """Load latest projection run (or named run_id). Returns list of {sha256, x, y, cluster_id}."""
        with self.connect() as conn:
            if run_id is None:
                row = conn.execute(
                    "SELECT run_id FROM artifact_projections ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
                if not row:
                    return []
                run_id = row[0]
            latest_cluster_run_row = conn.execute(
                "SELECT run_id FROM artifact_clusters ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            cluster_run = latest_cluster_run_row[0] if latest_cluster_run_row else None
            if cluster_run:
                rows_out = conn.execute(
                    "SELECT p.sha256, p.x, p.y, c.cluster_id "
                    "FROM artifact_projections p "
                    "LEFT JOIN artifact_clusters c ON p.sha256 = c.sha256 AND c.run_id = ? "
                    "WHERE p.run_id = ?",
                    (cluster_run, run_id),
                ).fetchall()
            else:
                rows_out = conn.execute(
                    "SELECT sha256, x, y, NULL as cluster_id FROM artifact_projections WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            return [dict(r) for r in rows_out]

    def cluster_summary(self, run_id: str | None = None) -> list[dict[str, Any]]:
        """Return per-cluster summary rows for the latest (or named) cluster run.

        Each row: {cluster_id, size, families, det_min, det_max, det_median,
                   tags, names, first_seen_min, first_seen_max}
        Clusters are sorted by size descending; noise (-1) is last.
        """
        with self.connect() as conn:
            if run_id is None:
                row = conn.execute(
                    "SELECT run_id FROM artifact_clusters ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
                if not row:
                    return []
                run_id = row[0]

            # Pull all cluster members with sample metadata + T3 family attribution
            rows = conn.execute(
                """
                SELECT ac.cluster_id, ac.sha256,
                       s.detections, s.first_seen, s.tags_json, s.name,
                       rm.rule_name
                FROM artifact_clusters ac
                JOIN samples s ON s.sha256 = ac.sha256
                LEFT JOIN rule_matches rm
                    ON rm.sample_sha256 = ac.sha256 AND rm.tier = 'T3'
                WHERE ac.run_id = ?
                ORDER BY ac.cluster_id, ac.sha256
                """,
                (run_id,),
            ).fetchall()

        if not rows:
            return []

        import statistics

        clusters: dict[int, dict[str, Any]] = {}
        for r in rows:
            cid = r["cluster_id"]
            if cid not in clusters:
                clusters[cid] = {
                    "cluster_id": cid,
                    "shas": set(),
                    "detections": [],
                    "first_seen": [],
                    "tags": set(),
                    "names": set(),
                    "families": set(),
                    "rule_names": set(),
                }
            c = clusters[cid]
            sha = r["sha256"]
            if sha not in c["shas"]:
                c["shas"].add(sha)
                if r["detections"] is not None:
                    c["detections"].append(r["detections"])
                if r["first_seen"]:
                    c["first_seen"].append(r["first_seen"])
                if r["name"]:
                    c["names"].add(r["name"])
                try:
                    import json as _json
                    for tag in _json.loads(r["tags_json"] or "[]"):
                        c["tags"].add(tag)
                except Exception:
                    pass
            if r["rule_name"]:
                c["rule_names"].add(r["rule_name"])
                rn = r["rule_name"]
                if rn.startswith("T3-") and "_" in rn:
                    c["families"].add(rn[3:].split("_")[0])

        result = []
        for c in clusters.values():
            dets = sorted(c["detections"])
            result.append({
                "cluster_id": c["cluster_id"],
                "size": len(c["shas"]),
                "shas": sorted(c["shas"]),
                "families": sorted(c["families"]),
                "attributed": bool(c["families"]),
                "rule_names": sorted(c["rule_names"]),
                "det_min": min(dets) if dets else None,
                "det_max": max(dets) if dets else None,
                "det_median": statistics.median(dets) if dets else None,
                "tags": sorted(c["tags"])[:10],
                "names": sorted(c["names"])[:5],
                "first_seen_min": min(c["first_seen"]) if c["first_seen"] else None,
                "first_seen_max": max(c["first_seen"]) if c["first_seen"] else None,
            })

        # Sort: attributed first (by size), then unattributed (by size), then noise
        result.sort(key=lambda x: (
            1 if x["cluster_id"] == -1 else 0,
            0 if x["attributed"] else 1,
            -x["size"],
        ))
        return result

    def enrich_near_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Attach name, file_type, detections, and rule_matches to cosine_near output rows."""
        if not results:
            return []
        shas = [r["sha256"] for r in results]
        placeholders = ",".join("?" * len(shas))
        with self.connect() as conn:
            sample_map = {
                row["sha256"]: row
                for row in conn.execute(
                    f"SELECT sha256, name, file_type, detections FROM samples "
                    f"WHERE sha256 IN ({placeholders})",
                    shas,
                ).fetchall()
            }
            match_map: dict[str, list[str]] = {}
            for row in conn.execute(
                f"SELECT sample_sha256, rule_name FROM rule_matches "
                f"WHERE sample_sha256 IN ({placeholders})",
                shas,
            ).fetchall():
                match_map.setdefault(row["sample_sha256"], []).append(row["rule_name"])
        enriched = []
        for r in results:
            sha = r["sha256"]
            sample = sample_map.get(sha)
            enriched.append(
                {
                    "sha256": sha,
                    "score": r["score"],
                    "name": sample["name"] if sample else "",
                    "file_type": sample["file_type"] if sample else "",
                    "detections": sample["detections"] if sample else 0,
                    "rule_matches": match_map.get(sha, []),
                }
            )
        return enriched


    def prune_excluded(self, excluded: set[str]) -> dict[str, int]:
        """Delete all samples whose SHA256 is in the exclusion set.

        Cascades to sample_filters, rule_matches, pivot_edges, artifact_embeddings,
        and artifact_clusters via ON DELETE CASCADE foreign keys. known_seeds entries
        are NOT deleted — a seed remaining in the exclusion list would be a data-model
        error, so we report those separately rather than silently dropping them.

        Returns {"pruned": N, "seed_conflicts": [sha256, ...]}.
        """
        if not excluded:
            return {"pruned": 0, "seed_conflicts": []}

        placeholders = ",".join("?" * len(excluded))
        values = list(excluded)

        with self.connect() as conn:
            seed_conflicts = [
                row[0]
                for row in conn.execute(
                    f"SELECT sha256 FROM known_seeds WHERE sha256 IN ({placeholders})", values
                ).fetchall()
            ]
            result = conn.execute(
                f"DELETE FROM samples WHERE sha256 IN ({placeholders})", values
            )
            pruned = result.rowcount

        return {"pruned": pruned, "seed_conflicts": seed_conflicts}

    def upsert_promptintel_ioc(
        self,
        record: dict[str, Any],
        *,
        binary_relevant: bool,
        synced_at: str,
    ) -> bool:
        """Upsert a PromptIntel IOC record. Returns True if the row is newly inserted."""
        with self.connect() as conn:
            existed = conn.execute(
                "SELECT id FROM promptintel_iocs WHERE id = ?", (record["id"],)
            ).fetchone()
            conn.execute(
                """
                INSERT INTO promptintel_iocs (
                    id, title, prompt, severity, categories_json, threats_json,
                    tags_json, nova_rule, reference_urls_json, author,
                    impact_description, binary_relevant, api_created_at,
                    synced_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title              = excluded.title,
                    prompt             = excluded.prompt,
                    severity           = excluded.severity,
                    categories_json    = excluded.categories_json,
                    threats_json       = excluded.threats_json,
                    tags_json          = excluded.tags_json,
                    nova_rule          = excluded.nova_rule,
                    reference_urls_json = excluded.reference_urls_json,
                    author             = excluded.author,
                    impact_description = excluded.impact_description,
                    binary_relevant    = excluded.binary_relevant,
                    synced_at          = excluded.synced_at,
                    updated_at         = excluded.updated_at
                """,
                (
                    record["id"],
                    record.get("title") or "",
                    record.get("prompt") or "",
                    record.get("severity") or "",
                    json.dumps(record.get("categories") or [], sort_keys=True),
                    json.dumps(record.get("threats") or [], sort_keys=True),
                    json.dumps(record.get("tags") or [], sort_keys=True),
                    record.get("nova_rule"),
                    json.dumps(record.get("reference_urls") or [], sort_keys=True),
                    record.get("author") or "",
                    record.get("impact_description"),
                    1 if binary_relevant else 0,
                    record.get("created_at") or synced_at,
                    synced_at,
                    synced_at,
                ),
            )
        return not bool(existed)

    def list_promptintel_iocs(self, *, binary_relevant_only: bool = False) -> list[dict[str, Any]]:
        """Return stored PromptIntel IOC records, newest first."""
        with self.connect() as conn:
            if binary_relevant_only:
                rows = conn.execute(
                    "SELECT * FROM promptintel_iocs WHERE binary_relevant = 1 "
                    "ORDER BY api_created_at DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM promptintel_iocs ORDER BY api_created_at DESC"
                ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["categories"] = json.loads(d.pop("categories_json", "[]"))
            d["threats"] = json.loads(d.pop("threats_json", "[]"))
            d["tags"] = json.loads(d.pop("tags_json", "[]"))
            d["reference_urls"] = json.loads(d.pop("reference_urls_json", "[]"))
            result.append(d)
        return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
