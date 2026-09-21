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

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from cairn.acquisition import fetch_submitters, get_filter, pivot_embedded_urls, pivot_from_seed, pull_enabled, pull_filter, refresh_samples
from cairn.config import load_acquisition_filters, load_exclusions, load_rules_text, load_threads, settings
from cairn.corpus import Corpus
from cairn.graph import export_graph
from cairn.promptintel import sync_promptintel
from cairn.reporting import export_markdown, export_summary_csv, summary
from cairn.rules import validate_yara_rules
from cairn.seeds import add_fruitshell_seed, add_seed, run_seed_validation


def main() -> None:
    parser = argparse.ArgumentParser(prog="cairn", description="CAIRN cognitive artifact research toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("filters", help="List configured VirusTotal acquisition filters")
    subparsers.add_parser("validate-rules", help="Validate local tiered YARA-style rules")

    pull = subparsers.add_parser("pull", help="Manually run one acquisition filter")
    pull.add_argument("--filter", required=True, help="Acquisition filter slug")
    pull.add_argument("--limit", type=int, default=None, help="Sample limit, max 100")
    pull.add_argument("--date-clause", default="", help='Optional VT date clause, for example fs:7d+')
    pull.add_argument("--deep", action="store_true", help="Run per-hash VT file lookup after search rows")
    pull.add_argument("--snippets", action="store_true",
                      help="Fetch content-match snippets via the VTGrep snippets endpoint (1 extra API call per pull)")

    pull_enabled_parser = subparsers.add_parser("pull-enabled", help="Manually run all enabled acquisition filters")
    pull_enabled_parser.add_argument("--limit", type=int, default=None, help="Override filter sample limit, max 100")
    pull_enabled_parser.add_argument("--date-clause", default="", help='Optional VT date clause, for example fs:7d+')
    pull_enabled_parser.add_argument("--deep", action="store_true", help="Run per-hash VT file lookup after search rows")
    pull_enabled_parser.add_argument("--snippets", action="store_true",
                                     help="Fetch content-match snippets via the VTGrep snippets endpoint (1 extra API call per filter)")

    subparsers.add_parser("summary", help="Print corpus summary")
    subparsers.add_parser("pull-status", help="Show last run date and date clause used per filter")

    graph = subparsers.add_parser("graph", help="Export graph JSON")
    graph.add_argument("--output", default="", help="Output path, default outputs/graphs/cairn_graph.json")

    report = subparsers.add_parser("report", help="Export summary CSV and markdown findings draft")
    report.add_argument("--markdown", default="", help="Markdown output path")
    report.add_argument("--csv", default="", help="CSV output path")

    seed = subparsers.add_parser("seed-add", help="Add a known seed hash and optional expected rule")
    seed.add_argument("--sha256", required=True)
    seed.add_argument("--family", required=True)
    seed.add_argument("--source-name", default="")
    seed.add_argument("--source-url", default="")
    seed.add_argument("--label", action="append", default=[], help="Label as key=value, repeatable")
    seed.add_argument("--expect", action="append", default=[], help="Expected rule as RULE or RULE:should_not_match")

    fruitshell = subparsers.add_parser("seed-fruitshell", help="Add a FRUITSHELL seed template for a provided SHA256")
    fruitshell.add_argument("--sha256", required=True)
    fruitshell.add_argument("--notes", default="")

    subparsers.add_parser("validate-seeds", help="Run known seed expected-rule validation")

    subparsers.add_parser(
        "rescan",
        help="Re-run YARA rules against all stored samples using their cached raw_json — no API calls",
    )

    pivot_rel_p = subparsers.add_parser(
        "pivot",
        help="Pivot from a seed (SHA256, domain, or IP) via VT relationship edges and import discovered samples",
    )
    pivot_rel_p.add_argument("seed", help="Seed value: 64-char SHA256, domain name, or IP address")
    pivot_rel_p.add_argument(
        "--rel", action="append", dest="relationships", metavar="RELATIONSHIP",
        help=(
            "Relationship to traverse. Repeatable. "
            "File seeds: similar_files, communicating_files, dropped_files, bundled_files, execution_parents. "
            "Domain/IP seeds: communicating_files. "
            "Default: similar_files (file) or communicating_files (domain/IP)."
        ),
    )
    pivot_rel_p.add_argument("--limit", type=int, default=40, help="Max results per relationship (max 40)")
    pivot_rel_p.add_argument("--min-detections", type=int, default=1,
                             help="Minimum detections to import a discovered sample (default 1)")
    pivot_rel_p.add_argument("--deep", action="store_true",
                             help="Fetch full file report + behaviours for each discovered sample")

    pivot_p = subparsers.add_parser(
        "pivot-urls",
        help="Look up all embedded_url relationship objects for a stored sample",
    )
    pivot_p.add_argument("sha256", help="SHA256 of the sample whose embedded URLs to pivot on")

    refresh_p = subparsers.add_parser(
        "refresh",
        help="Deep-lookup specific sha256s already in the corpus, update raw_json, and re-run YARA",
    )
    refresh_p.add_argument("--sha256", action="append", required=True, dest="sha256_list",
                           metavar="SHA256", help="SHA256 to refresh (repeatable)")
    refresh_p.add_argument("--behaviours", action="store_true",
                           help="Also fetch sandbox behavioural data (one extra API call per hash)")
    refresh_p.add_argument("--telemetry", action="store_true",
                           help="Also fetch Google Insights telemetry (one extra API call per hash)")

    telemetry_p = subparsers.add_parser(
        "telemetry",
        help="Fetch or display Google Insights telemetry for a sample",
    )
    telemetry_p.add_argument("sha256", nargs="?", help="SHA256 to fetch telemetry for")
    telemetry_p.add_argument("--corpus", action="store_true",
                             help="Summarize telemetry across all samples that have it stored")

    embed_p = subparsers.add_parser("embed", help="Encode sample scan_text into embeddings and store them")
    embed_p.add_argument("--model", default="all-MiniLM-L6-v2", help="Sentence-transformers model name")
    embed_p.add_argument("--min-chars", type=int, default=200, help="Skip samples whose scan_text is below this length")
    embed_p.add_argument("--reembed", action="store_true", help="Re-encode samples that already have a stored embedding")

    cluster_p = subparsers.add_parser("cluster", help="Cluster stored embeddings with HDBSCAN")
    cluster_p.add_argument("--model", default="all-MiniLM-L6-v2", help="Filter embeddings by this model name")
    cluster_p.add_argument("--min-cluster-size", type=int, default=3, help="HDBSCAN min_cluster_size")

    cluster_summary_p = subparsers.add_parser(
        "cluster-summary", help="Print per-cluster size, families, detection stats, and tags"
    )
    cluster_summary_p.add_argument("--min-size", type=int, default=1, help="Only show clusters with at least this many members")
    cluster_summary_p.add_argument("--unknown-only", action="store_true", help="Only show clusters with no T3 family attribution")
    cluster_summary_p.add_argument("--top", type=int, default=0, help="Limit to N largest clusters (0 = all)")
    cluster_summary_p.add_argument("--include-dead-ends", action="store_true",
        help="Include clusters suppressed by config/dead_end_hashes.txt (dead-end noise clusters)")

    project_p = subparsers.add_parser("project", help="Project embeddings to 2D for cluster visualization")
    project_p.add_argument("--model", default="all-MiniLM-L6-v2", help="Filter embeddings by this model name")
    project_p.add_argument("--method", default="auto", choices=["auto", "tsne", "umap"],
                           help="Projection method: auto (umap if available, else tsne), tsne, umap")

    near_p = subparsers.add_parser("near", help="Find nearest neighbours in embedding space for a given SHA256")
    near_p.add_argument("sha256", help="Query SHA256 (must be in the corpus)")
    near_p.add_argument("--model", default="all-MiniLM-L6-v2", help="Filter embeddings by this model name")
    near_p.add_argument("--top", type=int, default=10, help="Number of neighbours to return")

    explorer = subparsers.add_parser("explorer", help="Launch CAIRN Explorer — local graph UI in the browser")
    explorer.add_argument("--port", type=int, default=8421, help="Port (default 8421)")
    explorer.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")

    prune_p = subparsers.add_parser(
        "prune",
        help="Remove excluded samples from the corpus (reads config/exclusions.yaml)",
    )
    prune_p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be removed without making any changes",
    )

    threads_p = subparsers.add_parser("threads", help="List open investigation threads from THREADS.md")
    threads_p.add_argument("--json", action="store_true", dest="json_output", help="Emit raw JSON instead of formatted output")

    fetch_sub_p = subparsers.add_parser(
        "fetch-submitters",
        help="Backfill VT submission source_keys for corpus samples (requires VT Intelligence)",
    )
    fetch_sub_p.add_argument(
        "--limit", type=int, default=None,
        help="Max number of samples to process (default: all missing)",
    )
    fetch_sub_p.add_argument(
        "--t3-only", action="store_true",
        help="Only process samples with at least one T3 rule match",
    )

    audit_prov = subparsers.add_parser(
        "audit-provenance",
        help="Flag rule hits that rest only on VT sandbox-memory evidence (no API calls)",
    )
    audit_prov.add_argument(
        "--min-tier", default="T1", choices=["T1", "T2", "T3"],
        help="Only report hits at this tier or above (default T1)",
    )
    audit_prov.add_argument(
        "--summary-only", action="store_true",
        help="Print counts without the per-finding list",
    )

    subparsers.add_parser(
        "triage-gap",
        help="Surface high-detection samples with no or weak rule signal — the triage blind spot",
    )

    refresh_batch_p = subparsers.add_parser(
        "refresh-batch",
        help="Refresh a targeted batch of samples by SQL-driven criteria (T1-only, high-det, etc.)",
    )
    refresh_batch_p.add_argument(
        "--category",
        required=True,
        choices=["t1-only-high-det", "no-rules-high-det", "content-filter-no-rules",
                 "seeds-missing-behaviours", "go-no-rules", "go-t1-only"],
        help="Which triage-gap category to refresh",
    )
    refresh_batch_p.add_argument("--limit", type=int, default=50, help="Max samples to refresh (default 50)")
    refresh_batch_p.add_argument("--behaviours", action="store_true", help="Also fetch sandbox behavioural data")
    refresh_batch_p.add_argument("--dry-run", action="store_true", help="Show which samples would be refreshed without making API calls")

    sync_pi = subparsers.add_parser(
        "sync-promptintel",
        help="Sync PromptIntel IOC feed and report new binary-relevant records",
    )
    sync_pi.add_argument(
        "--all", action="store_true", dest="show_all",
        help="Print all stored IOCs, not just new binary-relevant ones",
    )

    args = parser.parse_args()
    if args.command == "filters":
        _print_filters()
    elif args.command == "validate-rules":
        _print_json(validate_yara_rules(load_rules_text()))
    elif args.command == "pull":
        acquisition_filter = get_filter(args.filter)
        result = asyncio.run(
            pull_filter(
                acquisition_filter,
                limit=args.limit,
                date_clause=args.date_clause,
                deep_lookup=args.deep,
                fetch_snippets=args.snippets,
            )
        )
        _print_json(result.__dict__)
    elif args.command == "pull-enabled":
        results = asyncio.run(
            pull_enabled(limit=args.limit, date_clause=args.date_clause, deep_lookup=args.deep, fetch_snippets=args.snippets)
        )
        _print_json([result.__dict__ for result in results])
    elif args.command == "summary":
        _print_json(summary())
    elif args.command == "pull-status":
        corpus = Corpus(settings().database_path)
        _print_json(corpus.pull_status())
    elif args.command == "graph":
        path = export_graph(Path(args.output) if args.output else None)
        print(path)
    elif args.command == "report":
        csv_path = export_summary_csv(Path(args.csv) if args.csv else None)
        markdown_path = export_markdown(Path(args.markdown) if args.markdown else None)
        _print_json({"csv": str(csv_path), "markdown": str(markdown_path)})
    elif args.command == "seed-add":
        _print_json(
            add_seed(
                args.sha256,
                family_name=args.family,
                source_name=args.source_name,
                source_url=args.source_url,
                labels=_labels(args.label),
                expectations=_expectations(args.expect),
            )
        )
    elif args.command == "seed-fruitshell":
        _print_json(add_fruitshell_seed(args.sha256, notes=args.notes))
    elif args.command == "validate-seeds":
        _print_json(run_seed_validation())
    elif args.command == "rescan":
        corpus = Corpus(settings().database_path)
        _print_json(corpus.rescan_samples(load_rules_text()))
    elif args.command == "pivot":
        _print_json(asyncio.run(
            pivot_from_seed(
                args.seed,
                relationships=args.relationships or None,
                limit=args.limit,
                min_detections=args.min_detections,
                deep_lookup=args.deep,
            )
        ))
    elif args.command == "pivot-urls":
        _print_json(asyncio.run(pivot_embedded_urls(args.sha256)))
    elif args.command == "refresh":
        _print_json(asyncio.run(refresh_samples(args.sha256_list, fetch_behaviours=args.behaviours, fetch_telemetry=args.telemetry)))
    elif args.command == "telemetry":
        _cmd_telemetry(args)
    elif args.command == "embed":
        _cmd_embed(args)
    elif args.command == "cluster":
        _cmd_cluster(args)
    elif args.command == "cluster-summary":
        _cmd_cluster_summary(args)
    elif args.command == "project":
        _cmd_project(args)
    elif args.command == "near":
        _cmd_near(args)
    elif args.command == "explorer":
        from cairn.explorer import serve
        serve(port=args.port, open_browser=not args.no_browser)
    elif args.command == "prune":
        _cmd_prune(args)
    elif args.command == "threads":
        threads = load_threads()
        if args.json_output:
            _print_json({"count": len(threads), "threads": threads})
        else:
            _print_threads(threads)
    elif args.command == "fetch-submitters":
        _print_json(asyncio.run(fetch_submitters(limit=args.limit, t3_only=args.t3_only)))
    elif args.command == "audit-provenance":
        corpus = Corpus(settings().database_path)
        payload = corpus.audit_provenance(load_rules_text(), min_tier=args.min_tier)
        if args.summary_only:
            payload.pop("findings", None)
        _print_json(payload)
    elif args.command == "triage-gap":
        corpus = Corpus(settings().database_path)
        _print_json(corpus.triage_gap())
    elif args.command == "refresh-batch":
        _cmd_refresh_batch(args)
    elif args.command == "sync-promptintel":
        _cmd_sync_promptintel(args)


def _cmd_embed(args: argparse.Namespace) -> None:
    from cairn.embed import encode
    from cairn.vt import VTRow, scan_text_from_vt_row

    corpus = Corpus(settings().database_path)

    existing: set[str] = set()
    if not args.reembed:
        existing = {row["sha256"] for row in corpus.load_embeddings(model=args.model)}

    with corpus.connect() as conn:
        sample_rows = conn.execute("SELECT sha256, raw_json FROM samples ORDER BY sha256").fetchall()

    to_embed: list[tuple[str, str]] = []
    skipped_thin = 0
    skipped_existing = 0

    for row in sample_rows:
        sha256 = row["sha256"]
        if sha256 in existing:
            skipped_existing += 1
            continue
        raw = json.loads(row["raw_json"] or "{}")
        vt_row = VTRow(
            object_id=sha256,
            attributes=raw.get("attributes", {}),
            relationships=raw.get("relationships", {}),
            raw=raw,
        )
        text = scan_text_from_vt_row(vt_row)
        if len(text) < args.min_chars:
            skipped_thin += 1
            continue
        to_embed.append((sha256, text))

    embedded = 0
    if to_embed:
        shas = [s for s, _ in to_embed]
        texts = [t for _, t in to_embed]
        vectors = encode(texts, args.model)
        corpus.store_embeddings(
            [(shas[i], args.model, vectors[i], len(texts[i])) for i in range(len(shas))]
        )
        embedded = len(to_embed)

    _print_json(
        {
            "embedded": embedded,
            "skipped_thin": skipped_thin,
            "skipped_existing": skipped_existing,
            "model": args.model,
        }
    )


def _cmd_cluster(args: argparse.Namespace) -> None:
    from cairn.embed import cluster, load_embeddings

    corpus = Corpus(settings().database_path)
    shas, matrix = load_embeddings(corpus, model=args.model)

    if not shas:
        _print_json({"error": "No embeddings found. Run 'cairn embed' first."})
        return

    labels = cluster(matrix, min_cluster_size=args.min_cluster_size)
    run_id = datetime.now(timezone.utc).isoformat()
    corpus.store_clusters(run_id, [(shas[i], int(labels[i]), args.model) for i in range(len(shas))])

    n_clusters = int(len(set(labels.tolist()) - {-1}))
    n_noise = int((labels == -1).sum())
    _print_json(
        {
            "run_id": run_id,
            "model": args.model,
            "clusters": n_clusters,
            "noise": n_noise,
            "total": len(shas),
        }
    )


def _load_dead_end_hashes() -> set[str]:
    """Load SHA256s from config/dead_end_hashes.txt. Returns empty set if file missing."""
    from cairn.config import PROJECT_ROOT
    path = PROJECT_ROOT / "config" / "dead_end_hashes.txt"
    if not path.exists():
        return set()
    shas: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            shas.add(line.lower())
    return shas


def _cmd_cluster_summary(args: argparse.Namespace) -> None:
    corpus = Corpus(settings().database_path)
    rows = corpus.cluster_summary()
    if not rows:
        _print_json({"error": "No cluster data. Run 'cairn cluster' first."})
        return

    if args.unknown_only:
        rows = [r for r in rows if not r["attributed"]]
    if args.min_size > 1:
        rows = [r for r in rows if r["size"] >= args.min_size]

    if not args.include_dead_ends:
        dead_end_shas = _load_dead_end_hashes()
        if dead_end_shas:
            rows = [r for r in rows if not any(sha in dead_end_shas for sha in r["shas"])]

    if args.top:
        rows = rows[:args.top]

    _print_json({
        "total_clusters": len(rows),
        "clusters": rows,
    })


def _cmd_project(args: argparse.Namespace) -> None:
    from cairn.embed import load_embeddings, project

    corpus = Corpus(settings().database_path)
    shas, matrix = load_embeddings(corpus, model=args.model)
    if not shas:
        _print_json({"error": "No embeddings found. Run 'cairn embed' first."})
        return

    coords = project(matrix, method=args.method)
    run_id = datetime.now(timezone.utc).isoformat()
    corpus.store_projections(
        run_id,
        [(shas[i], float(coords[i, 0]), float(coords[i, 1])) for i in range(len(shas))],
    )
    _print_json({"run_id": run_id, "projected": len(shas), "method": args.method})


def _cmd_near(args: argparse.Namespace) -> None:
    from cairn.embed import cosine_near, encode, load_embeddings

    corpus = Corpus(settings().database_path)
    shas, matrix = load_embeddings(corpus, model=args.model)

    if not shas:
        _print_json({"error": "No embeddings found. Run 'cairn embed' first."})
        return

    sha256 = args.sha256.lower().strip()

    if sha256 in shas:
        query_vec = matrix[shas.index(sha256)]
    else:
        with corpus.connect() as conn:
            row = conn.execute("SELECT raw_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
        if not row:
            _print_json({"error": f"SHA256 not found in corpus: {sha256}"})
            return
        from cairn.vt import VTRow, scan_text_from_vt_row

        raw = json.loads(row["raw_json"] or "{}")
        vt_row = VTRow(
            object_id=sha256,
            attributes=raw.get("attributes", {}),
            relationships=raw.get("relationships", {}),
            raw=raw,
        )
        query_vec = encode([scan_text_from_vt_row(vt_row)], args.model)[0]

    results = cosine_near(query_vec, matrix, shas, top_k=args.top + 1)
    results = [r for r in results if r["sha256"] != sha256][: args.top]
    _print_json(corpus.enrich_near_results(results))


def _cmd_prune(args: argparse.Namespace) -> None:
    excluded = load_exclusions()
    if not excluded:
        _print_json({"excluded": 0, "pruned": 0, "seed_conflicts": [], "dry_run": args.dry_run})
        return
    corpus = Corpus(settings().database_path)
    if args.dry_run:
        with corpus.connect() as conn:
            placeholders = ",".join("?" * len(excluded))
            present = [
                row[0]
                for row in conn.execute(
                    f"SELECT sha256 FROM samples WHERE sha256 IN ({placeholders})",
                    list(excluded),
                ).fetchall()
            ]
            seed_conflicts = [
                row[0]
                for row in conn.execute(
                    f"SELECT sha256 FROM known_seeds WHERE sha256 IN ({placeholders})",
                    list(excluded),
                ).fetchall()
            ]
        _print_json({
            "dry_run": True,
            "excluded": len(excluded),
            "would_prune": len(present),
            "would_prune_hashes": sorted(present),
            "seed_conflicts": seed_conflicts,
        })
    else:
        result = corpus.prune_excluded(excluded)
        _print_json({
            "dry_run": False,
            "excluded": len(excluded),
            "pruned": result["pruned"],
            "seed_conflicts": result["seed_conflicts"],
        })


def _cmd_telemetry(args: argparse.Namespace) -> None:
    if args.corpus:
        corpus = Corpus(settings().database_path)
        with corpus.connect() as conn:
            rows = conn.execute("SELECT sha256, raw_json FROM samples").fetchall()
        results = []
        for row in rows:
            raw = json.loads(row["raw_json"] or "{}")
            tel = (raw.get("cairn") or {}).get("telemetry")
            if tel:
                results.append({"sha256": row["sha256"], "telemetry": tel})
        _print_json({"total_with_telemetry": len(results), "samples": results})
        return

    if not args.sha256:
        _print_json({"error": "Provide a SHA256 or use --corpus"})
        return

    sha256 = args.sha256.lower().strip()
    corpus = Corpus(settings().database_path)

    # Check if already stored
    with corpus.connect() as conn:
        row = conn.execute("SELECT raw_json FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
    if not row:
        _print_json({"error": f"SHA256 not found in corpus: {sha256}"})
        return

    raw = json.loads(row["raw_json"] or "{}")
    cached = (raw.get("cairn") or {}).get("telemetry")
    if cached:
        _print_json({"sha256": sha256, "source": "cached", "telemetry": cached})
        return

    # Fetch from VT
    from cairn.vt import VirusTotalClient, VirusTotalError
    app_settings = settings()
    client = VirusTotalClient(
        api_key=app_settings.vt_api_key,
        rate_limit_per_minute=app_settings.rate_limit_per_minute,
        daily_limit=app_settings.daily_limit,
    )
    telemetry = asyncio.run(client.lookup_telemetry(sha256))
    if telemetry is None:
        _print_json({"sha256": sha256, "telemetry": None, "message": "No telemetry available (404/403)"})
        return

    # Store it
    raw.setdefault("cairn", {})["telemetry"] = telemetry
    with corpus.connect() as conn:
        conn.execute("UPDATE samples SET raw_json = ? WHERE sha256 = ?", (json.dumps(raw), sha256))
    _print_json({"sha256": sha256, "source": "fetched", "telemetry": telemetry})


def _cmd_refresh_batch(args: argparse.Namespace) -> None:
    """Refresh a targeted batch of samples identified by triage-gap category."""
    import sys

    corpus = Corpus(settings().database_path)

    with corpus.connect() as conn:
        if args.category == "t1-only-high-det":
            rows = conn.execute("""
                SELECT DISTINCT s.sha256
                FROM samples s
                INNER JOIN rule_matches rm ON s.sha256 = rm.sample_sha256
                WHERE rm.tier = 'T1' AND s.detections >= 10
                  AND NOT EXISTS (
                      SELECT 1 FROM rule_matches rm2
                      WHERE rm2.sample_sha256 = s.sha256 AND rm2.tier IN ('T2', 'T3')
                  )
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        elif args.category == "no-rules-high-det":
            rows = conn.execute("""
                SELECT s.sha256
                FROM samples s
                WHERE s.detections >= 15
                  AND NOT EXISTS (
                      SELECT 1 FROM rule_matches rm WHERE rm.sample_sha256 = s.sha256
                  )
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        elif args.category == "content-filter-no-rules":
            rows = conn.execute("""
                SELECT DISTINCT s.sha256
                FROM sample_filters sf
                INNER JOIN samples s ON sf.sample_sha256 = s.sha256
                INNER JOIN acquisition_runs ar ON sf.acquisition_run_id = ar.id
                WHERE ar.effective_query_text LIKE '%content:%'
                  AND NOT EXISTS (
                      SELECT 1 FROM rule_matches rm WHERE rm.sample_sha256 = s.sha256
                  )
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        elif args.category == "seeds-missing-behaviours":
            rows = conn.execute("""
                SELECT ks.sha256
                FROM known_seeds ks
                JOIN samples s ON ks.sha256 = s.sha256
                WHERE json_extract(s.raw_json, '$.behaviours') IS NULL
                   OR json_extract(s.raw_json, '$.behaviours') = '{}'
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        elif args.category == "go-no-rules":
            rows = conn.execute("""
                SELECT s.sha256
                FROM samples s
                WHERE json_extract(s.raw_json, '$.attributes.goresym') IS NOT NULL
                  AND s.detections >= 10
                  AND NOT EXISTS (
                      SELECT 1 FROM rule_matches rm WHERE rm.sample_sha256 = s.sha256
                  )
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        elif args.category == "go-t1-only":
            rows = conn.execute("""
                SELECT DISTINCT s.sha256
                FROM samples s
                INNER JOIN rule_matches rm ON s.sha256 = rm.sample_sha256
                WHERE json_extract(s.raw_json, '$.attributes.goresym') IS NOT NULL
                  AND rm.tier = 'T1'
                  AND NOT EXISTS (
                      SELECT 1 FROM rule_matches rm2
                      WHERE rm2.sample_sha256 = s.sha256 AND rm2.tier IN ('T2', 'T3')
                  )
                ORDER BY s.detections DESC
                LIMIT ?
            """, (args.limit,)).fetchall()
        else:
            _print_json({"error": f"Unknown category: {args.category}"})
            return

    sha256_list = [r["sha256"] for r in rows]

    if args.dry_run:
        _print_json({
            "dry_run": True,
            "category": args.category,
            "count": len(sha256_list),
            "sha256s": sha256_list,
        })
        return

    if not sha256_list:
        _print_json({"category": args.category, "count": 0, "message": "No samples match this category"})
        return

    print(f"Refreshing {len(sha256_list)} samples ({args.category})...", file=sys.stderr)
    results = asyncio.run(refresh_samples(sha256_list, fetch_behaviours=args.behaviours))

    gained_rules = sum(1 for r in results if r.get("rule_hits", 0) > 0)
    _print_json({
        "category": args.category,
        "refreshed": len(results),
        "gained_rule_hits": gained_rules,
        "results": results,
    })


def _cmd_sync_promptintel(args: argparse.Namespace) -> None:
    app_settings = settings()
    if not app_settings.promptintel_api_key:
        _print_json({"error": "PROMPTINTEL_API_KEY not set in environment or .env"})
        return

    result = asyncio.run(sync_promptintel(app_settings.promptintel_api_key))

    if args.show_all:
        corpus = Corpus(app_settings.database_path)
        result["all_iocs"] = corpus.list_promptintel_iocs()

    _print_json(result)


def _print_threads(threads: list) -> None:
    if not threads:
        print("No open threads.")
        return
    print(f"  {len(threads)} open thread(s)\n")
    for i, t in enumerate(threads, 1):
        print(f"[{i}] {t['title']}")
        print(f"    Status     : {t['status']}")
        print(f"    Added      : {t['date_added']}")
        print(f"    Source     : {t['source']}")
        if t["hashes"]:
            for h in t["hashes"]:
                print(f"    Hash       : {h}")
        if t["pivot_leads"]:
            print("    Pivot leads:")
            for lead in t["pivot_leads"]:
                print(f"      - {lead}")
        print()


def _print_filters() -> None:
    configured = bool(settings().vt_api_key)
    rows = []
    for acquisition_filter in load_acquisition_filters():
        rows.append(
            {
                "slug": acquisition_filter.slug,
                "name": acquisition_filter.name,
                "enabled": acquisition_filter.enabled,
                "category": acquisition_filter.category,
                "default_limit": acquisition_filter.default_limit,
                "min_detections": acquisition_filter.min_detections,
            }
        )
    _print_json({"vt_key_configured": configured, "filters": rows})


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _labels(values: list[str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Label must be key=value: {value}")
        key, label_value = value.split("=", 1)
        labels[key.strip()] = label_value.strip()
    return labels


def _expectations(values: list[str]) -> list[dict[str, str]]:
    expectations: list[dict[str, str]] = []
    for value in values:
        if ":" in value:
            rule_name, expected = value.split(":", 1)
        else:
            rule_name, expected = value, "should_match"
        expectations.append(
            {
                "rule_name": rule_name.strip(),
                "expected_result": expected.strip() or "should_match",
                "expectation_type": "positive_seed" if expected.strip() != "should_not_match" else "false_positive_guardrail",
            }
        )
    return expectations


if __name__ == "__main__":
    main()
