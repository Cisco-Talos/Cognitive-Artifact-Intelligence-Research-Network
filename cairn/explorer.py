from __future__ import annotations

import json
import re
import socket
import sqlite3
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cairn.config import PROJECT_ROOT, settings
from cairn.graph import build_graph


_CORPUS_PATH: Path | None = None
_RULES_PATH    = PROJECT_ROOT / "config" / "yara_rules.yar"
_FILTERS_PATH  = PROJECT_ROOT / "config" / "acquisition_filters.yaml"
_LOGO_PATH     = PROJECT_ROOT / "config" / "logo.png"
_FAVICON_PATH  = PROJECT_ROOT / "config" / "favicon.png"
_FAMILIES_DIR  = PROJECT_ROOT / "docs" / "families"


# ---------------------------------------------------------------------------
# Graph builder (enriched with imphash + domain nodes)
# ---------------------------------------------------------------------------

def build_explorer_graph(corpus_path: Path) -> dict[str, list[dict[str, Any]]]:
    base = build_graph(database_path=corpus_path)
    nodes: dict[str, dict[str, Any]] = {n["id"]: n for n in base["nodes"]}
    edges: list[dict[str, Any]] = list(base["edges"])

    # Derive family per sample from T3 rule name (parse FAMILY from T3-FAMILY_*)
    sample_families: dict[str, str] = {}
    for edge in edges:
        if edge["type"] == "matched_rule":
            rule = edge["target"]  # "rule:T3-DEEPZOO_..."
            rule_name = rule.removeprefix("rule:")
            if rule_name.startswith("T3-") and "_" in rule_name:
                family = rule_name[3:].split("_")[0]
                sha_node = edge["source"]
                sample_families.setdefault(sha_node, family)

    # Stamp family onto sample nodes
    for node_id, family in sample_families.items():
        if node_id in nodes:
            nodes[node_id]["family"] = family

    # Stamp cluster_id onto sample nodes from the latest cluster run
    with sqlite3.connect(corpus_path) as conn:
        conn.row_factory = sqlite3.Row
        run_row = conn.execute(
            "SELECT run_id FROM artifact_clusters ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if run_row:
            for crow in conn.execute(
                "SELECT sha256, cluster_id FROM artifact_clusters WHERE run_id = ?",
                (run_row["run_id"],),
            ).fetchall():
                nid = f"sample:{crow['sha256']}"
                if nid in nodes:
                    nodes[nid]["cluster_id"] = crow["cluster_id"]

    # Enrich with imphash + domain nodes from raw_json
    with sqlite3.connect(corpus_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT sha256, raw_json FROM samples WHERE raw_json IS NOT NULL").fetchall()

    # Pre-compute how many corpus samples each submitter key appears on
    submitter_counts: dict[str, int] = {}
    for _row in rows:
        try:
            _raw = json.loads(_row["raw_json"])
        except (TypeError, ValueError):
            continue
        for _key in (_raw.get("cairn") or {}).get("submitter_keys") or []:
            submitter_counts[_key] = submitter_counts.get(_key, 0) + 1

    for row in rows:
        sha256 = row["sha256"]
        sample_id = f"sample:{sha256}"
        if sample_id not in nodes:
            continue
        try:
            raw = json.loads(row["raw_json"])
        except (TypeError, ValueError):
            continue

        attrs = raw.get("attributes") or {}
        rels = raw.get("relationships") or {}

        # Imphash node
        imphash = (attrs.get("pe_info") or {}).get("imphash")
        if imphash:
            ih_id = f"imphash:{imphash}"
            if ih_id not in nodes:
                nodes[ih_id] = {"id": ih_id, "label": imphash[:12], "type": "imphash", "full": imphash}
            edges.append({"source": sample_id, "target": ih_id, "type": "shares_imphash", "weight": 1, "evidence": imphash})

        # Domain nodes from embedded_urls and contacted_domains
        domains: set[str] = set()
        for url_obj in (rels.get("embedded_urls") or {}).get("data", []):
            url_str = url_obj.get("id") or url_obj.get("url") or ""
            try:
                host = urlparse(url_str).hostname or ""
                if host and "." in host:
                    domains.add(host)
            except Exception:
                pass
        for dom_obj in (rels.get("contacted_domains") or {}).get("data", []):
            d = dom_obj.get("id") or dom_obj.get("name") or ""
            if d:
                domains.add(d)

        for domain in domains:
            dom_id = f"domain:{domain}"
            if dom_id not in nodes:
                nodes[dom_id] = {"id": dom_id, "label": domain, "type": "domain"}
            edges.append({"source": sample_id, "target": dom_id, "type": "communicates_with", "weight": 1, "evidence": domain})

        # Cert (rich_pe_header_hash) proxy node
        rich_hash = (attrs.get("pe_info") or {}).get("rich_pe_header_hash")
        if rich_hash:
            cert_id = f"cert:{rich_hash}"
            if cert_id not in nodes:
                nodes[cert_id] = {"id": cert_id, "label": rich_hash[:12], "type": "cert", "full": rich_hash}
            edges.append({"source": sample_id, "target": cert_id, "type": "shares_cert", "weight": 1, "evidence": rich_hash})

        # Submitter nodes from cairn.submitter_keys (populated by cairn fetch-submitters)
        cairn_meta = raw.get("cairn") or {}
        for key in (cairn_meta.get("submitter_keys") or []):
            sub_id = f"submitter:{key}"
            if sub_id not in nodes:
                nodes[sub_id] = {
                    "id": sub_id, "label": key, "type": "submitter", "full": key,
                    "corpus_sample_count": submitter_counts.get(key, 1),
                }
            edges.append({"source": sample_id, "target": sub_id, "type": "submitted_by", "weight": 1, "evidence": key})

    return {"nodes": list(nodes.values()), "edges": edges}


# ---------------------------------------------------------------------------
# YARA rule parser
# ---------------------------------------------------------------------------

def _parse_yara_rules(text: str) -> list[dict[str, Any]]:
    chunks = re.split(r'\n(?=rule\s)', text)
    rules = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk.startswith("rule "):
            continue
        name_m = re.match(r'rule\s+(\S+)', chunk)
        if not name_m:
            continue
        name = name_m.group(1)

        meta: dict[str, str] = {}
        meta_m = re.search(r'meta\s*:(.*?)(?:strings\s*:|condition\s*:)', chunk, re.DOTALL)
        if meta_m:
            for km in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|(\d+))', meta_m.group(1)):
                meta[km.group(1)] = km.group(2) if km.group(2) is not None else km.group(3)

        tier = meta.get("tier") or ("T3" if name.startswith("T3-") else "T2" if name.startswith("T2-") else "T1")
        rules.append({
            "name": name,
            "tier": tier,
            "description": meta.get("description", ""),
            "confidence": meta.get("confidence", ""),
            "artifact_class": meta.get("artifact_class", ""),
            "family": meta.get("family") or None,
        })
    return rules


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # silence access log
        pass

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._serve_html()
        elif path == "/logo.png":
            self._serve_logo()
        elif path == "/favicon.png":
            self._serve_favicon()
        elif path == "/api/graph":
            self._serve_json(build_explorer_graph(_CORPUS_PATH or settings().database_path))
        elif path == "/api/projections":
            self._serve_projections()
        elif path == "/api/samples":
            self._serve_json(self._query_samples())
        elif path.startswith("/api/sample/"):
            sha256 = path[len("/api/sample/"):]
            self._serve_json(self._query_sample(sha256))
        elif path == "/api/rules":
            self._serve_json(self._get_rules())
        elif path == "/api/filters":
            self._serve_json(self._get_filters())
        elif path.startswith("/api/family/"):
            self._serve_family_report(path[len("/api/family/"):])
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        try:
            body = json.loads(raw_body)
        except (ValueError, TypeError):
            self._serve_error(400, "Invalid JSON body")
            return

        if path == "/api/rules":
            self._save_rules(body)
        elif path == "/api/filters":
            self._save_filters(body)
        else:
            self.send_error(404)

    # ------------------------------------------------------------------

    def _serve_html(self) -> None:
        from cairn.explorer_ui import HTML
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_projections(self) -> None:
        from cairn.corpus import Corpus
        db = _CORPUS_PATH or settings().database_path
        corpus = Corpus(db)
        rows = corpus.load_projections()
        if not rows:
            self._serve_json([])
            return
        # Lightweight family lookup via T3 rule_matches
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            family_map: dict[str, str] = {}
            for frow in conn.execute(
                "SELECT sample_sha256, rule_name FROM rule_matches WHERE tier = 'T3'"
            ).fetchall():
                sha = frow["sample_sha256"]
                rn = frow["rule_name"]
                if sha not in family_map and rn.startswith("T3-") and "_" in rn:
                    family_map[sha] = rn[3:].split("_")[0]
        self._serve_json([{**r, "family": family_map.get(r["sha256"])} for r in rows])

    def _serve_logo(self) -> None:
        if not _LOGO_PATH.exists():
            self.send_error(404)
            return
        body = _LOGO_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def _serve_favicon(self) -> None:
        if not _FAVICON_PATH.exists():
            self.send_error(404)
            return
        body = _FAVICON_PATH.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_error(self, code: int, message: str) -> None:
        body = json.dumps({"error": message}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------

    def _get_rules(self) -> dict[str, Any]:
        text = _RULES_PATH.read_text(encoding="utf-8")
        rules = _parse_yara_rules(text)

        # Attach hit counts from rule_matches table
        try:
            db = _CORPUS_PATH or settings().database_path
            with sqlite3.connect(db) as conn:
                counts = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT rule_name, COUNT(DISTINCT sample_sha256) FROM rule_matches GROUP BY rule_name"
                    ).fetchall()
                }
                # Seed validation status: latest validation_status per seed per rule
                seed_stats: dict[str, dict[str, int]] = {}
                for vrow in conn.execute(
                    """SELECT rule_name, validation_status FROM validation_results vr1
                       WHERE validated_at = (
                           SELECT MAX(validated_at) FROM validation_results vr2
                           WHERE vr2.seed_sha256 = vr1.seed_sha256
                           AND vr2.rule_name = vr1.rule_name
                       )"""
                ).fetchall():
                    rn, vstatus = vrow[0], vrow[1]
                    if rn not in seed_stats:
                        seed_stats[rn] = {"total": 0, "pass": 0}
                    seed_stats[rn]["total"] += 1
                    if vstatus == "pass":
                        seed_stats[rn]["pass"] += 1
            for r in rules:
                r["hit_count"] = counts.get(r["name"], 0)
                stats = seed_stats.get(r["name"])
                if stats:
                    r["seed_count"] = stats["total"]
                    r["seed_status"] = "pass" if stats["pass"] == stats["total"] else "fail"
                else:
                    r["seed_count"] = 0
                    r["seed_status"] = None
        except Exception:
            for r in rules:
                r.setdefault("hit_count", 0)
                r.setdefault("seed_status", None)
                r.setdefault("seed_count", 0)

        return {"content": text, "rules": rules}

    def _get_filters(self) -> dict[str, Any]:
        from cairn.config import load_acquisition_filters
        text = _FILTERS_PATH.read_text(encoding="utf-8")
        filters = [
            {
                "name": f.name,
                "slug": f.slug,
                "category": f.category,
                "description": f.description,
                "query_text": f.query_text,
                "enabled": f.enabled,
                "default_limit": f.default_limit,
                "min_detections": f.min_detections,
            }
            for f in load_acquisition_filters()
        ]
        return {"content": text, "filters": filters}

    def _save_rules(self, body: dict[str, Any]) -> None:
        content = body.get("content")
        if not isinstance(content, str):
            self._serve_error(400, "Missing 'content' field")
            return
        tmp = _RULES_PATH.with_suffix(".yar.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.rename(_RULES_PATH)
        self._serve_json({"ok": True})

    def _save_filters(self, body: dict[str, Any]) -> None:
        content = body.get("content")
        if not isinstance(content, str):
            self._serve_error(400, "Missing 'content' field")
            return
        tmp = _FILTERS_PATH.with_suffix(".yaml.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.rename(_FILTERS_PATH)
        self._serve_json({"ok": True})

    def _serve_family_report(self, family: str) -> None:
        if not re.fullmatch(r'[A-Z0-9_]+', family):
            self.send_error(400)
            return
        md_path = _FAMILIES_DIR / f"{family}.md"
        if not md_path.exists():
            self._serve_json({"markdown": None, "exists": False})
            return
        self._serve_json({"markdown": md_path.read_text(encoding="utf-8"), "exists": True})

    # ------------------------------------------------------------------

    def _query_samples(self) -> list[dict[str, Any]]:
        db = _CORPUS_PATH or settings().database_path
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT s.sha256, s.name, s.file_type, s.first_seen, s.detections,
                       s.tags_json, s.vt_url,
                       GROUP_CONCAT(DISTINCT rm.rule_name) AS rule_names,
                       GROUP_CONCAT(DISTINCT CASE WHEN rm.tier='T3' THEN rm.rule_name END) AS t3_rules
                FROM samples s
                LEFT JOIN rule_matches rm ON s.sha256 = rm.sample_sha256
                GROUP BY s.sha256
                ORDER BY s.detections DESC
            """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["tags"] = json.loads(d.pop("tags_json") or "[]")
            t3 = d.pop("t3_rules") or ""
            family = None
            for rn in t3.split(","):
                rn = rn.strip()
                if rn.startswith("T3-") and "_" in rn:
                    family = rn[3:].split("_")[0]
                    break
            d["family"] = family
            d["rule_names"] = [r.strip() for r in (d["rule_names"] or "").split(",") if r.strip()]
            result.append(d)
        return result

    def _query_sample(self, sha256: str) -> dict[str, Any]:
        db = _CORPUS_PATH or settings().database_path
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
            if not row:
                return {"error": "not found"}
            matches = [dict(r) for r in conn.execute(
                "SELECT * FROM rule_matches WHERE sample_sha256 = ?", (sha256,)
            ).fetchall()]
        d = dict(row)
        d["tags"] = json.loads(d.pop("tags_json") or "[]")
        raw = json.loads(d.get("raw_json") or "{}")
        attrs = raw.get("attributes") or {}
        rels = raw.get("relationships") or {}
        cairn_meta = raw.get("cairn") or {}
        d["pe_info"] = attrs.get("pe_info")
        d["exiftool"] = attrs.get("exiftool")
        d["sigma_analysis_results"] = attrs.get("sigma_analysis_results")
        d["names"] = attrs.get("names")
        d["embedded_urls"] = (rels.get("embedded_urls") or {}).get("data", [])
        d["provider_references"] = cairn_meta.get("provider_references", [])
        d["rule_matches"] = matches
        # raw_json kept in d for the raw viewer — it's a JSON string
        return d


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _find_free_port(preferred: int) -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", preferred))
            return preferred
    except OSError:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def serve(port: int = 8421, corpus_path: Path | None = None, open_browser: bool = True) -> None:
    global _CORPUS_PATH
    _CORPUS_PATH = corpus_path or settings().database_path

    port = _find_free_port(port)
    server = HTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"CAIRN Explorer → {url}  (Ctrl-C to stop)")

    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
