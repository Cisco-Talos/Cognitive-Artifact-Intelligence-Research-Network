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

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from cairn.models import SampleRecord, VTRow

VT_INTELLIGENCE_SEARCH = "https://www.virustotal.com/api/v3/intelligence/search"
VT_SNIPPET_URL = "https://www.virustotal.com/api/v3/intelligence/search/snippets/{snippet_id}"
VT_FILE_LOOKUP = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_URL_LOOKUP = "https://www.virustotal.com/api/v3/urls/{url_id}"
VT_BEHAVIOURS_URL = "https://www.virustotal.com/api/v3/files/{sha256}/behaviours"
CONTENT_MODIFIER_RE = re.compile(r'content:("[^"]+"|\S+)', re.IGNORECASE)

_HEX64_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_VT_ENTITY = {"file": "files", "domain": "domains", "ip": "ip_addresses"}


def detect_seed_type(seed: str) -> str:
    """Classify a pivot seed as 'file' (SHA256), 'ip', or 'domain'."""
    s = seed.strip().lower()
    if _HEX64_RE.match(s):
        return "file"
    if _IP_RE.match(s):
        return "ip"
    return "domain"


class VirusTotalError(RuntimeError):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class VirusTotalClient:
    api_key: str
    rate_limit_per_minute: int = 4
    daily_limit: int = 500
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        self._requests_made = 0
        self._last_request_at: float | None = None

    async def search_intelligence(self, query: str, *, limit: int = 100) -> list[VTRow]:
        payload = await self._get_json(
            VT_INTELLIGENCE_SEARCH,
            params={"query": query, "limit": max(1, min(100, limit))},
        )
        rows = payload.get("data") or []
        return [_vt_row(row) for row in rows if isinstance(row, dict)]

    async def search_with_content_fallback(self, query: str, *, limit: int = 100) -> tuple[list[VTRow], str, str | None]:
        try:
            return await self.search_intelligence(query, limit=limit), query, None
        except VirusTotalError as exc:
            fallback_query = content_query_fallback(query)
            if exc.status != "failed" or fallback_query == query:
                raise
            rows = await self.search_intelligence(fallback_query, limit=limit)
            return rows, fallback_query, exc.message

    async def lookup_url(self, url_id: str) -> dict[str, Any]:
        """Fetch a VT URL object by its SHA256 id. Returns the raw attributes dict."""
        payload = await self._get_json(VT_URL_LOOKUP.format(url_id=url_id))
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            raise VirusTotalError("not_found", f"VirusTotal returned no URL object for {url_id}.")
        attrs = data.get("attributes") or {}
        return {
            "url_id": url_id,
            "url": attrs.get("url") or attrs.get("final_url") or "",
            "title": attrs.get("title") or "",
            "final_url": attrs.get("final_url") or "",
            "categories": attrs.get("categories") or {},
            "threat_names": attrs.get("threat_names") or [],
            "last_analysis_stats": attrs.get("last_analysis_stats") or {},
            "last_http_response_code": attrs.get("last_http_response_code"),
            "tags": attrs.get("tags") or [],
        }

    async def lookup_file(self, sha256: str) -> VTRow:
        payload = await self._get_json(
            VT_FILE_LOOKUP.format(sha256=sha256),
            params={"relationships": "contacted_urls,contacted_domains,contacted_ips,embedded_urls"},
        )
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            raise VirusTotalError("not_found", f"VirusTotal returned no file object for {sha256}.")
        return _vt_row(data)

    async def fetch_relationship(
        self, seed: str, seed_type: str, relationship: str, *, limit: int = 40
    ) -> list[VTRow]:
        """Fetch a VT relationship endpoint and return file objects found there.

        seed_type must be 'file', 'domain', or 'ip'.
        Common relationships: similar_files, communicating_files, dropped_files,
        bundled_files, execution_parents (file only).
        """
        entity = _VT_ENTITY.get(seed_type, "files")
        endpoint = f"https://www.virustotal.com/api/v3/{entity}/{seed}/{relationship}"
        payload = await self._get_json(endpoint, params={"limit": min(limit, 40)})
        items = payload.get("data") or []
        return [_vt_row(item) for item in items if isinstance(item, dict)]

    async def fetch_submissions(self, sha256: str, *, limit: int = 40) -> list[str]:
        """Fetch unique submission source_keys for a file (VT Intelligence endpoint).

        Returns an empty list on 404 or auth errors. Re-raises rate/quota errors so
        callers can abort rather than silently skip.
        """
        try:
            payload = await self._get_json(
                f"https://www.virustotal.com/api/v3/files/{sha256}/submissions",
                params={"limit": min(limit, 40)},
            )
        except VirusTotalError as exc:
            if exc.status in ("not_found", "auth_failed"):
                return []
            raise
        seen: set[str] = set()
        keys: list[str] = []
        for item in (payload.get("data") or []):
            key = (item.get("attributes") or {}).get("source_key")
            if key and key not in seen:
                seen.add(key)
                keys.append(str(key))
        return keys

    async def lookup_behaviours(self, sha256: str) -> dict[str, Any]:
        """Fetch sandbox behavioural reports and return an aggregated summary.

        Returns an empty dict if the file has no sandbox reports or the request fails.
        Fields in the returned dict: dns_hostnames, http_urls, memory_pattern_urls,
        memory_pattern_domains, processes_created, command_executions, files_dropped,
        signature_matches, tags.
        """
        try:
            payload = await self._get_json(VT_BEHAVIOURS_URL.format(sha256=sha256))
        except VirusTotalError:
            return {}
        sandboxes = payload.get("data") or []
        if not isinstance(sandboxes, list):
            return {}
        return _behaviours_summary(sandboxes)

    async def fetch_snippet(self, snippet_id: str) -> list[str]:
        """Fetch the content-match fragments for one snippet ID.

        snippet_id comes from context_attributes.snippet in a VT search result.
        Returns a list of hex-dump+ASCII fragment strings (each contains the
        matched text delimited by asterisks). Returns [] on any error.
        """
        try:
            payload = await self._get_json(
                VT_SNIPPET_URL.format(snippet_id=snippet_id),
            )
        except VirusTotalError:
            return []
        data = payload.get("data") or []
        return [str(s) for s in data if isinstance(s, str)]

    async def _get_json(self, endpoint: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.api_key:
            raise VirusTotalError("not_configured", "VirusTotal API key is not configured.")
        if self._requests_made >= self.daily_limit:
            raise VirusTotalError("daily_limit_reached", f"Configured daily request cap reached ({self.daily_limit}).")
        await self._respect_rate_limit()
        self._requests_made += 1
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            response = await client.get(
                endpoint,
                params=params,
                headers={"x-apikey": self.api_key, "Accept": "application/json"},
            )
        if response.status_code == 404:
            raise VirusTotalError("not_found", "VirusTotal object was not found.")
        if response.status_code == 429:
            raise VirusTotalError("rate_limited", "VirusTotal rate limit reached.")
        if response.status_code in {401, 403}:
            if "intelligence/search" in endpoint:
                raise VirusTotalError(
                    "intelligence_search_unavailable",
                    "VirusTotal Intelligence search is unavailable for this API key.",
                )
            raise VirusTotalError("auth_failed", "VirusTotal API key is missing privileges or is invalid.")
        if response.status_code >= 400:
            raise VirusTotalError("failed", f"VirusTotal request failed with HTTP {response.status_code}.")
        payload = response.json()
        if not isinstance(payload, dict) or "data" not in payload:
            raise VirusTotalError("not_found", "VirusTotal returned an empty response.")
        return payload

    async def _respect_rate_limit(self) -> None:
        if self.rate_limit_per_minute <= 0:
            return
        min_interval = 60 / self.rate_limit_per_minute
        now = asyncio.get_running_loop().time()
        if self._last_request_at is not None:
            wait_for = min_interval - (now - self._last_request_at)
            if wait_for > 0:
                await asyncio.sleep(wait_for)
        self._last_request_at = asyncio.get_running_loop().time()


def content_query_fallback(query: str) -> str:
    """Strip VT content: modifiers when VT returns transient 500s on content search."""
    return CONTENT_MODIFIER_RE.sub(lambda match: match.group(1), query)


def row_to_sample(row: VTRow) -> SampleRecord:
    attrs = row.attributes
    stats = attrs.get("last_analysis_stats") or {}
    sha256 = str(attrs.get("sha256") or row.object_id or "").lower()
    if len(sha256) != 64:
        sha256 = str(row.object_id or "").lower()
    names = attrs.get("names") if isinstance(attrs.get("names"), list) else []
    name = str(attrs.get("meaningful_name") or (names[0] if names else "") or sha256[:12])
    tags = attrs.get("tags") or attrs.get("type_tags") or []
    return SampleRecord(
        sha256=sha256,
        name=name,
        vt_url=f"https://www.virustotal.com/gui/file/{sha256}",
        first_seen=_epoch_to_iso(attrs.get("first_submission_date")),
        last_seen=_epoch_to_iso(attrs.get("last_analysis_date") or attrs.get("last_submission_date")),
        file_type=str(attrs.get("type_description") or attrs.get("type_tag") or "file"),
        detections=int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0),
        tags=[str(tag) for tag in tags[:40]] if isinstance(tags, list) else [],
        raw=row.raw,
        collected_at=datetime.now(timezone.utc),
    )


def scan_text_from_vt_row(row: VTRow) -> str:
    attrs = row.attributes
    useful = {
        "meaningful_name": attrs.get("meaningful_name"),
        "names": attrs.get("names"),
        "tags": attrs.get("tags") or attrs.get("type_tags"),
        "signature_info": {k: v for k, v in (attrs.get("signature_info") or {}).items() if k != "x509"},
        "context_attributes": attrs.get("context_attributes"),
        "sandbox_verdicts": attrs.get("sandbox_verdicts"),
        "popular_threat_classification": attrs.get("popular_threat_classification"),
        "crowdsourced_yara_results": attrs.get("crowdsourced_yara_results"),
        "magic": attrs.get("magic"),
        "capabilities_tags": attrs.get("capabilities_tags"),
        "sigma_analysis_results": attrs.get("sigma_analysis_results"),
        "crowdsourced_ids_results": attrs.get("crowdsourced_ids_results"),
        "exiftool": attrs.get("exiftool"),
        "pe_info": _pe_info_summary(attrs.get("pe_info")),
        "av_detection_names": _av_detection_names(attrs.get("last_analysis_results")),
        "behaviours": row.raw.get("behaviours"),
        "content_snippets": _decode_vt_snippets(row.raw.get("snippets")),
        "goresym": _goresym_summary(attrs.get("goresym")),
    }
    relationship_values = _relationship_values(row.relationships)
    return "\n".join([str(useful), str(relationship_values)])


def provider_references(text: str) -> list[str]:
    providers = {
        "OpenAI": ["openai", "api.openai.com", "chatgpt", "gpt-4"],
        "Anthropic": ["anthropic", "api.anthropic.com", "claude"],
        "Google": ["gemini", "generativelanguage.googleapis.com"],
        "DeepSeek": ["deepseek", "api.deepseek.com"],
        "Mistral": ["mistral", "api.mistral.ai"],
        "Hugging Face": ["huggingface", "transformers", "safetensors"],
        "Ollama": ["ollama", "localhost:11434"],
        "Groq": ["groq", "api.groq.com"],
        "OpenRouter": ["openrouter", "openrouter.ai"],
        "xAI": ["grok", "api.x.ai"],
        "Together AI": ["together", "api.together.xyz"],
        "Cohere": ["cohere", "api.cohere.ai"],
    }
    lowered = text.lower()
    return [name for name, needles in providers.items() if any(needle in lowered for needle in needles)]


def _vt_row(row: dict[str, Any]) -> VTRow:
    return VTRow(
        object_id=str(row.get("id") or ""),
        attributes=row.get("attributes") if isinstance(row.get("attributes"), dict) else {},
        relationships=row.get("relationships") if isinstance(row.get("relationships"), dict) else {},
        raw=row,
    )


_VT_SNIPPET_HIGHLIGHT_RE = re.compile(r'[\x1c\x1d]')
_VT_SNIPPET_LINE_RE = re.compile(r'^[0-9A-Fa-f]{8}:\s+(?:[0-9A-Fa-f]{2}\s+){1,16}\s+(.{1,16})\s*$')


def _decode_vt_snippets(snippets: list[str] | None) -> str:
    """Reconstruct ASCII text from VT hex-dump snippet fragments.

    VT snippets are formatted as:
        00000050: 46 6F 72 20 4C 4C 4D  ...   For LLM ...
    with \x1c/\x1d as highlight-start/end markers that split strings across lines.
    YARA can't match multi-word phrases across these line breaks; this function
    produces two concatenations of the ASCII column — one with empty join (exact
    bytes) and one with space join (covers words split at the 16-byte line boundary)
    — so YARA can match in either form.
    """
    if not snippets or not isinstance(snippets, list):
        return ""
    parts: list[str] = []
    for fragment in snippets:
        if not isinstance(fragment, str):
            continue
        clean = _VT_SNIPPET_HIGHLIGHT_RE.sub("", fragment)
        for line in clean.splitlines():
            m = _VT_SNIPPET_LINE_RE.match(line)
            if m:
                parts.append(m.group(1))
    return "".join(parts) + "\n" + " ".join(parts)


def _av_detection_names(last_analysis_results: dict[str, Any] | None) -> list[str]:
    """Extract non-null AV detection result strings from last_analysis_results."""
    if not last_analysis_results or not isinstance(last_analysis_results, dict):
        return []
    names: list[str] = []
    for entry in last_analysis_results.values():
        if not isinstance(entry, dict):
            continue
        result = entry.get("result")
        if result and isinstance(result, str):
            names.append(result)
    return names


def _pe_info_summary(pe_info: dict[str, Any] | None) -> dict[str, Any] | None:
    """Extract the string-bearing fields from pe_info that are useful for YARA matching.

    Full pe_info can be megabytes of section/resource data. We want:
    - imports: DLL names (reveals python3.dll, onnxruntime.dll, etc.)
    - exports: exported symbol names
    - compiler_product_versions: build toolchain hints
    - resource_details file types (can reveal embedded scripts)
    """
    if not pe_info or not isinstance(pe_info, dict):
        return None
    imports = pe_info.get("imports") or []
    exports = pe_info.get("exports") or []
    return {
        "imports": [str(i) for i in imports[:200]] if isinstance(imports, list) else [],
        "exports": [str(e) for e in exports[:200]] if isinstance(exports, list) else [],
        "compiler_product_versions": pe_info.get("compiler_product_versions"),
    }


def _goresym_summary(goresym: dict[str, Any] | None) -> dict[str, Any] | None:
    """Extract build settings from GoReSym analysis (present on Go binaries analysed by VT).

    Specifically surfaces the -ldflags build setting, which developers sometimes
    forget to strip — leaking hardcoded API keys injected via `-X main.VarName=value`.
    """
    if not goresym or not isinstance(goresym, dict):
        return None
    preview = goresym.get("report_preview") or {}
    build_info = preview.get("buildInfo") or {}
    settings = build_info.get("settings") or []
    return {
        "GoVersion": build_info.get("GoVersion"),
        "build_settings": [
            {"key": s.get("key"), "value": s.get("value")}
            for s in settings
            if isinstance(s, dict) and s.get("value") and s.get("value") != "None"
        ],
    }


def _relationship_values(relationships: dict[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for name, payload in relationships.items():
        data = payload.get("data") if isinstance(payload, dict) else None
        rows: list[str] = []
        if isinstance(data, list):
            for item in data[:80]:
                if not isinstance(item, dict):
                    continue
                if item.get("id"):
                    rows.append(str(item["id"]))
                # embedded_urls and contacted_urls store the actual URL in context_attributes.url
                ctx = item.get("context_attributes")
                if isinstance(ctx, dict) and ctx.get("url"):
                    rows.append(str(ctx["url"]))
        elif isinstance(data, dict) and data.get("id"):
            rows.append(str(data["id"]))
        if rows:
            values[name] = rows
    return values


def _behaviours_summary(sandboxes: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate behavioral fields across all sandbox reports into a flat summary dict."""
    dns_hostnames: list[str] = []
    http_urls: list[str] = []
    memory_urls: list[str] = []
    memory_domains: list[str] = []
    processes: list[str] = []
    commands: list[str] = []
    dropped_paths: list[str] = []
    sig_descriptions: list[str] = []
    tags: set[str] = set()

    for sb in sandboxes:
        attrs = sb.get("attributes") or {}
        for lookup in attrs.get("dns_lookups") or []:
            if isinstance(lookup, dict) and lookup.get("hostname"):
                dns_hostnames.append(lookup["hostname"])
        for conv in attrs.get("http_conversations") or []:
            if isinstance(conv, dict) and conv.get("url"):
                http_urls.append(conv["url"])
        memory_urls.extend(u for u in (attrs.get("memory_pattern_urls") or []) if isinstance(u, str))
        memory_domains.extend(d for d in (attrs.get("memory_pattern_domains") or []) if isinstance(d, str))
        processes.extend(p for p in (attrs.get("processes_created") or []) if isinstance(p, str))
        commands.extend(c for c in (attrs.get("command_executions") or []) if isinstance(c, str))
        for f in attrs.get("files_dropped") or []:
            if isinstance(f, dict) and f.get("path"):
                dropped_paths.append(f["path"])
        for sig in attrs.get("signature_matches") or []:
            if isinstance(sig, dict) and sig.get("description"):
                sig_descriptions.append(sig["description"])
        for tag in attrs.get("tags") or []:
            if isinstance(tag, str):
                tags.add(tag)

    def _dedup(lst: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for x in lst:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    result: dict[str, Any] = {}
    if dns_hostnames:
        result["dns_hostnames"] = _dedup(dns_hostnames)
    if http_urls:
        result["http_urls"] = _dedup(http_urls)
    if memory_urls:
        result["memory_pattern_urls"] = _dedup(memory_urls)
    if memory_domains:
        result["memory_pattern_domains"] = _dedup(memory_domains)
    if processes:
        result["processes_created"] = _dedup(processes)
    if commands:
        result["command_executions"] = _dedup(commands)
    if dropped_paths:
        result["files_dropped"] = _dedup(dropped_paths)
    if sig_descriptions:
        result["signature_matches"] = _dedup(sig_descriptions)
    if tags:
        result["tags"] = sorted(tags)
    return result


def _epoch_to_iso(value: Any) -> str | None:
    try:
        if value is None:
            return None
        return datetime.fromtimestamp(int(value), tz=timezone.utc).date().isoformat()
    except (TypeError, ValueError, OSError):
        return None
