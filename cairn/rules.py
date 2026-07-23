from __future__ import annotations

import re
from typing import Any

from cairn.models import RuleMatch, RuleStringHit, YaraRule, YaraString

RULE_HEADER_RE = re.compile(r"\brule\s+([^\s{]+)\s*\{", re.IGNORECASE)
STRING_RE = re.compile(r"^\s*(\$\w+)\s*=\s*\"((?:\\.|[^\"])*)\"(.*)$")
META_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")


def parse_yara_rules(rules_text: str) -> tuple[list[YaraRule], list[str]]:
    rules: list[YaraRule] = []
    errors: list[str] = []
    for name, body in _rule_blocks(rules_text):
        try:
            meta_body = _section(body, "meta:", "strings:")
            strings_body = _section(body, "strings:", "condition:")
            condition = _section(body, "condition:", None).strip()
            strings = _parse_strings(strings_body)
            if not strings:
                errors.append(f"{name}: no strings parsed")
            if not condition:
                errors.append(f"{name}: missing condition")
            rules.append(YaraRule(name=name, meta=_parse_meta(meta_body), strings=strings, condition=condition))
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
    if not rules:
        errors.append("no rules parsed")
    return rules, errors


def run_yara_rules(text: str, rules: list[YaraRule]) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in rules:
        hits = _string_hits(text, rule)
        if _condition_matches(rule.condition, rule, hits):
            matches.append(
                RuleMatch(
                    rule=rule.name,
                    tier=rule.tier,
                    artifact_type=str(rule.meta.get("artifact_type") or "artifact"),
                    artifact_class=str(rule.meta.get("artifact_class") or rule.name),
                    confidence=_confidence(rule.meta.get("confidence")),
                    description=str(rule.meta.get("description") or rule.name),
                    matched_strings=[hit for rule_hits in hits.values() for hit in rule_hits],
                )
            )
    return matches


def validate_yara_rules(rules_text: str) -> dict[str, Any]:
    rules, errors = parse_yara_rules(rules_text)
    return {
        "valid": bool(rules) and not errors,
        "rule_count": len(rules),
        "rules": [rule.name for rule in rules],
        "tiers": _tier_counts(rules),
        "errors": errors,
    }


def _rule_blocks(rules_text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for match in RULE_HEADER_RE.finditer(rules_text):
        name = match.group(1)
        start = match.end()
        depth = 1
        index = start
        while index < len(rules_text):
            char = rules_text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((name, rules_text[start:index]))
                    break
            index += 1
    return blocks


def _section(body: str, start_marker: str, end_marker: str | None) -> str:
    start = body.lower().find(start_marker.lower())
    if start < 0:
        raise ValueError(f"missing {start_marker}")
    start += len(start_marker)
    if end_marker is None:
        return body[start:]
    end = body.lower().find(end_marker.lower(), start)
    if end < 0:
        raise ValueError(f"missing {end_marker}")
    return body[start:end]


def _parse_meta(meta_body: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in meta_body.splitlines():
        match = META_RE.match(line)
        if not match:
            continue
        key, raw_value = match.groups()
        value = raw_value.strip().rstrip(",")
        if value.startswith('"') and value.endswith('"'):
            meta[key] = _decode_yara_string(value[1:-1])
            continue
        try:
            meta[key] = int(value)
        except ValueError:
            meta[key] = value
    return meta


def _parse_strings(strings_body: str) -> list[YaraString]:
    strings: list[YaraString] = []
    for line in strings_body.splitlines():
        match = STRING_RE.match(line)
        if not match:
            continue
        identifier, raw_pattern, modifiers = match.groups()
        strings.append(
            YaraString(
                identifier=identifier,
                pattern=_decode_yara_string(raw_pattern),
                nocase="nocase" in modifiers.lower(),
            )
        )
    return strings


def _decode_yara_string(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def _string_hits(text: str, rule: YaraRule) -> dict[str, list[RuleStringHit]]:
    hits: dict[str, list[RuleStringHit]] = {}
    for yara_string in rule.strings:
        haystack = text.lower() if yara_string.nocase else text
        needle = yara_string.pattern.lower() if yara_string.nocase else yara_string.pattern
        offset = haystack.find(needle)
        while offset >= 0:
            hits.setdefault(yara_string.identifier, []).append(
                RuleStringHit(
                    identifier=yara_string.identifier,
                    pattern=yara_string.pattern,
                    excerpt=_excerpt(text, offset, len(yara_string.pattern)),
                    offset=offset,
                )
            )
            offset = haystack.find(needle, offset + max(1, len(needle)))
    return hits


def _condition_matches(condition: str, rule: YaraRule, hits: dict[str, list[RuleStringHit]]) -> bool:
    hit_ids = {identifier for identifier, rule_hits in hits.items() if rule_hits}
    expression = " ".join(condition.split())

    def replace_group(match: re.Match[str]) -> str:
        count = int(match.group(1))
        members = [member.strip() for member in match.group(2).split(",")]
        matched = 0
        for member in members:
            if member.endswith("*"):
                prefix = member[:-1]
                matched += sum(1 for identifier in hit_ids if identifier.startswith(prefix))
            elif member in hit_ids:
                matched += 1
        return str(matched >= count)

    expression = re.sub(r"(\d+)\s+of\s+\(([^)]+)\)", replace_group, expression, flags=re.IGNORECASE)
    expression = re.sub(
        r"\bany\s+of\s+them\b",
        str(bool(hit_ids)),
        expression,
        flags=re.IGNORECASE,
    )
    expression = re.sub(
        r"\b(\d+)\s+of\s+them\b",
        lambda match: str(len(hit_ids) >= int(match.group(1))),
        expression,
        flags=re.IGNORECASE,
    )

    def replace_identifier(match: re.Match[str]) -> str:
        return str(match.group(0) in hit_ids)

    expression = re.sub(r"\$\w+", replace_identifier, expression)
    if not re.fullmatch(r"[TrueFalsandorNotefal\s().]+", expression):
        return False
    try:
        return bool(eval(expression, {"__builtins__": {}}, {}))
    except Exception:
        return False


def _confidence(value: Any) -> int:
    if isinstance(value, int):
        return max(0, min(100, value))
    normalized = str(value or "").strip().lower()
    if normalized == "high":
        return 90
    if normalized == "medium":
        return 70
    if normalized == "low":
        return 45
    try:
        return max(0, min(100, int(normalized)))
    except ValueError:
        return 70


def _excerpt(text: str, offset: int, length: int) -> str:
    start = max(0, offset - 96)
    end = min(len(text), offset + length + 96)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return prefix + text[start:end].replace("\n", " ").strip() + suffix


def _tier_counts(rules: list[YaraRule]) -> dict[str, int]:
    counts = {"T1": 0, "T2": 0, "T3": 0}
    for rule in rules:
        counts[rule.tier] = counts.get(rule.tier, 0) + 1
    return counts
