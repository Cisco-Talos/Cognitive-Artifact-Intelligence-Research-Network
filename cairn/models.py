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

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AcquisitionFilter:
    name: str
    slug: str
    category: str
    description: str
    query_text: str
    enabled: bool = True
    default_limit: int = 100
    min_detections: int = 5


@dataclass(frozen=True)
class AcquisitionRunSummary:
    filter_slug: str
    status: str
    requested: int
    found: int
    imported: int
    matched_samples: int
    rule_hits: int
    message: str
    fallback_query_used: bool = False


@dataclass(frozen=True)
class YaraString:
    identifier: str
    pattern: str
    nocase: bool = False


@dataclass(frozen=True)
class YaraRule:
    name: str
    meta: dict[str, Any]
    strings: list[YaraString]
    condition: str

    @property
    def tier(self) -> str:
        configured = str(self.meta.get("tier") or "").upper()
        if configured in {"T1", "T2", "T3"}:
            return configured
        if self.name.startswith("T1-"):
            return "T1"
        if self.name.startswith("T2-"):
            return "T2"
        if self.name.startswith("T3-"):
            return "T3"
        return "T1"


@dataclass(frozen=True)
class RuleStringHit:
    identifier: str
    pattern: str
    excerpt: str
    offset: int


@dataclass(frozen=True)
class RuleMatch:
    rule: str
    tier: str
    artifact_type: str
    artifact_class: str
    confidence: int
    description: str
    matched_strings: list[RuleStringHit] = field(default_factory=list)


@dataclass(frozen=True)
class SampleRecord:
    sha256: str
    name: str
    vt_url: str
    first_seen: str | None
    last_seen: str | None
    file_type: str
    detections: int
    tags: list[str]
    raw: dict[str, Any]
    collected_at: datetime


@dataclass(frozen=True)
class VTRow:
    object_id: str
    attributes: dict[str, Any]
    relationships: dict[str, Any]
    raw: dict[str, Any]
