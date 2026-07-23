from __future__ import annotations

from cairn.config import load_acquisition_filters
from cairn.vt import content_query_fallback


def test_acquisition_filters_are_independent_channels() -> None:
    filters = load_acquisition_filters()
    slugs = {row.slug for row in filters}

    assert {
        "broad-discovery",
        "prompt-residue",
        "local-llm-runtime",
        "provider-api-integration",
        "ai-analysis-evasion",
        "offensive-co-occurrence",
    } <= slugs


def test_content_modifier_fallback_preserves_terms() -> None:
    query = '(type:peexe OR type:pedll) AND positives:5+ AND content:"openai"'
    fallback = content_query_fallback(query)

    assert 'content:"openai"' not in fallback
    assert '"openai"' in fallback

