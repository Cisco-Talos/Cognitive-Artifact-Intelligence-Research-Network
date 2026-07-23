from __future__ import annotations

from datetime import datetime, timezone

from cairn.corpus import Corpus
from cairn.graph import build_graph
from cairn.models import AcquisitionFilter, RuleMatch, RuleStringHit, SampleRecord
from cairn.seeds import add_seed, run_seed_validation


def test_corpus_dedupes_samples_by_hash_and_preserves_filter_provenance(tmp_path) -> None:
    db_path = tmp_path / "cairn.sqlite"
    corpus = Corpus(db_path)
    acquisition_filter = AcquisitionFilter(
        name="Prompt Residue",
        slug="prompt-residue",
        category="prompt",
        description="test",
        query_text='content:"system prompt"',
    )
    run_id = corpus.start_run(acquisition_filter, requested=10)
    sample = SampleRecord(
        sha256="a" * 64,
        name="prompt-loader.exe",
        vt_url="https://www.virustotal.com/gui/file/" + "a" * 64,
        first_seen="2026-05-01",
        last_seen="2026-05-02",
        file_type="Win32 EXE",
        detections=8,
        tags=["peexe"],
        raw={"cairn": {"provider_references": ["OpenAI"]}},
        collected_at=datetime.now(timezone.utc),
    )
    match = RuleMatch(
        rule="T1-Prompt_Residue",
        tier="T1",
        artifact_type="prompt",
        artifact_class="prompt_residue",
        confidence=82,
        description="Prompt residue",
        matched_strings=[
            RuleStringHit(identifier="$system_prompt", pattern="system prompt", excerpt="system prompt", offset=0)
        ],
    )

    assert corpus.upsert_sample(sample, acquisition_filter, run_id, [match]) is True
    assert corpus.upsert_sample(sample, acquisition_filter, run_id, [match]) is False
    payload = corpus.summary()

    assert payload["samples"] == 1
    assert payload["rule_matches"] == 1

    graph = build_graph(database_path=db_path)
    assert any(node["type"] == "sample" for node in graph["nodes"])
    assert any(edge["type"] == "matched_rule" for edge in graph["edges"])


def test_known_seed_validation_uses_expected_rule_matches(tmp_path) -> None:
    db_path = tmp_path / "cairn.sqlite"
    corpus = Corpus(db_path)
    acquisition_filter = AcquisitionFilter(
        name="Prompt Residue",
        slug="prompt-residue",
        category="prompt",
        description="test",
        query_text='content:"system prompt"',
    )
    run_id = corpus.start_run(acquisition_filter, requested=10)
    sample = SampleRecord(
        sha256="b" * 64,
        name="prompt-loader.exe",
        vt_url="https://www.virustotal.com/gui/file/" + "b" * 64,
        first_seen="2026-05-01",
        last_seen="2026-05-02",
        file_type="Win32 EXE",
        detections=8,
        tags=["peexe"],
        raw={
            "id": "b" * 64,
            "attributes": {
                "meaningful_name": "prompt-loader.exe",
                "signature_info": {"comments": "system prompt: You are a triage assistant."},
            },
        },
        collected_at=datetime.now(timezone.utc),
    )
    corpus.upsert_sample(sample, acquisition_filter, run_id, [])
    add_seed(
        "b" * 64,
        family_name="PromptLoader",
        expectations=[{"rule_name": "T1-Prompt_Residue", "expected_result": "should_match"}],
        database_path=db_path,
    )

    payload = run_seed_validation(database_path=db_path)

    assert payload["summary"]["pass"] == 1
    assert payload["details"][0]["status"] == "pass"
