from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest


# ---------------------------------------------------------------------------
# cosine_near — no model download required
# ---------------------------------------------------------------------------

def test_cosine_near_ranks_correctly():
    from cairn.embed import cosine_near

    # Three L2-normalised 2-D vectors
    matrix = np.array(
        [[1.0, 0.0], [0.0, 1.0], [0.707, 0.707]],
        dtype=np.float32,
    )
    query = np.array([1.0, 0.0], dtype=np.float32)
    shas = ["aaa", "bbb", "ccc"]

    results = cosine_near(query, matrix, shas, top_k=3)

    assert len(results) == 3
    assert results[0]["sha256"] == "aaa"
    assert results[0]["score"] == pytest.approx(1.0, abs=1e-5)
    # ccc is closer to aaa than bbb is
    assert results[1]["sha256"] == "ccc"
    assert results[2]["sha256"] == "bbb"


def test_cosine_near_top_k_respected():
    from cairn.embed import cosine_near

    matrix = np.eye(5, dtype=np.float32)
    query = matrix[0]
    shas = [f"sha{i}" for i in range(5)]

    results = cosine_near(query, matrix, shas, top_k=2)
    assert len(results) == 2


def test_cosine_near_empty_matrix():
    from cairn.embed import cosine_near

    matrix = np.empty((0, 4), dtype=np.float32)
    query = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    results = cosine_near(query, matrix, [], top_k=5)
    assert results == []


# ---------------------------------------------------------------------------
# corpus round-trip — store and reload embeddings
# ---------------------------------------------------------------------------

def _make_corpus(tmp_path: Path):
    from cairn.corpus import Corpus

    corpus = Corpus(tmp_path / "test.sqlite")
    # Insert a minimal sample to satisfy the FK constraint
    with corpus.connect() as conn:
        conn.execute(
            """
            INSERT INTO samples
                (sha256, name, vt_url, file_type, detections, tags_json, raw_json,
                 collected_at, updated_at)
            VALUES ('abc123def456abc123def456abc123def456abc123def456abc123def456abc1',
                    'test', 'https://vt/test', 'PE32', 5, '[]', '{}',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')
            """
        )
    return corpus


SHA = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"


def test_store_and_load_embeddings(tmp_path):
    corpus = _make_corpus(tmp_path)
    vec = np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float32)

    corpus.store_embeddings([(SHA, "test-model", vec, 200)])

    rows = corpus.load_embeddings()
    assert len(rows) == 1
    assert rows[0]["sha256"] == SHA
    assert rows[0]["model"] == "test-model"
    assert rows[0]["text_len"] == 200

    loaded = np.frombuffer(bytes(rows[0]["embedding"]), dtype=np.float32)
    np.testing.assert_array_almost_equal(loaded, vec)


def test_load_embeddings_filter_by_model(tmp_path):
    corpus = _make_corpus(tmp_path)
    vec = np.array([1.0, 0.0], dtype=np.float32)

    corpus.store_embeddings([(SHA, "model-a", vec, 100)])

    assert len(corpus.load_embeddings(model="model-a")) == 1
    assert len(corpus.load_embeddings(model="model-b")) == 0


def test_store_embeddings_upsert(tmp_path):
    corpus = _make_corpus(tmp_path)
    v1 = np.array([1.0, 0.0], dtype=np.float32)
    v2 = np.array([0.0, 1.0], dtype=np.float32)

    corpus.store_embeddings([(SHA, "m", v1, 50)])
    corpus.store_embeddings([(SHA, "m", v2, 60)])

    rows = corpus.load_embeddings()
    assert len(rows) == 1
    loaded = np.frombuffer(bytes(rows[0]["embedding"]), dtype=np.float32)
    np.testing.assert_array_almost_equal(loaded, v2)


def test_store_clusters(tmp_path):
    corpus = _make_corpus(tmp_path)
    vec = np.array([1.0, 0.0], dtype=np.float32)
    corpus.store_embeddings([(SHA, "m", vec, 100)])

    corpus.store_clusters("run-001", [(SHA, 0, "m")])

    with corpus.connect() as conn:
        rows = conn.execute("SELECT * FROM artifact_clusters").fetchall()
    assert len(rows) == 1
    assert rows[0]["cluster_id"] == 0
    assert rows[0]["run_id"] == "run-001"


def test_enrich_near_results(tmp_path):
    corpus = _make_corpus(tmp_path)
    results = corpus.enrich_near_results([{"sha256": SHA, "score": 0.99}])

    assert len(results) == 1
    assert results[0]["sha256"] == SHA
    assert results[0]["score"] == pytest.approx(0.99)
    assert results[0]["name"] == "test"
    assert results[0]["rule_matches"] == []


def test_enrich_near_results_empty(tmp_path):
    corpus = _make_corpus(tmp_path)
    assert corpus.enrich_near_results([]) == []


# ---------------------------------------------------------------------------
# cluster() — no model download required
# ---------------------------------------------------------------------------

def test_cluster_returns_labels():
    pytest.importorskip("hdbscan")
    from cairn.embed import cluster

    rng = np.random.default_rng(42)
    # Two tight blobs of 20 points each in 4-D
    a = rng.normal(loc=[1, 0, 0, 0], scale=0.05, size=(20, 4)).astype(np.float32)
    b = rng.normal(loc=[0, 1, 0, 0], scale=0.05, size=(20, 4)).astype(np.float32)
    matrix = np.vstack([a, b])

    labels = cluster(matrix, min_cluster_size=5)
    assert labels.shape == (40,)
    # Should find at least 2 clusters
    assert len(set(labels.tolist()) - {-1}) >= 2


def test_cluster_too_few_points():
    pytest.importorskip("hdbscan")
    from cairn.embed import cluster

    matrix = np.eye(2, dtype=np.float32)
    labels = cluster(matrix, min_cluster_size=5)
    assert list(labels) == [-1, -1]


# ---------------------------------------------------------------------------
# encode() — skipped when sentence-transformers not installed
# ---------------------------------------------------------------------------

def test_encode_produces_normalised_vectors():
    SentenceTransformer = pytest.importorskip("sentence_transformers").SentenceTransformer  # noqa: F841
    from cairn.embed import encode

    texts = ["hello world", "foo bar baz", "malware analysis"]
    vectors = encode(texts, model_name="all-MiniLM-L6-v2")

    assert vectors.shape == (3, 384)
    norms = np.linalg.norm(vectors, axis=1)
    np.testing.assert_allclose(norms, np.ones(3), atol=1e-5)
