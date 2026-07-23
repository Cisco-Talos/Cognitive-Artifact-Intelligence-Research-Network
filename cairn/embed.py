from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from cairn.corpus import Corpus


def encode(texts: list[str], model_name: str = "all-MiniLM-L6-v2") -> np.ndarray:
    """Encode a list of texts into L2-normalised float32 vectors.

    Requires the 'embed' optional dependencies:
        pip install 'cairn[embed]'
    """
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        raise ImportError(
            "sentence-transformers is required for embedding. "
            "Install it with: pip install 'cairn[embed]'"
        )
    model = SentenceTransformer(model_name)
    vectors = model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=len(texts) > 50,
        batch_size=64,
    )
    return np.array(vectors, dtype=np.float32)


def load_embeddings(corpus: Corpus, model: str | None = None) -> tuple[list[str], np.ndarray]:
    """Load stored embeddings from the corpus into a (shas, matrix) pair.

    Returns an empty list and a zero-row array if no embeddings are stored.
    """
    rows = corpus.load_embeddings(model=model)
    if not rows:
        return [], np.empty((0,), dtype=np.float32)
    shas = [row["sha256"] for row in rows]
    vecs = [np.frombuffer(bytes(row["embedding"]), dtype=np.float32) for row in rows]
    matrix = np.stack(vecs)
    return shas, matrix


def cosine_near(
    query_vec: np.ndarray,
    matrix: np.ndarray,
    shas: list[str],
    top_k: int = 10,
) -> list[dict[str, Any]]:
    """Return the top_k nearest neighbours by cosine similarity.

    Assumes both query_vec and every row in matrix are L2-normalised,
    so cosine similarity reduces to a dot product.
    """
    if matrix.ndim != 2 or matrix.shape[0] == 0:
        return []
    scores = matrix @ query_vec
    n = min(top_k, len(shas))
    top_indices = np.argpartition(scores, -n)[-n:]
    top_indices = top_indices[np.argsort(scores[top_indices])[::-1]]
    return [{"sha256": shas[int(i)], "score": float(scores[i])} for i in top_indices]


def project(matrix: np.ndarray, method: str = "auto") -> np.ndarray:
    """Project high-dim embeddings to 2D for visualization.

    Returns float32 array shape (N, 2), normalized to [-1, 1].
    method="auto": tries umap-learn, falls back to sklearn t-SNE.
    """
    if matrix.shape[0] < 3:
        return np.zeros((matrix.shape[0], 2), dtype=np.float32)

    if method in ("auto", "umap"):
        try:
            import umap as umap_lib
            coords = umap_lib.UMAP(
                n_components=2, random_state=42, min_dist=0.1, n_neighbors=15
            ).fit_transform(matrix)
        except ImportError:
            if method == "umap":
                raise ImportError("umap-learn not installed. Run: pip install umap-learn")
            from sklearn.manifold import TSNE
            coords = TSNE(
                n_components=2, random_state=42,
                perplexity=min(30, matrix.shape[0] - 1),
            ).fit_transform(matrix)
    else:  # "tsne"
        from sklearn.manifold import TSNE
        coords = TSNE(
            n_components=2, random_state=42,
            perplexity=min(30, matrix.shape[0] - 1),
        ).fit_transform(matrix)

    lo, hi = coords.min(axis=0), coords.max(axis=0)
    rng = np.where(hi - lo > 0, hi - lo, 1.0)
    return ((2.0 * (coords - lo) / rng) - 1.0).astype(np.float32)


def cluster(matrix: np.ndarray, min_cluster_size: int = 3) -> np.ndarray:
    """Cluster embedding vectors with HDBSCAN.

    Returns an integer label array; -1 means noise/unclustered.
    Requires the 'embed' optional dependencies.
    """
    try:
        import hdbscan
    except ImportError:
        raise ImportError(
            "hdbscan is required for clustering. "
            "Install it with: pip install 'cairn[embed]'"
        )
    if matrix.shape[0] < min_cluster_size:
        return np.full(matrix.shape[0], -1, dtype=np.int32)
    clusterer = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size, metric="euclidean")
    labels = clusterer.fit_predict(matrix)
    return labels.astype(np.int32)
