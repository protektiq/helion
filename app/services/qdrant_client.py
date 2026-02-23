"""Layer B: Qdrant vector store for semantic similarity. Optional; requires QDRANT_URL."""

from typing import Any

from app.core.config import get_settings


def upsert_finding_vectors(
    collection_name: str,
    finding_ids: list[str],
    vectors: list[list[float]],
    payloads: list[dict[str, Any]] | None = None,
) -> bool:
    """
    Upsert vectors for findings into the given Qdrant collection.
    Returns True on success, False when Qdrant is not configured or on error.
    """
    settings = get_settings()
    if not settings.QDRANT_URL or not settings.QDRANT_URL.strip():
        return False
    if not finding_ids or not vectors or len(finding_ids) != len(vectors):
        return False
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import PointStruct, VectorParams, Distance
        client = QdrantClient(url=settings.QDRANT_URL)
        # Ensure collection exists
        try:
            client.get_collection(collection_name)
        except Exception:
            dim = len(vectors[0]) if vectors else 384
            client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )
        points = [
            PointStruct(
                id=str(i),
                vector=vec,
                payload={"finding_id": fid, **(payloads[i] if payloads and i < len(payloads) else {})},
            )
            for i, (fid, vec) in enumerate(zip(finding_ids, vectors))
        ]
        client.upsert(collection_name=collection_name, points=points)
        return True
    except ImportError:
        return False
    except Exception:
        return False


def search_similar_pairs(
    collection_name: str,
    finding_ids: list[str],
    vectors: list[list[float]],
    top_k: int,
    score_threshold: float,
) -> list[tuple[str, str]]:
    """
    For each finding, search top_k similar vectors in the collection; return pairs
    (finding_id_a, finding_id_b) where similarity >= score_threshold (cosine).
    """
    settings = get_settings()
    if not settings.QDRANT_URL or not settings.QDRANT_URL.strip():
        return []
    if not finding_ids or not vectors or len(finding_ids) != len(vectors):
        return []
    try:
        from qdrant_client import QdrantClient
        client = QdrantClient(url=settings.QDRANT_URL)
        pairs: set[tuple[str, str]] = set()
        for i, (fid, vec) in enumerate(zip(finding_ids, vectors)):
            results = client.search(
                collection_name=collection_name,
                query_vector=vec,
                limit=top_k + 1,
                score_threshold=score_threshold,
            )
            for hit in results:
                other_id = (hit.payload or {}).get("finding_id")
                if other_id and other_id != fid:
                    a, b = (fid, other_id) if fid < other_id else (other_id, fid)
                    pairs.add((a, b))
        return list(pairs)
    except ImportError:
        return []
    except Exception:
        return []
