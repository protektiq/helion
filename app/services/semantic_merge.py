"""Layer B semantic merge: embeddings + Qdrant. When CLUSTER_USE_SEMANTIC and Qdrant are enabled, returns merge pairs."""

import uuid
from typing import TYPE_CHECKING

from app.core.config import get_settings
from app.services.embeddings import build_embedding_text, embed_texts
from app.services.qdrant_client import search_similar_pairs, upsert_finding_vectors

if TYPE_CHECKING:
    from app.models.finding import Finding


def apply_semantic_merge(
    findings: list["Finding"],
    signatures: list[str],
) -> list[tuple[str, str]]:
    """
    When CLUSTER_USE_SEMANTIC and QDRANT_URL are set: build text per finding, embed,
    upsert to Qdrant, search top-k similar; return (finding_id_a, finding_id_b) pairs above threshold.
    When disabled or unavailable, returns [].
    """
    settings = get_settings()
    if not settings.CLUSTER_USE_SEMANTIC or not settings.QDRANT_URL or not settings.QDRANT_URL.strip():
        return []
    if not findings or len(findings) != len(signatures):
        return []
    texts = [build_embedding_text(f) for f in findings]
    vectors = embed_texts(texts)
    if not vectors or len(vectors) != len(findings):
        return []
    finding_ids = [str(f.id) for f in findings]
    collection_name = f"{settings.QDRANT_COLLECTION_PREFIX}_{uuid.uuid4().hex[:12]}"
    payloads = [{"deterministic_signature": sig} for sig in signatures]
    if not upsert_finding_vectors(collection_name, finding_ids, vectors, payloads):
        return []
    pairs = search_similar_pairs(
        collection_name,
        finding_ids,
        vectors,
        top_k=settings.CLUSTER_TOP_K,
        score_threshold=settings.CLUSTER_SIMILARITY_THRESHOLD,
    )
    return pairs
