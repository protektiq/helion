"""Layer B: embed finding text (description, rule message, CWE) for semantic similarity. Optional dependency."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.finding import Finding

# Max chars to embed per finding to avoid unbounded input.
_MAX_EMBED_TEXT_LEN = 4000


def build_embedding_text(finding: "Finding") -> str:
    """
    Build a single string from description, rule message, and CWE for embedding.
    Validates length and format; truncates to _MAX_EMBED_TEXT_LEN.
    """
    parts: list[str] = []
    desc = (finding.description or "").strip()
    if desc:
        parts.append(desc[: _MAX_EMBED_TEXT_LEN])
    raw = getattr(finding, "raw_payload", None)
    if raw and isinstance(raw, dict):
        extra = raw.get("extra")
        if isinstance(extra, dict) and extra.get("message"):
            msg = extra.get("message")
            if isinstance(msg, str) and msg.strip():
                parts.append(msg.strip()[:1024])
        meta = raw.get("metadata")
        if isinstance(meta, dict) and meta.get("cwe"):
            cwe_list = meta.get("cwe")
            if isinstance(cwe_list, list) and cwe_list:
                first = cwe_list[0]
                if isinstance(first, str) and first.strip():
                    parts.append(first.strip()[:512])
    text = " ".join(parts).strip()
    if not text:
        text = (finding.vulnerability_id or "unknown") + " " + (finding.description or "")
    return text[: _MAX_EMBED_TEXT_LEN]


def embed_texts(texts: list[str]) -> list[list[float]]:
    """
    Embed a list of strings. Returns list of vectors (same length as input).
    When sentence-transformers (or configured backend) is not available, returns empty list.
    Validate input: type, length; truncate per item.
    """
    if not texts or not isinstance(texts, list):
        return []
    validated: list[str] = []
    for t in texts:
        if not isinstance(t, str):
            validated.append("")
        else:
            validated.append((t or "").strip()[: _MAX_EMBED_TEXT_LEN])
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
        model = SentenceTransformer("all-MiniLM-L6-v2")
        vectors = model.encode(validated, convert_to_numpy=True)
        return [v.tolist() for v in vectors]
    except ImportError:
        return []
    except Exception:
        return []
