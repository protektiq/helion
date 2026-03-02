"""Entry point: run the exploitability agent for one cluster."""

from typing import TYPE_CHECKING

from app.schemas.exploitability import ExploitabilityOutput
from app.schemas.findings import VulnerabilityCluster
from app.services.agent.graph import build_exploitability_graph
from app.services.agent.state import ExploitabilityAgentState
from app.services.enrichment import save_cluster_enrichment

if TYPE_CHECKING:
    from app.core.config import Settings
    from sqlalchemy.orm import Session
else:
    Session = None


async def run_exploitability_agent(
    cluster: VulnerabilityCluster,
    settings: "Settings",
    *,
    session: "Session | None" = None,
    upload_job_id: int | None = None,
    persist_enrichment: bool = True,
    is_dev_only: bool = False,
) -> ExploitabilityOutput:
    """
    Run the grounded exploitability agent for one cluster. Returns ExploitabilityOutput
    with optional grounded fields (kev, epss, fixed_in_versions, evidence).
    If session is provided, persist_enrichment is True, and upload_job_id is not None,
    stores enrichment to DB (enrichments are only persisted when scoped to a job).
    When is_dev_only is True, KEV does not force Tier 1 (tier set to Tier 2).
    """
    graph = build_exploitability_graph(settings)
    initial: ExploitabilityAgentState = {"cluster": cluster, "is_dev_only": is_dev_only}
    result = await graph.ainvoke(initial)

    if (
        persist_enrichment
        and session is not None
        and upload_job_id is not None
        and "enrichment_raw" in result
    ):
        save_cluster_enrichment(
            session,
            upload_job_id,
            cluster.vulnerability_id,
            result["enrichment_raw"],
            dependency=cluster.dependency or "",
        )
        # Caller should commit the session (e.g. API endpoint).

    out = result.get("validated_output")
    if out is None:
        raise RuntimeError("Agent did not produce validated_output")
    return out
