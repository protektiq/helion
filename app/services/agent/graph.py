"""LangGraph: enrich → assess → llm_finalize → validate."""

from typing import TYPE_CHECKING

from langgraph.graph import END, START, StateGraph

from app.services.agent.nodes import (
    assess_node,
    enrich_node,
    llm_finalize_node,
    validate_node,
)
from app.services.agent.state import ExploitabilityAgentState

if TYPE_CHECKING:
    from app.core.config import Settings


def build_exploitability_graph(settings: "Settings"):
    """
    Build and compile the exploitability agent graph. Nodes are bound to settings.
    Returns compiled graph; use ainvoke(initial_state) to run.
    """
    async def enrich(state: ExploitabilityAgentState) -> ExploitabilityAgentState:
        return await enrich_node(state, settings=settings)

    async def llm_finalize(state: ExploitabilityAgentState) -> ExploitabilityAgentState:
        return await llm_finalize_node(state, settings=settings)

    graph = StateGraph(ExploitabilityAgentState)
    graph.add_node("enrich", enrich)
    graph.add_node("assess", assess_node)
    graph.add_node("llm_finalize", llm_finalize)
    graph.add_node("validate", validate_node)

    graph.add_edge(START, "enrich")
    graph.add_edge("enrich", "assess")
    graph.add_edge("assess", "llm_finalize")
    graph.add_edge("llm_finalize", "validate")
    graph.add_edge("validate", END)

    return graph.compile()
