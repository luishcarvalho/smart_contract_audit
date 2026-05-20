"""
LangGraph workflow builder for the dual-agent audit pipeline.

Graph topologies (resolved at instantiation time):

  RAG + Reviewer (cyclic debate loop):
    retrieve → generate_context → detector → reviewer
                                                 │
                                  ┌──────────────┴──────────────┐
                              CONFIRMED                   REFUTED/UNCERTAIN
                            or max_rounds                        │
                                  │                         feedback_node
                               reconcile                         │
                                  │                      detector (round N)
                             parse_output                        │
                                  │                      reviewer (round N)
                                 END                             │
                                                       [consensus or max_rounds]
                                                                 │
                                                             reconcile → ...

  RAG, no Reviewer (linear):
    retrieve → generate_context → detector → reconcile → parse_output → END

  Direct + Reviewer (cyclic, same loop as RAG+Reviewer but without retrieve/generate_context):
    detector → reviewer → [loop as above]

  Direct, no Reviewer (linear):
    detector → reconcile → parse_output → END
"""
from __future__ import annotations

import json
from typing import Optional

from langgraph.graph import END, StateGraph

from smart_contract_audit_agents.config import Config
from smart_contract_audit_agents.models.schemas import RAGState
from smart_contract_audit_agents.pipeline.nodes import (
    feedback_node,
    generate_context_node,
    make_detector_node,
    make_reconcile_node,
    make_retrieve_node,
    make_reviewer_node,
    parse_output_node,
)


def should_continue_debate(state: RAGState) -> str:
    """Conditional edge after reviewer_node.

    Returns:
      "reconcile" — consensus reached, or round limit hit (impasse → arbitration)
      "feedback"  — continue debate for another round
    """
    if state.get("consensus_reached", False):
        return "reconcile"
    if state.get("current_round", 1) >= state.get("max_rounds", 3):
        return "reconcile"
    return "feedback"


class AuditPipeline:
    """Main pipeline class.  Instantiate once, call `.analyze()` many times."""

    def __init__(
        self,
        llm,
        cfg: Config,
        vectorstore=None,
        owasp_lookup=None,
        vuln_desc_lookup=None,
    ):
        self.llm = llm
        self.cfg = cfg
        self.owasp_lookup = owasp_lookup
        self.vuln_desc_lookup = vuln_desc_lookup

        use_rag = cfg.retrieval.use_rag
        if use_rag and vectorstore is None:
            raise ValueError("use_rag=True requires a vectorstore.")

        self.workflow = self._build_workflow(llm, cfg, vectorstore)

    # ── build ─────────────────────────────────────────────────────────────────

    def _build_workflow(self, llm, cfg: Config, vectorstore):
        use_rag = cfg.retrieval.use_rag
        use_reviewer = cfg.agent.use_reviewer

        detector_node = make_detector_node(llm, cfg)
        reconcile_node = make_reconcile_node(cfg)

        graph = StateGraph(RAGState)
        graph.add_node("detector", detector_node)
        graph.add_node("reconcile", reconcile_node)
        graph.add_node("parse_output", parse_output_node)

        if use_reviewer:
            reviewer_node = make_reviewer_node(llm, cfg)
            graph.add_node("reviewer", reviewer_node)

        if use_rag:
            retrieve_node = make_retrieve_node(
                vectorstore,
                top_k=cfg.retrieval.top_k,
                use_hybrid=cfg.retrieval.use_hybrid,
                vuln_metadata_field=cfg.retrieval.vuln_metadata_field,
            )
            graph.add_node("retrieve", retrieve_node)
            graph.add_node("generate_context", generate_context_node)

            graph.set_entry_point("retrieve")
            graph.add_edge("retrieve", "generate_context")
            graph.add_edge("generate_context", "detector")
        else:
            graph.set_entry_point("detector")

        if use_reviewer:
            graph.add_node("feedback", feedback_node)
            graph.add_edge("detector", "reviewer")
            graph.add_conditional_edges(
                "reviewer",
                should_continue_debate,
                {
                    "reconcile": "reconcile",
                    "feedback": "feedback",
                },
            )
            graph.add_edge("feedback", "detector")
        else:
            graph.add_edge("detector", "reconcile")

        graph.add_edge("reconcile", "parse_output")
        graph.add_edge("parse_output", END)

        return graph.compile()

    # ── public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        query: str,
        vulnerability_name: str,
        vulnerability_description: str,
        debug: bool = False,
    ) -> dict:
        owasp_context = ""
        if self.owasp_lookup is not None:
            owasp_context = self.owasp_lookup.lookup_formatted(vulnerability_name) or ""

        # Priority: OWASP description → secondary CSV (with caveat) → param
        vuln_canonical_description = ""
        if self.owasp_lookup is not None:
            vuln_canonical_description = self.owasp_lookup.lookup_description(vulnerability_name) or ""
        if not vuln_canonical_description and self.vuln_desc_lookup is not None:
            fallback = self.vuln_desc_lookup.lookup(vulnerability_name) or ""
            if fallback:
                vuln_canonical_description = (
                    "[Note: description from secondary source — may be outdated]\n" + fallback
                )
        if not vuln_canonical_description:
            vuln_canonical_description = vulnerability_description

        initial_state = RAGState(
            query=query,
            documents=[],
            context="",
            response="",
            parsed_output={},
            messages=[],
            vulnerability_name=vulnerability_name,
            vulnerability_description=vulnerability_description,
            debug=debug,
            retrieval_mode="semantic_only",
            owasp_context=owasp_context,
            # Detector outputs (zeroed)
            detector_verdict="",
            detector_confidence=0.0,
            detector_reasoning="",
            detector_issues=[],
            # Reviewer outputs (zeroed)
            reviewer_verdict="",
            reviewer_confidence=0.0,
            reviewer_reasoning="",
            # Reconciler output (zeroed)
            reconciliation_rule="",
            final_verdict="",
            final_confidence=0.0,
            reconciliation_weight_ratio=0.0,
            # Canonical description for reviewer
            vuln_canonical_description=vuln_canonical_description,
            # Debate cycle control
            current_round=1,
            max_rounds=self.cfg.agent.max_rounds,
            consensus_reached=False,
            debate_history=[],
            reviewer_feedback="",
            conversation_log=[],
        )

        final_state = self.workflow.invoke(initial_state)

        debate_history = final_state.get("debate_history", [])
        current_round = final_state.get("current_round", 1)
        consensus_reached = final_state.get("consensus_reached", False)
        rounds_to_consensus = current_round if consensus_reached else final_state.get("max_rounds", 3)

        detector_confidence_delta = 0.0
        if len(debate_history) >= 2:
            detector_confidence_delta = round(
                debate_history[-1]["detector_confidence"] - debate_history[0]["detector_confidence"],
                4,
            )

        return {
            "json_output": json.dumps(final_state["parsed_output"]),
            "parsed_response": final_state["parsed_output"],
            "context": final_state.get("context", ""),
            "raw_response": final_state.get("response", ""),
            "retrieval_mode": final_state.get("retrieval_mode", "semantic_only"),
            # Detector fields
            "detector_verdict": final_state.get("detector_verdict", "ABSENT"),
            "detector_confidence": final_state.get("detector_confidence", 0.0),
            "detector_reasoning": final_state.get("detector_reasoning", ""),
            # Reviewer fields
            "reviewer_verdict": final_state.get("reviewer_verdict", ""),
            "reviewer_confidence": final_state.get("reviewer_confidence", 0.0),
            "reviewer_reasoning": final_state.get("reviewer_reasoning", ""),
            # Final reconciled fields
            "final_verdict": final_state.get("final_verdict", "ABSENT"),
            "final_confidence": final_state.get("final_confidence", 0.0),
            "reconciliation_rule": final_state.get("reconciliation_rule", ""),
            # Debate cycle metrics
            "rounds_to_consensus": rounds_to_consensus,
            "consensus_reached": consensus_reached,
            "debate_history": debate_history,
            "reconciliation_weight_ratio": final_state.get("reconciliation_weight_ratio", 0.0),
            "detector_confidence_delta": detector_confidence_delta,
            "conversation_log": final_state.get("conversation_log", []),
        }

    # Alias kept for compatibility
    def forward(
        self,
        query: str,
        vulnerability_name: str,
        vulnerability_description: str,
        debug: bool = False,
    ) -> dict:
        return self.analyze(query, vulnerability_name, vulnerability_description, debug)
