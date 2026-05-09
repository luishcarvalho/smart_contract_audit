"""
LangGraph workflow builder.

The RAG toggle lives here — it is resolved once at instantiation time
and never checked again elsewhere.

  use_rag=True  → retrieve → generate_context → analyze → parse_output
  use_rag=False →                               analyze → parse_output
"""
from __future__ import annotations

import json
from typing import Optional

from langgraph.graph import END, StateGraph

from smart_contract_audit.config import Config
from smart_contract_audit.models.schemas import RAGState
from smart_contract_audit.pipeline.nodes import (
    generate_context_node,
    make_analyze_node,
    make_retrieve_node,
    parse_output_node,
)


class AuditPipeline:
    """Main pipeline class.  Instantiate once, call `.analyze()` many times."""

    def __init__(self, llm, cfg: Config, vectorstore=None):
        self.llm = llm
        self.cfg = cfg
        use_rag = cfg.retrieval.use_rag

        if use_rag and vectorstore is None:
            raise ValueError("use_rag=True requires a vectorstore.")

        self.workflow = self._build_workflow(llm, cfg, vectorstore)

    # ── build ─────────────────────────────────────────────────────────────────

    def _build_workflow(self, llm, cfg: Config, vectorstore):
        use_rag = cfg.retrieval.use_rag
        top_k = cfg.retrieval.top_k

        analyze_node = make_analyze_node(
            llm,
            use_rag=use_rag,
            max_retries=cfg.llm.max_retries,
            retry_delay=cfg.llm.retry_delay,
            max_code_chars=cfg.llm.max_code_chars,
        )

        graph = StateGraph(RAGState)
        graph.add_node("analyze", analyze_node)
        graph.add_node("parse_output", parse_output_node)

        if use_rag:
            retrieve_node = make_retrieve_node(
                vectorstore,
                top_k=top_k,
                use_hybrid=cfg.retrieval.use_hybrid,
                vuln_metadata_field=cfg.retrieval.vuln_metadata_field,
            )
            graph.add_node("retrieve", retrieve_node)
            graph.add_node("generate_context", generate_context_node)

            graph.set_entry_point("retrieve")
            graph.add_edge("retrieve", "generate_context")
            graph.add_edge("generate_context", "analyze")
        else:
            graph.set_entry_point("analyze")

        graph.add_edge("analyze", "parse_output")
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
        )

        final_state = self.workflow.invoke(initial_state)

        return {
            "json_output": json.dumps(final_state["parsed_output"]),
            "parsed_response": final_state["parsed_output"],
            "context": final_state.get("context", ""),
            "raw_response": final_state["response"],
            "retrieval_mode": final_state.get("retrieval_mode", "semantic_only"),
        }

    # Alias kept for compatibility with the notebook's `rag_system.forward(...)` calls
    def forward(
        self,
        query: str,
        vulnerability_name: str,
        vulnerability_description: str,
        debug: bool = False,
    ) -> dict:
        return self.analyze(query, vulnerability_name, vulnerability_description, debug)
