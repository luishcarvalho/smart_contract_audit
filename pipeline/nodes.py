"""
LangGraph node functions.

Each function receives a RAGState, performs one step, and returns
the updated state. Nodes are pure functions — no class state.

Nodes:
  retrieve_node        — vector similarity search (RAG only)
  generate_context_node — format retrieved docs as text (RAG only)
  analyze_node         — call LLM with structured prompt
  parse_output_node    — parse LLM response into VulnerabilityAnalysis JSON
"""
from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

from smart_contract_audit.models.schemas import RAGState, VulnerabilityAnalysis
from smart_contract_audit.pipeline.prompt import DIRECT_PROMPT_TEMPLATE, RAG_PROMPT_TEMPLATE

if TYPE_CHECKING:
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaLLM

# Shared output parser (stateless, safe to reuse)
_output_parser = PydanticOutputParser(pydantic_object=VulnerabilityAnalysis)


# ─── Code truncation ──────────────────────────────────────────────────────────

def _truncate_code(code: str, max_chars: int) -> str:
    """Truncate *code* to *max_chars*, keeping the first 2/3 and last 1/3.

    Preserves pragma/imports/state variables (top) and the final functions
    (bottom), discarding the middle — the least likely location for
    vulnerability-critical logic.
    """
    if len(code) <= max_chars:
        return code

    keep_top = (max_chars * 2) // 3
    keep_bottom = max_chars - keep_top
    truncated = (
        code[:keep_top]
        + f"\n\n// ... [{len(code) - max_chars} chars truncated] ...\n\n"
        + code[-keep_bottom:]
    )
    print(
        f"[truncation] Contract truncated: {len(code)} → {len(truncated)} chars "
        f"(kept first {keep_top} + last {keep_bottom})"
    )
    return truncated


# ─── RAG nodes ────────────────────────────────────────────────────────────────

def make_retrieve_node(
    vectorstore: "Chroma",
    top_k: int,
    use_hybrid: bool = True,
    vuln_metadata_field: str = "vulnerability",
):
    """Return a retrieve node bound to *vectorstore* and *top_k*.

    use_hybrid=True  → category-filtered search first, semantic fallback fills remaining slots
    use_hybrid=False → pure semantic similarity search (original behaviour)
    """

    def retrieve_node(state: RAGState) -> RAGState:
        vuln_name = state["vulnerability_name"]
        query = state["query"]

        try:
            if use_hybrid:
                # Step 1: category-filtered search
                try:
                    filtered_docs = vectorstore.similarity_search(
                        query, k=top_k, filter={vuln_metadata_field: vuln_name}
                    )
                except Exception:
                    filtered_docs = []

                if len(filtered_docs) == 0:
                    print(
                        f"[retrieve] No examples for '{vuln_name}' in vectorstore "
                        f"— using semantic fallback"
                    )
                    docs = vectorstore.similarity_search(query, k=top_k)
                    retrieval_mode = "semantic_only"
                elif len(filtered_docs) >= top_k:
                    docs = filtered_docs[:top_k]
                    retrieval_mode = "category_only"
                else:
                    # Complement filtered results with semantic search to reach top_k
                    semantic_docs = vectorstore.similarity_search(query, k=top_k)
                    seen = {d.page_content for d in filtered_docs}
                    complement = [d for d in semantic_docs if d.page_content not in seen]
                    needed = top_k - len(filtered_docs)
                    docs = filtered_docs + complement[:needed]
                    retrieval_mode = "hybrid"
            else:
                docs = vectorstore.similarity_search(query, k=top_k)
                retrieval_mode = "semantic_only"

            state["documents"] = docs
            state["retrieval_mode"] = retrieval_mode
            state["messages"].append(
                SystemMessage(content=f"Retrieved {len(docs)} documents (mode={retrieval_mode})")
            )
        except Exception as e:
            state["documents"] = []
            state["retrieval_mode"] = "semantic_only"
            state["messages"].append(SystemMessage(content=f"Retrieval failed: {e}"))

        return state

    return retrieve_node


def generate_context_node(state: RAGState) -> RAGState:
    """Format retrieved documents into a context string."""
    if state["documents"]:
        parts = []
        for i, doc in enumerate(state["documents"], 1):
            vuln = doc.metadata.get("vulnerability", "unknown")
            parts.append(f"Example {i} ({vuln}):\n{doc.page_content[:500]}...")
        state["context"] = "\n\n".join(parts)
    else:
        state["context"] = "No relevant examples found."
    return state


# ─── Shared nodes ─────────────────────────────────────────────────────────────

def make_analyze_node(
    llm: "OllamaLLM",
    use_rag: bool,
    max_retries: int = 3,
    retry_delay: float = 5.0,
    max_code_chars: int = 120_000,
):
    """Return an analyze node bound to *llm* and the correct prompt template.

    Includes retry logic to handle Ollama runner crashes
    ('failed to sample token' / EOF errors).
    """
    template = RAG_PROMPT_TEMPLATE if use_rag else DIRECT_PROMPT_TEMPLATE

    def analyze_node(state: RAGState) -> RAGState:
        code = _truncate_code(state["query"], max_code_chars)
        swc_raw = state.get("swc_context", "")
        swc_section = (
            "SWC Registry Reference\n"
            "Authoritative definition and known fix pattern from the Smart Contract "
            "Weakness Classification registry. Use it to calibrate the exact vulnerability "
            "pattern — do NOT treat it as evidence that the contract is vulnerable.\n\n"
            + swc_raw
        ) if swc_raw else ""

        fmt_kwargs = dict(
            query=code,
            vulnerability_name=state["vulnerability_name"],
            vulnerability_description=state["vulnerability_description"],
            format_instructions=_output_parser.get_format_instructions(),
            swc_section=swc_section,
        )
        if use_rag:
            fmt_kwargs["context"] = state.get("context", "")

        prompt = template.format(**fmt_kwargs)

        if state.get("debug", False):
            print("=" * 80)
            print("LLM FINAL PROMPT (DEBUG MODE)")
            print("=" * 80)
            print(prompt)
            print("=" * 80)
            print("Sending prompt to LLM...\n")

        last_error: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                response = llm.invoke(prompt)
                state["response"] = response
                state["messages"].append(HumanMessage(content="Analysis completed"))
                return state
            except Exception as e:
                last_error = e
                is_ollama_crash = any(
                    kw in str(e).lower()
                    for kw in ("eof", "connection", "failed to sample", "500", "timeout")
                )
                if is_ollama_crash and attempt < max_retries:
                    print(
                        f"\n[Retry {attempt}/{max_retries}] Ollama runner error: {e}. "
                        f"Waiting {retry_delay}s before retry..."
                    )
                    time.sleep(retry_delay)
                else:
                    break

        state["response"] = f"Analysis failed after {max_retries} attempts: {last_error}"
        state["messages"].append(
            HumanMessage(content=f"Analysis failed: {last_error}")
        )
        return state

    return analyze_node


def parse_output_node(state: RAGState) -> RAGState:
    """Parse LLM response into structured VulnerabilityAnalysis JSON."""
    try:
        parsed = _output_parser.parse(state["response"])
        state["parsed_output"] = parsed.model_dump()
    except Exception as primary_err:
        try:
            match = re.search(r"\{.*\}", state["response"], re.DOTALL)
            if match:
                state["parsed_output"] = json.loads(match.group())
            else:
                raise ValueError("No JSON found in response")
        except Exception:
            state["parsed_output"] = {
                "issues": [
                    {
                        "issue": "analysis_error",
                        "description": (
                            f"Failed to parse response: {primary_err}. "
                            f"Raw: {state['response'][:200]}..."
                        ),
                        "severity": "low",
                    }
                ],
                "summary": "Analysis completed with parsing errors",
            }
    return state
