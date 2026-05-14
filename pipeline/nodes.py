"""
LangGraph node functions for the dual-agent audit pipeline.

Nodes:
  make_retrieve_node        — vector similarity search (RAG only)
  generate_context_node     — format retrieved docs as text (RAG only)
  make_detector_node        — Detector LLM call (active vulnerability search)
  make_reviewer_node        — Reviewer LLM call (devil's advocate validation)
  make_reconcile_node       — deterministic reconciliation of Detector + Reviewer
  parse_output_node         — assemble final parsed_output from state fields
"""
from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

from smart_contract_audit_agents.models.schemas import (
    RAGState,
    ReviewerOutput,
    VulnerabilityAnalysis,
)
from smart_contract_audit_agents.pipeline.prompt import (
    DETECTOR_DIRECT_PROMPT_TEMPLATE,
    DETECTOR_RAG_PROMPT_TEMPLATE,
    REVIEWER_PROMPT_TEMPLATE,
)

if TYPE_CHECKING:
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaLLM
    from smart_contract_audit_agents.config import Config

# Shared output parsers (stateless, safe to reuse)
_detector_parser = PydanticOutputParser(pydantic_object=VulnerabilityAnalysis)
_reviewer_parser = PydanticOutputParser(pydantic_object=ReviewerOutput)


# ─── Code truncation ──────────────────────────────────────────────────────────

def _truncate_code(code: str, max_chars: int) -> str:
    """Truncate *code* to *max_chars*, keeping the first 2/3 and last 1/3."""
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
    use_hybrid=False → pure semantic similarity search
    """

    def retrieve_node(state: RAGState) -> RAGState:
        vuln_name = state["vulnerability_name"]
        query = state["query"]

        try:
            if use_hybrid:
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


# ─── Detector node ────────────────────────────────────────────────────────────

def make_detector_node(
    llm: "OllamaLLM",
    cfg: "Config",
):
    """Return a Detector node that actively searches for a vulnerability.

    Uses RAG or direct prompt based on cfg.retrieval.use_rag.
    Writes: detector_verdict, detector_confidence, detector_reasoning,
            detector_issues, response (raw LLM output).
    """
    use_rag = cfg.retrieval.use_rag
    max_retries = cfg.llm.max_retries
    retry_delay = cfg.llm.retry_delay
    max_code_chars = cfg.llm.max_code_chars
    template = DETECTOR_RAG_PROMPT_TEMPLATE if use_rag else DETECTOR_DIRECT_PROMPT_TEMPLATE

    def detector_node(state: RAGState) -> RAGState:
        code = _truncate_code(state["query"], max_code_chars)
        owasp_raw = state.get("owasp_context", "")
        swc_section = (
            "OWASP SCWE Reference\n"
            "Authoritative definition and known fix pattern from the OWASP Smart Contract "
            "Weakness Enumeration. Use it to calibrate the exact vulnerability "
            "pattern — do NOT treat it as evidence that the contract is vulnerable.\n\n"
            + owasp_raw
        ) if owasp_raw else ""

        fmt_kwargs = dict(
            query=code,
            vulnerability_name=state["vulnerability_name"],
            vulnerability_description=state["vulnerability_description"],
            format_instructions=_detector_parser.get_format_instructions(),
            swc_section=swc_section,
        )
        if use_rag:
            fmt_kwargs["context"] = state.get("context", "")

        prompt = template.format(**fmt_kwargs)

        if state.get("debug", False):
            print("=" * 80)
            print("DETECTOR PROMPT (DEBUG MODE)")
            print("=" * 80)
            print(prompt)
            print("=" * 80)
            print("Sending detector prompt to LLM...\n")

        last_error: Exception | None = None
        raw_response = ""
        for attempt in range(1, max_retries + 1):
            try:
                raw_response = llm.invoke(prompt)
                state["response"] = raw_response
                state["messages"].append(HumanMessage(content="Detector analysis completed"))
                break
            except Exception as e:
                last_error = e
                is_ollama_crash = any(
                    kw in str(e).lower()
                    for kw in ("eof", "connection", "failed to sample", "500", "timeout")
                )
                if is_ollama_crash and attempt < max_retries:
                    print(
                        f"\n[Detector retry {attempt}/{max_retries}] Ollama runner error: {e}. "
                        f"Waiting {retry_delay}s before retry..."
                    )
                    time.sleep(retry_delay)
                else:
                    raw_response = f"Detector failed after {max_retries} attempts: {last_error}"
                    state["response"] = raw_response
                    state["messages"].append(
                        HumanMessage(content=f"Detector failed: {last_error}")
                    )
                    break

        # Parse detector output
        try:
            parsed = _detector_parser.parse(raw_response)
            analysis = parsed.model_dump()
        except Exception as primary_err:
            try:
                match = re.search(r"\{.*\}", raw_response, re.DOTALL)
                if match:
                    analysis = json.loads(match.group())
                else:
                    raise ValueError("No JSON found in detector response")
            except Exception:
                analysis = {
                    "issues": [
                        {
                            "issue": "analysis_error",
                            "description": (
                                f"Failed to parse detector response: {primary_err}. "
                                f"Raw: {raw_response[:200]}..."
                            ),
                            "severity": "low",
                        }
                    ],
                    "confidence": 0.0,
                    "summary": "Detector completed with parsing errors",
                }

        issues = analysis.get("issues", []) or []
        confidence = float(analysis.get("confidence", 0.0))
        summary = str(analysis.get("summary", ""))

        state["detector_verdict"] = "PRESENT" if len(issues) > 0 else "ABSENT"
        state["detector_confidence"] = confidence
        state["detector_reasoning"] = summary
        state["detector_issues"] = [i if isinstance(i, dict) else {} for i in issues]

        return state

    return detector_node


# ─── Reviewer node ────────────────────────────────────────────────────────────

def make_reviewer_node(
    llm: "OllamaLLM",
    cfg: "Config",
):
    """Return a Reviewer node that challenges the Detector's finding.

    Does NOT use RAG — sources are ground-truth descriptions and SWC reference only.
    Writes: reviewer_verdict, reviewer_confidence, reviewer_reasoning.
    """
    max_retries = cfg.llm.max_retries
    retry_delay = cfg.llm.retry_delay
    max_code_chars = cfg.llm.max_code_chars

    def reviewer_node(state: RAGState) -> RAGState:
        # Reviewer sees the same truncated code as the Detector
        code = _truncate_code(state["query"], max_code_chars)
        owasp_raw = state.get("owasp_context", "")
        swc_section = (
            "OWASP SCWE Reference\n"
            "Authoritative definition and known fix pattern from the OWASP Smart Contract "
            "Weakness Enumeration.\n\n"
            + owasp_raw
        ) if owasp_raw else ""

        detector_reasoning = state.get("detector_reasoning", "") or ""
        if not detector_reasoning:
            # Fall back to raw response summary if reasoning is empty
            detector_reasoning = state.get("response", "")[:500]

        prompt = REVIEWER_PROMPT_TEMPLATE.format(
            detector_verdict=state.get("detector_verdict", "ABSENT"),
            detector_reasoning=detector_reasoning,
            vulnerability_name=state["vulnerability_name"],
            vuln_canonical_description=state.get("vuln_canonical_description", state["vulnerability_description"]),
            swc_section=swc_section,
            query=code,
            format_instructions=_reviewer_parser.get_format_instructions(),
        )

        if state.get("debug", False):
            print("=" * 80)
            print("REVIEWER PROMPT (DEBUG MODE)")
            print("=" * 80)
            print(prompt)
            print("=" * 80)
            print("Sending reviewer prompt to LLM...\n")

        last_error: Exception | None = None
        raw_response = ""
        for attempt in range(1, max_retries + 1):
            try:
                raw_response = llm.invoke(prompt)
                state["messages"].append(HumanMessage(content="Reviewer analysis completed"))
                break
            except Exception as e:
                last_error = e
                is_ollama_crash = any(
                    kw in str(e).lower()
                    for kw in ("eof", "connection", "failed to sample", "500", "timeout")
                )
                if is_ollama_crash and attempt < max_retries:
                    print(
                        f"\n[Reviewer retry {attempt}/{max_retries}] Ollama runner error: {e}. "
                        f"Waiting {retry_delay}s before retry..."
                    )
                    time.sleep(retry_delay)
                else:
                    raw_response = f"Reviewer failed after {max_retries} attempts: {last_error}"
                    state["messages"].append(
                        HumanMessage(content=f"Reviewer failed: {last_error}")
                    )
                    break

        # Parse reviewer output
        try:
            parsed = _reviewer_parser.parse(raw_response)
            reviewer_data = parsed.model_dump()
        except Exception as primary_err:
            try:
                match = re.search(r"\{.*\}", raw_response, re.DOTALL)
                if match:
                    reviewer_data = json.loads(match.group())
                else:
                    raise ValueError("No JSON found in reviewer response")
            except Exception:
                reviewer_data = {
                    "reviewer_verdict": "UNCERTAIN",
                    "reviewer_confidence": 0.0,
                    "reviewer_reasoning": (
                        f"Failed to parse reviewer response: {primary_err}. "
                        f"Raw: {raw_response[:200]}..."
                    ),
                }

        # Validate verdict value
        verdict = str(reviewer_data.get("reviewer_verdict", "UNCERTAIN")).upper()
        if verdict not in ("CONFIRMED", "REFUTED", "UNCERTAIN"):
            verdict = "UNCERTAIN"

        state["reviewer_verdict"] = verdict
        state["reviewer_confidence"] = float(reviewer_data.get("reviewer_confidence", 0.0))
        state["reviewer_reasoning"] = str(reviewer_data.get("reviewer_reasoning", ""))

        return state

    return reviewer_node


# ─── Reconciler node (deterministic, no LLM) ─────────────────────────────────

def make_reconcile_node(cfg: "Config"):
    """Return a deterministic reconciliation node.

    Applies one of 6 priority rules (or rule_0 when reviewer is disabled)
    to produce final_verdict, final_confidence, and reconciliation_rule.
    """
    use_reviewer = cfg.agent.use_reviewer

    def reconcile_node(state: RAGState) -> RAGState:
        d_verdict = state.get("detector_verdict", "ABSENT")
        d_conf = float(state.get("detector_confidence", 0.0))

        if not use_reviewer:
            state["final_verdict"] = d_verdict
            state["final_confidence"] = d_conf
            state["reconciliation_rule"] = "rule_0_detector_only"
            if state.get("debug", False):
                print("=" * 80)
                print("RECONCILIATION (DEBUG MODE)")
                print("=" * 80)
                print(f"Mode: single-agent (rule_0_detector_only)")
                print(f"Detector verdict: {d_verdict} | confidence: {d_conf:.3f}")
                print(f"Final verdict:    {d_verdict} | confidence: {d_conf:.3f}")
                print("=" * 80)
            return state

        r_verdict = state.get("reviewer_verdict", "UNCERTAIN")
        r_conf = float(state.get("reviewer_confidence", 0.0))

        # 6 priority rules
        if d_verdict == "PRESENT" and r_verdict == "CONFIRMED":
            final_verdict = "PRESENT"
            final_confidence = (d_conf + r_conf) / 2
            rule = "rule_1_detector_present_reviewer_confirmed"
        elif d_verdict == "ABSENT" and r_verdict == "CONFIRMED":
            final_verdict = "ABSENT"
            final_confidence = (d_conf + r_conf) / 2
            rule = "rule_2_detector_absent_reviewer_confirmed"
        elif d_verdict == "PRESENT" and r_verdict == "REFUTED":
            final_verdict = "ABSENT"
            final_confidence = r_conf * 0.8
            rule = "rule_3_detector_present_reviewer_refuted"
        elif d_verdict == "ABSENT" and r_verdict == "REFUTED":
            final_verdict = "PRESENT"
            final_confidence = r_conf * 0.7
            rule = "rule_4_detector_absent_reviewer_refuted"
        elif d_verdict == "PRESENT" and r_verdict == "UNCERTAIN":
            final_verdict = "PRESENT"
            final_confidence = d_conf * 0.6
            rule = "rule_5_detector_present_reviewer_uncertain"
        else:  # ABSENT + UNCERTAIN (or any unexpected combination)
            final_verdict = "ABSENT"
            final_confidence = d_conf * 0.6
            rule = "rule_6_detector_absent_reviewer_uncertain"

        state["final_verdict"] = final_verdict
        state["final_confidence"] = final_confidence
        state["reconciliation_rule"] = rule

        if state.get("debug", False):
            print("=" * 80)
            print("RECONCILIATION (DEBUG MODE)")
            print("=" * 80)
            print(f"Rule applied: {rule}")
            print(f"Detector:  {d_verdict} | confidence: {d_conf:.3f}")
            print(f"Reviewer:  {r_verdict} | confidence: {r_conf:.3f}")
            print(f"Final:     {final_verdict} | confidence: {final_confidence:.3f}")
            print("=" * 80)

        return state

    return reconcile_node


# ─── Parse output node ────────────────────────────────────────────────────────

def parse_output_node(state: RAGState) -> RAGState:
    """Assemble parsed_output from final_verdict, final_confidence, and detector_issues."""
    final_verdict = state.get("final_verdict", "ABSENT")
    final_confidence = float(state.get("final_confidence", 0.0))
    detector_issues = state.get("detector_issues", []) or []
    reconciliation_rule = state.get("reconciliation_rule", "")

    state["parsed_output"] = {
        "issues": detector_issues,
        "confidence": final_confidence,
        "summary": (
            f"Final verdict: {final_verdict} (confidence: {final_confidence:.3f}) "
            f"via {reconciliation_rule}"
        ),
    }
    return state
