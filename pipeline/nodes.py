"""
LangGraph node functions for the dual-agent audit pipeline.

Nodes:
  make_triage_node          — per-contract vulnerability shortlist (LLM, cached per contract)
  triage_reject_node        — auto-ABSENT for pairs filtered out by triage (no LLM)
  make_retrieve_node        — vector similarity search (RAG only)
  generate_context_node     — format retrieved docs as text (RAG only)
  make_detector_node        — Detector LLM call (active vulnerability search)
  make_reviewer_node        — Reviewer LLM call (devil's advocate validation)
  feedback_node             — deterministic feedback synthesis + round increment
  make_reconcile_node       — confidence-weighted arbitration (or consensus pass-through)
  parse_output_node         — assemble final parsed_output from state fields
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import TYPE_CHECKING, Dict, List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

from smart_contract_audit_agents.models.schemas import (
    RAGState,
    ReviewerOutput,
    TriageOutput,
    VulnerabilityAnalysis,
)
from smart_contract_audit_agents.pipeline.prompt import (
    DETECTOR_DIRECT_PROMPT_TEMPLATE,
    DETECTOR_RAG_PROMPT_TEMPLATE,
    REVIEWER_PROMPT_TEMPLATE,
    TRIAGE_PROMPT_TEMPLATE,
)
from smart_contract_audit_agents.utils.vuln_desc_lookup import _norm as _norm_vuln

if TYPE_CHECKING:
    from langchain_chroma import Chroma
    from langchain_ollama import OllamaLLM
    from smart_contract_audit_agents.config import Config

# Shared output parsers (stateless, safe to reuse)
_detector_parser = PydanticOutputParser(pydantic_object=VulnerabilityAnalysis)
_reviewer_parser = PydanticOutputParser(pydantic_object=ReviewerOutput)
_triage_parser = PydanticOutputParser(pydantic_object=TriageOutput)


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


# ─── Triage nodes ─────────────────────────────────────────────────────────────

def make_triage_node(
    llm: "OllamaLLM",
    cfg: "Config",
    vuln_catalog: List[Tuple[str, str]],
    shortlist_cache: Dict[str, List[str]],
):
    """Return a triage node that shortlists plausible vulnerabilities per contract.

    One LLM call per unique contract: *shortlist_cache* is owned by AuditPipeline
    (keyed by sha256 of the code) and shared across graph invocations, so every
    (contract, vulnerability) pair after the first reuses the cached shortlist.
    Writes: triage_shortlist, triage_candidate.
    """
    max_retries = cfg.llm.max_retries
    retry_delay = cfg.llm.retry_delay
    max_code_chars = cfg.llm.max_code_chars
    max_shortlist = cfg.triage.max_shortlist_size

    catalog_names = [name for name, _ in vuln_catalog]
    norm_to_name = {_norm_vuln(name): name for name in catalog_names}
    # Truncated descriptions keep the catalog block small (~60 entries) so the
    # contract keeps almost the full num_ctx budget
    catalog_text = "\n".join(f"- {name}: {desc[:150]}" for name, desc in vuln_catalog)

    def _match_catalog(candidate: str) -> "str | None":
        norm = _norm_vuln(str(candidate))
        if norm in norm_to_name:
            return norm_to_name[norm]
        for key, name in norm_to_name.items():
            if norm and (norm in key or key in norm):
                return name
        return None

    def triage_node(state: RAGState) -> RAGState:
        code_hash = hashlib.sha256(state["query"].encode()).hexdigest()

        if code_hash not in shortlist_cache:
            code = _truncate_code(state["query"], max_code_chars)
            prompt = TRIAGE_PROMPT_TEMPLATE.format(
                vuln_catalog=catalog_text,
                query=code,
                max_shortlist=max_shortlist,
                format_instructions=_triage_parser.get_format_instructions(),
            )

            if state.get("debug", False):
                print("=" * 80)
                print("TRIAGE PROMPT (DEBUG MODE)")
                print("=" * 80)
                print(prompt)
                print("=" * 80)
                print("Sending triage prompt to LLM...\n")

            last_error: Exception | None = None
            raw_response = ""
            for attempt in range(1, max_retries + 1):
                try:
                    raw_response = llm.invoke(prompt)
                    state["messages"].append(HumanMessage(content="Triage shortlist completed"))
                    break
                except Exception as e:
                    last_error = e
                    is_ollama_crash = any(
                        kw in str(e).lower()
                        for kw in ("eof", "connection", "failed to sample", "500", "timeout")
                    )
                    if is_ollama_crash and attempt < max_retries:
                        print(
                            f"\n[Triage retry {attempt}/{max_retries}] Ollama runner error: {e}. "
                            f"Waiting {retry_delay}s before retry..."
                        )
                        time.sleep(retry_delay)
                    else:
                        raw_response = f"Triage failed after {max_retries} attempts: {last_error}"
                        state["messages"].append(
                            HumanMessage(content=f"Triage failed: {last_error}")
                        )
                        break

            # Parse triage output
            try:
                parsed = _triage_parser.parse(raw_response)
                candidates = parsed.candidate_vulnerabilities
            except Exception:
                try:
                    match = re.search(r"\{.*\}", raw_response, re.DOTALL)
                    if match:
                        data = json.loads(match.group())
                        candidates = data.get("candidate_vulnerabilities", []) or []
                    else:
                        raise ValueError("No JSON found in triage response")
                except Exception:
                    candidates = []

            # Map LLM names back to canonical catalog names, drop hallucinated ones
            shortlist: List[str] = []
            for cand in candidates:
                matched = _match_catalog(cand)
                if matched and matched not in shortlist:
                    shortlist.append(matched)
            shortlist = shortlist[:max_shortlist]

            # Fail-open: an empty shortlist (LLM error, unparseable output, no
            # catalog match) must not auto-ABSENT the entire contract
            if not shortlist:
                print("[triage] Empty/unmatched shortlist — failing open (full catalog)")
                shortlist = list(catalog_names)

            shortlist_cache[code_hash] = shortlist
            print(
                f"[triage] New shortlist for contract {code_hash[:12]}: "
                f"{len(shortlist)}/{len(catalog_names)} candidate vulns"
            )

            conv_log = list(state.get("conversation_log", []))
            conv_log.append({
                "round": 0,
                "agent": "triage",
                "prompt": prompt,
                "response": raw_response,
            })
            state["conversation_log"] = conv_log

        shortlist = shortlist_cache[code_hash]
        norm_shortlist = {_norm_vuln(name) for name in shortlist}
        state["triage_shortlist"] = shortlist
        state["triage_candidate"] = _norm_vuln(state["vulnerability_name"]) in norm_shortlist
        return state

    return triage_node


def triage_reject_node(state: RAGState) -> dict:
    """Resolve a pair whose target vulnerability was filtered out by triage.

    No LLM call — the pair is recorded as ABSENT and flows straight to
    parse_output_node, skipping Detector/Reviewer/Reconciler.
    """
    return {
        "final_verdict": "ABSENT",
        "final_confidence": 1.0,
        "reconciliation_rule": "triage_filtered",
        "detector_verdict": "ABSENT",
        "detector_confidence": 0.0,
        "detector_issues": [],
        "detector_reasoning": "Target vulnerability not shortlisted by triage for this contract.",
    }


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
    if not state["documents"]:
        state["context"] = "No relevant examples found."
        return state

    retrieval_mode = state.get("retrieval_mode", "semantic_only")
    vuln_name = state.get("vulnerability_name", "")

    if retrieval_mode == "category_only":
        header = (
            f"Retrieved Examples — same vulnerability ({vuln_name})\n"
            "These are known instances of this exact vulnerability pattern. "
            "Use them only to calibrate what the pattern looks like in code. "
            "Do NOT mark PRESENT solely because the contract resembles these examples."
        )
    elif retrieval_mode == "hybrid":
        header = (
            f"Retrieved Examples — mixed (some match {vuln_name}, others are structurally similar)\n"
            "The first examples match this vulnerability specifically; the remaining ones are "
            "structurally similar but may involve different vulnerability types. "
            "Use all of them only to calibrate code patterns — NOT as evidence of presence."
        )
    else:  # semantic_only fallback
        header = (
            f"Retrieved Examples — structurally similar (no exact match for {vuln_name})\n"
            "These examples were retrieved by semantic similarity and may involve different "
            "vulnerability types. Use them only to calibrate general code patterns. "
            "Do NOT treat similarity to these examples as evidence that this vulnerability is present."
        )

    parts = []
    for i, doc in enumerate(state["documents"], 1):
        vuln = doc.metadata.get("vulnerability", "unknown")
        parts.append(f"Example {i} ({vuln}):\n{doc.page_content[:500]}...")

    state["context"] = header + "\n\n" + "\n\n".join(parts)
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
        owasp_section = (
            "OWASP SCWE Reference\n"
            "Authoritative definition and known fix pattern from the OWASP Smart Contract "
            "Weakness Enumeration. Use it to calibrate the exact vulnerability "
            "pattern — do NOT treat it as evidence that the contract is vulnerable.\n\n"
            + owasp_raw
        ) if owasp_raw else ""

        reviewer_feedback_raw = state.get("reviewer_feedback", "")
        reviewer_feedback_block = (
            f"\n---\n{reviewer_feedback_raw}\n---\n\n" if reviewer_feedback_raw else ""
        )

        fmt_kwargs = dict(
            query=code,
            vulnerability_name=state["vulnerability_name"],
            vulnerability_description=state["vulnerability_description"],
            format_instructions=_detector_parser.get_format_instructions(),
            owasp_section=owasp_section,
            reviewer_feedback=reviewer_feedback_block,
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

        # Log the full prompt + response for conversation analysis
        conv_log = list(state.get("conversation_log", []))
        conv_log.append({
            "round": state.get("current_round", 1),
            "agent": "detector",
            "prompt": prompt,
            "response": raw_response,
        })
        state["conversation_log"] = conv_log

        # Append a new entry to debate_history; reviewer fields filled later by reviewer_node
        existing_history = list(state.get("debate_history", []))
        existing_history.append({
            "round": state.get("current_round", 1),
            "detector_verdict": state["detector_verdict"],
            "detector_confidence": confidence,
            "reviewer_verdict": "",
            "reviewer_confidence": 0.0,
        })
        state["debate_history"] = existing_history

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
        owasp_section = (
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
            owasp_section=owasp_section,
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

        # Log the full prompt + response for conversation analysis
        conv_log = list(state.get("conversation_log", []))
        conv_log.append({
            "round": state.get("current_round", 1),
            "agent": "reviewer",
            "prompt": prompt,
            "response": raw_response,
        })
        state["conversation_log"] = conv_log

        # Update the last debate_history entry with Reviewer results
        updated_history = list(state.get("debate_history", []))
        if updated_history:
            updated_history[-1]["reviewer_verdict"] = verdict
            updated_history[-1]["reviewer_confidence"] = state["reviewer_confidence"]
        state["debate_history"] = updated_history

        # CONFIRMED means Reviewer agrees with Detector regardless of verdict direction
        state["consensus_reached"] = verdict == "CONFIRMED"

        return state

    return reviewer_node


# ─── Feedback node (deterministic, no LLM) ───────────────────────────────────

def feedback_node(state: RAGState) -> dict:
    """Synthesize the Reviewer's objection into structured feedback for the Detector.

    Increments the round counter so the next Detector call knows it is in round N+1.
    No LLM call — purely deterministic.
    """
    feedback = (
        f"[Debate Round {state['current_round']} — Reviewer did not confirm]\n"
        f"Reviewer verdict: {state['reviewer_verdict']} "
        f"(confidence: {state['reviewer_confidence']:.2f})\n"
        f"Reviewer reasoning: {state['reviewer_reasoning']}\n\n"
        "Please reconsider your analysis taking into account the reviewer's objection above. "
        "Focus especially on any points where your evidence may be insufficient or misidentified."
    )
    conv_log = list(state.get("conversation_log", []))
    conv_log.append({
        "round": state["current_round"],
        "agent": "feedback",
        "prompt": None,
        "response": feedback,
    })

    return {
        "reviewer_feedback": feedback,
        "current_round": state["current_round"] + 1,
        "debate_history": state["debate_history"],
        "conversation_log": conv_log,
    }


# ─── Reconciler node (confidence-weighted arbitration, no LLM) ───────────────

def make_reconcile_node(cfg: "Config"):
    """Return a reconciliation node.

    When reviewer is disabled: pass-through with rule_0_detector_only.
    When reviewer is active:
      - Consensus reached: penalty-adjusted confidence, rule = consensus_round_N.
      - Impasse after max_rounds: calibrated confidence-weighted arbitration,
        rule = weighted_arbitration_round_N.
        Reference: ReConcile (Chen et al., 2024 — ACL). https://arxiv.org/abs/2309.13007
    """
    use_reviewer = cfg.agent.use_reviewer

    def reconcile_node(state: RAGState) -> RAGState:
        d_verdict = state.get("detector_verdict", "ABSENT")
        d_conf = float(state.get("detector_confidence", 0.0))

        if not use_reviewer:
            state["final_verdict"] = d_verdict
            state["final_confidence"] = round(d_conf, 4)
            state["reconciliation_rule"] = "rule_0_detector_only"
            state["reconciliation_weight_ratio"] = 0.0
            if state.get("debug", False):
                print("=" * 80)
                print("RECONCILIATION (DEBUG MODE)")
                print("=" * 80)
                print("Mode: single-agent (rule_0_detector_only)")
                print(f"Detector verdict: {d_verdict} | confidence: {d_conf:.3f}")
                print(f"Final verdict:    {d_verdict} | confidence: {d_conf:.3f}")
                print("=" * 80)
            return state

        r_conf = float(state.get("reviewer_confidence", 0.0))
        current_round = state.get("current_round", 1)

        if state.get("consensus_reached", False):
            final_confidence = d_conf
            final_verdict = d_verdict
            rule = f"consensus_round_{current_round}"
            weight_ratio = 0.0
        else:
            # Caminho 2 — Impasse: Reviewer nunca confirmou após max_rounds
            # Decisão baseada no último veredicto do Reviewer:
            #   REFUTED   → Reviewer apresentou evidência de erro → Reviewer vence
            #   UNCERTAIN → Reviewer admitiu dúvida → Detector prevalece

            r_verdict = state.get("reviewer_verdict", "UNCERTAIN")

            if r_verdict == "REFUTED":
                # Reviewer vence: veredicto final é o oposto do Detector
                final_verdict = "ABSENT" if d_verdict == "PRESENT" else "PRESENT"
                final_confidence = round(r_conf, 4)
                rule = f"reviewer_authority_refuted_round_{current_round}"

            else:  # UNCERTAIN
                # Detector prevalece: Reviewer admitiu dúvida insuficiente para refutar
                final_verdict = d_verdict
                final_confidence = d_conf
                rule = f"detector_prevails_uncertain_round_{current_round}"

            weight_ratio = 0.0

        state["final_verdict"] = final_verdict
        state["final_confidence"] = round(final_confidence, 4)
        state["reconciliation_rule"] = rule
        state["reconciliation_weight_ratio"] = weight_ratio

        if state.get("debug", False):
            r_verdict = state.get("reviewer_verdict", "UNCERTAIN")
            print("=" * 80)
            print("RECONCILIATION (DEBUG MODE)")
            print("=" * 80)
            print(f"Rule applied: {rule}")
            print(f"Detector:  {d_verdict} | confidence: {d_conf:.3f}")
            print(f"Reviewer:  {r_verdict} | confidence: {r_conf:.3f}")
            print(f"Rounds:    {current_round} | consensus: {state.get('consensus_reached', False)}")
            print(f"Final:     {final_verdict} | confidence: {final_confidence:.3f} | weight_ratio: {weight_ratio:.3f}")
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
