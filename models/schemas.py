from __future__ import annotations

from typing import Annotated, Any, Dict, List

from langchain_core.messages import BaseMessage
from langchain_core.documents import Document
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from typing_extensions import TypedDict


class VulnerabilityIssue(BaseModel):
    issue: str = Field(description="Type of vulnerability (e.g., 'reentrancy', 'access_control')")
    description: str = Field(description="Detailed description of the vulnerability")
    severity: str = Field(description="Severity level: high, medium, or low", default="medium")
    line_numbers: List[int] = Field(description="Line numbers where vulnerability occurs", default=[])


class VulnerabilityAnalysis(BaseModel):
    issues: List[VulnerabilityIssue] = Field(description="List of identified vulnerabilities")
    confidence: float = Field(
        description="Certainty that the vulnerability is PRESENT (0.0 = clearly absent, 1.0 = certain). Use ≥0.7 only when all required elements are met with strong evidence.",
        default=0.5,
        ge=0.0,
        le=1.0,
    )
    summary: str = Field(description="Overall security assessment summary", default="")


class ReviewerOutput(BaseModel):
    reviewer_verdict: str = Field(
        description="CONFIRMED if Detector is correct, REFUTED if Detector made an error, UNCERTAIN if evidence is insufficient to decide"
    )
    reviewer_confidence: float = Field(
        description="Confidence in the reviewer verdict (0.0 = no confidence, 1.0 = certain)",
        default=0.5,
        ge=0.0,
        le=1.0,
    )
    reviewer_reasoning: str = Field(
        description="Detailed explanation of why the Detector verdict is confirmed, refuted, or uncertain",
        default="",
    )


class TriageOutput(BaseModel):
    candidate_vulnerabilities: List[str] = Field(
        description="Names of catalog vulnerabilities that are plausible candidates for this contract, copied VERBATIM from the catalog",
        default=[],
    )


class RAGState(TypedDict):
    """State carried through the LangGraph workflow."""
    query: str
    documents: List[Document]
    context: str
    response: str
    parsed_output: Dict[str, Any]
    messages: Annotated[List[BaseMessage], add_messages]
    vulnerability_name: str
    vulnerability_description: str
    debug: bool
    retrieval_mode: str  # "semantic_only" | "category_only" | "hybrid"
    owasp_context: str   # formatted OWASP SCWE entry, or "" if no match

    # Triage outputs
    triage_shortlist: List[str]  # catalog vulns shortlisted for this contract
    triage_candidate: bool       # False → pair auto-resolved as ABSENT ("triage_filtered")

    # Detector outputs
    detector_verdict: str       # "PRESENT" | "ABSENT"
    detector_confidence: float
    detector_reasoning: str
    detector_issues: List[Dict]
    detector_parse_failed: bool  # True → output unparseable after a retry; pair ends as error

    # Reviewer outputs
    reviewer_verdict: str       # "CONFIRMED" | "REFUTED" | "UNCERTAIN"
    reviewer_confidence: float
    reviewer_reasoning: str

    # Reconciler output
    reconciliation_rule: str    # which rule was applied, e.g. "rule_3_detector_present_reviewer_refuted"
    final_verdict: str          # "PRESENT" | "ABSENT"
    final_confidence: float     # reconciled confidence

    # Canonical description for the Reviewer (from vulnerabilities_description.csv)
    vuln_canonical_description: str

    # Debate cycle control
    current_round: int          # current debate round (starts at 1)
    max_rounds: int             # maximum rounds before arbitration (default: 3)
    consensus_reached: bool     # True when Reviewer confirms Detector (any verdict direction)
    debate_history: list        # [{round, detector_verdict, detector_confidence,
                                #   reviewer_verdict, reviewer_confidence}, ...]
    reviewer_feedback: str      # structured objection injected into next Detector prompt

    # Arbitration metrics (set by reconcile_node)
    reconciliation_weight_ratio: float  # dominant weight ratio in weighted arbitration; 0.0 on consensus

    # Full conversation transcript (always collected; printed with --conversation)
    conversation_log: list  # [{round, agent, prompt, response}, ...]
