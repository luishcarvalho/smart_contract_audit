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
    swc_context: str     # formatted SWC registry entry, or "" if no match
