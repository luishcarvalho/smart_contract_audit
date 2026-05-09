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
