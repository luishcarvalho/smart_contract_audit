"""Factory for the Ollama LLM."""
from __future__ import annotations

from langchain_ollama import OllamaLLM

from smart_contract_audit.config import LLMConfig


def build_llm(cfg: LLMConfig) -> OllamaLLM:
    return OllamaLLM(
        model=cfg.model,
        base_url=cfg.base_url,
        num_ctx=cfg.num_ctx,
        temperature=cfg.temperature,
        num_predict=cfg.num_predict,
        client_kwargs={"timeout": cfg.timeout},
    )
