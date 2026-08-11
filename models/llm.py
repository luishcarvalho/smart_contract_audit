"""Factory for the Ollama LLM."""
from __future__ import annotations

from langchain_ollama import OllamaLLM

from smart_contract_audit_agents.config import LLMConfig


def build_llm(cfg: LLMConfig) -> OllamaLLM:
    return OllamaLLM(
        model=cfg.model,
        base_url=cfg.base_url,
        num_ctx=cfg.num_ctx,
        temperature=cfg.temperature,
        num_predict=cfg.num_predict,
        # Disable the model's internal <think> block. Hybrid reasoning models
        # (e.g. qwen3.6) otherwise emit a long thinking trace that eats the whole
        # num_predict budget before the JSON, causing truncation → parse errors
        # and huge latency. The prompts already ask for step-by-step reasoning in
        # the answer text, so this only removes the hidden thinking. Harmless for
        # non-thinking models (gemma3), which ignore the option.
        reasoning=False,
        client_kwargs={"timeout": cfg.timeout},
    )
