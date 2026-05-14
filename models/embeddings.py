"""Factory for embedding models."""
from __future__ import annotations

from typing import Union

from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_ollama import OllamaEmbeddings

from smart_contract_audit_agents.config import EmbeddingConfig


def build_embeddings(cfg: EmbeddingConfig) -> Union[HuggingFaceEmbeddings, OllamaEmbeddings]:
    """Return the configured embedding model.

    use_fast=True  → HuggingFace all-MiniLM-L6-v2 (CPU, fast)
    use_fast=False → Ollama starcoder2:3b (GPU, code-specialised, slower)
    """
    if cfg.use_fast:
        return HuggingFaceEmbeddings(model_name=cfg.fast_model)
    return OllamaEmbeddings(model=cfg.slow_model)
