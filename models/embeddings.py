"""Factory for embedding models."""
from __future__ import annotations

from typing import Union

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_ollama import OllamaEmbeddings

from smart_contract_audit_agents.config import EmbeddingConfig


def build_embeddings(cfg: EmbeddingConfig) -> Union[HuggingFaceEmbeddings, OllamaEmbeddings]:
    """Return the configured embedding model.

    use_fast=True  → HuggingFace fast_model (default: jina code embedder, 768-dim,
                     runs locally on CPU via sentence-transformers)
    use_fast=False → Ollama slow_model (starcoder2:3b)
    """
    if cfg.use_fast:
        return HuggingFaceEmbeddings(
            model_name=cfg.fast_model,
            # trust_remote_code is required by the jina custom model class;
            # device cpu keeps the GPU free for the Ollama LLM.
            model_kwargs={"trust_remote_code": cfg.trust_remote_code, "device": "cpu"},
            encode_kwargs={"normalize_embeddings": cfg.normalize_embeddings},
        )
    return OllamaEmbeddings(model=cfg.slow_model)
