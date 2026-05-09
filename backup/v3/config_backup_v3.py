"""
Central configuration for the smart contract audit pipeline.

All hyperparameters live here. To change model, temperature, top-k,
RAG toggle, dataset paths, etc. — edit ONLY this file (or override
via CLI flags in run.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ─────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────
@dataclass
class LLMConfig:
    model: str = "gemma3:27b"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.0
    num_ctx: int = 40_960       # max prompt breakdown (RAG mode, largest contract):
                                #   code ~32K tokens + template ~1K + RAG ctx ~660 + fmt ~360 = ~34K total
                                #   40960 leaves ~7K token safety buffer
    num_predict: int = 1024
    timeout: int = 600          # seconds (connect + read)
    max_retries: int = 3        # retries on Ollama runner crash (failed to sample token)
    retry_delay: float = 5.0    # seconds between retries
    max_code_chars: int = 150_000  # safety truncation: largest contract in dataset = ~130K chars
                                   # budget with RAG overhead = ~157K chars, so 150K gives a 7K buffer


# ─────────────────────────────────────────────
# Embeddings
# ─────────────────────────────────────────────
@dataclass
class EmbeddingConfig:
    use_fast: bool = True                          # True = MiniLM (CPU), False = starcoder2:3b (Ollama)
    fast_model: str = "all-MiniLM-L6-v2"
    slow_model: str = "starcoder2:3b"
    batch_size: int = 128
    checkpoint_path: str = "langchain_embedding_checkpoint.pkl"
    vectorstore_path: str = "./langchain_smart_contract_chromadb"


# ─────────────────────────────────────────────
# Retrieval / RAG
# ─────────────────────────────────────────────
@dataclass
class RetrievalConfig:
    use_rag: bool = True        # True = RAG pipeline; False = direct LLM
    top_k: int = 3
    use_hybrid: bool = True     # True = category filter + semantic fallback; False = semantic only
    vuln_metadata_field: str = "vulnerability"  # ChromaDB metadata key for vulnerability category


# ─────────────────────────────────────────────
# Evaluation loop
# ─────────────────────────────────────────────
@dataclass
class EvalConfig:
    n_runs: int = 1
    # Resume: set these to continue an interrupted run
    resume_run: int = 1
    resume_contract_index: int = 1
    resume_vuln_pos: int = 1
    # Skip a specific contract index
    skip_contract: bool = False
    skip_contract_index: int = -1
    # Confidence threshold: pairs where model confidence < this are treated as ABSENT
    confidence_threshold: float = 0.7
    # Output
    results_dir: str = "results"
    store_raw_response: bool = False


# ─────────────────────────────────────────────
# Datasets
# ─────────────────────────────────────────────
@dataclass
class DataConfig:
    train_path: str = "/home/luis.carvalho/all_data.parquet"
    test_path: str = "/home/luis.carvalho/gervais_dataset.csv"
    vuln_desc_path: str = "/home/luis.carvalho/vulnerabilities_description.csv"
    test_subset_size: int = 0    # 0 = use full test set


# ─────────────────────────────────────────────
# Root config — the only object imported elsewhere
# ─────────────────────────────────────────────
@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    eval: EvalConfig = field(default_factory=EvalConfig)
    data: DataConfig = field(default_factory=DataConfig)


# Default instance — import this in other modules:
#   from smart_contract_audit.config import DEFAULT_CONFIG
DEFAULT_CONFIG = Config()
