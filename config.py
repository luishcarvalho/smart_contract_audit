"""
Central configuration for the smart contract audit agents pipeline.

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
    model: str = "qwen3.6:27b"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.2
    num_ctx: int = 65_536       # context window. Measured: largest test contract ~18.5K tokens,
                                #   so even with top_k=5 RAG + template the prompt stays <22K.
                                #   65536 is generous headroom for larger test sets. VRAM cost
                                #   measured on an A40: ~24GB / 46GB with gemma3:27b (KV f16).
    num_predict: int = 2048     # raised from 1024: coder/thinking models can emit reasoning
                                #   before the JSON; 1024 risked truncating the output mid-JSON
                                #   (parse errors). 2048 leaves room for the analysis + JSON.
    timeout: int = 600          # seconds (connect + read)
    max_retries: int = 3        # retries on Ollama runner crash (failed to sample token)
    retry_delay: float = 5.0    # seconds between retries
    max_code_chars: int = 250_000  # safety truncation only. No contract in the current test sets
                                    # reaches this; raised from 150K so large contracts are not
                                    # cut before the model's own context window even applies.


# ─────────────────────────────────────────────
# Embeddings
# ─────────────────────────────────────────────
@dataclass
class EmbeddingConfig:
    use_fast: bool = True                          # True = HuggingFace (local), False = Ollama slow_model
    # Code-specialized embedder (768-dim). Beats the general-purpose MiniLM at
    # retrieving structurally similar Solidity. Loaded via sentence-transformers
    # with trust_remote_code=True.
    fast_model: str = "jinaai/jina-embeddings-v2-base-code"
    slow_model: str = "starcoder2:3b"
    trust_remote_code: bool = True                 # required by the jina custom model class
    normalize_embeddings: bool = True              # unit-normalize so cosine distance is exact
    distance: str = "cosine"                        # ChromaDB HNSW space: cosine | l2 | ip
    batch_size: int = 128
    # Separate checkpoint + store from the old MiniLM build: the embedding
    # dimensionality (384 → 768) and distance (l2 → cosine) both changed, so the
    # store MUST be rebuilt from scratch on the next RAG run (one-time cost).
    checkpoint_path: str = "langchain_embedding_checkpoint_jina.pkl"
    vectorstore_path: str = "/home/luis.carvalho/smart_contract_audit_agents/chromadb_jina_code_cosine"


# ─────────────────────────────────────────────
# Retrieval / RAG
# ─────────────────────────────────────────────
@dataclass
class RetrievalConfig:
    use_rag: bool = True        # True = RAG pipeline; False = direct LLM
    top_k: int = 5              # retrieved examples per pair (raised from 3 — extra context is
                                # cheap: each example is truncated to 500 chars ≈ ~130 tokens)
    use_hybrid: bool = True     # True = category filter + semantic fallback; False = semantic only
    vuln_metadata_field: str = "vulnerability"  # ChromaDB metadata key for vulnerability category


# ─────────────────────────────────────────────
# Agent system
# ─────────────────────────────────────────────
@dataclass
class AgentConfig:
    # Controls whether the Reviewer is active (disable via --no-reviewer to compare with single-agent)
    use_reviewer: bool = True
    # If False, the Detector runs alone and its result becomes the final result
    reviewer_sees_code: bool = True  # always True in this project, documented here for clarity
    # Maximum debate rounds before the Reconciler arbitrates (only used when use_reviewer=True)
    max_rounds: int = 3


# ─────────────────────────────────────────────
# Triage (pre-filter before Detector/Reviewer)
# ─────────────────────────────────────────────
@dataclass
class TriageConfig:
    # One LLM call per contract shortlists plausible vulnerabilities;
    # pairs outside the shortlist are auto-resolved as ABSENT (rule "triage_filtered")
    use_triage: bool = True
    max_shortlist_size: int = 15   # hard cap on candidates kept per contract (raised from 15 to
                                   # cut the systematic FN the triage was introducing — the last
                                   # full run discarded 54 GT-positive pairs at shortlist=15)


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
    # Output
    results_dir: str = "results"
    store_raw_response: bool = False


# ─────────────────────────────────────────────
# Datasets
# ─────────────────────────────────────────────
@dataclass
class DataConfig:
    train_path: str = "/home/luis.carvalho/all_data.parquet"
    # Extração determinística do Web3Bugs: uma linha por bug, com file_path e
    # vulnerability_mapped. O carregador agrupa por arquivo e o ground truth vira
    # o CONJUNTO de rótulos daquele arquivo — 68,3% dos bugs vivem em arquivos
    # com mais de um bug, e antes cada irmão desses contava como falso positivo.
    test_path: str = "/home/luis.carvalho/web3bugs/extract/out/web3bugs_testset.csv"
    # Descarta a família O, que o próprio artigo Web3Bugs declara fora de escopo
    # (96 dos 467 bugs). Só tem efeito no formato multi-rótulo.
    in_scope_only: bool = True
    # "code" = com comentários; "code_no_comments" existe no CSV irmão e serve
    # para a ablação de viés lexical.
    code_column: str = "code"
    vuln_desc_path: str = "/home/luis.carvalho/vulnerabilities_description.csv"
    owasp_registry_path: str = "/home/luis.carvalho/owasp_scwe.csv"
    test_subset_size: int = 5    # contracts to evaluate when use_test_subset=True
    use_test_subset: bool = False  # set to True for quick testing (overridden by --subset N)


# ─────────────────────────────────────────────
# Root config — the only object imported elsewhere
# ─────────────────────────────────────────────
@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    triage: TriageConfig = field(default_factory=TriageConfig)
    eval: EvalConfig = field(default_factory=EvalConfig)
    data: DataConfig = field(default_factory=DataConfig)


# Default instance — import this in other modules:
#   from smart_contract_audit_agents.config import DEFAULT_CONFIG
DEFAULT_CONFIG = Config()
