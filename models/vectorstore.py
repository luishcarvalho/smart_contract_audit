"""ChromaDB vector store: creation with batched embedding + checkpoint, and loading."""
from __future__ import annotations

import hashlib
import os
from typing import List, Optional

import pandas as pd
from langchain_chroma import Chroma
from langchain_core.documents import Document
from tqdm import tqdm

from smart_contract_audit_agents.config import EmbeddingConfig
from smart_contract_audit_agents.models.embeddings import build_embeddings
from smart_contract_audit_agents.utils.io import (
    completed_batch_indices,
    load_checkpoint,
    save_checkpoint,
)


# ─── Document helpers ─────────────────────────────────────────────────────────

def dataframe_to_documents(df: pd.DataFrame) -> List[Document]:
    """Convert a training DataFrame to LangChain Documents."""
    docs = []
    for _, row in df.iterrows():
        docs.append(
            Document(
                page_content=str(row["code"]),
                metadata={
                    # "vulnerability" matches RetrievalConfig.vuln_metadata_field — used for hybrid retrieval filtering
                    "vulnerability": str(row.get("vulnerability", "unknown")),
                    "line": int(str(row.get("line", 0)).split(",")[0]) if row.get("line") else 0,
                    "source": str(row.get("source", "unknown")),
                },
            )
        )
    return docs


def _doc_hash(doc: Document) -> str:
    return hashlib.md5(doc.page_content.encode()).hexdigest()


# ─── Build (embed + persist) ──────────────────────────────────────────────────

def build_vectorstore(
    documents: List[Document],
    cfg: EmbeddingConfig,
    force_rebuild: bool = False,
) -> Chroma:
    """Embed *documents* in batches and persist to ChromaDB.

    Resumes from checkpoint if a previous run was interrupted.
    Set *force_rebuild=True* to start from scratch.
    """
    embeddings = build_embeddings(cfg)
    checkpoint_path = cfg.checkpoint_path
    persist_path = cfg.vectorstore_path

    if force_rebuild and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)

    checkpoint = load_checkpoint(checkpoint_path)
    done_batches = set(completed_batch_indices(checkpoint))

    batches = [
        documents[i : i + cfg.batch_size]
        for i in range(0, len(documents), cfg.batch_size)
    ]

    vectorstore: Optional[Chroma] = None

    # Load existing store if available
    if os.path.exists(persist_path) and not force_rebuild:
        vectorstore = Chroma(
            persist_directory=persist_path,
            embedding_function=embeddings,
        )

    for batch_idx, batch in enumerate(tqdm(batches, desc="Embedding batches")):
        if batch_idx in done_batches:
            continue

        if vectorstore is None:
            vectorstore = Chroma.from_documents(
                documents=batch,
                embedding=embeddings,
                persist_directory=persist_path,
            )
        else:
            vectorstore.add_documents(batch)

        done_batches.add(batch_idx)
        save_checkpoint(
            checkpoint_path,
            {"completed_batches": list(done_batches), "total_batches": len(batches)},
        )

    if vectorstore is None:
        raise RuntimeError("No documents were embedded — check your DataFrame.")

    print(f"Vector store ready: {len(documents)} documents in {persist_path}")
    return vectorstore


# ─── Load existing store ──────────────────────────────────────────────────────

def load_vectorstore(cfg: EmbeddingConfig) -> Chroma:
    """Load a previously built ChromaDB store from disk."""
    if not os.path.exists(cfg.vectorstore_path):
        raise FileNotFoundError(
            f"Vector store not found at '{cfg.vectorstore_path}'. "
            "Run build_vectorstore() first."
        )
    embeddings = build_embeddings(cfg)
    return Chroma(
        persist_directory=cfg.vectorstore_path,
        embedding_function=embeddings,
    )
