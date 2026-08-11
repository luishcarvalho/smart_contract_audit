"""
Constrói (ou retoma) o vectorstore ChromaDB de forma ISOLADA.

Não precisa do Ollama/LLM nem do loop de avaliação — só do embedder
(jina code, CPU) + do parquet de treino em `DataConfig.train_path`.
Embeda os ~27,7k documentos em lotes, com checkpoint: se a execução for
interrompida, rodar de novo retoma de onde parou.

Uso:
    python build_store.py            # constrói/retoma no caminho do config
    python build_store.py --force    # ignora checkpoint e reconstrói do zero
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

# Torna o pacote importável ao rodar como script (mesmo truque do run.py)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smart_contract_audit_agents.config import DEFAULT_CONFIG
from smart_contract_audit_agents.models.vectorstore import (
    build_vectorstore,
    dataframe_to_documents,
)


def main() -> None:
    p = argparse.ArgumentParser(description="Build the ChromaDB vectorstore in isolation")
    p.add_argument("--train", default=DEFAULT_CONFIG.data.train_path, help="Parquet de treino")
    p.add_argument("--force", action="store_true", help="Reconstruir do zero (ignora checkpoint)")
    args = p.parse_args()

    cfg = DEFAULT_CONFIG.embedding
    print(f"Embedder:   {cfg.fast_model if cfg.use_fast else cfg.slow_model}")
    print(f"Distância:  {cfg.distance}  | normalizado: {cfg.normalize_embeddings}")
    print(f"Destino:    {cfg.vectorstore_path}")
    print(f"Treino:     {args.train}")

    df = pd.read_parquet(args.train)
    print(f"Documentos: {len(df)}")

    docs = dataframe_to_documents(df)
    build_vectorstore(docs, cfg, force_rebuild=args.force)
    print("Vectorstore pronto.")


if __name__ == "__main__":
    main()
