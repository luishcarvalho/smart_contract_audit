"""
Entrypoint CLI for the smart contract audit pipeline.

Usage examples:

  # Default (no RAG, gemma3:27b, temperature=0.2)
  python run.py

  # Enable RAG
  python run.py --rag

  # Change model and temperature
  python run.py --model deepseek-r1:14b --temperature 0.0

  # Change top-k (only relevant with --rag)
  python run.py --rag --top-k 10

  # Change subset size and number of runs
  python run.py --subset 100 --runs 3

  # Resume an interrupted run
  python run.py --resume-run 1 --resume-contract 5 --resume-vuln 3

  # Debug mode: print full prompt for each call
  python run.py --subset 1 --debug
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

# ── Make the package importable when run as a script ─────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smart_contract_audit.config import (
    Config, DataConfig, DEFAULT_CONFIG, EmbeddingConfig, EvalConfig, LLMConfig, RetrievalConfig,
)
from smart_contract_audit.evaluation.results import save_results
from smart_contract_audit.evaluation.runner import run_evaluation
from smart_contract_audit.models.llm import build_llm
from smart_contract_audit.pipeline.graph import AuditPipeline
from smart_contract_audit.utils.display import banner


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Smart Contract Vulnerability Audit Pipeline")
    _llm  = DEFAULT_CONFIG.llm
    _ret  = DEFAULT_CONFIG.retrieval
    _emb  = DEFAULT_CONFIG.embedding
    _ev   = DEFAULT_CONFIG.eval
    _data = DEFAULT_CONFIG.data

    # LLM
    p.add_argument("--model",        default=_llm.model,            help="Ollama model name")
    p.add_argument("--temperature",  type=float, default=_llm.temperature,  help="LLM temperature")
    p.add_argument("--num-ctx",      type=int,   default=_llm.num_ctx,      help="Context window tokens")
    p.add_argument("--num-predict",  type=int,   default=_llm.num_predict,  help="Max output tokens")
    p.add_argument("--timeout",      type=int,   default=_llm.timeout,      help="Ollama timeout (seconds)")

    # RAG / retrieval  (--rag to enable, --no-rag to disable; default from config)
    p.add_argument("--rag",          action=argparse.BooleanOptionalAction,
                                     default=_ret.use_rag,          help="Enable/disable RAG retrieval")
    p.add_argument("--top-k",        type=int,   default=_ret.top_k,        help="Number of docs to retrieve")
    p.add_argument("--fast-embed",   action="store_true", default=_emb.use_fast,
                                                                     help="Use fast HuggingFace embeddings (default)")
    p.add_argument("--slow-embed",   action="store_true",           help="Use Ollama starcoder2 embeddings")

    # Data
    p.add_argument("--train",   default=_data.train_path)
    p.add_argument("--test",    default=_data.test_path)
    p.add_argument("--vulns",   default=_data.vuln_desc_path)
    p.add_argument("--subset",  type=int, default=_data.test_subset_size,   help="Max contracts to evaluate (0=all)")

    # Eval
    p.add_argument("--runs",             type=int, default=_ev.n_runs)
    p.add_argument("--resume-run",       type=int, default=_ev.resume_run)
    p.add_argument("--resume-contract",  type=int, default=_ev.resume_contract_index)
    p.add_argument("--resume-vuln",      type=int, default=_ev.resume_vuln_pos)
    p.add_argument("--skip-contract",    type=int, default=-1,      help="Dataset index to skip (-1=none)")
    p.add_argument("--results-dir",      default=_ev.results_dir)
    p.add_argument("--resume-dir",       default=None,              help="Path to an existing results dir to resume (e.g. results/gemma3-27b/norag_28-03-26_02-14-00)")
    p.add_argument("--store-raw",        action="store_true",       help="Store raw LLM responses in CSV")
    p.add_argument("--debug",            action="store_true",       help="Print full prompt for each call")

    return p.parse_args()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    # ── Build Config from CLI args ────────────────────────────────────────────
    cfg = Config(
        llm=LLMConfig(
            model=args.model,
            temperature=args.temperature,
            num_ctx=args.num_ctx,
            num_predict=args.num_predict,
            timeout=args.timeout,
        ),
        embedding=EmbeddingConfig(
            use_fast=not args.slow_embed,
        ),
        retrieval=RetrievalConfig(
            use_rag=args.rag,
            top_k=args.top_k,
        ),
        eval=EvalConfig(
            n_runs=args.runs,
            resume_run=args.resume_run,
            resume_contract_index=args.resume_contract,
            resume_vuln_pos=args.resume_vuln,
            skip_contract=args.skip_contract >= 0,
            skip_contract_index=args.skip_contract,
            results_dir=args.results_dir,
            store_raw_response=args.store_raw,
        ),
        data=DataConfig(
            train_path=args.train,
            test_path=args.test,
            vuln_desc_path=args.vulns,
            test_subset_size=args.subset,
        ),
    )

    banner("SMART CONTRACT AUDIT PIPELINE")
    print(f"Model:       {cfg.llm.model}")
    print(f"Temperature: {cfg.llm.temperature}")
    print(f"RAG:         {cfg.retrieval.use_rag}  (top-k={cfg.retrieval.top_k})")
    print(f"Runs:        {cfg.eval.n_runs}")

    # ── Load datasets ─────────────────────────────────────────────────────────
    banner("Loading datasets")
    test_df = pd.read_csv(cfg.data.test_path)
    if "line" not in [c.lower() for c in test_df.columns]:
        test_df["line"] = 0

    vuln_desc_df = pd.read_csv(cfg.data.vuln_desc_path)
    print(f"Test contracts:      {len(test_df)}")
    print(f"Vulnerability types: {len(vuln_desc_df)}")

    # ── Prepare selected examples ─────────────────────────────────────────────
    subset = test_df if cfg.data.test_subset_size == 0 else test_df.iloc[: cfg.data.test_subset_size]
    selected_examples = [
        {
            "name": f"{row['vulnerability']} Example {idx}",
            "code": row["code"],
            "vulnerability": row["vulnerability"],
            "line": row.get("line", 0),
            "index": idx,
        }
        for idx, row in subset.iterrows()
    ]
    print(f"Selected examples:   {len(selected_examples)}")

    # ── Build LLM ─────────────────────────────────────────────────────────────
    banner("Initialising LLM")
    llm = build_llm(cfg.llm)
    print(f"LLM ready: {cfg.llm.model}")

    # ── Build vectorstore (only if RAG) ───────────────────────────────────────
    vectorstore = None
    if cfg.retrieval.use_rag:
        from smart_contract_audit.models.vectorstore import (
            build_vectorstore,
            dataframe_to_documents,
            load_vectorstore,
        )
        banner("Setting up vector store")
        try:
            vectorstore = load_vectorstore(cfg.embedding)
            print("Loaded existing vector store.")
        except FileNotFoundError:
            print("Vector store not found — building from training data...")
            train_df = pd.read_parquet(cfg.data.train_path)
            documents = dataframe_to_documents(train_df)
            vectorstore = build_vectorstore(documents, cfg.embedding)

    # ── Load SWC registry (static lookup, independent of RAG mode) ───────────
    swc_lookup = None
    if cfg.data.swc_registry_path:
        from smart_contract_audit.utils.swc_lookup import SWCLookup
        swc_lookup = SWCLookup.from_csv(cfg.data.swc_registry_path)
        print(f"SWC registry loaded: {len(swc_lookup._df)} entries")

    # ── Build pipeline ────────────────────────────────────────────────────────
    banner("Building pipeline")
    pipeline = AuditPipeline(llm=llm, cfg=cfg, vectorstore=vectorstore, swc_lookup=swc_lookup)
    print("Pipeline ready.")

    # ── Run evaluation ────────────────────────────────────────────────────────
    import time as _time
    _eval_start = _time.time()
    pair_results, contract_results, output_dir = run_evaluation(
        pipeline=pipeline,
        selected_examples=selected_examples,
        vuln_desc_df=vuln_desc_df,
        cfg=cfg,
        output_dir=args.resume_dir,   # None = create new dir; path = resume existing
    )
    total_time_seconds = _time.time() - _eval_start

    # ── Save final summary (CSVs already written incrementally) ───────────────
    save_results(pair_results, contract_results, cfg, output_dir=output_dir,
                 total_time_seconds=total_time_seconds)


if __name__ == "__main__":
    main()
