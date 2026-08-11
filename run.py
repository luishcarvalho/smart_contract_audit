"""
Entrypoint CLI for the smart contract dual-agent audit pipeline.

Usage examples:

  # Default (RAG, gemma3:27b, temperature=0.2, dual-agent)
  python run.py

  # Disable RAG
  python run.py --no-rag

  # Change model and temperature
  python run.py --model deepseek-r1:14b --temperature 0.0

  # Single-agent mode (Detector only, no Reviewer)
  python run.py --no-reviewer

  # Debug mode: print full prompts for Detector, Reviewer, and reconciliation
  python run.py --subset 1 --debug

  # Resume an interrupted run
  python run.py --resume-dir results/gemma3-27b/05-2026/rag_10-05-26_12-00-00

  # Limit to N contracts (quick debug)
  python run.py --subset 10

  # Multiple runs for variance measurement
  python run.py --runs 3
"""
from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

# ── Make the package importable when run as a script ─────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smart_contract_audit_agents.config import (
    AgentConfig,
    Config,
    DataConfig,
    DEFAULT_CONFIG,
    EmbeddingConfig,
    EvalConfig,
    LLMConfig,
    RetrievalConfig,
    TriageConfig,
)
from smart_contract_audit_agents.evaluation.results import save_results
from smart_contract_audit_agents.evaluation.runner import run_evaluation
from smart_contract_audit_agents.models.llm import build_llm
from smart_contract_audit_agents.pipeline.graph import AuditPipeline
from smart_contract_audit_agents.utils.display import banner


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Smart Contract Dual-Agent Vulnerability Audit Pipeline")
    _llm   = DEFAULT_CONFIG.llm
    _ret   = DEFAULT_CONFIG.retrieval
    _emb   = DEFAULT_CONFIG.embedding
    _ev     = DEFAULT_CONFIG.eval
    _data   = DEFAULT_CONFIG.data
    _agent  = DEFAULT_CONFIG.agent
    _triage = DEFAULT_CONFIG.triage

    # LLM
    p.add_argument("--model",        default=_llm.model,            help="Ollama model name")
    p.add_argument("--temperature",  type=float, default=_llm.temperature,  help="LLM temperature")
    p.add_argument("--num-ctx",      type=int,   default=_llm.num_ctx,      help="Context window tokens")
    p.add_argument("--num-predict",  type=int,   default=_llm.num_predict,  help="Max output tokens")
    p.add_argument("--timeout",      type=int,   default=_llm.timeout,      help="Ollama timeout (seconds)")

    # RAG / retrieval
    p.add_argument("--rag",          action=argparse.BooleanOptionalAction,
                                     default=_ret.use_rag,          help="Enable/disable RAG retrieval")
    p.add_argument("--top-k",        type=int,   default=_ret.top_k,        help="Number of docs to retrieve")
    p.add_argument("--fast-embed",   action="store_true", default=_emb.use_fast,
                                                                     help="Use fast HuggingFace embeddings (default)")
    p.add_argument("--slow-embed",   action="store_true",           help="Use Ollama starcoder2 embeddings")

    # Agent mode
    p.add_argument("--no-reviewer",  action="store_true", default=not _agent.use_reviewer,
                                     help="Disable the Reviewer agent (single-agent mode)")
    p.add_argument("--max-rounds",   type=int, default=_agent.max_rounds,
                                     help="Max debate rounds before arbitration (default: 3)")

    # Triage
    p.add_argument("--triage",       action=argparse.BooleanOptionalAction,
                                     default=_triage.use_triage,
                                     help="Enable/disable per-contract triage shortlist")
    p.add_argument("--max-shortlist", type=int, default=_triage.max_shortlist_size,
                                     help="Max candidate vulnerabilities kept by triage per contract")

    # Data
    p.add_argument("--train",   default=_data.train_path)
    p.add_argument("--test",    default=_data.test_path)
    p.add_argument("--vulns",   default=_data.vuln_desc_path)
    p.add_argument("--subset",  type=int, default=0,
                                     help="Max contracts to evaluate (0=use config/all)")

    # Eval
    p.add_argument("--runs",             type=int, default=_ev.n_runs)
    p.add_argument("--resume-run",       type=int, default=_ev.resume_run)
    p.add_argument("--resume-contract",  type=int, default=_ev.resume_contract_index)
    p.add_argument("--resume-vuln",      type=int, default=_ev.resume_vuln_pos)
    p.add_argument("--skip-contract",    type=int, default=-1,      help="Dataset index to skip (-1=none)")
    p.add_argument("--results-dir",      default=_ev.results_dir)
    p.add_argument("--resume-dir",       default=None,              help="Path to an existing results dir to resume")
    p.add_argument("--store-raw",        action="store_true",       help="Store raw LLM responses in CSV")
    p.add_argument("--debug",            action="store_true",       help="Print full prompts for each LLM call")
    p.add_argument("--verbose",          action="store_true",       help="Saída detalhada por par (desliga a interface limpa com barras de progresso)")
    p.add_argument("--conversation",     action="store_true",       help="Print full Detector↔Reviewer conversation after each pair")
    p.add_argument("--save-conversation", default=None, metavar="FILE",
                                         help="Write conversation log to FILE (one entry per pair, appended)")
    p.add_argument("--no-prompts",       action="store_true",       help="With --conversation/--save-conversation: hide prompts, show only LLM responses")

    return p.parse_args()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    use_reviewer = not args.no_reviewer
    # Interface limpa (barras de progresso, uma operação por vez) por padrão.
    # Desligada automaticamente quando se pede saída detalhada (debug/conversa/verbose).
    clean_ui = not (args.verbose or args.debug or args.conversation)

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
        agent=AgentConfig(
            use_reviewer=use_reviewer,
            max_rounds=args.max_rounds,
        ),
        triage=TriageConfig(
            use_triage=args.triage,
            max_shortlist_size=args.max_shortlist,
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
            # test_subset_size and use_test_subset come from config.py defaults
        ),
    )

    agent_mode_label = (
        f"Dual-Agent [Detector + Reviewer, max_rounds={cfg.agent.max_rounds}]"
        if use_reviewer else "Single-Agent [Detector only]"
    )
    banner("SMART CONTRACT AUDIT PIPELINE")
    print(f"Mode:        {agent_mode_label}")
    print(f"Model:       {cfg.llm.model}")
    print(f"Temperature: {cfg.llm.temperature}")
    print(f"RAG:         {cfg.retrieval.use_rag}  (top-k={cfg.retrieval.top_k})")
    print(f"Triage:      {cfg.triage.use_triage}  (max-shortlist={cfg.triage.max_shortlist_size})")
    print(f"Max rounds:  {cfg.agent.max_rounds if use_reviewer else 'N/A (single-agent)'}")
    print(f"Runs:        {cfg.eval.n_runs}")
    print(f"Interface:   {'limpa (barras de progresso)' if clean_ui else 'detalhada (verbose)'}")

    # ── Resolve effective subset size ─────────────────────────────────────────
    # Priority: --subset CLI > use_test_subset config toggle > full dataset
    if args.subset > 0:
        effective_subset = args.subset
    elif cfg.data.use_test_subset:
        effective_subset = cfg.data.test_subset_size
    else:
        effective_subset = 0  # full dataset

    subset_label = f"{effective_subset} contracts (quick test)" if effective_subset > 0 else "full dataset"
    print(f"Dataset:     {subset_label}")

    # ── Load datasets ─────────────────────────────────────────────────────────
    banner("Loading datasets")
    test_df = pd.read_csv(cfg.data.test_path)
    if "line" not in [c.lower() for c in test_df.columns]:
        test_df["line"] = 0

    vuln_desc_df = pd.read_csv(cfg.data.vuln_desc_path)
    print(f"Test contracts:      {len(test_df)}")
    print(f"Vulnerability types: {len(vuln_desc_df)}")

    # ── Prepare selected examples ─────────────────────────────────────────────
    subset = test_df if effective_subset == 0 else test_df.iloc[:effective_subset]
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
        from smart_contract_audit_agents.models.vectorstore import (
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

    # ── Load OWASP SCWE registry ──────────────────────────────────────────────
    owasp_lookup = None
    if cfg.data.owasp_registry_path:
        from smart_contract_audit_agents.utils.owasp_lookup import OWASPLookup
        owasp_lookup = OWASPLookup.from_csv(cfg.data.owasp_registry_path)
        print(f"OWASP SCWE registry loaded: {len(owasp_lookup._df)} entries")

    # ── Load vulnerability description lookup (for Reviewer) ──────────────────
    from smart_contract_audit_agents.utils.vuln_desc_lookup import VulnDescLookup
    vuln_desc_lookup = VulnDescLookup.from_csv(cfg.data.vuln_desc_path)
    print(f"Vuln description lookup loaded: {len(vuln_desc_lookup._index)} entries")

    # ── Build pipeline ────────────────────────────────────────────────────────
    banner("Building pipeline")
    pipeline = AuditPipeline(
        llm=llm,
        cfg=cfg,
        vectorstore=vectorstore,
        owasp_lookup=owasp_lookup,
        vuln_desc_lookup=vuln_desc_lookup,
        vuln_desc_df=vuln_desc_df,
    )
    print(f"Pipeline ready. Mode: {agent_mode_label}")

    # ── Run evaluation ────────────────────────────────────────────────────────
    import time as _time
    _eval_start = _time.time()
    pair_results, contract_results, output_dir = run_evaluation(
        pipeline=pipeline,
        selected_examples=selected_examples,
        vuln_desc_df=vuln_desc_df,
        cfg=cfg,
        output_dir=args.resume_dir,
        debug=args.debug,
        show_conversation=args.conversation,
        save_conversation=args.save_conversation,
        show_prompts=not args.no_prompts,
        clean=clean_ui,
    )
    total_time_seconds = _time.time() - _eval_start

    # ── Save final summary (CSVs already written incrementally) ───────────────
    save_results(pair_results, contract_results, cfg, output_dir=output_dir,
                 total_time_seconds=total_time_seconds)


if __name__ == "__main__":
    main()
