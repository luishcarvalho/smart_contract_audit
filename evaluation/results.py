"""Save evaluation results to CSV files and a Markdown experiment summary."""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd

from smart_contract_audit_agents.config import Config
from smart_contract_audit_agents.evaluation.metrics import Metrics, _safe_div


def _df_to_md(df: pd.DataFrame, float_fmt: str = ".4f") -> str:
    """Convert a DataFrame to a Markdown table string."""
    cols = list(df.columns)
    header = "| " + " | ".join(cols) + " |"
    sep    = "| " + " | ".join("---" for _ in cols) + " |"
    rows   = []
    for _, row in df.iterrows():
        cells = []
        for col in cols:
            val = row[col]
            if isinstance(val, float):
                cells.append(f"{val:{float_fmt}}")
            else:
                cells.append(str(val))
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, sep] + rows)


def _vuln_top_table(vuln_df: pd.DataFrame, n: int = 10) -> str:
    """Top-N vulnerabilities by F1, formatted as Markdown table."""
    df = vuln_df.copy()
    df["precision"] = df.apply(lambda r: _safe_div(r.tp, r.tp + r.fp), axis=1)
    df["recall"]    = df.apply(lambda r: _safe_div(r.tp, r.tp + r.fn), axis=1)
    df["f1"]        = df.apply(
        lambda r: _safe_div(2 * r.precision * r.recall, r.precision + r.recall), axis=1
    )
    top = (
        df[["vulnerability", "tp", "fp", "tn", "fn", "precision", "recall", "f1"]]
        .sort_values("f1", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )
    return _df_to_md(top)


def save_results(
    pair_results: List[Dict[str, Any]],
    contract_results: List[Dict[str, Any]],
    cfg: Config,
    output_dir: str | None = None,
    total_time_seconds: float = 0.0,
) -> str:
    """Write aggregate CSVs and Markdown summary to *output_dir*.

    If *output_dir* is None a new timestamped directory is created.
    The pairs/contract CSVs were already written incrementally by the runner;
    this function only writes the aggregated vuln/global CSVs and the summary.
    """
    if output_dir is None:
        llm_name   = cfg.llm.model.replace(":", "-")
        tag        = "rag" if cfg.retrieval.use_rag else "norag"
        timestamp  = datetime.now().strftime("%d-%m-%y_%H-%M-%S")
        output_dir = os.path.join(cfg.eval.results_dir, llm_name, f"{tag}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    # Prefer reading from the incremental CSV on disk so that the summary
    # reflects ALL sessions (including resumed ones), not just the current run.
    pair_csv_path = os.path.join(output_dir, "results_pairs.csv")
    if os.path.exists(pair_csv_path):
        pairs_df = pd.read_csv(pair_csv_path)
    else:
        pairs_df = pd.DataFrame(pair_results)

    contract_csv_path = os.path.join(output_dir, "results_contract.csv")
    if os.path.exists(contract_csv_path):
        contracts_df = pd.read_csv(contract_csv_path)
    else:
        contracts_df = pd.DataFrame(contract_results)

    # ── Filter successful pairs ───────────────────────────────────────────────
    successful = (
        pairs_df[pairs_df["success"] == True]
        if "success" in pairs_df.columns
        else pairs_df
    )

    # ── Per vulnerability ─────────────────────────────────────────────────────
    agg_cols = {"tp": "sum", "fp": "sum", "tn": "sum", "fn": "sum"}
    if "rounds_to_consensus" in successful.columns:
        agg_cols["rounds_to_consensus"] = "mean"
    if "consensus_reached" in successful.columns:
        agg_cols["consensus_reached"] = "mean"

    vuln_df = (
        successful
        .groupby(["run", "target_vulnerability"])
        .agg(agg_cols)
        .reset_index()
        .rename(columns={
            "target_vulnerability": "vulnerability",
            "consensus_reached": "consensus_rate",
            "rounds_to_consensus": "avg_rounds_to_consensus",
        })
    )

    # ── Global per run ────────────────────────────────────────────────────────
    global_df = (
        successful
        .groupby("run")[["tp", "fp", "tn", "fn"]]
        .sum()
        .reset_index()
    )
    global_df["n_pairs"]   = successful.groupby("run").size().values
    global_df["precision"] = global_df.apply(lambda r: _safe_div(r.tp, r.tp + r.fp), axis=1)
    global_df["recall"]    = global_df.apply(lambda r: _safe_div(r.tp, r.tp + r.fn), axis=1)
    global_df["f1"]        = global_df.apply(
        lambda r: _safe_div(2 * r.precision * r.recall, r.precision + r.recall), axis=1
    )
    global_df["accuracy"]  = global_df.apply(
        lambda r: _safe_div(r.tp + r.tn, r.tp + r.fp + r.tn + r.fn), axis=1
    )

    # ── Overall totals ────────────────────────────────────────────────────────
    totals = successful[["tp", "fp", "tn", "fn"]].sum()
    m = Metrics(
        tp=int(totals["tp"]),
        fp=int(totals["fp"]),
        tn=int(totals["tn"]),
        fn=int(totals["fn"]),
    )

    n_contracts  = successful["dataset_index"].nunique() if "dataset_index" in successful.columns else "?"
    n_vuln_types = successful["target_vulnerability"].nunique() if "target_vulnerability" in successful.columns else "?"
    n_failed     = len(pairs_df) - len(successful)
    avg_time     = successful["analysis_time"].mean() if "analysis_time" in successful.columns else 0.0

    total_h = int(total_time_seconds // 3600)
    total_m = int((total_time_seconds % 3600) // 60)
    total_s = int(total_time_seconds % 60)
    total_time_str = f"{total_h}h {total_m}m {total_s}s" if total_h else f"{total_m}m {total_s}s"

    # ── Agent mode info ───────────────────────────────────────────────────────
    use_reviewer = cfg.agent.use_reviewer
    agent_mode = (
        f"Dual-Agent [Detector + Reviewer, max_rounds={cfg.agent.max_rounds}]"
        if use_reviewer else "Single-Agent [Detector only]"
    )

    # ── File paths ────────────────────────────────────────────────────────────
    pair_csv     = os.path.join(output_dir, "results_pairs.csv")
    contract_csv = os.path.join(output_dir, "results_contract.csv")
    vuln_csv     = os.path.join(output_dir, "results_vuln.csv")
    global_csv   = os.path.join(output_dir, "results_global.csv")
    summary_md   = os.path.join(output_dir, "experiment_summary.md")

    pairs_df.to_csv(pair_csv, index=False)
    contracts_df.to_csv(contract_csv, index=False)
    vuln_df.to_csv(vuln_csv, index=False)
    global_df.to_csv(global_csv, index=False)

    # ── Markdown summary ──────────────────────────────────────────────────────
    run_table  = _df_to_md(
        global_df[["run", "n_pairs", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy"]]
    )
    vuln_table = _vuln_top_table(vuln_df, n=15)

    md = f"""\
# Experiment Summary

> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
> Output folder: `{output_dir}`

---

## Configuration

### Agent System

| Parameter | Value |
| --- | --- |
| Mode | `{agent_mode}` |
| use_reviewer | `{use_reviewer}` |
| max_rounds | `{cfg.agent.max_rounds}` |

### LLM

| Parameter | Value |
| --- | --- |
| Model | `{cfg.llm.model}` |
| Temperature | `{cfg.llm.temperature}` |
| Context window (`num_ctx`) | `{cfg.llm.num_ctx:,}` tokens |
| Max output tokens (`num_predict`) | `{cfg.llm.num_predict}` |
| Timeout | `{cfg.llm.timeout}` s |
| Max retries on crash | `{cfg.llm.max_retries}` |
| Retry delay | `{cfg.llm.retry_delay}` s |
| Max code chars (truncation) | `{cfg.llm.max_code_chars:,}` |

### Retrieval

| Parameter | Value |
| --- | --- |
| RAG enabled | `{cfg.retrieval.use_rag}` |
| Top-k | `{cfg.retrieval.top_k}` |
| Embedding model | `{cfg.embedding.fast_model if cfg.embedding.use_fast else cfg.embedding.slow_model}` |

### Evaluation

| Parameter | Value |
| --- | --- |
| N runs | `{cfg.eval.n_runs}` |
| Resume run | `{cfg.eval.resume_run}` |
| Resume contract index | `{cfg.eval.resume_contract_index}` |
| Resume vuln position | `{cfg.eval.resume_vuln_pos}` |
| Store raw responses | `{cfg.eval.store_raw_response}` |

### Data

| Parameter | Value |
| --- | --- |
| Test set | `{cfg.data.test_path}` |
| Vuln descriptions | `{cfg.data.vuln_desc_path}` |
| Subset size | `{cfg.data.test_subset_size}` |

---

## Overall Results

| Metric | Value |
| --- | --- |
| Contracts evaluated | {n_contracts} |
| Vulnerability types | {n_vuln_types} |
| Total pairs | {len(successful)} |
| Failed pairs (skipped) | {n_failed} |
| Avg. time per pair | {avg_time:.1f} s |
| Total execution time | {total_time_str} |

### Confusion Matrix

| | Predicted PRESENT | Predicted ABSENT |
| --- | --- | --- |
| **Ground Truth PRESENT** | TP = {m.tp} | FN = {m.fn} |
| **Ground Truth ABSENT** | FP = {m.fp} | TN = {m.tn} |

### Metrics

| Metric | Value |
| --- | --- |
| Precision | **{m.precision:.4f}** |
| Recall | **{m.recall:.4f}** |
| F1-score | **{m.f1:.4f}** |
| Accuracy | **{m.accuracy:.4f}** |

---

## Results per Run

{run_table}

---

## Top Vulnerabilities by F1

{vuln_table}

---

## Generated Files

| File | Description |
| --- | --- |
| `results_pairs.csv` | One row per (run, contract, vulnerability) pair |
| `results_contract.csv` | Per-contract summary |
| `results_vuln.csv` | Per-vulnerability aggregated metrics |
| `results_global.csv` | Global metrics per run |
| `experiment_summary.md` | This file |

### New columns in results_pairs.csv (dual-agent)

| Column | Description |
| --- | --- |
| `detector_verdict` | PRESENT or ABSENT — raw Detector output |
| `detector_confidence` | Detector confidence (0.0–1.0) |
| `detector_reasoning` | Detector chain-of-thought summary |
| `reviewer_verdict` | CONFIRMED, REFUTED, or UNCERTAIN |
| `reviewer_confidence` | Reviewer confidence (0.0–1.0) |
| `reviewer_reasoning` | Reviewer explanation |
| `reconciliation_rule` | `consensus_round_N` or `weighted_arbitration_round_N` (or `rule_0_detector_only`) |
| `rounds_to_consensus` | Rounds until agreement, or `max_rounds` on impasse |
| `consensus_reached` | True if Reviewer confirmed Detector before the round limit |
| `reconciliation_weight_ratio` | Dominant weight ratio in weighted arbitration (0.0 on consensus) |
| `detector_confidence_delta` | Detector confidence change from round 1 to final round |

### New columns in results_vuln.csv (dual-agent)

| Column | Description |
| --- | --- |
| `avg_rounds_to_consensus` | Mean rounds to agreement per vulnerability type |
| `consensus_rate` | Fraction of pairs that reached consensus (reveals controversial vulnerabilities) |
"""

    with open(summary_md, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\nResults saved to: {output_dir}")
    print(f"Precision={m.precision:.4f} | Recall={m.recall:.4f} | F1={m.f1:.4f} | Accuracy={m.accuracy:.4f}")

    return output_dir
