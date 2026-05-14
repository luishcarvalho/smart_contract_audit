"""
Main evaluation loop for the dual-agent audit pipeline.

Iterates over selected_examples × vulnerability_descriptions,
calls the pipeline for each pair, collects TP/FP/TN/FN.

Features:
  - Incremental CSV saving after every pair  →  no results lost on SSH disconnect
  - Automatic resume from last saved row     →  restart from where it stopped
  - Multi-run support with resume params
  - New columns: detector/reviewer verdicts, reconciliation_rule
"""
from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

from smart_contract_audit_agents.config import Config
from smart_contract_audit_agents.evaluation.metrics import Metrics, classify_pair
from smart_contract_audit_agents.utils.display import banner, hr, print_llm_preview
from smart_contract_audit_agents.utils.io import safe_json_dumps


# ─── Incremental CSV writer ───────────────────────────────────────────────────

class IncrementalCSV:
    """Appends one row at a time to a CSV file.

    The header is written once on first write; subsequent writes append
    without re-opening the full file.  Safe to resume: if the file already
    exists, new rows are appended and the header is skipped.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._exists = os.path.exists(path)

    def append(self, row: Dict[str, Any]) -> None:
        df = pd.DataFrame([row])
        df.to_csv(
            self.path,
            mode="a",
            header=not self._exists,
            index=False,
        )
        self._exists = True


def _already_done(pairs_csv: str) -> set[tuple]:
    """Return set of (run, dataset_index, target_vulnerability) already in the CSV."""
    if not os.path.exists(pairs_csv):
        return set()
    try:
        df = pd.read_csv(pairs_csv, usecols=["run", "dataset_index", "target_vulnerability"])
        return {
            (int(r.run), int(r.dataset_index), str(r.target_vulnerability))
            for _, r in df.iterrows()
        }
    except Exception:
        return set()


# ─── Single-pair helper ───────────────────────────────────────────────────────

def analyze_pair(
    pipeline,
    example_data: Dict[str, Any],
    vulnerability_name: str,
    vulnerability_description: str,
    *,
    store_raw_response: bool = False,
    confidence_threshold: float = 0.7,
    debug: bool = False,
) -> Dict[str, Any]:
    """Analyse one (contract, vulnerability) pair and return a result dict."""
    contract_idx  = example_data["index"]
    contract_name = example_data["name"]
    code          = example_data["code"]

    banner(f"CONTRACT ANALYSIS | idx={contract_idx} | {contract_name}", char="-")
    print(f"Ground Truth:  {example_data['vulnerability']}")
    print(f"Target vuln:   {vulnerability_name}")
    print(f"Code:          {len(code)} chars | {len(code.splitlines())} lines")

    start = time.time()
    try:
        response = pipeline.forward(
            query=code,
            vulnerability_name=vulnerability_name,
            vulnerability_description=vulnerability_description,
            debug=debug,
        )

        print_llm_preview(
            response,
            title=f"LLM RESPONSE PREVIEW | target={vulnerability_name}",
            max_chars=900,
            max_lines=14,
        )

        elapsed = time.time() - start
        print(f"\nCompleted in {elapsed:.2f}s")

        retrieval_mode = response.get("retrieval_mode", "unknown")
        parsed = response.get("parsed_response", {})
        if hasattr(parsed, "model_dump"):
            analysis = parsed.model_dump()
        elif hasattr(parsed, "dict"):
            analysis = parsed.dict()
        elif isinstance(parsed, dict):
            analysis = parsed
        else:
            analysis = {}

        # Agent-specific fields
        detector_verdict   = response.get("detector_verdict", "ABSENT")
        detector_confidence = float(response.get("detector_confidence", 0.0))
        detector_reasoning  = response.get("detector_reasoning", "")
        reviewer_verdict    = response.get("reviewer_verdict", "")
        reviewer_confidence = float(response.get("reviewer_confidence", 0.0))
        reviewer_reasoning  = response.get("reviewer_reasoning", "")
        final_verdict       = response.get("final_verdict", "ABSENT")
        final_confidence    = float(response.get("final_confidence", 0.0))
        reconciliation_rule = response.get("reconciliation_rule", "")

        # Issues always come from the Detector
        detector_issues = analysis.get("issues", []) or []

        # Prediction: based on final_verdict and final_confidence threshold
        is_predicted_positive = (final_verdict == "PRESENT") and (final_confidence >= confidence_threshold)
        predicted_vulns = [vulnerability_name] if is_predicted_positive else []

        print(
            f"\nDetector: {detector_verdict} ({detector_confidence:.2f}) | "
            f"Reviewer: {reviewer_verdict} ({reviewer_confidence:.2f}) | "
            f"Final: {final_verdict} ({final_confidence:.2f}) via {reconciliation_rule}"
        )
        print(f"Issues found: {len(detector_issues)} | threshold: {confidence_threshold:.2f}")
        for i, issue in enumerate(detector_issues[:5], 1):
            print(f"  {i}. [{issue.get('severity','?')}] {issue.get('description','')[:160]}")
        if len(detector_issues) > 5:
            print(f"  ... (+{len(detector_issues)-5} more)")

        m = classify_pair(
            example_data["vulnerability"],
            vulnerability_name,
            predicted_vulns,
        )

        print(f"\nGT positive: {bool(m.tp + m.fn)} | Pred positive: {is_predicted_positive}")
        print(f"TP={m.tp} FP={m.fp} TN={m.tn} FN={m.fn}")

        return {
            "run": None,
            "example_name": contract_name,
            "dataset_index": contract_idx,
            "ground_truth_vulnerability": example_data["vulnerability"],
            "target_vulnerability": vulnerability_name,
            "is_ground_truth_positive": bool(m.tp + m.fn),
            "is_predicted_positive": is_predicted_positive,
            "tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn,
            "issues_count": len(detector_issues),
            "model_confidence": final_confidence,
            "predicted_vulnerabilities": predicted_vulns,
            "parsed_ok": True,
            "success": True,
            "analysis_time": elapsed,
            "timestamp": datetime.now().isoformat(),
            "n_lines": len(code.splitlines()),
            "raw_response_json": safe_json_dumps(response) if store_raw_response else "",
            "retrieval_mode": retrieval_mode,
            "skipped": False,
            "skip_reason": "",
            # Dual-agent columns
            "detector_verdict": detector_verdict,
            "detector_confidence": detector_confidence,
            "detector_reasoning": detector_reasoning,
            "reviewer_verdict": reviewer_verdict,
            "reviewer_confidence": reviewer_confidence,
            "reviewer_reasoning": reviewer_reasoning,
            "reconciliation_rule": reconciliation_rule,
        }

    except Exception as e:
        elapsed = time.time() - start
        print(f"\nFAILED: {type(e).__name__}: {e}")
        return {
            "run": None,
            "example_name": contract_name,
            "dataset_index": contract_idx,
            "ground_truth_vulnerability": example_data["vulnerability"],
            "target_vulnerability": vulnerability_name,
            "is_ground_truth_positive": False,
            "is_predicted_positive": False,
            "tp": 0, "fp": 0, "tn": 0, "fn": 0,
            "issues_count": 0,
            "predicted_vulnerabilities": [],
            "parsed_ok": False,
            "success": False,
            "error": f"{type(e).__name__}: {e}",
            "analysis_time": elapsed,
            "timestamp": datetime.now().isoformat(),
            "n_lines": len(code.splitlines()) if isinstance(code, str) else 0,
            "raw_response_json": "",
            "retrieval_mode": "unknown",
            "skipped": False,
            "skip_reason": "",
            # Dual-agent columns (empty on failure)
            "detector_verdict": "",
            "detector_confidence": 0.0,
            "detector_reasoning": "",
            "reviewer_verdict": "",
            "reviewer_confidence": 0.0,
            "reviewer_reasoning": "",
            "reconciliation_rule": "",
        }


# ─── Main loop ────────────────────────────────────────────────────────────────

def run_evaluation(
    pipeline,
    selected_examples: List[Dict[str, Any]],
    vuln_desc_df: pd.DataFrame,
    cfg: Config,
    output_dir: Optional[str] = None,
    debug: bool = False,
) -> tuple[List[Dict], List[Dict], str]:
    """Run the full evaluation loop with incremental saving.

    Every pair result is written to CSV immediately after evaluation.
    If *output_dir* already contains a partial `results_pairs.csv`, those
    pairs are skipped automatically — run the same command to resume.

    Returns:
        pair_results     — one row per (run, contract, vulnerability)
        contract_results — one row per (run, contract)
        output_dir       — path to the results directory
    """
    # ── Prepare output directory ──────────────────────────────────────────────
    if output_dir is None:
        llm_name   = cfg.llm.model.replace(":", "-")
        tag        = "rag" if cfg.retrieval.use_rag else "norag"
        now        = datetime.now()
        month_dir  = now.strftime("%m-%Y")
        timestamp  = now.strftime("%d-%m-%y_%H-%M-%S")
        output_dir = os.path.join(cfg.eval.results_dir, llm_name, month_dir, f"{tag}_{timestamp}")

    os.makedirs(output_dir, exist_ok=True)

    pair_csv     = os.path.join(output_dir, "results_pairs.csv")
    contract_csv = os.path.join(output_dir, "results_contract.csv")

    pair_writer     = IncrementalCSV(pair_csv)
    contract_writer = IncrementalCSV(contract_csv)

    # ── Detect already-done pairs (resume support) ────────────────────────────
    done_pairs = _already_done(pair_csv)
    if done_pairs:
        banner(f"RESUMING — {len(done_pairs)} pairs already saved, skipping them")

    ecfg = cfg.eval
    pair_results: List[Dict] = []
    contract_results: List[Dict] = []
    total_start = time.time()

    for run in range(ecfg.resume_run, ecfg.n_runs + 1):
        banner(f"STARTING RUN {run}/{ecfg.n_runs}")

        run_metrics = Metrics()
        run_start   = time.time()

        eligible = [
            ex for ex in selected_examples
            if not (ecfg.skip_contract and ex["index"] == ecfg.skip_contract_index)
        ]

        for contract_pos, example_data in enumerate(eligible, 1):
            contract_idx = example_data["index"]
            original_pos = next(
                j for j, ex in enumerate(selected_examples, 1)
                if ex["index"] == contract_idx
            )

            banner(
                f"CONTRACT {contract_pos}/{len(eligible)} "
                f"| original={original_pos}/{len(selected_examples)} "
                f"| idx={contract_idx} | RUN {run}"
            )

            contract_m     = Metrics()
            contract_start = time.time()
            n_eval = 0

            for v_idx, row in vuln_desc_df.iterrows():
                vuln_name = str(row["vulnerability"])
                vuln_desc = str(row["description"])

                # Skip already-done pairs (resume)
                if (run, contract_idx, vuln_name) in done_pairs:
                    print(f"  [skip] already done: run={run} idx={contract_idx} vuln={vuln_name}")
                    continue

                print(
                    f"\nRUN {run} | Contract {contract_pos}/{len(eligible)} "
                    f"| idx={contract_idx} "
                    f"| Vuln [{v_idx+1}/{len(vuln_desc_df)}]: {vuln_name}"
                )
                print(hr("-"))

                result = analyze_pair(
                    pipeline,
                    example_data,
                    vuln_name,
                    vuln_desc,
                    store_raw_response=ecfg.store_raw_response,
                    confidence_threshold=ecfg.confidence_threshold,
                    debug=debug,
                )
                result["run"] = run
                result["contract_position_in_run"] = contract_pos
                result["total_contracts_in_run"]   = len(eligible)
                result["contract_position_original"] = original_pos
                result["total_contracts_original"]   = len(selected_examples)

                # ── Save immediately ──────────────────────────────────────────
                pair_writer.append(result)
                done_pairs.add((run, contract_idx, vuln_name))

                pair_results.append(result)

                pair_m     = Metrics(tp=result["tp"], fp=result["fp"],
                                     tn=result["tn"], fn=result["fn"])
                contract_m = contract_m + pair_m
                n_eval    += 1

            contract_time = time.time() - contract_start
            contract_row = {
                "run": run,
                "example_name": example_data["name"],
                "dataset_index": contract_idx,
                "ground_truth_vulnerability": example_data["vulnerability"],
                "contract_position_in_run": contract_pos,
                "total_contracts_in_run": len(eligible),
                "contract_position_original": original_pos,
                "total_contracts_original": len(selected_examples),
                "tp_sum": contract_m.tp, "fp_sum": contract_m.fp,
                "tn_sum": contract_m.tn, "fn_sum": contract_m.fn,
                "n_vulnerabilities_evaluated": n_eval,
                "contract_time": contract_time,
            }
            contract_writer.append(contract_row)
            contract_results.append(contract_row)

            run_metrics = run_metrics + contract_m

            print(hr("-"))
            print(
                f"CONTRACT SUMMARY | idx={contract_idx} | RUN {run} | "
                f"TP={contract_m.tp} FP={contract_m.fp} "
                f"TN={contract_m.tn} FN={contract_m.fn} | "
                f"time={contract_time:.1f}s"
            )
            print(hr("-"))

        run_time = time.time() - run_start
        print(hr())
        print(f"RUN {run} COMPLETE | {run_time/60:.2f} min")
        print(f"RUN TOTALS: TP={run_metrics.tp} FP={run_metrics.fp} "
              f"TN={run_metrics.tn} FN={run_metrics.fn}")
        print(hr())

    total_time = time.time() - total_start
    banner("EVALUATION COMPLETE")
    print(f"Total time: {total_time/60:.2f} minutes")
    print(f"Pair evaluations: {len(pair_results)}")
    print(f"Results saved incrementally to: {output_dir}")

    return pair_results, contract_results, output_dir
