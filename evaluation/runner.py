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

import contextlib
import io
import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd
from tqdm import tqdm

from smart_contract_audit_agents.config import Config
from smart_contract_audit_agents.evaluation.evidence import issue_evidence_counts
from smart_contract_audit_agents.evaluation.metrics import Metrics, classify_pair
from smart_contract_audit_agents.utils.display import banner, hr, print_conversation_log, print_llm_preview
from smart_contract_audit_agents.utils.io import safe_json_dumps
from smart_contract_audit_agents.utils.vuln_desc_lookup import _norm as _norm_vuln


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


class JsonlSidecar:
    """Appends one JSON object per line to a file, creating it on first write.

    Used for the raw Detector output, which does not fit a CSV cell: the
    existing `raw_response_json` column runs through safe_json_dumps with a
    20 000-char cap, and a whole `response` (it carries conversation_log, i.e.
    the full prompts) is far larger than that — the stored value is truncated
    mid-string and no longer parses as JSON.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def append(self, obj: Dict[str, Any]) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def _triage_rank(shortlist: List[str], target: str) -> "int | str":
    """1-based position of *target* in *shortlist*, or "" if it is not there.

    Uses the same normalisation the triage node uses to match catalog names
    (utils.vuln_desc_lookup._norm), so the rank agrees with the shortlist
    membership test in pipeline/nodes.py.
    """
    if not shortlist:
        return ""
    tgt = _norm_vuln(str(target))
    for i, name in enumerate(shortlist, 1):
        if _norm_vuln(str(name)) == tgt:
            return i
    return ""


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
    debug: bool = False,
    show_conversation: bool = False,
    save_conversation: "str | None" = None,
    show_prompts: bool = True,
    clean: bool = False,
) -> Dict[str, Any]:
    """Analyse one (contract, vulnerability) pair and return a result dict."""
    contract_idx  = example_data["index"]
    contract_name = example_data["name"]
    code          = example_data["code"]

    if not clean:
        banner(f"CONTRACT ANALYSIS | idx={contract_idx} | {contract_name}", char="-")
        print(f"Ground Truth:  {example_data['vulnerability']}")
        print(f"Target vuln:   {vulnerability_name}")
        print(f"Code:          {len(code)} chars | {len(code.splitlines())} lines")

    start = time.time()
    try:
        if clean:
            # Interface limpa: silencia os prints internos dos nós; só erros/retries
            # sobem via tqdm.write para não quebrar as barras de progresso.
            _buf = io.StringIO()
            with contextlib.redirect_stdout(_buf):
                response = pipeline.forward(
                    query=code,
                    vulnerability_name=vulnerability_name,
                    vulnerability_description=vulnerability_description,
                    debug=debug,
                )
            for _line in _buf.getvalue().splitlines():
                _low = _line.lower()
                if "retry" in _low or "failed after" in _low or "traceback" in _low:
                    tqdm.write(_line)
        else:
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

        conv_log = response.get("conversation_log", [])

        if show_conversation and not clean:
            print_conversation_log(
                conv_log,
                title=f"{contract_name}  │  {vulnerability_name}",
                show_prompts=show_prompts,
            )

        if save_conversation and conv_log:
            with open(save_conversation, "a", encoding="utf-8") as f:
                print_conversation_log(
                    conv_log,
                    title=f"{contract_name}  │  {vulnerability_name}",
                    show_prompts=show_prompts,
                    file=f,
                )

        elapsed = time.time() - start
        if not clean:
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
        # Debate cycle metrics
        rounds_to_consensus          = response.get("rounds_to_consensus", 1)
        consensus_reached            = response.get("consensus_reached", False)
        reconciliation_weight_ratio  = float(response.get("reconciliation_weight_ratio", 0.0))
        detector_confidence_delta    = float(response.get("detector_confidence_delta", 0.0))
        # Triage fields
        triage_candidate = bool(response.get("triage_candidate", True))
        triage_filtered  = reconciliation_rule == "triage_filtered"
        triage_shortlist = response.get("triage_shortlist", []) or []

        # Issues always come from the Detector
        detector_issues = analysis.get("issues", []) or []

        # Evidence audit (measurement only — does NOT influence any verdict).
        # Counts how many issues would satisfy the evidence requirements the
        # Detector prompt already states but nothing enforces.
        evidence_counts = issue_evidence_counts(
            detector_issues, code, vulnerability_name
        )

        # Prediction: verdict from the Reconciler is the final decision
        is_predicted_positive = (final_verdict == "PRESENT")
        predicted_vulns = [vulnerability_name] if is_predicted_positive else []

        if not clean:
            if triage_filtered:
                print(
                    "\n[triage] Target vulnerability not in contract shortlist — "
                    "auto-ABSENT (Detector/Reviewer skipped)"
                )
            print(
                f"\nDetector: {detector_verdict} ({detector_confidence:.2f}) | "
                f"Reviewer: {reviewer_verdict} ({reviewer_confidence:.2f}) | "
                f"Final: {final_verdict} ({final_confidence:.2f}) via {reconciliation_rule}"
            )
            print(f"Issues found: {len(detector_issues)}")
            for i, issue in enumerate(detector_issues[:5], 1):
                print(f"  {i}. [{issue.get('severity','?')}] {issue.get('description','')[:160]}")
            if len(detector_issues) > 5:
                print(f"  ... (+{len(detector_issues)-5} more)")

        m = classify_pair(
            example_data["vulnerability"],
            vulnerability_name,
            predicted_vulns,
        )

        if not clean:
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
            # Popped by the caller into raw_detector/<run>.jsonl — never a CSV
            # column. Holds the full issues[] (line_numbers included), which the
            # truncated raw_response_json cannot reliably carry.
            "_raw_detector": {
                "issues": detector_issues,
                "detector_verdict": detector_verdict,
                "detector_confidence": detector_confidence,
                "detector_reasoning": detector_reasoning,
                "reviewer_verdict": reviewer_verdict,
                "reviewer_reasoning": reviewer_reasoning,
                "final_verdict": final_verdict,
                "reconciliation_rule": reconciliation_rule,
                "n_lines": len(code.splitlines()),
                **evidence_counts,
            } if store_raw_response else None,
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
            # Debate cycle columns
            "rounds_to_consensus": rounds_to_consensus,
            "consensus_reached": consensus_reached,
            "reconciliation_weight_ratio": reconciliation_weight_ratio,
            "detector_confidence_delta": detector_confidence_delta,
            # Triage columns
            "triage_candidate": triage_candidate,
            "triage_filtered": triage_filtered,
            # Triage audit columns: the shortlist the triage produced for this
            # contract and where the target sat in it. Logged so max_shortlist
            # can be swept post-hoc without re-running the pipeline.
            "triage_shortlist": safe_json_dumps(triage_shortlist, max_chars=8_000),
            "triage_shortlist_size": len(triage_shortlist),
            "triage_rank": _triage_rank(triage_shortlist, vulnerability_name),
            # Evidence audit columns (logging only)
            **evidence_counts,
        }

    except Exception as e:
        elapsed = time.time() - start
        if clean:
            tqdm.write(f"[FAIL] idx={contract_idx} · {vulnerability_name}: {type(e).__name__}: {e}")
        else:
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
            # Debate cycle columns (empty on failure)
            "rounds_to_consensus": 0,
            "consensus_reached": False,
            "reconciliation_weight_ratio": 0.0,
            "detector_confidence_delta": 0.0,
            # Triage columns (defaults on failure)
            "triage_candidate": True,
            "triage_filtered": False,
            "triage_shortlist": "",
            "triage_shortlist_size": 0,
            "triage_rank": "",
            "n_issues_admissible": 0,
            "n_issues_with_lines": 0,
            "n_issues_with_snippet": 0,
            "n_issues_type_match": 0,
        }


# ─── Main loop ────────────────────────────────────────────────────────────────

def run_evaluation(
    pipeline,
    selected_examples: List[Dict[str, Any]],
    vuln_desc_df: pd.DataFrame,
    cfg: Config,
    output_dir: Optional[str] = None,
    debug: bool = False,
    show_conversation: bool = False,
    save_conversation: "str | None" = None,
    show_prompts: bool = True,
    clean: bool = False,
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
    # Raw Detector output (only written when store_raw_response is on)
    raw_dir = os.path.join(output_dir, "raw_detector")

    # ── Detect already-done pairs (resume support) ────────────────────────────
    done_pairs = _already_done(pair_csv)
    if done_pairs:
        banner(f"RESUMING — {len(done_pairs)} pairs already saved, skipping them")

    ecfg = cfg.eval
    pair_results: List[Dict] = []
    contract_results: List[Dict] = []
    total_start = time.time()

    for run in range(ecfg.resume_run, ecfg.n_runs + 1):
        if clean:
            tqdm.write(f"══════ RUN {run}/{ecfg.n_runs} ══════")
        else:
            banner(f"STARTING RUN {run}/{ecfg.n_runs}")

        raw_writer = (
            JsonlSidecar(os.path.join(raw_dir, f"run{run}.jsonl"))
            if ecfg.store_raw_response else None
        )

        run_metrics = Metrics()
        run_start   = time.time()

        eligible = [
            ex for ex in selected_examples
            if not (ecfg.skip_contract and ex["index"] == ecfg.skip_contract_index)
        ]

        # Barra ÚNICA (robusta em tmux/SSH): progresso por PAR sobre todos os
        # contratos. Barras aninhadas com position= vazavam escapes ^[[A no tmux;
        # uma barra só usa apenas \r e mostra contrato atual + placar na linha.
        total_pairs = len(eligible) * len(vuln_desc_df)
        bar = (
            tqdm(total=total_pairs, desc="Auditoria", unit="par",
                 dynamic_ncols=True, mininterval=0.5, smoothing=0.05)
            if clean else None
        )

        for contract_pos, example_data in enumerate(eligible, 1):
            contract_idx = example_data["index"]
            original_pos = next(
                j for j, ex in enumerate(selected_examples, 1)
                if ex["index"] == contract_idx
            )

            if not clean:
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
                    if clean:
                        bar.update(1)
                    else:
                        print(f"  [skip] already done: run={run} idx={contract_idx} vuln={vuln_name}")
                    continue

                if clean:
                    bar.set_description(
                        f"Contrato {contract_pos}/{len(eligible)} (idx={contract_idx}) "
                        f"· vuln {v_idx + 1}/{len(vuln_desc_df)}"
                    )
                    bar.set_postfix_str(f"→ {vuln_name[:24]}")
                else:
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
                    debug=debug,
                    show_conversation=show_conversation,
                    save_conversation=save_conversation,
                    show_prompts=show_prompts,
                    clean=clean,
                )
                result["run"] = run
                # Move the raw Detector payload out of the row: it goes to the
                # sidecar, keyed by (run, dataset_index, target_vulnerability),
                # so results_pairs.csv keeps one flat row per pair.
                raw_payload = result.pop("_raw_detector", None)
                if raw_payload is not None and raw_writer is not None:
                    raw_writer.append({
                        "run": run,
                        "dataset_index": contract_idx,
                        "target_vulnerability": vuln_name,
                        "example_name": example_data["name"],
                        "ground_truth_vulnerability": example_data["vulnerability"],
                        **raw_payload,
                    })
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

                if clean:
                    _tag = ("TP" if result["tp"] else "FP" if result["fp"]
                            else "FN" if result["fn"] else "TN")
                    _rm = run_metrics + contract_m  # placar acumulado até aqui
                    bar.set_postfix_str(
                        f"{vuln_name[:14]}→{result.get('final_verdict', '?')[:3]}[{_tag}] | "
                        f"TP={_rm.tp} FP={_rm.fp} FN={_rm.fn} MCC={_rm.mcc:.3f}"
                    )
                    bar.update(1)

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

            if clean:
                tqdm.write(
                    f"✓ contrato {contract_pos}/{len(eligible)} (idx={contract_idx}) "
                    f"em {contract_time:.0f}s · TP={run_metrics.tp} FP={run_metrics.fp} "
                    f"FN={run_metrics.fn} TN={run_metrics.tn} | MCC={run_metrics.mcc:.3f}"
                )
            else:
                print(hr("-"))
                print(
                    f"CONTRACT SUMMARY | idx={contract_idx} | RUN {run} | "
                    f"TP={contract_m.tp} FP={contract_m.fp} "
                    f"TN={contract_m.tn} FN={contract_m.fn} | "
                    f"time={contract_time:.1f}s"
                )
                print(hr("-"))

        if clean and bar is not None:
            bar.close()

        run_time = time.time() - run_start
        if clean:
            tqdm.write(
                f"Run {run} completo em {run_time/60:.1f} min | "
                f"TP={run_metrics.tp} FP={run_metrics.fp} TN={run_metrics.tn} "
                f"FN={run_metrics.fn} | MCC={run_metrics.mcc:.4f}"
            )
        else:
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
