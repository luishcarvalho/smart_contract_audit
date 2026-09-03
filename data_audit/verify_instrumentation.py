"""Verify the Wave-1 instrumentation without touching Ollama.

Drives the real `run_evaluation` loop with a stub pipeline that returns exactly
the dict shape `AuditPipeline.analyze()` returns, so the whole write path — row
assembly, CSV columns, sidecar JSONL — is exercised for real. No LLM, no
vectorstore, runs in under a second.

Checks:
  1. triage_shortlist / triage_shortlist_size / triage_rank are written, and the
     rank matches the target's position in the shortlist ("" when filtered out).
  2. n_issues_admissible and the three per-criterion counts are written, and a
     well-cited issue scores 1 while a vague one scores 0.
  3. raw_detector/run<N>.jsonl exists, is keyed by
     (run, dataset_index, target_vulnerability), and preserves line_numbers.
  4. The private _raw_detector payload never reaches results_pairs.csv.
  5. **Verdicts are unchanged.** A pair whose issues are all inadmissible still
     scores exactly as it did before — the evidence columns are logging only,
     the decision is still len(issues) > 0.

Usage:
    python data_audit/verify_instrumentation.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

import pandas as pd

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
)

from smart_contract_audit_agents.config import Config  # noqa: E402
from smart_contract_audit_agents.evaluation.runner import run_evaluation  # noqa: E402


CODE = """contract Vault {
    mapping(address => uint) public balances;
    function withdraw(uint amt) public {
        (bool ok, ) = msg.sender.call{value: amt}("");
        balances[msg.sender] -= amt;
    }
}
"""

SHORTLIST = ["access control", "reentrancy", "arithmetic"]


class StubPipeline:
    """Returns AuditPipeline.analyze()'s dict shape without calling an LLM."""

    def forward(self, query, vulnerability_name, vulnerability_description, debug=False):
        base = {
            "context": "",
            "raw_response": "raw",
            "triage_shortlist": SHORTLIST,
            "debate_history": [],
            "reconciliation_weight_ratio": 0.0,
            "detector_confidence_delta": 0.0,
            "conversation_log": [],
        }

        if vulnerability_name not in SHORTLIST:
            return {
                **base,
                "json_output": "{}",
                "parsed_response": {"issues": [], "confidence": 1.0, "summary": ""},
                "retrieval_mode": "semantic_only",
                "triage_candidate": False,
                "detector_verdict": "ABSENT",
                "detector_confidence": 0.0,
                "detector_reasoning": "",
                "reviewer_verdict": "",
                "reviewer_confidence": 0.0,
                "reviewer_reasoning": "",
                "final_verdict": "ABSENT",
                "final_confidence": 1.0,
                "reconciliation_rule": "triage_filtered",
                "rounds_to_consensus": 0,
                "consensus_reached": False,
            }

        if vulnerability_name == "reentrancy":
            # Cites a line and quotes code that is really in the contract
            issues = [{
                "issue": "reentrancy",
                "description": 'State update after `msg.sender.call{value: amt}("")`.',
                "severity": "high",
                "line_numbers": [4, 5],
            }]
        else:
            # The B-δ archetype: a generic assertion, no line, no quote
            issues = [{
                "issue": vulnerability_name,
                "description": "The contract looks broadly unsafe.",
                "severity": "medium",
                "line_numbers": [],
            }]

        return {
            **base,
            "json_output": json.dumps({"issues": issues}),
            "parsed_response": {"issues": issues, "confidence": 0.8, "summary": "s"},
            "retrieval_mode": "category_only",
            "triage_candidate": True,
            "detector_verdict": "PRESENT",
            "detector_confidence": 0.8,
            "detector_reasoning": "reasoning",
            "reviewer_verdict": "CONFIRMED",
            "reviewer_confidence": 0.9,
            "reviewer_reasoning": "rr",
            "final_verdict": "PRESENT",
            "final_confidence": 0.8,
            "reconciliation_rule": "consensus_round_1",
            "rounds_to_consensus": 1,
            "consensus_reached": True,
        }


def main() -> int:
    out_dir = tempfile.mkdtemp(prefix="verify_instrumentation_")
    try:
        cfg = Config()
        cfg.eval.store_raw_response = True
        cfg.eval.n_runs = 1

        examples = [
            {"index": 1, "name": "0xabc", "code": CODE, "vulnerability": "reentrancy"}
        ]
        vulns = pd.DataFrame(
            {
                "vulnerability": ["reentrancy", "access control", "front running"],
                "description": ["d1", "d2", "d3"],
            }
        )

        run_evaluation(StubPipeline(), examples, vulns, cfg, output_dir=out_dir, clean=True)

        pairs = pd.read_csv(os.path.join(out_dir, "results_pairs.csv"))
        by_target = pairs.set_index("target_vulnerability")

        checks = []

        def check(label: str, got, expected) -> None:
            checks.append((label, got, expected, got == expected))

        # 1. triage columns
        check("triage_rank(reentrancy) — 2º na shortlist",
              int(by_target.loc["reentrancy", "triage_rank"]), 2)
        check("triage_rank(access control) — 1º na shortlist",
              int(by_target.loc["access control", "triage_rank"]), 1)
        check("triage_rank(front running) — fora da shortlist",
              pd.isna(by_target.loc["front running", "triage_rank"]), True)
        check("triage_shortlist_size",
              int(by_target.loc["reentrancy", "triage_shortlist_size"]), 3)
        check("triage_shortlist serializado",
              json.loads(by_target.loc["reentrancy", "triage_shortlist"]), SHORTLIST)

        # 2. evidence columns
        check("n_issues_admissible — issue bem citada",
              int(by_target.loc["reentrancy", "n_issues_admissible"]), 1)
        check("n_issues_admissible — asserção genérica",
              int(by_target.loc["access control", "n_issues_admissible"]), 0)
        check("n_issues_with_lines — asserção genérica (sem linha)",
              int(by_target.loc["access control", "n_issues_with_lines"]), 0)
        check("n_issues_type_match — asserção genérica (tipo bate)",
              int(by_target.loc["access control", "n_issues_type_match"]), 1)

        # 3. sidecar
        sidecar = os.path.join(out_dir, "raw_detector", "run1.jsonl")
        check("raw_detector/run1.jsonl existe", os.path.exists(sidecar), True)
        records = [json.loads(l) for l in open(sidecar, encoding="utf-8")]
        check("sidecar: uma linha por par", len(records), 3)
        keyed = {r["target_vulnerability"]: r for r in records}
        check("sidecar: chave (run, dataset_index)",
              (keyed["reentrancy"]["run"], keyed["reentrancy"]["dataset_index"]), (1, 1))
        check("sidecar: line_numbers preservados",
              keyed["reentrancy"]["issues"][0]["line_numbers"], [4, 5])

        # 4. private payload must not leak into the CSV
        check("_raw_detector fora do CSV", "_raw_detector" in pairs.columns, False)

        # 5. verdicts unchanged — the evidence columns decide nothing
        check("veredito ainda len(issues)>0: FP inadmissível continua FP",
              int(by_target.loc["access control", "fp"]), 1)
        check("TP preservado", int(by_target.loc["reentrancy", "tp"]), 1)
        check("TN preservado", int(by_target.loc["front running", "tn"]), 1)

        width = max(len(c[0]) for c in checks)
        print()
        print(f"{'verificação'.ljust(width)}  {'obtido':<12} {'esperado':<12} ")
        print("-" * (width + 30))
        failed = 0
        for label, got, exp, ok in checks:
            if not ok:
                failed += 1
            print(f"{label.ljust(width)}  {str(got):<12} {str(exp):<12} {'OK' if ok else '<<< FALHOU'}")
        print()
        if failed:
            print(f"{failed}/{len(checks)} verificações FALHARAM")
            return 1
        print(f"Todas as {len(checks)} verificações passaram.")
        return 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
