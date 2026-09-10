"""Train/test leakage audit: RAG corpus vs. the evaluation test sets.

Answers the question the zero-contamination claim rests on: does any contract
in a test set also appear, whole or in part, in `all_data.parquet` — the corpus
the RAG retrieves from?

Granularity mismatch (read this before reading the numbers)
-----------------------------------------------------------
The two sides are not the same kind of object:

    corpus doc      median   199 chars   (a snippet / single function)
    test contract   median 15 000 chars  (a whole source file)

So sha256 equality between the two is almost vacuous — a 199-char snippet will
essentially never equal a 15 000-char file, and a report built only on hashes
would conclude "no leakage" no matter what. It is reported anyway (the audit
asked for it) but the measure that carries the signal here is CONTAINMENT:

    containment(doc, contract) = |shingles(doc) ∩ shingles(contract)|
                                 ─────────────────────────────────────
                                          |shingles(doc)|

i.e. how much of a corpus snippet is present inside a test contract. That is
the leakage shape that actually threatens the experiment: the retriever handing
the Detector a snippet lifted from the very contract under analysis.

Jaccard is reported alongside it; it stays low by construction here (a small
snippet against a large file) and is kept only so the symmetric view is on
record.

Caveat this script does NOT resolve
-----------------------------------
A match may be ubiquitous library code — OpenZeppelin, SafeMath, ERC20
boilerplate — which is shared by construction and is not contamination in any
meaningful sense. The matched text is written out so a human can judge. This
script reports; it does not adjudicate and it does not modify any dataset.

Usage:
    python data_audit/check_leakage.py
    python data_audit/check_leakage.py --shingle-k 8 --near-threshold 0.8
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import zlib
from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

import pandas as pd

# data_audit/ sits one level below the repo root, so the package parent is
# three dirnames up (run.py, at the root, needs only two).
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
)

from smart_contract_audit_agents.config import DEFAULT_CONFIG  # noqa: E402


# ─── Normalisation ────────────────────────────────────────────────────────────

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_WS = re.compile(r"\s+")


def normalise_code(code: str) -> str:
    """Strip comments and collapse whitespace.

    Comments go because reformatting or re-commenting the same source must not
    hide a match; nothing else is touched, so identifiers and literals still
    have to agree for a match to count.
    """
    s = str(code)
    s = _BLOCK_COMMENT.sub(" ", s)
    s = _LINE_COMMENT.sub(" ", s)
    return _WS.sub(" ", s).strip()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


# ─── Shingles ─────────────────────────────────────────────────────────────────

_TOKEN = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|\d+|[^\sA-Za-z0-9_$]")


def tokenise(text: str) -> List[str]:
    return _TOKEN.findall(text)


def shingles(tokens: Sequence[str], k: int) -> set:
    """Hashed k-token shingles. Empty when the text is shorter than k tokens.

    crc32, not the built-in hash(): Python randomises string hashing per process,
    so collisions — and therefore the reported counts — would drift between runs
    of a report meant to be cited.
    """
    if len(tokens) < k:
        return set()
    return {
        zlib.crc32(" ".join(tokens[i : i + k]).encode("utf-8"))
        for i in range(len(tokens) - k + 1)
    }


# ─── Loading ──────────────────────────────────────────────────────────────────

def load_corpus(path: str) -> pd.DataFrame:
    import pyarrow.parquet as pq

    table = pq.read_table(path, columns=["code", "vulnerability"])
    df = table.to_pandas()
    df["code"] = df["code"].astype(str)
    return df


def load_testset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["code"] = df["code"].astype(str)
    # dataset_index is 0-BASED, matching example["index"] in run.py, which comes
    # from `for idx, row in subset.iterrows()` — the DataFrame's positional label.
    # Verified against the reference run: ground-truth labels line up 268/268
    # with 0-based and only 77/267 with 1-based.
    df["dataset_index"] = range(len(df))
    return df


# ─── Audit ────────────────────────────────────────────────────────────────────

def audit(
    corpus: pd.DataFrame,
    test: pd.DataFrame,
    *,
    shingle_k: int,
    near_threshold: float,
    report_threshold: float,
) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """Return (matches, stats) for one test set against the corpus."""
    # ── Test side: normalise, hash, index shingles ────────────────────────────
    test_norm = [normalise_code(c) for c in test["code"]]
    test_hashes = {sha256(n): i for i, n in enumerate(test_norm)}
    test_raw_hashes = {sha256(str(c)): i for i, c in enumerate(test["code"])}

    inverted: Dict[int, set] = defaultdict(set)
    test_shingle_sets: List[set] = []
    for i, n in enumerate(test_norm):
        sh = shingles(tokenise(n), shingle_k)
        test_shingle_sets.append(sh)
        for h in sh:
            inverted[h].add(i)

    # ── Corpus side ───────────────────────────────────────────────────────────
    stats = {
        "corpus_docs": len(corpus),
        "corpus_too_short": 0,
        "exact_hash_equal_norm": 0,
        "exact_hash_equal_raw": 0,
        "docs_with_any_match": 0,
    }
    rows: List[dict] = []

    for doc_pos, (code, vuln) in enumerate(
        zip(corpus["code"], corpus["vulnerability"])
    ):
        norm = normalise_code(code)

        if sha256(norm) in test_hashes:
            stats["exact_hash_equal_norm"] += 1
        if sha256(str(code)) in test_raw_hashes:
            stats["exact_hash_equal_raw"] += 1

        toks = tokenise(norm)
        doc_sh = shingles(toks, shingle_k)
        if not doc_sh:
            stats["corpus_too_short"] += 1
            continue

        # Count shingle hits per test contract via the inverted index
        hits: Dict[int, int] = defaultdict(int)
        for h in doc_sh:
            for i in inverted.get(h, ()):
                hits[i] += 1
        if not hits:
            continue

        matched = False
        for i, n_hits in hits.items():
            containment = n_hits / len(doc_sh)
            if containment < report_threshold:
                continue
            matched = True
            inter = n_hits
            union = len(doc_sh) + len(test_shingle_sets[i]) - inter
            rows.append(
                {
                    "corpus_row": doc_pos,
                    "corpus_vulnerability": vuln,
                    "corpus_doc_chars": len(norm),
                    "dataset_index": int(test["dataset_index"].iloc[i]),
                    "test_address": str(test.iloc[i].get("address", "")),
                    "test_gt_vulnerability": str(test.iloc[i].get("vulnerability", "")),
                    "containment": round(containment, 4),
                    "jaccard": round(inter / union, 4) if union else 0.0,
                    "exact_substring": norm in test_norm[i],
                    "tier": (
                        "EXACT_CONTAINMENT"
                        if norm in test_norm[i]
                        else "NEAR_DUPLICATE"
                        if containment >= near_threshold
                        else "PARTIAL"
                    ),
                    "corpus_snippet": norm[:300],
                }
            )
        if matched:
            stats["docs_with_any_match"] += 1

    matches = pd.DataFrame(rows)
    if not matches.empty:
        # Breadth separates boilerplate from a genuinely specific match: a
        # corpus doc found in many test contracts is shared library code
        # (Uniswap mint/burn, Compound getPriorVotes, ERC20). A doc found in
        # exactly ONE test contract is the dangerous shape — code specific to
        # the contract under analysis, sitting in the retrieval corpus.
        breadth = matches.groupby("corpus_row")["dataset_index"].nunique()
        matches["match_breadth"] = matches["corpus_row"].map(breadth)
        matches = matches.sort_values(
            ["containment", "corpus_doc_chars"], ascending=[False, False]
        ).reset_index(drop=True)
    return matches, stats


# ─── Reporting ────────────────────────────────────────────────────────────────

def summarise(name: str, test: pd.DataFrame, matches: pd.DataFrame, stats: dict) -> str:
    n_test = len(test)
    out = [f"## {name}", ""]
    out.append(f"- Contratos no test set: **{n_test}**")
    out.append(f"- Documentos no corpus: **{stats['corpus_docs']}**")
    out.append(
        f"- Documentos do corpus curtos demais para avaliar "
        f"(< k tokens): **{stats['corpus_too_short']}**"
    )
    out.append("")
    out.append("### 1. Igualdade exata de hash (sha256)")
    out.append("")
    out.append(
        f"- Docs do corpus com sha256 **idêntico** a um contrato de teste "
        f"(código bruto): **{stats['exact_hash_equal_raw']}**"
    )
    out.append(
        f"- Idem, após normalização (sem comentários, espaços colapsados): "
        f"**{stats['exact_hash_equal_norm']}**"
    )
    out.append("")
    out.append(
        "> Este número é esperado ser ~0 e **não deve ser lido como ausência de "
        "vazamento**: doc do corpus tem mediana de 199 chars e contrato de teste "
        "~15.000. Ver a seção de contenção abaixo."
    )
    out.append("")
    out.append("### 2. Contenção (a medida que carrega o sinal)")
    out.append("")

    if matches.empty:
        out.append("Nenhum documento do corpus atingiu o limiar de contenção reportável.")
        out.append("")
        return "\n".join(out)

    exact = matches[matches.tier == "EXACT_CONTAINMENT"]
    near = matches[matches.tier == "NEAR_DUPLICATE"]
    partial = matches[matches.tier == "PARTIAL"]

    n_contracts_exact = exact.dataset_index.nunique() if not exact.empty else 0
    n_contracts_near = near.dataset_index.nunique() if not near.empty else 0
    n_contracts_any = matches.dataset_index.nunique()

    out.append("| Nível | Pares (doc do corpus × contrato) | Contratos de teste afetados |")
    out.append("|---|---:|---:|")
    out.append(
        f"| `EXACT_CONTAINMENT` — o doc do corpus ocorre **literalmente** dentro do contrato "
        f"| {len(exact)} | {n_contracts_exact} ({n_contracts_exact / n_test:.1%}) |"
    )
    out.append(
        f"| `NEAR_DUPLICATE` — contenção ≥ limiar, sem casamento literal "
        f"| {len(near)} | {n_contracts_near} ({n_contracts_near / n_test:.1%}) |"
    )
    out.append(f"| `PARTIAL` — contenção acima do piso de reporte | {len(partial)} | — |")
    out.append(
        f"| **Qualquer nível** | **{len(matches)}** | "
        f"**{n_contracts_any} ({n_contracts_any / n_test:.1%})** |"
    )
    out.append("")

    affected = sorted(matches.dataset_index.unique().tolist())
    out.append(f"**dataset_index afetados ({len(affected)}):** `{affected}`")
    out.append("")

    if n_contracts_exact:
        out.append(
            f"**dataset_index com EXACT_CONTAINMENT ({n_contracts_exact}):** "
            f"`{sorted(exact.dataset_index.unique().tolist())}`"
        )
        out.append("")

    specific = matches[
        (matches.match_breadth == 1) & (matches.tier != "PARTIAL")
    ].sort_values("corpus_doc_chars", ascending=False)

    out.append("### 3. Casamentos ESPECÍFICOS — os que exigem sua decisão")
    out.append("")
    out.append(
        "`match_breadth` = em quantos contratos de teste **distintos** aquele doc do "
        "corpus aparece. Breadth alto = biblioteca compartilhada (Uniswap `mint`/`burn`, "
        "Compound `getPriorVotes`, ERC20) — presente em milhares de contratos, **não é "
        "contaminação em nenhum sentido útil**. Breadth **= 1** é a forma perigosa: "
        "código específico daquele contrato, sentado no corpus de retrieval."
    )
    out.append("")
    # The corpus holds duplicate documents (the same snippet stored many times),
    # so collapse them for display: one row per (snippet, test contract).
    specific_u = (
        specific.drop_duplicates(subset=["corpus_snippet", "dataset_index"])
        if not specific.empty
        else specific
    )
    out.append(
        f"- Casamentos com `breadth == 1` e tier ≥ NEAR_DUPLICATE: **{len(specific)}** "
        f"pares brutos → **{len(specific_u)} trechos distintos**, atingindo "
        f"**{specific.dataset_index.nunique() if not specific.empty else 0}** "
        f"contratos de teste"
    )
    out.append("")
    out.append(
        "> O corpus contém **documentos duplicados** (o mesmo trecho armazenado várias "
        "vezes), então a tabela abaixo mostra um trecho distinto por linha; a contagem "
        "de pares brutos acima é maior por causa dessas repetições."
    )
    out.append("")
    if not specific_u.empty:
        out.append("| corpus_row | chars | contenção | tier | dataset_index | rótulo GT do teste | trecho |")
        out.append("|---:|---:|---:|---|---:|---|---|")
        for r in specific_u.head(20).itertuples():
            snip = r.corpus_snippet[:110].replace("|", "\\|").replace("`", "'")
            out.append(
                f"| {r.corpus_row} | {r.corpus_doc_chars} | {r.containment:.2f} | {r.tier} "
                f"| {r.dataset_index} | {r.test_gt_vulnerability} | `{snip}…` |"
            )
        out.append("")

    out.append("### 4. Maiores casamentos (para julgamento manual)")
    out.append("")
    out.append(
        "Ordenados pelo tamanho do doc do corpus — casamentos longos são os que "
        "menos plausivelmente são boilerplate."
    )
    out.append("")
    out.append("| corpus_row | chars | contenção | tier | breadth | dataset_index | rótulo GT do teste |")
    out.append("|---:|---:|---:|---|---:|---:|---|")
    top = matches.sort_values("corpus_doc_chars", ascending=False).drop_duplicates(
        subset=["corpus_doc_chars", "dataset_index"]
    ).head(15)
    for r in top.itertuples():
        out.append(
            f"| {r.corpus_row} | {r.corpus_doc_chars} | {r.containment:.2f} | {r.tier} "
            f"| {r.match_breadth} | {r.dataset_index} | {r.test_gt_vulnerability} |"
        )
    out.append("")
    return "\n".join(out)


def main() -> None:
    data = DEFAULT_CONFIG.data
    p = argparse.ArgumentParser(description="RAG corpus vs. test set leakage audit")
    p.add_argument("--corpus", default=data.train_path)
    p.add_argument(
        "--test",
        action="append",
        metavar="NAME=PATH",
        help="Test set to audit; repeatable. Defaults to both known sets.",
    )
    p.add_argument("--shingle-k", type=int, default=8, help="Tokens per shingle")
    p.add_argument(
        "--near-threshold", type=float, default=0.8, help="Containment for NEAR_DUPLICATE"
    )
    p.add_argument(
        "--report-threshold", type=float, default=0.5, help="Containment floor for reporting"
    )
    p.add_argument("--out-dir", default=os.path.dirname(os.path.abspath(__file__)))
    args = p.parse_args()

    if args.test:
        testsets = [t.split("=", 1) for t in args.test]
    else:
        testsets = [
            ("gervais_dataset (70 linhas — test set configurado hoje)", data.test_path),
            (
                "web3bugs_testset_human (268 — base da run de referência 28-07)",
                "/home/luis.carvalho/AuditAgents-properties/web3bugs_testset_human.csv",
            ),
        ]

    print(f"Corpus: {args.corpus}")
    corpus = load_corpus(args.corpus)
    print(f"  {len(corpus)} documentos carregados")

    sections: List[str] = []
    all_matches: List[pd.DataFrame] = []

    for name, path in testsets:
        if not os.path.exists(path):
            sections.append(f"## {name}\n\n> Arquivo não encontrado: `{path}` — pulado.\n")
            print(f"[skip] {path} não existe")
            continue
        print(f"Auditando: {name}")
        test = load_testset(path)
        matches, stats = audit(
            corpus,
            test,
            shingle_k=args.shingle_k,
            near_threshold=args.near_threshold,
            report_threshold=args.report_threshold,
        )
        print(
            f"  {len(matches)} pares acima do piso | "
            f"{matches.dataset_index.nunique() if not matches.empty else 0} contratos afetados"
        )
        sections.append(summarise(name, test, matches, stats))
        if not matches.empty:
            m = matches.copy()
            m.insert(0, "testset", name)
            all_matches.append(m)

    os.makedirs(args.out_dir, exist_ok=True)
    report_path = os.path.join(args.out_dir, "leakage_report.md")
    matches_path = os.path.join(args.out_dir, "leakage_matches.csv")

    header = [
        "# Auditoria de vazamento — corpus do RAG × test sets",
        "",
        f"> Gerado por `data_audit/check_leakage.py` "
        f"(shingle_k={args.shingle_k}, near_threshold={args.near_threshold}, "
        f"report_threshold={args.report_threshold}).",
        f"> Corpus: `{args.corpus}`",
        "",
        "**Este relatório documenta; não corrige nada.** Nenhum dataset foi alterado.",
        "",
        "## Como ler",
        "",
        "Os dois lados têm granularidades diferentes — doc do corpus tem mediana de "
        "**199 chars** (trecho/função), contrato de teste tem mediana de **~15.000** "
        "(arquivo inteiro). Por isso:",
        "",
        "- **Igualdade de hash** é praticamente vazia aqui e vai dar ~0 mesmo havendo "
        "vazamento. Está no relatório porque foi pedida, não porque decide a questão.",
        "- **Contenção** (`|shingles(doc) ∩ shingles(contrato)| / |shingles(doc)|`) é a "
        "medida que importa: mede quanto de um trecho do corpus está dentro de um "
        "contrato de teste — a forma de vazamento que de fato ameaça o experimento, "
        "porque é o retriever devolvendo ao Detector um pedaço do próprio contrato "
        "sob análise.",
        "- **Jaccard** fica baixo por construção (trecho pequeno × arquivo grande); "
        "está registrado só para deixar a visão simétrica no papel.",
        "",
        "⚠️ Um casamento pode ser **boilerplate** (OpenZeppelin, SafeMath, ERC20), que é "
        "compartilhado por construção e não é contaminação em nenhum sentido útil. "
        "O texto casado é exportado em `leakage_matches.csv` para julgamento humano. "
        "Casamentos longos são os menos plausivelmente boilerplate.",
        "",
        "---",
        "",
    ]
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header) + "\n\n---\n\n".join(sections) + "\n")

    if all_matches:
        pd.concat(all_matches, ignore_index=True).to_csv(matches_path, index=False)
        print(f"Matches: {matches_path}")
    print(f"Relatório: {report_path}")


if __name__ == "__main__":
    main()
