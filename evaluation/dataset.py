"""Carregamento do test set, com suporte a ground truth multi-rótulo.

Dois formatos são aceitos, detectados automaticamente:

**Legado** (`gervais_dataset.csv`, `web3bugs_testset_human.csv`)
    Uma linha por par (contrato, rótulo), coluna `vulnerability` com um rótulo só.
    Cada linha vira uma unidade de avaliação independente — que é justamente o
    problema: quando o mesmo arquivo aparece em duas linhas com rótulos
    diferentes, detectar o rótulo "irmão" conta como falso positivo.

**Novo** (`web3bugs/extract/out/web3bugs_testset.csv`)
    Uma linha por bug, com `file_path` identificando o arquivo e
    `vulnerability_mapped` já traduzido para o catálogo de 61 tipos. Aqui as
    linhas são agrupadas por arquivo e o ground truth vira o **conjunto** de
    rótulos daquele arquivo, então um segundo bug real do mesmo arquivo passa a
    ser TP em vez de FP.

O que muda na conta, medido no dataset novo: 319 dos 467 bugs (68,3%) vivem em
arquivos com mais de um bug. No modo legado esses 319 empurravam a precisão
para baixo artificialmente.

Colunas do formato novo que este módulo usa:
    contest_id, file_path identidade da unidade de avaliação (o path é relativo ao contest)
    vulnerability_mapped  rótulo traduzido para o catálogo de 61 tipos
    in_scope              False para a família O, que o próprio artigo
                          Web3Bugs declara fora de escopo
    label_family          L / S / O, para recortar métricas depois
    code                  fonte do arquivo (idêntico em todas as linhas do mesmo arquivo)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import pandas as pd

# Presença destas colunas identifica o formato novo
_NEW_FORMAT_COLS = {"file_path", "vulnerability_mapped"}


def is_multilabel_format(df: pd.DataFrame) -> bool:
    return _NEW_FORMAT_COLS.issubset(set(df.columns))


def _join_labels(labels: List[str]) -> str:
    """Representação legível do conjunto, para CSV e telas."""
    return " | ".join(labels)


def load_examples(
    path: str,
    *,
    in_scope_only: bool = True,
    subset: int = 0,
    code_column: str = "code",
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Carrega o test set e devolve (examples, info).

    Cada example tem:
        index                  posição 0-based (o `dataset_index` dos resultados)
        name                   identificador legível da unidade
        code                   fonte a analisar
        vulnerability          rótulos como string, para exibição e CSV
        vulnerability_labels   lista dos rótulos canônicos — é o que a métrica usa
        line, file_path, label_families, n_bugs   metadados

    `info` traz os números que o run.py imprime e que entram no summary.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Test set não encontrado: {path}")

    df = pd.read_csv(path)
    if "line" not in [c.lower() for c in df.columns]:
        df["line"] = 0

    if not is_multilabel_format(df):
        return _load_legacy(df, subset=subset, code_column=code_column, path=path)

    return _load_multilabel(
        df, in_scope_only=in_scope_only, subset=subset, code_column=code_column, path=path
    )


# ─── Formato legado ───────────────────────────────────────────────────────────

def _load_legacy(
    df: pd.DataFrame, *, subset: int, code_column: str, path: str
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sub = df if subset == 0 else df.iloc[:subset]
    examples = [
        {
            "index": idx,
            "name": f"{row['vulnerability']} Example {idx}",
            "code": row[code_column],
            "vulnerability": row["vulnerability"],
            "vulnerability_labels": [str(row["vulnerability"])],
            "line": row.get("line", 0),
            "file_path": "",
            "label_families": "",
            "n_bugs": 1,
        }
        for idx, row in sub.iterrows()
    ]
    info = {
        "format": "legado (single-label)",
        "path": path,
        "rows": len(df),
        "units": len(examples),
        "positive_pairs": len(examples),
        "in_scope_only": False,
        "gt_types": sorted({str(e["vulnerability"]) for e in examples}),
    }
    return examples, info


# ─── Formato novo (multi-rótulo por arquivo) ──────────────────────────────────

def _load_multilabel(
    df: pd.DataFrame,
    *,
    in_scope_only: bool,
    subset: int,
    code_column: str,
    path: str,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    n_rows_total = len(df)

    n_dropped_scope = 0
    if in_scope_only and "in_scope" in df.columns:
        before = len(df)
        df = df[df["in_scope"].astype(bool)]
        n_dropped_scope = before - len(df)

    if code_column not in df.columns:
        raise KeyError(
            f"Coluna de código '{code_column}' não existe. "
            f"Disponíveis: {[c for c in df.columns if 'code' in c.lower()]}"
        )

    examples: List[Dict[str, Any]] = []
    # file_path é relativo ao contest: o mesmo caminho em dois contests (ex.:
    # VaderPoolV2.sol nos contests 52 e 70) são arquivos diferentes, com código
    # diferente. Agrupar só por file_path fundia os dois num exemplo com o código
    # de um e os rótulos de ambos.
    keys = ["contest_id", "file_path"] if "contest_id" in df.columns else ["file_path"]
    # sort=False preserva a ordem de aparição no CSV, então --subset N pega
    # sempre os mesmos arquivos e o resume continua válido.
    for idx, (key, grp) in enumerate(df.groupby(keys, sort=False)):
        file_path = "/".join(str(k) for k in key) if isinstance(key, tuple) else str(key)
        labels = sorted({
            str(v).strip()
            for v in grp["vulnerability_mapped"].dropna()
            if str(v).strip()
        })
        if not labels:
            # Sem rótulo mapeado não há como pontuar o arquivo; entraria só como
            # negativo puro e inflaria os TN sem informar nada.
            continue

        families = sorted({str(f) for f in grp.get("label_family", pd.Series(dtype=str)).dropna()})
        examples.append({
            "index": idx,
            "name": str(grp["file_name"].iloc[0]) if "file_name" in grp else str(file_path),
            "code": grp[code_column].iloc[0],
            "vulnerability": _join_labels(labels),
            "vulnerability_labels": labels,
            "line": int(grp["line"].iloc[0]) if "line" in grp else 0,
            "file_path": str(file_path),
            "label_families": ",".join(families),
            "n_bugs": len(grp),
        })

    if subset:
        examples = examples[:subset]
        # Reindexa para o subset ficar contíguo a partir de 0
        for new_idx, ex in enumerate(examples):
            ex["index"] = new_idx

    positive_pairs = sum(len(e["vulnerability_labels"]) for e in examples)
    gt_types = sorted({l for e in examples for l in e["vulnerability_labels"]})

    info = {
        "format": "multi-rótulo por arquivo",
        "path": path,
        "rows": n_rows_total,
        "rows_dropped_out_of_scope": n_dropped_scope,
        "units": len(examples),
        "positive_pairs": positive_pairs,
        "in_scope_only": in_scope_only,
        "multilabel_units": sum(1 for e in examples if len(e["vulnerability_labels"]) > 1),
        "code_column": code_column,
        "gt_types": gt_types,
    }
    return examples, info


def format_info(info: Dict[str, Any], n_vuln_types: int) -> str:
    """Bloco legível para o run.py imprimir no início."""
    lines = [f"Formato:             {info['format']}"]
    lines.append(f"Linhas no CSV:       {info['rows']}")
    if info.get("rows_dropped_out_of_scope"):
        lines.append(
            f"  descartadas (fora de escopo, família O): {info['rows_dropped_out_of_scope']}"
        )
    lines.append(f"Unidades avaliadas:  {info['units']}")
    if "multilabel_units" in info:
        lines.append(
            f"  com 2+ rótulos:    {info['multilabel_units']} "
            f"({info['multilabel_units'] / max(info['units'], 1):.1%})"
        )
    lines.append(f"Pares positivos:     {info['positive_pairs']}")
    total_pairs = info["units"] * n_vuln_types
    if total_pairs:
        lines.append(
            f"Matriz:              {info['units']} × {n_vuln_types} = {total_pairs} pares "
            f"({info['positive_pairs'] / total_pairs:.2%} positivos)"
        )
    lines.append(
        f"Tipos presentes no GT: {len(info['gt_types'])} de {n_vuln_types} "
        f"(os outros {n_vuln_types - len(info['gt_types'])} só podem gerar FP ou TN)"
    )
    if info.get("code_column"):
        lines.append(f"Coluna de código:    {info['code_column']}")
    return "\n".join(lines)
