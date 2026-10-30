# Smart Contract Audit Agents

Pipeline de pesquisa que decide, para cada par **(arquivo Solidity, tipo de vulnerabilidade)**, se o tipo está **PRESENT** ou **ABSENT** no arquivo. Usa um LLM local via Ollama, RAG sobre um corpus de código vulnerável e dois agentes em debate (Detector e Reviewer), orquestrados com LangGraph. A avaliação usa um benchmark derivado do Web3Bugs.

## Fluxo

```
Triage ──(tipo fora da shortlist)──────────────────────────────► ABSENT
   │
   ▼
Retrieve + contexto (RAG, só para o Detector)
   │
   ▼
Detector ──► Reviewer ──(CONFIRMED)──► Reconcile ──► veredicto final
   ▲            │
   └─ feedback ◄┘ (REFUTED/UNCERTAIN, até max_rounds)
```

1. **Triage** — 1 chamada por arquivo; mantém até 15 tipos plausíveis.
2. **Retrieve** — ChromaDB (`jinaai/jina-embeddings-v2-base-code`, cosseno, `top_k=5`), busca filtrada pelo tipo completada por busca semântica.
3. **Detector** — prompt de 4 passos; o veredicto é PRESENT se a lista `issues` não estiver vazia. JSON ilegível duas vezes → par registrado como erro e excluído das métricas.
4. **Reviewer** — CONFIRMED, REFUTED ou UNCERTAIN; não vê o RAG nem as rodadas anteriores; recebe o bloco OWASP SCWE.
5. **Reconcile** — determinístico: consenso mantém o Detector; no impasse, REFUTED inverte e UNCERTAIN mantém.

A confiança é registrada, mas não entra na decisão.

## Estrutura

| Pasta / arquivo | Conteúdo |
|---|---|
| `run.py`, `config.py` | Ponto de entrada e configuração (caminhos dos dados, modelo, parâmetros) |
| `pipeline/` | Grafo LangGraph, nós e prompts |
| `models/` | LLM (Ollama), embeddings, vectorstore e schemas Pydantic |
| `evaluation/` | Dataset multi-rótulo, runner incremental, métricas e geração de resultados |
| `utils/` | Lookups do catálogo de tipos, OWASP SCWE e SWC |
| `data_audit/` | Auditoria de sobreposição corpus × teste e checagens da instrumentação |
| `build_store.py` | Constrói o ChromaDB sem precisar do Ollama |
| `peek.py` | Métricas parciais de uma run em andamento |

## Dados

Configurados em `config.py`:

- **Teste:** `web3bugs_testset.csv` (extrator determinístico do Web3Bugs, só bugs High em escopo): 226 arquivos × 61 tipos = 13.786 pares, 304 positivos.
- **Corpus do RAG:** `all_data.parquet`, 27.714 fragmentos de código rotulados.
- **Catálogos:** `vulnerabilities_description.csv` (61 tipos) e `owasp_scwe.csv`.

## Uso

```bash
source ~/.venv/bin/activate
ollama pull qwen3.6:27b             # Ollama rodando em http://localhost:11434
python run.py                       # pipeline completo, modelo padrão
python run.py --subset 2            # teste rápido
python run.py --no-rag | --no-reviewer | --no-triage | --max-rounds 1
python run.py --resume-dir results/<modelo>/<mm-aaaa>/<run>
python data_audit/verify_instrumentation.py   # checagens sem LLM
```

`python run.py --help` lista todas as flags.

## Saídas

Cada run grava em `results/<modelo>/<mm-aaaa>/rag_<data>/`:

- `results_pairs.csv` — uma linha por par (veredictos, regra de reconciliação, rodadas, tempo);
- `results_vuln.csv`, `results_contract.csv`, `results_global.csv` — agregações;
- `experiment_summary.md` — resumo com P, R, F1, especificidade, balanced accuracy e **MCC** (métrica principal), no universo completo (61 tipos) e no restrito (tipos presentes no ground truth);
- `raw_detector/run<N>.jsonl` — saída bruta do Detector (com `--store-raw`).

## Requisitos

Python 3.12 com langgraph, langchain, langchain-ollama, langchain-chroma, langchain-huggingface, chromadb, sentence-transformers, torch, pandas, pydantic, tqdm e matplotlib. Ollama com o modelo desejado.
