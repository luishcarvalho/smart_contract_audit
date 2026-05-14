# Smart Contract Audit Agents — Documentação do Projeto

## Visão Geral

Este projeto implementa um **pipeline de auditoria de segurança de smart contracts baseado em LLMs**, usando uma arquitetura de **dois agentes** (Detector + Reviewer) orquestrada com [LangGraph](https://github.com/langchain-ai/langgraph). O pipeline analisa contratos Solidity em busca de vulnerabilidades conhecidas, compara os resultados com um ground truth e calcula métricas de classificação binária (TP, FP, TN, FN, Precision, Recall, F1, Accuracy).

O modelo de linguagem é executado **localmente via [Ollama](https://ollama.com/)** (padrão: `gemma3:27b`). O contexto de referência sobre vulnerabilidades vem do catálogo **OWASP Smart Contract Weakness Enumeration (SCWE)**.

---

## Estrutura de Arquivos

```
smart_contract_audit_agents/
├── run.py                        # Entrypoint CLI (executa o pipeline)
├── config.py                     # Configurações centrais (LLM, RAG, avaliação, dados)
├── __init__.py
│
├── pipeline/
│   ├── graph.py                  # Montagem do grafo LangGraph (AuditPipeline)
│   ├── nodes.py                  # Funções de nó: Detector, Reviewer, Reconciler, etc.
│   └── prompt.py                 # Templates de prompt (Detector RAG, Detector Direct, Reviewer)
│
├── models/
│   ├── schemas.py                # Tipos: RAGState (TypedDict), VulnerabilityAnalysis, ReviewerOutput
│   ├── llm.py                    # Factory do OllamaLLM
│   ├── embeddings.py             # Factory de embeddings (HuggingFace ou Ollama)
│   └── vectorstore.py            # Criação/carregamento do ChromaDB
│
├── evaluation/
│   ├── runner.py                 # Loop de avaliação: itera (contrato × vulnerabilidade)
│   ├── metrics.py                # TP/FP/TN/FN, Precision, Recall, F1, Accuracy
│   └── results.py                # Geração de CSVs e Markdown de resumo
│
└── utils/
    ├── owasp_lookup.py           # OWASPLookup: busca entradas SCWE por nome de vulnerabilidade
    ├── vuln_desc_lookup.py       # VulnDescLookup: descrições canônicas do CSV de vulnerabilidades
    ├── display.py                # Helpers de terminal (banner, hr, preview de resposta LLM)
    └── io.py                     # JSON seguro, checkpoints de embedding (pickle)
```

---

## Fontes de Dados

### 1. Dataset de Teste — `gervais_dataset.csv`
**Caminho:** `/home/luis.carvalho/gervais_dataset.csv`

Contém contratos Solidity rotulados com a vulnerabilidade presente. Colunas usadas:
- `code` — código-fonte do contrato
- `vulnerability` — label da vulnerabilidade (ground truth)
- `line` — linha da vulnerabilidade (opcional, padrão 0)

O pipeline avalia **cada contrato contra cada tipo de vulnerabilidade** da lista de descrições. Isso gera pares `(contrato, vulnerabilidade_alvo)`, com resultado TP, FP, TN ou FN comparando o ground truth com a predição do pipeline.

### 2. Descrições de Vulnerabilidades — `vulnerabilities_description.csv`
**Caminho:** `/home/luis.carvalho/vulnerabilities_description.csv`

CSV com duas colunas: `vulnerability` e `description`. Define o conjunto de vulnerabilidades que o pipeline testa em cada contrato (~60 tipos). É usado de duas formas:
- No **loop de avaliação**: itera sobre cada linha para definir o alvo de cada execução.
- No **Reviewer**: fornece a descrição canônica da vulnerabilidade para o agente revisor (via `VulnDescLookup`).

### 3. Catálogo OWASP SCWE — `owasp_scwe.csv`
**Caminho:** `/home/luis.carvalho/owasp_scwe.csv`

156 entradas do catálogo [OWASP Smart Contract Weakness Enumeration](https://owasp.org/www-project-smart-contract-security/). Colunas:
- `id` — identificador (ex: `SCWE-046`)
- `name` — nome da fraqueza (ex: `Reentrancy Attacks`)
- `category` — categoria OWASP (ex: `SCSVS-CODE`)
- `description` — descrição da vulnerabilidade
- `remediation` — como corrigir
- `example_vulnerable` — código Solidity vulnerável
- `example_fixed` — código Solidity corrigido

Usado pela classe `OWASPLookup` para injetar contexto de referência nos prompts do Detector e do Reviewer. A busca faz matching por nome normalizado com fallback de alias e substring.

### 4. Dataset de Treino (RAG) — `all_data.parquet`
**Caminho:** `/home/luis.carvalho/all_data.parquet`

Usado apenas na **construção do vectorstore**. Contém contratos rotulados para gerar os embeddings. Colunas esperadas: `code`, `vulnerability`, `line`, `source`.

### 5. Vectorstore ChromaDB (pré-construído)
**Caminho:** `/home/luis.carvalho/smart_contract_audit/langchain_smart_contract_chromadb`

Base vetorial persistida com os embeddings dos contratos de treino. Carregada automaticamente se existir; caso contrário, construída a partir do `all_data.parquet`. Usada pelo nó de recuperação (RAG) para buscar exemplos similares ao contrato em análise.

---

## Configuração — `config.py`

Todas as configurações vivem em dataclasses agrupadas na classe `Config`:

```python
Config(
    llm       = LLMConfig(...)         # modelo, temperatura, contexto, timeout
    embedding = EmbeddingConfig(...)   # tipo de embedding, caminho do vectorstore
    retrieval = RetrievalConfig(...)   # RAG on/off, top-k, modo híbrido
    agent     = AgentConfig(...)       # dual-agent ou single-agent
    eval      = EvalConfig(...)        # runs, resume, threshold, output dir
    data      = DataConfig(...)        # caminhos dos CSVs e parquet
)
```

### Parâmetros principais

| Grupo | Parâmetro | Padrão | Descrição |
|---|---|---|---|
| LLM | `model` | `gemma3:27b` | Modelo Ollama |
| LLM | `temperature` | `0.2` | Temperatura da geração |
| LLM | `num_ctx` | `40960` | Janela de contexto em tokens |
| LLM | `num_predict` | `1024` | Máximo de tokens gerados |
| LLM | `max_code_chars` | `150000` | Truncamento do contrato |
| LLM | `max_retries` | `3` | Tentativas em caso de crash |
| Embedding | `use_fast` | `True` | `True`=MiniLM (CPU); `False`=starcoder2:3b (Ollama) |
| Retrieval | `use_rag` | `True` | Habilita/desabilita RAG |
| Retrieval | `top_k` | `7` | Documentos recuperados por query |
| Retrieval | `use_hybrid` | `True` | Filtro por categoria + fallback semântico |
| Agent | `use_reviewer` | `True` | Dual-agent (True) ou single-agent (False) |
| Eval | `confidence_threshold` | `0.7` | Confiança mínima para classificar como PRESENT |
| Data | `owasp_registry_path` | `.../owasp_scwe.csv` | Catálogo OWASP SCWE |

---

## Arquitetura do Pipeline

### Topologias do Grafo LangGraph

O grafo é montado em `pipeline/graph.py` e varia conforme as flags:

```
RAG + Dual-Agent (padrão):
  retrieve → generate_context → detector → reviewer → reconcile → parse_output → END

RAG + Single-Agent (--no-reviewer):
  retrieve → generate_context → detector → reconcile → parse_output → END

Sem RAG + Dual-Agent (--no-rag):
  detector → reviewer → reconcile → parse_output → END

Sem RAG + Single-Agent:
  detector → reconcile → parse_output → END
```

### Estado do Grafo — `RAGState`

TypedDict que flui por todos os nós:

```python
RAGState:
  query                   # código-fonte do contrato (truncado)
  vulnerability_name      # nome da vulnerabilidade alvo
  vulnerability_description  # descrição do CSV de vulnerabilidades
  owasp_context           # bloco formatado do catálogo OWASP SCWE (ou "")
  vuln_canonical_description  # descrição canônica para o Reviewer
  documents               # docs recuperados pelo RAG
  context                 # docs formatados como texto
  # Saídas do Detector
  detector_verdict        # "PRESENT" | "ABSENT"
  detector_confidence     # 0.0 – 1.0
  detector_reasoning      # raciocínio em cadeia
  detector_issues         # lista de issues encontradas
  # Saídas do Reviewer
  reviewer_verdict        # "CONFIRMED" | "REFUTED" | "UNCERTAIN"
  reviewer_confidence     # 0.0 – 1.0
  reviewer_reasoning      # explicação do revisor
  # Saídas do Reconciler
  final_verdict           # "PRESENT" | "ABSENT"
  final_confidence        # confiança reconciliada
  reconciliation_rule     # regra aplicada (rule_1 a rule_6, ou rule_0)
```

---

## Nós do Pipeline — `pipeline/nodes.py`

### `retrieve_node` (RAG)
Consulta o ChromaDB com o nome da vulnerabilidade e o código do contrato. Usa estratégia **híbrida** por padrão:
1. Busca filtrada por `vulnerability == vulnerability_name` no metadata.
2. Se não há exemplos suficientes, completa com busca semântica pura.

### `generate_context_node` (RAG)
Formata os documentos recuperados em texto (`Example 1 (vuln): <code[:500]>...`) e salva em `state["context"]`.

### `detector_node`
O agente Detector. Recebe:
- Código do contrato (truncado)
- Nome e descrição da vulnerabilidade
- Contexto RAG (se ativo)
- Bloco OWASP SCWE (se houver match)

Instrui o LLM a seguir 4 passos:
1. Busca ativa do padrão mínimo da vulnerabilidade
2. Evidência elemento a elemento com citação de linhas
3. Verificação de mitigações (reentrancy guard, SafeMath, require, etc.)
4. Veredicto final: `PRESENT` ou `ABSENT`

Saída JSON parseada para `detector_verdict`, `detector_confidence`, `detector_reasoning`, `detector_issues`.

### `reviewer_node`
O agente Reviewer. Atua como **advogado do diabo** — desafia o Detector. Recebe:
- Veredicto e raciocínio do Detector
- Descrição canônica da vulnerabilidade
- Bloco OWASP SCWE
- Código do contrato

Segue 4 passos de revisão:
1. Confirma se o padrão mínimo está de facto presente
2. Verifica mitigações ignoradas pelo Detector
3. Avalia qualidade das evidências (diretas vs. circunstanciais)
4. Emite: `CONFIRMED`, `REFUTED` ou `UNCERTAIN`

### `reconcile_node` (determinístico, sem LLM)
Aplica **6 regras de prioridade** para combinar Detector + Reviewer:

| Regra | Detector | Reviewer | Final | Confiança |
|---|---|---|---|---|
| rule_1 | PRESENT | CONFIRMED | PRESENT | média(D, R) |
| rule_2 | ABSENT | CONFIRMED | ABSENT | média(D, R) |
| rule_3 | PRESENT | REFUTED | ABSENT | R × 0.8 |
| rule_4 | ABSENT | REFUTED | PRESENT | R × 0.7 |
| rule_5 | PRESENT | UNCERTAIN | PRESENT | D × 0.6 |
| rule_6 | ABSENT | UNCERTAIN | ABSENT | D × 0.6 |
| rule_0 | — | (desativado) | = Detector | = Detector |

### `parse_output_node`
Monta o `parsed_output` final com `final_verdict`, `final_confidence` e `detector_issues`.

---

## Prompts — `pipeline/prompt.py`

Três templates com placeholders `{...}`:

### `DETECTOR_RAG_PROMPT_TEMPLATE`
Usado quando RAG está ativo. Contém:
- Descrição da vulnerabilidade alvo
- `{swc_section}` — bloco OWASP SCWE (se houver match)
- `{context}` — exemplos recuperados do vectorstore
- `{query}` — código do contrato
- Instruções de 4 passos + `{format_instructions}` (JSON schema Pydantic)

### `DETECTOR_DIRECT_PROMPT_TEMPLATE`
Idêntico ao anterior mas sem `{context}`. Usado quando RAG está desativado.

### `REVIEWER_PROMPT_TEMPLATE`
Contém:
- Veredicto e raciocínio do Detector
- Descrição canônica da vulnerabilidade
- `{swc_section}` — bloco OWASP SCWE
- `{query}` — código do contrato
- Instruções de 4 passos + `{format_instructions}`

---

## Lookup do Catálogo OWASP — `utils/owasp_lookup.py`

A classe `OWASPLookup` indexa o `owasp_scwe.csv` pelo campo `name` (normalizado) e resolve matches por três estratégias em cascata:

1. **Exact match** após normalização (minúsculas, sem pontuação)
2. **Aliases explícitos** — dicionário `_ALIASES` que mapeia nomes do dataset de teste para nomes OWASP. Exemplos:
   - `"arithmetic"` → `"integer overflows and underflows"` (SCWE-047)
   - `"bad randomness"` → `"weak randomness sources"` (SCWE-024)
   - `"reentrancy"` → `"reentrancy attacks"` (SCWE-046)
   - `"suicidal contract"` → `"unprotected selfdestruct instruction"` (SCWE-050)
   - `"unlimited compiler versions"` → `"floating pragma"` (SCWE-060)
   - `"front running"` → `"insufficient protection against frontrunning"` (SCWE-037)
3. **Substring containment** — fallback para variações menores de nome

O bloco formatado incluído nos prompts mostra: ID SCWE, remediação, código vulnerável e código corrigido (até 600 chars cada).

---

## Loop de Avaliação — `evaluation/runner.py`

O `run_evaluation()` itera:
```
para cada run em [1..n_runs]:
  para cada contrato em selected_examples:
    para cada vulnerabilidade em vuln_desc_df:
      resultado = pipeline.analyze(código, vuln_name, vuln_desc)
      classifica como TP/FP/TN/FN
      salva incrementalmente em results_pairs.csv
```

### Funcionalidades
- **Salvamento incremental**: cada par é escrito no CSV imediatamente, sem perder progresso em caso de desconexão SSH.
- **Resume automático**: ao reiniciar, compara pares já salvos e pula os concluídos.
- **Skip de contrato**: `--skip-contract N` pula um índice específico.
- **Multi-run**: `--runs N` repete a avaliação N vezes para medir variância.

---

## Métricas — `evaluation/metrics.py`

Para cada par `(contrato, vulnerabilidade_alvo)`:

```
ground_truth_positive = (ground_truth_vuln == target_vuln)
predicted_positive    = (final_verdict == "PRESENT") AND (final_confidence >= threshold)

TP: GT=positivo, Pred=positivo
FP: GT=negativo, Pred=positivo
TN: GT=negativo, Pred=negativo
FN: GT=positivo, Pred=negativo
```

Métricas calculadas: Precision, Recall, F1, Accuracy.

---

## Saídas — `evaluation/results.py`

Ao fim da avaliação, são gerados 5 arquivos em `results/<model>/<MM-YYYY>/<tag>_<timestamp>/`:

| Arquivo | Conteúdo |
|---|---|
| `results_pairs.csv` | Um row por par (run, contrato, vulnerabilidade) com TP/FP/TN/FN, veredictos, confiança, raciocínio |
| `results_contract.csv` | Sumário por contrato: soma de TP/FP/TN/FN, tempo |
| `results_vuln.csv` | Métricas agregadas por tipo de vulnerabilidade |
| `results_global.csv` | Métricas globais por run (Precision, Recall, F1, Accuracy) |
| `experiment_summary.md` | Relatório Markdown com configuração, matriz de confusão e top vulnerabilidades por F1 |

Colunas específicas do dual-agent em `results_pairs.csv`:
- `detector_verdict`, `detector_confidence`, `detector_reasoning`
- `reviewer_verdict`, `reviewer_confidence`, `reviewer_reasoning`
- `reconciliation_rule`

---

## Como Executar

### Execução padrão (RAG + dual-agent + gemma3:27b)
```bash
python run.py
```

### Principais flags CLI
```bash
# Desabilitar RAG (LLM direto)
python run.py --no-rag

# Single-agent (só Detector, sem Reviewer)
python run.py --no-reviewer

# Mudar modelo e temperatura
python run.py --model deepseek-r1:14b --temperature 0.0

# Testar em subconjunto de N contratos
python run.py --subset 10

# Modo debug: imprime prompts completos
python run.py --subset 1 --debug

# Múltiplas runs para medir variância
python run.py --runs 3

# Retomar execução interrompida
python run.py --resume-dir results/gemma3-27b/05-2026/rag_10-05-26_12-00-00
```

---

## Dependências Principais

| Biblioteca | Uso |
|---|---|
| `langchain-ollama` | Interface com o servidor Ollama (LLM + embeddings) |
| `langchain-chroma` | Vectorstore ChromaDB |
| `langchain-community` | HuggingFace embeddings (MiniLM) |
| `langchain-core` | Documentos, mensagens, parsers Pydantic |
| `langgraph` | Orquestração do grafo de agentes |
| `pydantic` | Schemas de saída do LLM (parsing JSON) |
| `pandas` | Leitura de CSVs e Parquet |
| `tqdm` | Progresso do embedding em batches |
| `ollama` | Servidor local de LLMs (externo ao Python) |

---

## Fluxo Completo de Execução

```
run.py
│
├─ Carrega test_df (gervais_dataset.csv)
├─ Carrega vuln_desc_df (vulnerabilities_description.csv)
├─ Constrói OWASPLookup (owasp_scwe.csv) ──────────────────────► 156 entradas SCWE
├─ Constrói VulnDescLookup (vulnerabilities_description.csv)
├─ Inicializa OllamaLLM (gemma3:27b via localhost:11434)
├─ [RAG] Carrega ChromaDB ou constrói de all_data.parquet
│
└─ AuditPipeline.analyze(código, vuln_name, vuln_desc)
    │
    ├─ OWASPLookup.lookup_formatted(vuln_name)  ──► injecta bloco OWASP no estado
    ├─ VulnDescLookup.lookup(vuln_name)         ──► descrição canônica para Reviewer
    │
    └─ LangGraph workflow:
        │
        ├─ [RAG] retrieve_node
        │   └─ ChromaDB.similarity_search (híbrido: filtro por categoria + semântico)
        │
        ├─ [RAG] generate_context_node
        │   └─ formata docs recuperados em texto
        │
        ├─ detector_node
        │   ├─ monta prompt (código + descrição + OWASP SCWE + contexto RAG)
        │   ├─ OllamaLLM.invoke(prompt)  [até 3 retentativas]
        │   └─ parseia JSON → detector_verdict, detector_confidence, detector_issues
        │
        ├─ [Dual-Agent] reviewer_node
        │   ├─ monta prompt (veredicto Detector + descrição canônica + OWASP SCWE + código)
        │   ├─ OllamaLLM.invoke(prompt)  [até 3 retentativas]
        │   └─ parseia JSON → reviewer_verdict, reviewer_confidence
        │
        ├─ reconcile_node (determinístico)
        │   └─ aplica rule_1..rule_6 → final_verdict, final_confidence
        │
        └─ parse_output_node
            └─ monta parsed_output final

evaluation/runner.py
│
└─ classify_pair(ground_truth, target_vuln, predicted_vulns)
    └─ TP | FP | TN | FN
    └─ salva incrementalmente em results_pairs.csv

evaluation/results.py
└─ agrega métricas → results_vuln.csv, results_global.csv, experiment_summary.md
```
