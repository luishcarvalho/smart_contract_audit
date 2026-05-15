# Smart Contract Audit Agents — Documentação do Projeto

## Visão Geral

Este projeto implementa um **pipeline de auditoria de segurança de smart contracts baseado em LLMs**, usando uma arquitetura de **debate iterativo entre dois agentes** (Detector + Reviewer) orquestrada com [LangGraph](https://github.com/langchain-ai/langgraph). O pipeline analisa contratos Solidity em busca de vulnerabilidades conhecidas, compara os resultados com um ground truth e calcula métricas de classificação binária (TP, FP, TN, FN, Precision, Recall, F1, Accuracy).

O Detector identifica vulnerabilidades ativamente; o Reviewer as desafia como advogado do diabo. Quando o Reviewer não confirma o veredicto do Detector (`REFUTED` ou `UNCERTAIN`), um **nó de feedback determinístico** sintetiza a objeção e a devolve ao Detector para reavaliação na próxima rodada. Esse ciclo se repete até que os agentes cheguem a consenso ou o limite de rodadas (`max_rounds`) seja atingido. Em caso de **impasse**, o Reconciler atua como árbitro usando **arbitragem ponderada por confiança calibrada**, inspirada no ReConcile (Chen et al., ACL 2024).

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
│   ├── nodes.py                  # Funções de nó: Detector, Reviewer, Feedback, Reconciler, etc.
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
    agent     = AgentConfig(...)       # dual-agent ou single-agent, max_rounds
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
| Agent | `max_rounds` | `3` | Máximo de rodadas de debate antes da arbitragem |
| Eval | `confidence_threshold` | `0.7` | Confiança mínima para classificar como PRESENT |
| Data | `owasp_registry_path` | `.../owasp_scwe.csv` | Catálogo OWASP SCWE |

---

## Arquitetura do Pipeline

### Topologias do Grafo LangGraph

O grafo é montado em `pipeline/graph.py` e varia conforme as flags. Quando o Reviewer está ativo, o grafo forma um **loop de debate**; quando desativado, permanece linear.

```
RAG + Dual-Agent (padrão):
  retrieve → generate_context → detector → reviewer
                                               │
                              ┌────────────────┴────────────────┐
                        consensus_reached=True             consensus_reached=False
                        ou current_round >= max_rounds     e current_round < max_rounds
                              │                                  │
                          reconcile                        feedback_node
                              │                                  │
                         parse_output              detector (rodada seguinte)
                              │                                  │
                             END                       reviewer (rodada seguinte)
                                                                 │
                                                          [loop continua]

RAG + Single-Agent (--no-reviewer):
  retrieve → generate_context → detector → reconcile → parse_output → END

Sem RAG + Dual-Agent (--no-rag):
  detector → reviewer → [loop ou reconcile] → parse_output → END

Sem RAG + Single-Agent:
  detector → reconcile → parse_output → END
```

O loop é fechado pela edge `feedback → detector`. O roteamento condicional após `reviewer` é feito pela função `should_continue_debate` (ver seção de nós abaixo).

### Estado do Grafo — `RAGState`

TypedDict que flui por todos os nós. Os valores iniciais são definidos em `AuditPipeline.analyze()` antes de invocar o grafo.

```python
RAGState:
  # Entrada
  query                        # código-fonte do contrato (truncado se > max_code_chars)
  vulnerability_name           # nome da vulnerabilidade alvo
  vulnerability_description    # descrição do CSV de vulnerabilidades
  owasp_context                # bloco formatado do catálogo OWASP SCWE (ou "")
  vuln_canonical_description   # descrição canônica para o Reviewer

  # RAG
  documents                    # docs recuperados pelo ChromaDB
  context                      # docs formatados como texto
  retrieval_mode               # "semantic_only" | "category_only" | "hybrid"

  # Saídas do Detector (última rodada)
  detector_verdict             # "PRESENT" | "ABSENT"
  detector_confidence          # 0.0 – 1.0
  detector_reasoning           # sumário do raciocínio em cadeia
  detector_issues              # lista de issues encontradas

  # Saídas do Reviewer (última rodada)
  reviewer_verdict             # "CONFIRMED" | "REFUTED" | "UNCERTAIN"
  reviewer_confidence          # 0.0 – 1.0
  reviewer_reasoning           # explicação do revisor

  # Controle do ciclo de debate
  current_round                # rodada atual — inicia em 1, incrementado pelo feedback_node
  max_rounds                   # limite de rodadas — copiado de cfg.agent.max_rounds no início
  consensus_reached            # True quando reviewer_verdict == "CONFIRMED" em qualquer rodada
  debate_history               # lista de dicts com o histórico de todas as rodadas:
                               #   [{ "round": int,
                               #      "detector_verdict": str, "detector_confidence": float,
                               #      "reviewer_verdict": str, "reviewer_confidence": float }, ...]
  reviewer_feedback            # objeção estruturada do Reviewer para o Detector reler na próxima rodada

  # Saídas do Reconciler
  final_verdict                # "PRESENT" | "ABSENT"
  final_confidence             # confiança reconciliada (arredondada a 4 casas)
  reconciliation_rule          # "consensus_round_N" | "weighted_arbitration_round_N" | "rule_0_detector_only"
  reconciliation_weight_ratio  # ratio do peso dominante na arbitragem ponderada (0.0 quando consenso)
```

**Quem escreve o quê:**

| Campo | Inicializado por | Escrito por | Lido por |
|---|---|---|---|
| `current_round` | `analyze()` = 1 | `feedback_node` (+1) | `detector_node`, `reconcile_node`, `should_continue_debate` |
| `max_rounds` | `analyze()` = `cfg.agent.max_rounds` | — | `should_continue_debate`, `reconcile_node` |
| `consensus_reached` | `analyze()` = False | `reviewer_node` | `should_continue_debate`, `reconcile_node` |
| `debate_history` | `analyze()` = [] | `detector_node` (append), `reviewer_node` (update último) | `feedback_node`, `analyze()` (para delta) |
| `reviewer_feedback` | `analyze()` = "" | `feedback_node` | `detector_node` |

---

## Nós do Pipeline — `pipeline/nodes.py`

### `retrieve_node` (RAG)
Consulta o ChromaDB com o nome da vulnerabilidade e o código do contrato. Usa estratégia **híbrida** por padrão:
1. Busca filtrada por `vulnerability == vulnerability_name` no metadata.
2. Se não há exemplos suficientes, completa com busca semântica pura.

### `generate_context_node` (RAG)
Formata os documentos recuperados em texto (`Example 1 (vuln): <code[:500]>...`) e salva em `state["context"]`.

### `detector_node`

O agente Detector. Executa **uma chamada LLM por rodada** e pode ser invocado múltiplas vezes no mesmo pipeline quando o loop de debate está ativo.

**Rodada 1** — comportamento idêntico ao design original:
- Recebe código do contrato (truncado), nome e descrição da vulnerabilidade, contexto RAG (se ativo), bloco OWASP SCWE.
- `reviewer_feedback` está vazio; o placeholder `{reviewer_feedback}` no template renderiza como string vazia — nenhuma linha extra é inserida no prompt.

**Rodadas subsequentes (N > 1)**:
- Lê `state["reviewer_feedback"]`, que contém a objeção estruturada gerada pelo `feedback_node`.
- O bloco é inserido no prompt como `\n---\n<feedback>\n---\n\n`, imediatamente antes da seção `Smart Contract Code`. O Detector recebe a objeção do Reviewer junto com o código original e é instruído a reconsiderar.

**Após o LLM responder**, independente da rodada:
- Parseia o JSON de saída para `detector_verdict` (`PRESENT` se `issues` não estiver vazio, `ABSENT` caso contrário), `detector_confidence`, `detector_reasoning`, `detector_issues`.
- **Acumula** o `debate_history` com um novo entry `{round, detector_verdict, detector_confidence, reviewer_verdict: "", reviewer_confidence: 0.0}`. Os campos do Reviewer são preenchidos mais tarde pelo `reviewer_node`.

### `reviewer_node`

O agente Reviewer. Atua como **advogado do diabo** — desafia o Detector. Não usa RAG; usa apenas descrição canônica e OWASP SCWE como referência. Recebe:
- Veredicto e raciocínio do Detector (da última rodada)
- Descrição canônica da vulnerabilidade
- Bloco OWASP SCWE
- Código do contrato

Segue 4 passos de revisão:
1. Confirma se o padrão mínimo está de facto presente
2. Verifica mitigações ignoradas pelo Detector
3. Avalia qualidade das evidências (diretas vs. circunstanciais)
4. Emite: `CONFIRMED`, `REFUTED` ou `UNCERTAIN`

**Após o LLM responder:**
- Atualiza o **último entry** do `debate_history` com `reviewer_verdict` e `reviewer_confidence`.
- Escreve `consensus_reached = (reviewer_verdict == "CONFIRMED")`.

**Lógica de consenso:** `CONFIRMED` significa que o Reviewer concorda com o Detector — independentemente de o veredicto do Detector ser `PRESENT` ou `ABSENT`. Ou seja: `CONFIRMED` + Detector `PRESENT` = "vulnerabilidade presente confirmada"; `CONFIRMED` + Detector `ABSENT` = "ausência confirmada". Em ambos os casos, `consensus_reached = True` e o loop termina.

### `feedback_node` *(novo — determinístico, sem LLM)*

Executado quando o Reviewer discordou (`REFUTED` ou `UNCERTAIN`) **e** ainda há rodadas disponíveis (`current_round < max_rounds`). É o nó que **fecha o loop** devolvendo o controle ao Detector.

**Lê do estado:**
- `current_round`, `reviewer_verdict`, `reviewer_confidence`, `reviewer_reasoning`, `debate_history`

**Escreve no estado (retorna dict parcial):**
- `reviewer_feedback` — texto estruturado com a objeção, no formato:
  ```
  [Debate Round N — Reviewer did not confirm]
  Reviewer verdict: REFUTED (confidence: 0.65)
  Reviewer reasoning: <texto do Reviewer>

  Please reconsider your analysis taking into account the reviewer's objection above.
  Focus especially on any points where your evidence may be insufficient or misidentified.
  ```
- `current_round` — incrementado em 1 (`current_round + 1`)
- `debate_history` — repassado sem modificação (já atualizado pelo `reviewer_node`)

### `should_continue_debate` *(nova função de roteamento)*

Função de edge condicional registrada após o `reviewer_node` no grafo LangGraph. Decide o próximo nó com base em dois critérios:

```python
def should_continue_debate(state) -> str:
    if state["consensus_reached"]:          # Reviewer confirmou → encerra o loop
        return "reconcile"
    if state["current_round"] >= state["max_rounds"]:  # limite atingido → impasse
        return "reconcile"
    return "feedback"                        # continua o debate
```

| Condição | Próximo nó | Significado |
|---|---|---|
| `consensus_reached == True` | `reconcile` | Agentes concordaram — Reconciler passa o resultado |
| `current_round >= max_rounds` | `reconcile` | Impasse — Reconciler arbitra |
| Nenhuma das anteriores | `feedback` | Continua: `feedback → detector → reviewer` |

### `reconcile_node` *(atualizado)*

Nó determinístico sem LLM. Possui três caminhos distintos:

**Caminho 0 — Reviewer desativado (`--no-reviewer`):**
- Passa o resultado do Detector diretamente.
- `reconciliation_rule = "rule_0_detector_only"`

**Caminho 1 — Consenso atingido (`consensus_reached == True`):**

O Detector tem razão (confirmado pelo Reviewer). A confiança final é penalizada por rodadas extras, pois consenso tardio indica menor certeza:

```
rounds_penalty   = (current_round - 1) × 0.05
final_confidence = max(detector_confidence - rounds_penalty, 0.1)
final_verdict    = detector_verdict
```

Exemplos: consenso na rodada 1 → sem penalidade; rodada 2 → -0.05; rodada 3 → -0.10.

`reconciliation_rule = "consensus_round_N"` (ex: `consensus_round_1`, `consensus_round_3`)

**Caminho 2 — Impasse após `max_rounds` (`consensus_reached == False`):**

Arbitragem ponderada por confiança calibrada, inspirada no **ReConcile** (Chen et al., ACL 2024 — [arxiv.org/abs/2309.13007](https://arxiv.org/abs/2309.13007)). A temperatura `T = 0.7 < 1` suaviza o overconfidence dos LLMs comprimindo a distribuição de pesos:

```
TEMPERATURE = 0.7

# Pesos na direção do veredicto de cada agente:
if detector_verdict == "PRESENT":
    w_present = detector_confidence ^ (1 / T)   # Detector apoia PRESENT
    w_absent  = reviewer_confidence ^ (1 / T)   # Reviewer (ao refutar) apoia ABSENT
else:  # detector disse ABSENT
    w_absent  = detector_confidence ^ (1 / T)
    w_present = reviewer_confidence ^ (1 / T)

total       = w_present + w_absent
ratio       = w_present / total

final_verdict    = "PRESENT" if ratio > 0.5 else "ABSENT"
final_confidence = max(w_present, w_absent) / total   # confiança do lado vencedor
```

Caso especial: se `total == 0` (ambas as confidências são 0.0), `final_verdict = "ABSENT"` e `final_confidence = 0.0`.

`reconciliation_rule = "weighted_arbitration_round_N"` (ex: `weighted_arbitration_round_3`)

`reconciliation_weight_ratio` guarda o `final_confidence` arredondado (ratio do peso dominante), disponível como coluna de diagnóstico no CSV.

### `parse_output_node`
Monta o `parsed_output` final com `final_verdict`, `final_confidence` e `detector_issues`.

---

## Prompts — `pipeline/prompt.py`

Três templates com placeholders `{...}`:

### `DETECTOR_RAG_PROMPT_TEMPLATE`
Usado quando RAG está ativo. Contém (na ordem):
- Descrição da vulnerabilidade alvo
- `{swc_section}` — bloco OWASP SCWE (se houver match)
- Exemplos recuperados: `{context}`
- **`{reviewer_feedback}`** — objeção estruturada do Reviewer (ver abaixo)
- `{query}` — código do contrato
- Instruções de 4 passos + `{format_instructions}` (JSON schema Pydantic)

### `DETECTOR_DIRECT_PROMPT_TEMPLATE`
Idêntico ao anterior mas sem `{context}`. Usado quando RAG está desativado. Também inclui `{reviewer_feedback}` na mesma posição.

### Placeholder `{reviewer_feedback}`

O placeholder é inserido entre os exemplos RAG (ou bloco OWASP, no template direto) e a seção `Smart Contract Code`.

- **Rodada 1** (`reviewer_feedback == ""`): o placeholder expande para string vazia — o prompt não contém linhas extras nem separadores `---`. O Detector não vê nenhum feedback.
- **Rodadas > 1**: o `detector_node` envolve o feedback em `\n---\n<texto>\n---\n\n` antes de formatar o template. O prompt passa a conter a objeção do Reviewer com separadores visuais entre os exemplos e o código do contrato.

O conteúdo do bloco de feedback tem o formato:
```
---
[Debate Round N — Reviewer did not confirm]
Reviewer verdict: REFUTED (confidence: 0.65)
Reviewer reasoning: <raciocínio do Reviewer>

Please reconsider your analysis taking into account the reviewer's objection above.
Focus especially on any points where your evidence may be insufficient or misidentified.
---
```

### `REVIEWER_PROMPT_TEMPLATE`
Contém:
- Veredicto e raciocínio do Detector
- Descrição canônica da vulnerabilidade
- `{swc_section}` — bloco OWASP SCWE
- `{query}` — código do contrato
- Instruções de 4 passos + `{format_instructions}`

O Reviewer **não recebe** o `reviewer_feedback` — ele vê apenas o veredicto mais recente do Detector, não o histórico do debate.

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
| `results_vuln.csv` | Métricas agregadas por tipo de vulnerabilidade (inclui métricas de debate) |
| `results_global.csv` | Métricas globais por run (Precision, Recall, F1, Accuracy) |
| `experiment_summary.md` | Relatório Markdown com configuração, matriz de confusão e top vulnerabilidades por F1 |

### Colunas em `results_pairs.csv` — dual-agent

Colunas do agente individual (existentes):
- `detector_verdict`, `detector_confidence`, `detector_reasoning`
- `reviewer_verdict`, `reviewer_confidence`, `reviewer_reasoning`
- `reconciliation_rule` — nome da regra aplicada (`consensus_round_N`, `weighted_arbitration_round_N` ou `rule_0_detector_only`)

Colunas do ciclo de debate (novas):

| Coluna | Origem | Descrição |
|---|---|---|
| `rounds_to_consensus` | `current_round` se consenso, senão `max_rounds` | Rodadas até acordo — ou o limite se houve impasse |
| `consensus_reached` | `state["consensus_reached"]` | `True` se os agentes concordaram antes do limite |
| `reconciliation_weight_ratio` | `reconcile_node` | Ratio do peso dominante na arbitragem ponderada; `0.0` quando houve consenso |
| `detector_confidence_delta` | `debate_history[-1].confidence - debate_history[0].confidence` | Variação de confiança do Detector entre a primeira e a última rodada; `0.0` se só houve uma rodada |

### Novas agregações em `results_vuln.csv`

Além das métricas de classificação (TP/FP/TN/FN), o CSV por vulnerabilidade inclui:

| Coluna | Descrição |
|---|---|
| `avg_rounds_to_consensus` | Média de rodadas até acordo para cada tipo de vulnerabilidade |
| `consensus_rate` | Fração de pares que chegaram a consenso antes do limite |

**Valor analítico:** vulnerabilidades com `avg_rounds_to_consensus` alta e `consensus_rate` baixa são as mais **controversas** entre os agentes — indicam casos em que o padrão é genuinamente ambíguo no código, o Detector e o Reviewer interpretam evidências de forma divergente, ou a definição canônica é insuficientemente precisa. Esse padrão é um resultado de pesquisa por si só, independente das métricas de classificação final.

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

# Definir número máximo de rodadas de debate (padrão: 3)
python run.py --max-rounds 5

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
| `langgraph` | Orquestração do grafo de agentes (inclui suporte a loops cíclicos) |
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
    ├─ Inicializa estado: current_round=1, max_rounds=N,
    │                     consensus_reached=False, debate_history=[], reviewer_feedback=""
    │
    └─ LangGraph workflow:
        │
        ├─ [RAG] retrieve_node
        │   └─ ChromaDB.similarity_search (híbrido: filtro por categoria + semântico)
        │
        ├─ [RAG] generate_context_node
        │   └─ formata docs recuperados em texto
        │
        ├─ detector_node  ◄──────────────────────────────────────────────────┐
        │   ├─ se reviewer_feedback != "": injeta objeção no prompt          │
        │   ├─ monta prompt (código + descrição + OWASP SCWE + ctx RAG       │
        │   │                + bloco reviewer_feedback se rodada > 1)        │
        │   ├─ OllamaLLM.invoke(prompt)  [até 3 tentativas]                  │
        │   ├─ parseia JSON → detector_verdict, detector_confidence, issues  │
        │   └─ acumula debate_history (append entry da rodada atual)         │
        │                                                                     │
        ├─ [Dual-Agent] reviewer_node                                        │
        │   ├─ monta prompt (veredicto Detector + descrição canônica         │
        │   │                + OWASP SCWE + código)                          │
        │   ├─ OllamaLLM.invoke(prompt)  [até 3 tentativas]                  │
        │   ├─ parseia JSON → reviewer_verdict, reviewer_confidence          │
        │   ├─ atualiza último entry do debate_history com dados do Reviewer │
        │   └─ escreve consensus_reached = (reviewer_verdict == "CONFIRMED") │
        │                                                                     │
        ├─ should_continue_debate  ── edge condicional                       │
        │   ├─ consensus_reached == True ──────────────────────► reconcile   │
        │   ├─ current_round >= max_rounds ────────────────────► reconcile   │
        │   └─ caso contrário ─────────────────────────────────► feedback ───┤
        │                                                                     │
        │   [se feedback]:                                                    │
        │   └─ feedback_node (determinístico, sem LLM)                       │
        │       ├─ sintetiza objeção → reviewer_feedback                     │
        │       ├─ incrementa current_round                                  │
        │       └─ retorna ao detector_node ──────────────────────────────►──┘
        │
        ├─ reconcile_node (determinístico, sem LLM)
        │   ├─ [single-agent] rule_0_detector_only → passa Detector direto
        │   ├─ [consenso] final = detector_verdict
        │   │             confiança = max(d_conf - (round-1)×0.05, 0.1)
        │   │             rule = "consensus_round_N"
        │   └─ [impasse]  arbitragem ponderada: w = conf^(1/0.7)
        │                 final = PRESENT se w_present/total > 0.5
        │                 rule = "weighted_arbitration_round_N"
        │
        └─ parse_output_node
            └─ monta parsed_output final

evaluation/runner.py
│
└─ classify_pair(ground_truth, target_vuln, predicted_vulns)
    └─ TP | FP | TN | FN
    └─ salva incrementalmente em results_pairs.csv
       (inclui rounds_to_consensus, consensus_reached,
        reconciliation_weight_ratio, detector_confidence_delta)

evaluation/results.py
└─ agrega métricas → results_vuln.csv (+ avg_rounds_to_consensus, consensus_rate)
                   → results_global.csv, experiment_summary.md
```
