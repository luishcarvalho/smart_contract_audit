# Smart Contract Audit Pipeline

Sistema de detecção automática de vulnerabilidades em smart contracts Solidity usando LLMs locais via Ollama com suporte opcional a RAG (Retrieval-Augmented Generation).

## Objetivo

Avaliar a capacidade de modelos de linguagem em detectar vulnerabilidades de segurança em contratos inteligentes. Para cada par (contrato, tipo de vulnerabilidade), o modelo decide se a vulnerabilidade está **PRESENT** ou **ABSENT**, e os resultados são comparados com um ground truth para calcular métricas de classificação binária (Precision, Recall, F1, Accuracy).

## Arquitetura

```
smart_contract_audit/
├── config.py              # Configuração central — único arquivo a editar para mudar hiperparâmetros
├── run.py                 # Entrypoint CLI da pipeline
├── models/
│   ├── llm.py             # Instancia o modelo Ollama
│   ├── embeddings.py      # Embeddings (MiniLM ou starcoder2)
│   └── vectorstore.py     # ChromaDB — build e load do vectorstore RAG
├── pipeline/
│   ├── prompt.py          # Templates de prompt (RAG e direto)
│   ├── nodes.py           # Nós do grafo LangGraph (retrieve, analyze, parse)
│   └── graph.py           # AuditPipeline — monta e executa o grafo
├── evaluation/
│   ├── metrics.py         # TP/FP/TN/FN, Precision, Recall, F1
│   ├── runner.py          # Loop de avaliação com salvamento incremental e resume
│   └── results.py         # Geração dos CSVs e experiment_summary.md
└── utils/
    ├── display.py         # Banners e preview do output da LLM
    └── io.py              # Checkpoints e JSON helpers
```

## Datasets

| Arquivo | Descrição |
| --- | --- |
| `~/gervais_dataset.csv` | Dataset de teste — contratos com ground truth (70 contratos, 21 tipos de vulnerabilidade) |
| `~/all_data.parquet` | Dataset de treino — usado para construir o vectorstore RAG |
| `~/vulnerabilities_description.csv` | Descrições textuais dos 61 tipos de vulnerabilidade avaliados |

## Configuração

Todos os hiperparâmetros estão em `config.py`. Editar esse arquivo afeta todas as runs subsequentes sem precisar passar flags no CLI.

| Parâmetro | Padrão | Descrição |
| --- | --- | --- |
| `model` | `gemma3:27b` | Modelo Ollama |
| `temperature` | `0.2` | Temperatura da LLM |
| `num_ctx` | `40960` | Janela de contexto (tokens) |
| `num_predict` | `1024` | Máximo de tokens de saída |
| `timeout` | `600` | Timeout da chamada Ollama (segundos) |
| `max_retries` | `3` | Tentativas em caso de crash do Ollama |
| `use_rag` | `True` | Ativar/desativar RAG |
| `top_k` | `7` | Documentos recuperados pelo RAG |
| `test_subset_size` | `0` | Nº de contratos a avaliar (0 = todos) |
| `store_raw_response` | `False` | Salvar resposta bruta da LLM no CSV |

---

## Cheatsheet de Comandos

### Ambiente

```bash
# Ativar o ambiente virtual
source ~/.venv/bin/activate

# Entrar na pasta do projeto
cd ~/smart_contract_audit
```

---

### tmux — Sessões persistentes (resistem a desconexões SSH)

```bash
# Criar nova sessão chamada "pipeline"
tmux new-session -s pipeline

# Criar sessão com nome personalizado
tmux new-session -s meu_nome

# Listar sessões ativas
tmux ls

# Verificar se existe alguma sessão ativa (retorna erro se nenhuma)
tmux ls 2>/dev/null && echo "tmux ativo" || echo "nenhuma sessao"

# Entrar (reattach) em uma sessão existente
tmux attach -t pipeline

# Entrar na sessão mais recente (qualquer uma)
tmux attach

# Sair do tmux sem matar a sessão (processo continua rodando)
# Dentro do tmux: Ctrl+B, depois D

# Matar uma sessão específica
tmux kill-session -t pipeline

# Matar TODAS as sessões
tmux kill-server

# Habilitar scroll com mouse (dentro de uma sessão tmux)
tmux set -g mouse on

# Criar nova janela dentro da sessão atual
# Dentro do tmux: Ctrl+B, depois C

# Alternar entre janelas
# Dentro do tmux: Ctrl+B, depois N (próxima) ou P (anterior)

# Ver todas as janelas da sessão atual
# Dentro do tmux: Ctrl+B, depois W
```

---

### Pipeline — Execução

```bash
# Run completa com configurações padrão do config.py
python run.py

# Run sem RAG (sobrescreve config.py)
python run.py --no-rag

# Run com RAG explícito
python run.py --rag

# Avaliar apenas os primeiros N contratos
python run.py --subset 10

# Múltiplos runs (para medir variância)
python run.py --runs 3

# Modo debug — exibe o prompt completo enviado à LLM
python run.py --debug

# Salvar resposta bruta da LLM no CSV
python run.py --store-raw
```

---

### Pipeline — Sobrescrever hiperparâmetros via CLI

```bash
# Trocar modelo
python run.py --model deepseek-r1:14b

# Mudar temperatura
python run.py --temperature 0.0

# Mudar janela de contexto
python run.py --num-ctx 32768

# Mudar máximo de tokens de saída
python run.py --num-predict 2048

# Mudar top-k do RAG
python run.py --top-k 5

# Combinação de flags
python run.py --model gemma3:27b --temperature 0.1 --no-rag --subset 20
```

---

### Pipeline — Resume (continuar de onde parou)

```bash
# Retomar run interrompida (substitua pelo nome real da pasta)
python run.py --resume-dir results/gemma3-27b/rag_08-04-26_00-21-20

# Verificar quantos pares já foram salvos numa pasta
wc -l results/gemma3-27b/rag_08-04-26_00-21-20/results_pairs.csv

# Ver quais contratos já foram avaliados
python3 -c "
import pandas as pd
df = pd.read_csv('results/gemma3-27b/rag_08-04-26_00-21-20/results_pairs.csv')
print('Contratos avaliados:', sorted(df['dataset_index'].unique()))
print('Total pares:', len(df))
"

# Listar todas as pastas de resultados
ls results/gemma3-27b/

# Ver métricas rápidas de uma run
python3 -c "
import pandas as pd
df = pd.read_csv('results/gemma3-27b/rag_08-04-26_00-21-20/results_pairs.csv')
s = df[df['success']==True]
tp,fp,tn,fn = s.tp.sum(),s.fp.sum(),s.tn.sum(),s.fn.sum()
prec = tp/(tp+fp) if tp+fp else 0
rec  = tp/(tp+fn) if tp+fn else 0
f1   = 2*prec*rec/(prec+rec) if prec+rec else 0
print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
print(f'Precision={prec:.4f} Recall={rec:.4f} F1={f1:.4f}')
"
```

---

### Pipeline — Fluxo completo recomendado (com tmux)

```bash
# 1. Criar sessão tmux
tmux new-session -s pipeline

# 2. Dentro da sessão: ativar ambiente e entrar no projeto
source ~/.venv/bin/activate
cd ~/smart_contract_audit

# 3. Executar
python run.py

# 4. Para sair sem matar (deixar rodando): Ctrl+B, depois D

# 5. Para voltar à sessão depois
tmux attach -t pipeline

# 6. Para pausar a execução: Ctrl+C (dentro do tmux)

# 7. Para retomar de onde parou
python run.py --resume-dir results/gemma3-27b/<nome-da-pasta>
```

---

### Resultados

```bash
# Ver o experiment summary (abrir no VSCode)
code results/gemma3-27b/rag_08-04-26_00-21-20/experiment_summary.md

# Arquivos gerados por run
# results_pairs.csv      — um par (contrato, vulnerabilidade) por linha
# results_contract.csv   — resumo por contrato
# results_vuln.csv       — métricas por tipo de vulnerabilidade
# results_global.csv     — métricas globais por run
# experiment_summary.md  — resumo completo em Markdown
```

---

### Vectorstore (RAG)

```bash
# O vectorstore é construído automaticamente na primeira run com --rag
# Fica salvo em: ~/langchain_smart_contract_chromadb/
# Nas runs seguintes é carregado do disco (não precisa reconstruir)

# Verificar se o vectorstore existe
ls ~/langchain_smart_contract_chromadb/

# Forçar reconstrução do vectorstore (apagar e rodar novamente)
rm -rf ~/langchain_smart_contract_chromadb/
python run.py --rag
```

---

### Ollama

```bash
# Verificar se o Ollama está rodando
curl -s http://localhost:11434/api/tags | python3 -m json.tool

# Listar modelos disponíveis
curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; [print(m['name']) for m in json.load(sys.stdin)['models']]"

# Baixar novo modelo
ollama pull deepseek-r1:14b
```
