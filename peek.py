"""Métricas parciais da run mais recente, sem interromper nada.

Lê o results_pairs.csv que está sendo escrito e mostra onde a run está.
Seguro rodar a qualquer momento, quantas vezes quiser.

Uso:
    python peek.py                 # run mais recente
    python peek.py <pasta_da_run>
"""
import glob, os, sys, math
import pandas as pd

d = sys.argv[1] if len(sys.argv) > 1 else max(
    glob.glob("results/*/*/*/"), key=os.path.getmtime)
p = os.path.join(d, "results_pairs.csv")
if not os.path.exists(p):
    sys.exit(f"ainda sem resultados em {d}")

df = pd.read_csv(p, low_memory=False)
tp, fp, tn, fn = (int(df[c].sum()) for c in ("tp", "fp", "tn", "fn"))
prec = tp / (tp + fp) if tp + fp else 0
rec = tp / (tp + fn) if tp + fn else 0
den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
mcc = ((tp*tn)-(fp*fn))/den if den else 0
an = df[df.reconciliation_rule != "triage_filtered"]

print(f"\n{os.path.basename(d.rstrip('/'))}")
print(f"  contratos feitos : {df.dataset_index.nunique()}")
print(f"  pares gravados   : {len(df)}   (analisados pelo LLM: {len(an)})")
if len(an):
    print(f"  s/par analisado  : {an.analysis_time.mean():.1f}")
print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
print(f"  precisao={prec:.4f}  recall={rec:.4f}  MCC={mcc:.4f}")

gt = set(df.loc[df.is_ground_truth_positive.astype(bool), "target_vulnerability"])
r = df[df.target_vulnerability.isin(gt)]
rtp, rfp = int(r.tp.sum()), int(r.fp.sum())
if rtp + rfp:
    print(f"  eixo restrito ({len(gt)} tipos): precisao={rtp/(rtp+rfp):.4f}")

if (df.is_predicted_positive.astype(bool)).sum():
    print("\n  onde estao os positivos preditos:")
    v = df[df.is_predicted_positive.astype(bool)].target_vulnerability.value_counts()
    for k, n in v.head(8).items():
        acertos = int(df[(df.target_vulnerability == k) & (df.tp == 1)].tp.sum())
        print(f"    {n:3d}x {k[:44]:<44} ({acertos} certos)")
print()
