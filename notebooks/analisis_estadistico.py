import pandas as pd
from statsmodels.stats.proportion import proportion_confint
from statsmodels.stats.contingency_tables import mcnemar
from itertools import combinations

# CSV esperado: columnas payload_id, vector, model, run, outcome
try:
    df = pd.read_csv("lab/results/bateria_repetida.csv")
    df = df[df.outcome != "invalid"]
    df["success"] = (df.outcome == "success").astype(int)

    print("=== Análisis de ASR con Intervalos de Confianza de Wilson (95%) ===")
    for model, g in df.groupby("model"):
        k = g.success.sum()
        n = len(g)
        lo, hi = proportion_confint(k, n, alpha=0.05, method='wilson')
        print(f"Modelo {model}: ASR = {k/n*100:.1f}% [{lo*100:.1f}% - {hi*100:.1f}%] (n={n})")
        
    print("\n=== Test de McNemar (Diferencia pareada por payload) ===")
    # Agregar por payload: proporción de éxito (no binarizar)
    df_agg = df.groupby(['model', 'payload_id'])['success'].mean()
    
    models = sorted(df['model'].unique())
    # Compare ALL pairs of models, not just the first two
    for m1, m2 in combinations(models, 2):
        try:
            p1 = df_agg.xs(m1, level='model')
            p2 = df_agg.xs(m2, level='model')
            merged = pd.concat([p1, p2], axis=1, keys=[m1, m2]).dropna()
            
            # Binarize at 0.5 for McNemar (majority vote)
            b1 = (merged[m1] > 0.5).astype(int)
            b2 = (merged[m2] > 0.5).astype(int)
            
            b = ((b1 == 0) & (b2 == 1)).sum()
            c = ((b1 == 1) & (b2 == 0)).sum()
            
            if b + c > 0:
                res = mcnemar([[0, b], [c, 0]], exact=True)
                print(f"\n{m1} vs {m2}:")
                print(f"  Discordantes: b={b}, c={c}")
                print(f"  p-value (exact): {res.pvalue:.4e}")
            else:
                print(f"\n{m1} vs {m2}: sin discordancias (idénticos)")
        except Exception as e:
            print(f"\n{m1} vs {m2}: Error - {e}")
            
    print("\n=== Proporción de éxito por payload (variabilidad) ===")
    for model in models:
        print(f"\n{model}:")
        model_data = df[df.model == model]
        for pid, g in model_data.groupby("payload_id"):
            k = g.success.sum()
            n = len(g)
            label = "DETERMINISTA-VULNERABLE" if k == n else ("DETERMINISTA-ROBUSTO" if k == 0 else "ESTOCÁSTICO")
            print(f"  {pid}: {k}/{n} ({k/n*100:.0f}%) [{label}]")
            
except FileNotFoundError:
    print("Módulo estadístico cargado. (Falta bateria_repetida.csv).")
