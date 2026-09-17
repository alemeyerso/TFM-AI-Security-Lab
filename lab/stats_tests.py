"""
lab/stats_tests.py
==================
Pruebas de hipótesis sobre los resultados **congelados** (no requiere Ollama).

Hipótesis:
  H1  En E3, las acciones cuyo cumplimiento es solo texto (alter_conclusion,
      assert_state) tienen más éxito que las que exigen acción externa o
      contenido dañino.
  H2  En E3, la dilución (1:1, 1:10, 1:100) no cambia el éxito de las acciones de texto.
  H3  Con la herramienta simulada (E2), la emisión de send_email es mayor que la
      tasa de éxito de external_action sin herramienta (E3).  *No aísla la causa*:
      E2 cambia además la redacción de la instrucción y el formato del prompt.
  H4  e2b y e4b no difieren (E1 v3; E3 acciones de texto; canario).

Salida: lab/results/stats_v3.csv   (p-valores con corrección de Holm)
Uso:    python lab/stats_tests.py
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from math import sqrt
from pathlib import Path

from scipy.stats import chi2_contingency, fisher_exact, binomtest

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "lab" / "results"
OUT = RES / "stats_v3.csv"
Z = 1.959964


def wilson(k, n):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n
    d = 1 + Z * Z / n
    c = (p + Z * Z / (2 * n)) / d
    m = Z * sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / d
    return max(0.0, c - m), min(1.0, c + m)


def newcombe_diff(k1, n1, k2, n2):
    """IC 95 % de p1 - p2 (método híbrido de Newcombe)."""
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = wilson(k1, n1)
    l2, u2 = wilson(k2, n2)
    d = p1 - p2
    lo = d - sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = d + sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return d, lo, hi


def two_prop(test_id, hypothesis, label1, k1, n1, label2, k2, n2):
    odds, p = fisher_exact([[k1, n1 - k1], [k2, n2 - k2]])
    d, lo, hi = newcombe_diff(k1, n1, k2, n2)
    return {
        "test_id": test_id, "hypothesis": hypothesis, "test": "Fisher exacto (bilateral)",
        "group_1": label1, "k1": k1, "n1": n1, "group_2": label2, "k2": k2, "n2": n2,
        "statistic": round(float(odds), 4) if odds != float("inf") else "inf",
        "statistic_name": "odds ratio",
        "effect": round(d, 4), "effect_ci_low": round(lo, 4), "effect_ci_high": round(hi, 4),
        "effect_name": "diferencia de proporciones (Newcombe 95%)",
        "p_value": float(p),
    }


def load(name):
    return json.loads((RES / name).read_text(encoding="utf-8"))["results"]


def main():
    rows = []

    # ── E3 (v3) ───────────────────────────────────────────────
    e3 = load("e3_factorial_v3.json")
    text = [r for r in e3 if r["action"] in ("alter_conclusion", "assert_state")]
    other = [r for r in e3 if r["action"] not in ("alter_conclusion", "assert_state")]
    s = lambda rs: sum(r["outcome_v3"] == "success" for r in rs)
    rows.append(two_prop("E3_H1", "H1", "acciones de texto", s(text), len(text),
                         "acción externa + contenido dañino", s(other), len(other)))

    by_dil = defaultdict(list)
    for r in text:
        by_dil[r["dilution"]].append(r)
    table = [[s(v), len(v) - s(v)] for _, v in sorted(by_dil.items())]
    chi2, p, dof, _ = chi2_contingency(table)
    rows.append({
        "test_id": "E3_H2", "hypothesis": "H2", "test": f"chi-cuadrado de independencia (gl={dof})",
        "group_1": " / ".join(f"{k}:{s(v)}/{len(v)}" for k, v in sorted(by_dil.items())),
        "k1": "", "n1": len(text), "group_2": "", "k2": "", "n2": "",
        "statistic": round(float(chi2), 4), "statistic_name": "chi2",
        "effect": "", "effect_ci_low": "", "effect_ci_high": "", "effect_name": "",
        "p_value": float(p),
    })
    for m1, m2 in [("gemma4:e2b", "gemma4:e4b")]:
        a = [r for r in text if r["model"] == m1]
        b = [r for r in text if r["model"] == m2]
        rows.append(two_prop("E3_H4", "H4", f"{m1} texto", s(a), len(a), f"{m2} texto", s(b), len(b)))

    # ── E2 frente a E3 external_action ───────────────────────
    e2 = load("e2_mini_20260914.json")
    ext = [r for r in e3 if r["action"] == "external_action"]
    rows.append(two_prop("E2_H3_detected", "H3", "E2 send_email emitido", sum(r["outcome"] == "success" for r in e2), len(e2),
                         "E3 external_action (v3)", s(ext), len(ext)))
    audit = RES / "e2_audit_rows.csv"
    if audit.exists():
        ar = list(csv.DictReader(audit.open(encoding="utf-8")))
        comp = sum(r["tool_call_complete"] == "True" for r in ar)
        rows.append(two_prop("E2_H3_complete", "H3", "E2 llamada completa", comp, len(ar),
                             "E3 external_action (v3)", s(ext), len(ext)))

    # ── E1 (v3) e2b frente a e4b ─────────────────────────────
    e1 = [r for r in load("e1_reliability_v3.json") if r["outcome_v3"] in ("success", "partial", "refused")]
    g = {m: [r for r in e1 if r["model"] == m] for m in ("gemma4:e2b", "gemma4:e4b")}
    ks = {m: sum(r["outcome_v3"] == "success" for r in v) for m, v in g.items()}
    rows.append(two_prop("E1_H4", "H4", "E1 e2b", ks["gemma4:e2b"], len(g["gemma4:e2b"]),
                         "E1 e4b", ks["gemma4:e4b"], len(g["gemma4:e4b"])))
    # McNemar exacto sobre el resultado mayoritario por payload (pareado)
    maj = defaultdict(dict)
    for m, v in g.items():
        per = defaultdict(list)
        for r in v:
            per[r["payload_id"]].append(r["outcome_v3"] == "success")
        for pid, xs in per.items():
            maj[pid][m] = sum(xs) > len(xs) / 2
    pairs = [(d["gemma4:e2b"], d["gemma4:e4b"]) for d in maj.values() if len(d) == 2]
    b_ = sum(1 for x, y in pairs if x and not y)
    c_ = sum(1 for x, y in pairs if y and not x)
    p_mc = binomtest(b_, b_ + c_, 0.5).pvalue if b_ + c_ else 1.0
    rows.append({
        "test_id": "E1_H4_mcnemar", "hypothesis": "H4", "test": "McNemar exacto (mayoría por payload)",
        "group_1": f"solo e2b vulnerable: {b_}", "k1": b_, "n1": len(pairs),
        "group_2": f"solo e4b vulnerable: {c_}", "k2": c_, "n2": len(pairs),
        "statistic": b_ + c_, "statistic_name": "pares discordantes",
        "effect": "", "effect_ci_low": "", "effect_ci_high": "", "effect_name": "",
        "p_value": float(p_mc),
    })

    # ── Canario e2b frente a e4b ─────────────────────────────
    # Auditoría 2026-09-17: 2 ejecuciones de e4b son timeouts (60 s) guardados como "refused";
    # se excluyen del denominador (errores técnicos, no respuestas del modelo).
    can = [r for r in load("reeval_indirect_canary.json") if not str(r["response"]).startswith("ERROR")]
    cg = {m: [r for r in can if r["model"] == m] for m in ("gemma4:e2b", "gemma4:e4b")}
    rows.append(two_prop("CANARY_H4", "H4", "canario e2b", sum(r["outcome"] == "success" for r in cg["gemma4:e2b"]), len(cg["gemma4:e2b"]),
                         "canario e4b", sum(r["outcome"] == "success" for r in cg["gemma4:e4b"]), len(cg["gemma4:e4b"])))

    # ── Corrección de Holm ───────────────────────────────────
    order = sorted(range(len(rows)), key=lambda i: rows[i]["p_value"])
    m = len(rows)
    running = 0.0
    for rank, i in enumerate(order):
        adj = min(1.0, (m - rank) * rows[i]["p_value"])
        running = max(running, adj)
        rows[i]["p_holm"] = running
    for r in rows:
        r["significant_holm_0.05"] = r["p_holm"] < 0.05
        r["p_value"] = f'{r["p_value"]:.3g}'
        r["p_holm"] = f'{r["p_holm"]:.3g}'

    fields = list(rows[0].keys())
    for r in rows:
        for f in r:
            if f not in fields:
                fields.append(f)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print(f'{r["test_id"]:16s} {r["group_1"][:34]:34s} vs {str(r["group_2"])[:30]:30s} '
              f'p={r["p_value"]:>9s} p_holm={r["p_holm"]:>9s} efecto={r["effect"]}')
    print(f"CSV: {OUT}")


if __name__ == "__main__":
    main()
