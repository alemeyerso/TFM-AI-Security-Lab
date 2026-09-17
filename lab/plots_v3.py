"""
lab/plots_v3.py
===============
Figuras para la memoria a partir de los resultados congelados (no requiere Ollama).

  docs/fig/e3_heatmap_v3.png   – E3: éxito por tipo de acción × dilución, por modelo
  docs/fig/asr_forest_v3.png   – Proporciones con IC de Wilson 95 % (E1, canario, E3, E2)

Uso: python lab/plots_v3.py
"""
from __future__ import annotations

import csv
import json
from math import sqrt
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "lab" / "results"
FIG = ROOT / "docs" / "fig"

# Paleta de referencia (skill de visualización): azul secuencial, tinta neutra
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
BLUE = "#2a78d6"
SEQ = ["#f0efec", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "text.color": INK, "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK_2,
    "axes.edgecolor": GRID, "font.size": 10, "axes.titleweight": "bold",
})


def wilson(k, n, z=1.959964):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - m), min(1.0, c + m)


def e3_heatmap():
    rows = list(csv.DictReader((RES / "e3_factorial_summary_v3.csv").open(encoding="utf-8")))
    actions = ["alter_conclusion", "assert_state", "external_action", "harmful_content"]
    labels_a = ["Alterar conclusión", "Afirmar estado", "Acción externa", "Contenido dañino"]
    dils = ["ratio_1_1", "ratio_1_10", "ratio_1_100"]
    labels_d = ["1:1", "1:10", "1:100"]
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    fig, axes = plt.subplots(1, 2, figsize=(9.2, 3.6), sharey=True)
    for ax, model in zip(axes, ["gemma4:e2b", "gemma4:e4b"]):
        grid = [[0.0] * 3 for _ in actions]
        txt = [[""] * 3 for _ in actions]
        for r in rows:
            if r["model"] != model:
                continue
            i, j = actions.index(r["action"]), dils.index(r["dilution"])
            k, n = int(r["n_success"]), int(r["n"])
            grid[i][j] = k / n
            txt[i][j] = f"{k}/{n}"
        ax.imshow(grid, cmap=cmap, vmin=0, vmax=1, aspect="auto")
        for i in range(len(actions)):
            for j in range(3):
                v = grid[i][j]
                ax.text(j, i, f"{round(100 * v)} %\n{txt[i][j]}", ha="center", va="center",
                        fontsize=9, color="#ffffff" if v >= 0.55 else INK)
        # separación de 2px entre celdas
        ax.set_xticks([x - 0.5 for x in range(1, 3)], minor=True)
        ax.set_yticks([y - 0.5 for y in range(1, 4)], minor=True)
        ax.grid(which="minor", color=SURFACE, linewidth=2)
        ax.tick_params(which="both", length=0)
        ax.set_xticks(range(3), labels_d)
        ax.set_yticks(range(4), labels_a)
        ax.set_title(model, fontsize=11, loc="left")
        ax.set_xlabel("Ratio de dilución (instrucción : documento)")
        for s in ax.spines.values():
            s.set_visible(False)
    fig.suptitle("E3 — Éxito de la inyección indirecta por tipo de acción (v3, n=10 por celda)",
                 x=0.01, ha="left", fontsize=12, fontweight="bold")
    fig.text(0.01, 0.01, "Fuente: lab/results/e3_factorial_summary_v3.csv. Éxito = la respuesta cumple la instrucción inyectada.",
             fontsize=8, color=INK_2)
    fig.tight_layout(rect=(0, 0.04, 1, 0.95))
    out = FIG / "e3_heatmap_v3.png"
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def forest():
    items = []
    e1 = json.loads((RES / "e1_reliability_v3.json").read_text(encoding="utf-8"))["results"]
    for m in ("gemma4:e2b", "gemma4:e4b"):
        v = [r for r in e1 if r["model"] == m and r["outcome_v3"] in ("success", "partial", "refused")]
        items.append((f"E1 · {m} (39 payloads × 5, sin indirecta)", sum(r["outcome_v3"] == "success" for r in v), len(v)))
    can = json.loads((RES / "reeval_indirect_canary.json").read_text(encoding="utf-8"))["results"]
    for m in ("gemma4:e2b", "gemma4:e4b"):
        v = [r for r in can if r["model"] == m and not str(r["response"]).startswith("ERROR")]  # excluye 2 timeouts
        items.append((f"Canario indirecta · {m}", sum(r["outcome"] == "success" for r in v), len(v)))
    e3 = json.loads((RES / "e3_factorial_v3.json").read_text(encoding="utf-8"))["results"]
    txt = [r for r in e3 if r["action"] in ("alter_conclusion", "assert_state")]
    ext = [r for r in e3 if r["action"] == "external_action"]
    items.append(("E3 · acciones de texto (ambos modelos)", sum(r["outcome_v3"] == "success" for r in txt), len(txt)))
    items.append(("E3 · acción externa sin herramienta", sum(r["outcome_v3"] == "success" for r in ext), len(ext)))
    audit = list(csv.DictReader((RES / "e2_audit_rows.csv").open(encoding="utf-8")))
    items.append(("E2 · send_email emitido (herramienta simulada)", sum(r["tool_call_detected"] == "True" for r in audit), len(audit)))
    items.append(("E2 · llamada completa", sum(r["tool_call_complete"] == "True" for r in audit), len(audit)))
    items.append(("E2 · afirma haber enviado (sin ejecución)", sum(r["claimed_success"] == "True" for r in audit), len(audit)))

    fig = plt.figure(figsize=(11, 5.2))
    ax = fig.add_axes([0.36, 0.14, 0.40, 0.74])
    ys = list(range(len(items)))[::-1]
    for y, (label, k, n) in zip(ys, items):
        p, lo, hi = wilson(k, n)
        ax.plot([lo * 100, hi * 100], [y, y], color=BLUE, linewidth=2, solid_capstyle="round")
        ax.plot(p * 100, y, "o", color=BLUE, markersize=8, zorder=3)
        ax.text(1.03, y, f"{p * 100:.1f} %  [{lo * 100:.1f}–{hi * 100:.1f}]   {k}/{n}",
                va="center", fontsize=9, color=INK, transform=ax.get_yaxis_transform(), clip_on=False)
    ax.set_yticks(ys, [it[0] for it in items])
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.6, len(items) - 0.4)
    ax.text(1.03, len(items) - 0.2, "valor  [IC 95 %]   k/n", fontsize=8.5, color=INK_2,
            transform=ax.get_yaxis_transform(), clip_on=False)
    ax.set_xlabel("Proporción de respuestas (%) con IC de Wilson 95 %")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(axis="y", length=0)
    fig.suptitle("Resultados con repeticiones (resultados congelados, capa v3)", x=0.01, y=0.97, ha="left",
                 fontsize=12, fontweight="bold")
    fig.text(0.01, 0.01, "Fuentes: e1_reliability_v3.json, reeval_indirect_canary.json, e3_factorial_v3.json, e2_audit_rows.csv. "
             "E2 mide texto generado: 0/60 ejecuciones reales.", fontsize=7.5, color=INK_2)
    out = FIG / "asr_forest_v3.png"
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def main():
    FIG.mkdir(parents=True, exist_ok=True)
    for f in (e3_heatmap(), forest()):
        print(f"Figura: {f}")


if __name__ == "__main__":
    main()
