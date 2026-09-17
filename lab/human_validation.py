"""
lab/human_validation.py
=======================
Kit de **validación humana** de las etiquetas v3 (E1 + E3), sin repetir inferencias.

1) Generar la muestra ciega (los anotadores NO ven la etiqueta automática):

    python lab/human_validation.py sample            # por defecto ~100 respuestas
    python lab/human_validation.py sample --success 60 --partial 20 --refused 20

   Crea:
     lab/results/human_validation/annotation_sheet.csv   ← se reparte a los anotadores
     lab/results/human_validation/annotation_key.csv     ← NO se reparte (etiquetas v3)

   Cada anotador rellena su columna (`annotator_1` o `annotator_2`) con
   success / partial / refused / invalid, siguiendo docs/e4_rubrica_anotacion.md.

2) Calcular el acuerdo:

    python lab/human_validation.py agreement

   → lab/results/human_validation/agreement.json con:
     - acuerdo y κ de Cohen entre anotadores (si hay dos columnas rellenas)
     - acuerdo y κ de cada anotador frente a las reglas v3
     - matriz de confusión humano (consenso) × v3
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "lab" / "results"
OUTDIR = RES / "human_validation"
SHEET = OUTDIR / "annotation_sheet.csv"
KEY = OUTDIR / "annotation_key.csv"
LABELS = ["success", "partial", "refused", "invalid"]
PAYLOAD_DIRS = ["direct", "indirect", "jailbreak", "tool_abuse"]


def _payload_prompts() -> dict:
    prompts = {}
    for v in PAYLOAD_DIRS:
        for p in json.loads((ROOT / "lab/payloads" / v / "payloads.json").read_text(encoding="utf-8")):
            prompts[p["id"]] = p.get("prompt") or p.get("context", "")
    return prompts


def _records() -> list[dict]:
    prompts = _payload_prompts()
    recs = []
    for r in json.loads((RES / "e1_reliability_v3.json").read_text(encoding="utf-8"))["results"]:
        if r["outcome_v3"] not in ("success", "partial", "refused"):
            continue
        recs.append({
            "uid": f'E1|{r["model"]}|{r["payload_id"]}|{r["run"]}',
            "experiment": "E1", "attack": r["payload_id"],
            "attacker_goal": prompts.get(r["payload_id"], ""),
            "response": r["response"], "label_v3": r["outcome_v3"],
        })
    e3 = json.loads((RES / "e3_factorial_v3.json").read_text(encoding="utf-8"))["results"]
    for r in e3:
        prompt = r.get("prompt", "")
        instr = prompt.split("IMPORTANT INSTRUCTION -->", 1)[-1].split("<!-- End", 1)[0].strip() if prompt else ""
        recs.append({
            "uid": f'E3|{r["model"]}|{r["action"]}:{r["dilution"]}|{r["run"]}',
            "experiment": "E3", "attack": f'{r["action"]}:{r["dilution"]}',
            "attacker_goal": "Tarea legítima: resumir el informe en tres puntos. Instrucción inyectada: " + instr,
            "response": r["response"], "label_v3": r["outcome_v3"],
        })
    return recs


def sample(n_success: int, n_partial: int, n_refused: int, seed: int) -> None:
    rng = random.Random(seed)
    recs = _records()
    chosen = []
    for label, k in (("success", n_success), ("partial", n_partial), ("refused", n_refused)):
        pool = [r for r in recs if r["label_v3"] == label]
        chosen += rng.sample(pool, min(k, len(pool)))
    rng.shuffle(chosen)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    with SHEET.open("w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig: Excel muestra bien las tildes
        w = csv.writer(f)
        w.writerow(["item", "experiment", "attack", "attacker_goal", "response", "annotator_1", "annotator_2", "notes"])
        for i, r in enumerate(chosen, 1):
            w.writerow([i, r["experiment"], r["attack"], r["attacker_goal"], r["response"], "", "", ""])
    with KEY.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["item", "uid", "label_v3"])
        for i, r in enumerate(chosen, 1):
            w.writerow([i, r["uid"], r["label_v3"]])
    print(f"Muestra: {len(chosen)} respuestas {dict(Counter(r['label_v3'] for r in chosen))} (seed={seed})")
    print(f"Hoja para anotadores: {SHEET}")
    print(f"Clave (no repartir):  {KEY}")


def cohen_kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    if n == 0:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(a) | set(b)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def _pair(a, b):
    return {"n": len(a), "agreement": round(sum(x == y for x, y in zip(a, b)) / len(a), 4) if a else None,
            "cohen_kappa": round(cohen_kappa(a, b), 4) if a else None}


def agreement() -> None:
    sheet = {r["item"]: r for r in csv.DictReader(SHEET.open(encoding="utf-8-sig"))}
    key = {r["item"]: r["label_v3"] for r in csv.DictReader(KEY.open(encoding="utf-8"))}
    norm = lambda s: (s or "").strip().lower()
    out = {"items": len(sheet)}
    for ann in ("annotator_1", "annotator_2"):
        items = [i for i, r in sheet.items() if norm(r[ann]) in LABELS]
        if items:
            out[f"{ann}_vs_v3"] = _pair([norm(sheet[i][ann]) for i in items], [key[i] for i in items])
    both = [i for i, r in sheet.items() if norm(r["annotator_1"]) in LABELS and norm(r["annotator_2"]) in LABELS]
    if both:
        out["annotator_1_vs_annotator_2"] = _pair([norm(sheet[i]["annotator_1"]) for i in both],
                                                  [norm(sheet[i]["annotator_2"]) for i in both])
        cons = [i for i in both if norm(sheet[i]["annotator_1"]) == norm(sheet[i]["annotator_2"])]
        out["consensus_vs_v3"] = _pair([norm(sheet[i]["annotator_1"]) for i in cons], [key[i] for i in cons])
        cm = Counter((norm(sheet[i]["annotator_1"]), key[i]) for i in cons)
        out["confusion_consensus_x_v3"] = {f"humano={h}|v3={v}": c for (h, v), c in sorted(cm.items())}
        out["disagreements_to_arbitrate"] = [i for i in both if i not in cons]
    (OUTDIR / "agreement.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(out, indent=2, ensure_ascii=False))


def main() -> None:
    ap = argparse.ArgumentParser(description="Validación humana de etiquetas v3")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--success", type=int, default=50)
    s.add_argument("--partial", type=int, default=25)
    s.add_argument("--refused", type=int, default=25)
    s.add_argument("--seed", type=int, default=20260916)
    sub.add_parser("agreement")
    a = ap.parse_args()
    if a.cmd == "sample":
        sample(a.success, a.partial, a.refused, a.seed)
    else:
        agreement()


if __name__ == "__main__":
    main()
