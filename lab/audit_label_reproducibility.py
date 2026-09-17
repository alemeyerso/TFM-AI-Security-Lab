"""
lab/audit_label_reproducibility.py — SOLO LECTURA
===================================================
Auditoría 2026-09-17 (GAP-005). Compara, para cada conjunto de resultados
históricos, la etiqueta GUARDADA con la que produce HOY el clasificador que le
corresponde. No modifica ningún JSON/CSV de ``lab/results/``: solo escribe el
informe en la ruta indicada (por defecto ``audit/``).

Uso:
    python lab/audit_label_reproducibility.py
    python lab/audit_label_reproducibility.py --out audit/label_reproducibility.json

Una discrepancia NO significa que la etiqueta histórica sea incorrecta: puede
deberse a revisión manual, a otra versión del clasificador o a otro estímulo.
Este script no decide cuál es la correcta.
"""

from __future__ import annotations

import argparse
import collections
import csv
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
# Importar los scripts de experimentos no debe crear carpetas en lab/results.
os.environ.setdefault("LAB_RUN_DIR", tempfile.mkdtemp(prefix="label_audit_"))

from lab.core.outcome import classify_outcome  # noqa: E402
from lab.core import payload_registry as reg  # noqa: E402

RES = ROOT / "lab" / "results"


def _rel(p: Path) -> str:
    return str(Path(p).resolve().relative_to(ROOT))


def _compare(rows):
    """rows: iterable of (record_id, stored, recalculated, note)."""
    c = collections.Counter()
    diffs = []
    for rid, stored, recalc, note in rows:
        c[(stored, recalc)] += 1
        if stored != recalc:
            diffs.append({"record": rid, "stored": stored, "recalculated": recalc, "note": note})
    total = sum(c.values())
    same = sum(v for (a, b), v in c.items() if a == b)
    return {
        "total": total,
        "identical": same,
        "discrepancies": total - same,
        "transitions": {f"{a}->{b}": v for (a, b), v in sorted(c.items()) if a != b},
        "details": diffs,
    }


def dataset_main_battery():
    """Batería principal (agosto): eval_gemma4_*_202608*.json, clasificador actual + dataset."""
    out = {}
    for f in sorted(RES.glob("eval_gemma4_*_202608*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        rows = []
        for r in d["results"]:
            cand = reg.resolve(r["id"], "dataset")
            if not cand:
                rows.append((r["id"], r["outcome"], "UNRESOLVED", "id no encontrado"))
                continue
            rows.append((r["id"], r["outcome"], classify_outcome(r["response"], cand[0]["payload"]), ""))
        out[_rel(f)] = _compare(rows)
    return {
        "classifier_recomputed_with": "lab/core/outcome.classify_outcome (actual) + keywords de lab/payloads",
        "stored_labels_origin": "No registrado en el fichero. Incluye la etiqueta 'invalid' (ejecución nula: "
                                "en indirect_001-003 el prompt solo contenía el NOMBRE del documento, "
                                "ver memoria §4 notas sobre la batería inicial).",
        "files": out,
    }


def dataset_pilot_cli():
    """Piloto PromptGuard 11/09 (oficiales/2026091*): evaluador CLI."""
    out = {}
    for f in sorted((RES / "oficiales").glob("2026091*_gemma4_e2b.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        rows = []
        for t in d["tests"]:
            cand = reg.resolve(t["payload_id"], "cli")
            if not cand:
                rows.append((t["payload_id"], t["outcome"], "UNRESOLVED", "id no encontrado en lab/attacks"))
                continue
            if t.get("defense_blocked"):
                # Con el código actual un bloqueo se registra como 'blocked'
                rows.append((t["payload_id"], t["outcome"], "blocked", "defense_blocked=True"))
                continue
            rows.append((t["payload_id"], t["outcome"],
                         classify_outcome(t["response"], cand[0]["payload"]), ""))
        out[_rel(f)] = _compare(rows)
    return {
        "classifier_recomputed_with": "classify_outcome (actual) + keywords de lab/attacks/*.py; "
                                      "bloqueos → 'blocked' (antes 'refused')",
        "stored_labels_origin": "Evaluator CLI del 11/09 (versión anterior de las defensas).",
        "files": out,
    }


def dataset_notebook05():
    f = RES / "oficiales" / "notebook05_20260913" / "05_comparativa_consolidada_20260913_004400.json"
    d = json.loads(f.read_text(encoding="utf-8"))
    battery = reg.notebook05_battery()
    rows = []
    for r in d["all_results"]:
        a = battery.get(r["attack_id"])
        if not a:
            rows.append((f"{r['model']}/{r['attack_id']}", r["outcome"], "UNRESOLVED", ""))
            continue
        note = "respuesta truncada a 500 caracteres en el JSON" if len(r["response"]) >= 500 else ""
        rows.append((f"{r['model']}/{r['attack_id']}", r["outcome"],
                     classify_outcome(r["response"], {"detection_keywords": a["success_kw"]}), note))
    return {
        "classifier_recomputed_with": "classify_outcome con success_kw del notebook 05 (refuse_kw no se usa, igual que en el notebook)",
        "stored_labels_origin": "Notebook 05 (evaluate_outcome → classify_outcome) sobre la respuesta COMPLETA.",
        "limitation": "El JSON congelado guarda response[:500] y payload[:200] (ver celda de guardado del "
                      "notebook). 16 de 24 respuestas están truncadas, así que el recálculo NO es concluyente: "
                      "una discrepancia puede deberse solo al truncado.",
        "files": {_rel(f): _compare(rows)},
    }


def dataset_live(folder: Path, label: str):
    out = {}
    for f in sorted(folder.glob("live_attack_*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        t = d["tests"][0]
        if str(t.get("response", "")).startswith("ERROR"):
            out[_rel(f)] = {"skipped": "respuesta de error guardada como resultado (no es observación válida)"}
            continue
        cand = reg.resolve(d["payload_id"], "dataset")
        if d.get("defense_blocked") and d.get("defense_applied"):
            recalc = "blocked"
        elif not cand:
            recalc = "UNRESOLVED"
        else:
            recalc = classify_outcome(t["response"], cand[0]["payload"])
        out[_rel(f)] = _compare([(d["payload_id"], t["outcome"], recalc, "")])
    agg = collections.Counter()
    for v in out.values():
        if "total" in v:
            agg["total"] += v["total"]
            agg["discrepancies"] += v["discrepancies"]
    return {
        "classifier_recomputed_with": "classify_outcome (actual) + keywords de lab/payloads",
        "stored_labels_origin": f"{label}: versión del servidor en la fecha de cada fichero (no registrada).",
        "aggregate": dict(agg),
        "files": out,
    }


def dataset_e1():
    mod = importlib.import_module("lab.e1_reliability")
    d = json.loads((RES / "e1_reliability_20260913.json").read_text(encoding="utf-8"))
    rows = []
    for r in (d["results"] if isinstance(d, dict) else d):
        cand = reg.resolve(r["payload_id"], "dataset")
        kw = cand[0]["payload"].get("detection_keywords") if cand else None
        rows.append((f"{r['model']}/{r['payload_id']}/run{r['run']}", r["outcome"],
                     mod.classify_outcome(r["response"], kw), ""))
    return {
        "classifier_recomputed_with": "lab/e1_reliability.classify_outcome (propio de E1) sobre el JSON CRUDO",
        "stored_labels_origin": "E1 crudo. Las cifras del TFM usan los derivados v2/v3 "
                                "(reclassify_e1_e3.py + reclass_v3_overrides.csv), no estas etiquetas.",
        "files": {"lab/results/e1_reliability_20260913.json": _compare(rows)},
    }


def dataset_e3():
    mod = importlib.import_module("lab.e3_factorial")
    d = json.loads((RES / "e3_factorial_20260914.json").read_text(encoding="utf-8"))
    rows = []
    for r in (d["results"] if isinstance(d, dict) else d):
        kw = mod.ACTIONS[r["action"]]["detection_keywords"]
        rows.append((f"{r['model']}/{r['action']}/{r['dilution']}/run{r['run']}", r["outcome"],
                     mod.classify(r["response"], kw), ""))
    return {
        "classifier_recomputed_with": "lab/e3_factorial.classify (propio de E3) sobre el JSON CRUDO",
        "stored_labels_origin": "E3 crudo. Las cifras del TFM usan los derivados v3.",
        "files": {"lab/results/e3_factorial_20260914.json": _compare(rows)},
    }


def dataset_e2():
    mod = importlib.import_module("lab.e2_mini")
    d = json.loads((RES / "e2_mini_20260914.json").read_text(encoding="utf-8"))
    rows = [(f"{r['model']}/{r['dilution']}/run{r['run']}", r["outcome"], mod.classify(r["response"]), "")
            for r in d["results"]]
    return {
        "classifier_recomputed_with": "lab/e2_mini.classify (propio de E2)",
        "stored_labels_origin": "E2 (herramienta simulada; 0 ejecuciones reales).",
        "files": {"lab/results/e2_mini_20260914.json": _compare(rows)},
    }


NOT_RECOMPUTED = {
    "lab/results/reeval_indirect_canary.json":
        "Clasificador y canario definidos en lab/reeval_indirect_canary.py (script de ejecución, "
        "no importable sin lanzar inferencias). Trazabilidad por fila en reeval_indirect_canary_labels.csv.",
    "lab/results/*_reclassified.json, *_v3.json":
        "Etiquetas derivadas por reglas y overrides explícitos; se reproducen con "
        "lab/reclassify_v3_overrides.py (tests/test_analysis_frozen.py).",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "audit" / "label_reproducibility_2026-09-17.json"))
    ap.add_argument("--csv", default=None, help="CSV opcional con las discrepancias")
    args = ap.parse_args(argv)

    report = {
        "description": "Etiquetas guardadas vs. recalculadas con el código actual. Solo lectura.",
        "warning": "Una discrepancia no indica cuál de las dos etiquetas es correcta.",
        "datasets": {
            "bateria_principal_agosto": dataset_main_battery(),
            "piloto_promptguard_11_09": dataset_pilot_cli(),
            "notebook05_qwen": dataset_notebook05(),
            "live_api_raiz": dataset_live(RES, "Ejecuciones live (API) en la raíz de lab/results"),
            "exploratorias_16_09": dataset_live(RES / "exploratory_20260916", "Exploratorias 16/09"),
            "e1_crudo": dataset_e1(),
            "e2": dataset_e2(),
            "e3_crudo": dataset_e3(),
        },
        "not_recomputed": NOT_RECOMPUTED,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"{'conjunto':32s} {'total':>6s} {'iguales':>8s} {'distintas':>9s}")
    for name, ds in report["datasets"].items():
        tot = same = 0
        for v in ds["files"].values():
            if "total" in v:
                tot += v["total"]
                same += v["identical"]
        print(f"{name:32s} {tot:6d} {same:8d} {tot - same:9d}")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["dataset", "file", "record", "stored", "recalculated", "note"])
            for name, ds in report["datasets"].items():
                for fname, v in ds["files"].items():
                    for d in v.get("details", []):
                        w.writerow([name, fname, d["record"], d["stored"], d["recalculated"], d["note"]])
    print(f"\nInforme: {out}")
    return report


if __name__ == "__main__":
    main()
