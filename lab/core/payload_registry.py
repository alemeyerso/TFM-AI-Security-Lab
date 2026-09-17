"""
lab/core/payload_registry.py
============================
Resolución de ``payload_id`` → definición del payload, SEGÚN SU ORIGEN
(auditoría 2026-09-17, GAP-009).

Hallazgo que motiva este módulo: los IDs ``tool_abuse_001…008`` (evaluador
CLI, ``lab/attacks/tool_abuse.py``) y ``tool_001…008`` (API/dashboard,
``lab/payloads/tool_abuse/payloads.json``) NO son alias: son dos juegos
DISTINTOS de prompts (verificado comparando el texto guardado en los
resultados). Por eso aquí no existe una tabla de equivalencia
``tool_abuse_00X → tool_00X``: se documenta la correspondencia de ORIGEN y
cada ID se resuelve contra su propia fuente.

Fuentes:
- ``dataset``   → ``lab/payloads/<vector>/payloads.json`` (API, dashboard, E1…)
- ``cli``       → ``lab/attacks/*.py`` (``run_lab.py`` / Evaluator)
- ``notebook05`` → ``ATTACK_BATTERY`` del notebook 05 (IDs DI-/II-/JB-)

Solo lectura: no modifica ningún fichero.
"""

from __future__ import annotations

import ast
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ("direct", "indirect", "jailbreak", "tool_abuse")
NOTEBOOK05 = ROOT / "notebooks" / "05_comparativa_modelos_qwen_TFM_FINAL_EJECUTADO.ipynb"

# Documentación de la correspondencia de ORIGEN (no de equivalencia).
ID_NAMESPACES = {
    "tool_abuse_": {"source": "cli", "file": "lab/attacks/tool_abuse.py",
                    "note": "Prompts distintos de tool_00X; no comparables."},
    "tool_": {"source": "dataset", "file": "lab/payloads/tool_abuse/payloads.json",
              "note": "Prompts distintos de tool_abuse_00X; no comparables."},
    "DI-": {"source": "notebook05", "file": str(NOTEBOOK05.relative_to(ROOT))},
    "II-": {"source": "notebook05", "file": str(NOTEBOOK05.relative_to(ROOT))},
    "JB-": {"source": "notebook05", "file": str(NOTEBOOK05.relative_to(ROOT))},
}


def _prompt_to_text(prompt: Any) -> str:
    if isinstance(prompt, str):
        return prompt
    return json.dumps(prompt, ensure_ascii=False)


@lru_cache(maxsize=1)
def dataset_payloads() -> dict[str, dict]:
    out = {}
    for v in VECTORS:
        for p in json.loads((ROOT / "lab/payloads" / v / "payloads.json").read_text(encoding="utf-8")):
            out[p["id"]] = {**p, "vector": v, "_source": f"dataset:lab/payloads/{v}/payloads.json"}
    return out


@lru_cache(maxsize=1)
def cli_payloads() -> dict[str, dict]:
    from lab.attacks.direct_injection import DirectInjectionAttack
    from lab.attacks.indirect_injection import IndirectInjectionAttack
    from lab.attacks.jailbreak import JailbreakAttack
    from lab.attacks.tool_abuse import ToolAbuseAttack

    out = {}
    for v, cls in (("direct", DirectInjectionAttack), ("indirect", IndirectInjectionAttack),
                   ("jailbreak", JailbreakAttack), ("tool_abuse", ToolAbuseAttack)):
        for p in cls().get_payloads():
            out[p["id"]] = {**p, "vector": v, "_source": f"cli:lab/attacks ({v})"}
    return out


@lru_cache(maxsize=1)
def notebook05_battery() -> dict[str, dict]:
    """Lee ``ATTACK_BATTERY`` del notebook 05 sin ejecutarlo (ast.literal_eval)."""
    nb = json.loads(NOTEBOOK05.read_text(encoding="utf-8"))
    for cell in nb["cells"]:
        src = "".join(cell.get("source", []))
        if "ATTACK_BATTERY" in src and "success_kw" in src:
            i = src.index("ATTACK_BATTERY")
            j = src.index("[", i)
            depth = 0
            for k in range(j, len(src)):
                depth += src[k] == "["
                depth -= src[k] == "]"
                if depth == 0:
                    break
            battery = ast.literal_eval(src[j:k + 1])
            return {a["id"]: {**a, "_source": f"notebook05:{NOTEBOOK05.name}"} for a in battery}
    raise RuntimeError("ATTACK_BATTERY no encontrado en el notebook 05")


def resolve(payload_id: str, source: Optional[str] = None) -> list[dict]:
    """Candidatos para ``payload_id``. ``source`` en {dataset, cli, notebook05}
    restringe la búsqueda. Lista vacía = no resoluble."""
    tables = {"dataset": dataset_payloads, "cli": cli_payloads, "notebook05": notebook05_battery}
    names = [source] if source else list(tables)
    found = []
    for name in names:
        table = tables[name]()
        if payload_id in table:
            found.append({"source": name, "payload": table[payload_id]})
    return found


def prompt_of(entry: dict) -> str:
    """Texto del prompt de un candidato, tal como lo construye su fuente."""
    p = entry["payload"]
    if entry["source"] == "notebook05":
        return _prompt_to_text(p.get("messages") or p.get("payload") or "")
    return _prompt_to_text(p.get("prompt", ""))
