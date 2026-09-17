"""
lab/core/payload_revisions.py
=============================
Revisiones versionadas de payloads (auditoría 2026-09-17, GAP-017 / F-12).

- La revisión 1 es el payload tal como está en ``lab/payloads/<vector>/payloads.json``
  (estímulo usado en las ejecuciones históricas). Es la que se usa POR DEFECTO.
- Las revisiones posteriores viven en ``lab/payloads/revisions/<id>.r<N>.json``
  y solo se usan si se piden explícitamente:

      PAYLOAD_REVISIONS="indirect_004=2"   (varias: "a=2,b=3")

- Cada payload devuelto lleva ``revision`` y ``_source`` para que el registro de
  la ejecución indique qué estímulo se usó.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Optional

LAB_DIR = Path(__file__).resolve().parents[1]
REVISIONS_DIR = LAB_DIR / "payloads" / "revisions"


def requested_revisions(spec: Optional[str] = None) -> dict[str, int]:
    """Interpreta ``PAYLOAD_REVISIONS`` ("id=N,id2=M"). Error explícito si está mal formado."""
    spec = os.environ.get("PAYLOAD_REVISIONS", "") if spec is None else spec
    out: dict[str, int] = {}
    for part in filter(None, (x.strip() for x in spec.split(","))):
        if "=" not in part:
            raise ValueError(f"PAYLOAD_REVISIONS mal formado: '{part}' (esperado id=N)")
        pid, rev = part.split("=", 1)
        out[pid.strip()] = int(rev)
    return out


def load_revision(payload_id: str, revision: int) -> dict:
    path = REVISIONS_DIR / f"{payload_id}.r{revision}.json"
    if not path.exists():
        raise FileNotFoundError(f"No existe la revisión {revision} de {payload_id}: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("id") != payload_id or data.get("revision") != revision:
        raise ValueError(f"Fichero de revisión incoherente: {path}")
    return data


def available_revisions(payload_id: str) -> list[int]:
    revs = [1]
    for p in REVISIONS_DIR.glob(f"{payload_id}.r*.json"):
        try:
            revs.append(int(p.name.rsplit(".r", 1)[1].split(".")[0]))
        except ValueError:
            continue
    return sorted(set(revs))


def apply_revisions(payloads: Iterable[dict], source_file: str,
                    spec: Optional[str] = None) -> list[dict]:
    """Devuelve copias de los payloads con ``revision`` y ``_source``,
    sustituyendo las revisiones pedidas explícitamente."""
    wanted = requested_revisions(spec)
    out = []
    ids = set()
    for p in payloads:
        p = dict(p)
        ids.add(p.get("id"))
        rev = wanted.get(p.get("id"))
        if rev and rev != p.get("revision", 1):
            p = load_revision(p["id"], rev)
            p["_source"] = f"lab/payloads/revisions/{p['id']}.r{rev}.json"
        else:
            p.setdefault("revision", 1)
            p["_source"] = source_file
        out.append(p)
    unknown = set(wanted) - ids
    if unknown:
        # Solo es error si ninguno de los ids pedidos pertenece a este conjunto
        # y el id no existe en ningún fichero de revisiones.
        missing = [u for u in unknown if not list(REVISIONS_DIR.glob(f"{u}.r*.json"))]
        if missing:
            raise ValueError(f"PAYLOAD_REVISIONS pide ids sin revisiones: {missing}")
    return out
