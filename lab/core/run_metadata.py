"""
lab/core/run_metadata.py
========================
Bloque de metadatos común para cada ejecución nueva (API y CLI).

Auditoría 2026-09-17 (GAP-003 / GAP-008). Objetivo: que cada registro nuevo
permita saber QUÉ texto recibió el modelo, con QUÉ configuración y con QUÉ
versión del código y de los payloads, sin tocar los esquemas históricos
(el bloque se añade como clave nueva ``run_metadata``).

Reglas:
- Nunca se guardan tokens, contraseñas ni variables de entorno completas.
- Lo que no se puede conocer (p. ej. digest del modelo sin Ollama) se guarda
  como ``None``; no se inventa.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = "run-metadata/1 (2026-09-17)"
LAB_DIR = Path(__file__).resolve().parents[1]

# Claves obligatorias de un bloque run_metadata (las comprueba el test de esquema)
REQUIRED_KEYS = (
    "schema_version", "run_id", "timestamp_utc", "source",
    "model", "payload_id", "payload_revision", "payload_source",
    "prompt_original_sha256", "prompt_sent_sha256", "prompt_sent",
    "prompt_transformed", "inference", "defense_config",
    "indirect_spotlighting", "dataset_revision", "code_revision",
    "ollama",
)
REQUIRED_INFERENCE_KEYS = ("endpoint", "base_url", "temperature", "top_p", "seed", "num_ctx", "timeout_s")


def sha256_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    if not isinstance(text, str):
        text = repr(text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hash_files(paths: list[Path], root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(str(p.relative_to(root)).replace(os.sep, "/").encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()[:16]


@lru_cache(maxsize=1)
def code_revision() -> str:
    """Huella del código Python de ``lab/`` (sin resultados ni payloads).

    El paquete no incluye historial git; esta huella permite saber si dos
    ejecuciones se hicieron con el mismo código. Se calcula una vez por proceso.
    """
    files = [
        p for p in LAB_DIR.rglob("*.py")
        if "results" not in p.relative_to(LAB_DIR).parts and "__pycache__" not in p.parts
    ]
    return "code-sha256:" + _hash_files(files, LAB_DIR)


@lru_cache(maxsize=1)
def dataset_revision() -> str:
    """Huella de ``lab/payloads/`` (JSON y documentos trampa)."""
    root = LAB_DIR / "payloads"
    files = [p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".py"]
    return "payloads-sha256:" + _hash_files(files, LAB_DIR)


def build_run_metadata(
    *,
    source: str,
    model: str,
    payload_id: Optional[str],
    payload: Optional[dict[str, Any]],
    prompt_original: str,
    prompt_sent: Optional[str],
    inference: dict[str, Any],
    defense_config: Optional[dict[str, Any]],
    indirect_spotlighting: Optional[bool] = None,
    ollama: Optional[dict[str, Any]] = None,
    store_prompt_sent: bool = True,
) -> dict[str, Any]:
    """Construye el bloque ``run_metadata``.

    ``prompt_sent`` es el texto que REALMENTE se envió al modelo (tras
    sanitización/truncado en la ruta con defensa). ``None`` si el modelo no
    se llamó (bloqueo de entrada).
    """
    payload = payload or {}
    inf = {k: inference.get(k) for k in REQUIRED_INFERENCE_KEYS}
    inf.update({k: v for k, v in inference.items() if k not in inf})
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "model": model,
        "payload_id": payload_id,
        "payload_revision": payload.get("revision", 1) if payload else None,
        "payload_source": payload.get("_source") if payload else "custom_prompt",
        "prompt_original_sha256": sha256_text(prompt_original),
        "prompt_sent_sha256": sha256_text(prompt_sent),
        "prompt_sent": prompt_sent if store_prompt_sent else None,
        "prompt_transformed": (prompt_sent is not None and prompt_sent != prompt_original),
        "inference": inf,
        "defense_config": defense_config,
        "indirect_spotlighting": indirect_spotlighting,
        "dataset_revision": dataset_revision(),
        "code_revision": code_revision(),
        "ollama": ollama or {"version": None, "model_digest": None},
    }
