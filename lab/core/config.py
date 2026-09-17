"""
lab/core/config.py
==================
Configuración compartida de conexión con Ollama.

Auditoría 2026-09-16 (F-08): antes cada componente leía ``OLLAMA_HOST`` a su
manera (o lo ignoraba). Un valor sin esquema (``host.docker.internal:11434``,
usado en docker-compose para el servicio ``lab``) hacía fallar a ``requests``
con ``InvalidSchema``, y los scripts de experimentos tenían ``localhost``
fijo, por lo que no funcionaban dentro de un contenedor.
"""

from __future__ import annotations

import os

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_NUM_CTX = 127000


def normalize_ollama_url(value: str | None) -> str:
    """Normaliza un valor de OLLAMA_HOST a una URL base utilizable por un cliente.

    - Vacío/None           -> http://localhost:11434
    - "host:11434"         -> http://host:11434
    - "0.0.0.0[:puerto]"   -> http://127.0.0.1[:puerto]  (0.0.0.0 es una
      dirección de escucha de ``ollama serve``, no un destino fiable)
    - Sin puerto           -> se añade :11434
    - Barra final          -> se elimina
    """
    raw = (value or "").strip()
    if not raw:
        return DEFAULT_OLLAMA_URL
    if "://" not in raw:
        raw = f"http://{raw}"
    scheme, rest = raw.split("://", 1)
    rest = rest.rstrip("/")
    hostport = rest.split("/", 1)[0]
    path = rest[len(hostport):]
    host, sep, port = hostport.rpartition(":")
    if not sep or not port.isdigit():
        host, port = hostport, "11434"
    if host in {"0.0.0.0", "[::]", "::"}:
        host = "127.0.0.1"
    return f"{scheme}://{host}:{port}{path}"


def ollama_base_url() -> str:
    """URL base de Ollama según el entorno (leída en cada llamada, no al importar)."""
    return normalize_ollama_url(os.environ.get("OLLAMA_HOST"))


def num_ctx_from_env(default: int = DEFAULT_NUM_CTX) -> int:
    """Valor de ``NUM_CTX`` del entorno; si no es un entero válido, ``default``."""
    try:
        return int(os.environ.get("NUM_CTX", default))
    except (TypeError, ValueError):
        return default
