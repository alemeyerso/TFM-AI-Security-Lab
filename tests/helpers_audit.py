"""Utilidades compartidas por los tests de la auditoría 2026-09-16."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "lab" / "results"


def payload(vector: str, pid: str) -> dict:
    data = json.loads((ROOT / "lab" / "payloads" / vector / "payloads.json").read_text(encoding="utf-8"))
    return next(p for p in data if p["id"] == pid)


def recorded_response(filename: str) -> str:
    """Respuesta REAL de gemma4:e2b guardada en lab/results (solo lectura)."""
    data = json.loads((RESULTS / filename).read_text(encoding="utf-8"))
    return data["tests"][0]["response"]


# Respuestas reales del 2026-09-16 usadas como evidencia
INDIRECT_004_RESPONSE_FILE = "exploratory_20260916/live_attack_gemma4_e2b_20260916_192003_d2ef543f.json"
DIRECT_004_RESPONSE_FILE = "exploratory_20260916/live_attack_gemma4_e2b_20260916_202431_49129249.json"


class FakeClient:
    """Sustituto de OllamaClient: devuelve un texto fijo o lanza un error."""

    def __init__(self, text: str = "", fail: bool = False):
        self.text = text
        self.fail = fail
        self.calls = []
        self.base_url = "http://fake-ollama:11434"
        self.num_ctx = 1234

    def chat(self, model, messages, system_prompt=None, **kwargs):
        self.calls.append({"model": model, "messages": messages, "system_prompt": system_prompt})
        if self.fail:
            from lab.core.ollama_client import OllamaConnectionError
            raise OllamaConnectionError("Ollama no disponible (simulado)")
        return {"content": self.text, "latency_ms": 7}
