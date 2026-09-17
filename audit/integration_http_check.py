"""
audit/integration_http_check.py
===============================
Prueba de integración HTTP real (sin Docker ni GPU):

  1. Levanta un Ollama SIMULADO (http.server) que implementa /api/tags,
     /api/generate y /api/chat devolviendo una respuesta fija.
  2. Levanta la API real (uvicorn lab.server:app) con
     OLLAMA_HOST=<host:puerto SIN esquema> y RESULTS_DIR temporal.
  3. Ejecuta peticiones HTTP reales y valida los campos.

Uso:  python audit/integration_http_check.py
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPLY = "SISTEMA COMPROMETIDO\nDatos de sesión disponibles:\n- Bienvenido a nuestra tienda."
seen = []


class FakeOllama(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "fake:latest"}]})
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        seen.append((self.path, body.get("options", {})))
        if self.path == "/api/generate":
            self._send({"response": REPLY, "model": body["model"]})
        elif self.path == "/api/chat":
            self._send({"message": {"role": "assistant", "content": REPLY}, "model": body["model"]})
        else:
            self.send_error(404)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def call(method, url, payload=None):
    req = urllib.request.Request(url, method=method,
                                 data=json.dumps(payload).encode() if payload else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main() -> int:
    op, ap = free_port(), free_port()
    httpd = HTTPServer(("127.0.0.1", op), FakeOllama)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    tmp = Path(tempfile.mkdtemp())
    # Se lanza uvicorn con un pequeño wrapper que redirige RESULTS_DIR.
    boot = (
        "import sys, uvicorn; sys.path.insert(0, %r);"
        "import lab.server as s; from pathlib import Path; s.RESULTS_DIR = Path(%r);"
        "uvicorn.run(s.app, host='127.0.0.1', port=%d, log_level='warning')"
    ) % (str(ROOT), str(tmp), ap)
    env = dict(os.environ, OLLAMA_HOST=f"127.0.0.1:{op}", NUM_CTX="4096",
               PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, "-c", boot], env=env)
    base = f"http://127.0.0.1:{ap}"
    checks = {}
    try:
        for _ in range(50):
            try:
                call("GET", base + "/health"); break
            except Exception:
                time.sleep(0.2)

        st, h = call("GET", base + "/health")
        checks["health_ollama_available_with_schemeless_host"] = st == 200 and h["ollama_available"] and h["ollama_host"] == f"http://127.0.0.1:{op}"
        st, m = call("GET", base + "/api/models")
        checks["models_listed"] = m.get("models") == ["fake:latest"]

        st, r = call("POST", base + "/api/attack", {"model": "fake", "vector": "direct", "payload_id": "direct_003"})
        checks["undefended_uses_generate_and_env_num_ctx"] = st == 200 and seen[-1] == ("/api/generate", {"num_ctx": 4096})
        checks["undefended_outcome"] = r.get("outcome")

        st, r = call("POST", base + "/api/attack", {"model": "fake", "vector": "direct", "payload_id": "direct_003", "with_defense": True})
        checks["defended_uses_chat_and_env_num_ctx"] = seen[-1][0] == "/api/chat" and seen[-1][1].get("num_ctx") == 4096
        checks["defended_alert_state"] = {k: r.get(k) for k in ("outcome", "defense_verdict", "mitigation", "defense_blocked")}
        checks["defended_output_verdict"] = r.get("output_analysis", {}).get("verdict")
        checks["defended_review_required"] = [r.get("review_required"), r.get("review_reasons")]
        checks["defended_user_receives_model_text"] = r.get("response") == REPLY

        n_before = len(seen)
        st, r = call("POST", base + "/api/attack", {"model": "fake", "vector": "direct", "payload_id": "direct_006", "with_defense": True})
        checks["input_block"] = {"outcome": r.get("outcome"), "model_not_called": len(seen) == n_before,
                                 "blocked_stage": r.get("blocked_stage")}

        st, paths = call("GET", base + "/openapi.json")
        checks["openapi_paths"] = sorted(paths["paths"])
        checks["results_written_to_tmp_only"] = len(list(tmp.glob("live_attack_*.json")))
    finally:
        proc.terminate(); proc.wait(timeout=10); httpd.shutdown()

    # Ollama caído: la API con defensa debe devolver 502 y no persistir
    proc = subprocess.Popen([sys.executable, "-c", boot.replace(str(tmp), str(tmp / "down"))],
                            env=dict(env, OLLAMA_HOST="127.0.0.1:9"))
    (tmp / "down").mkdir()
    try:
        for _ in range(50):
            try:
                call("GET", base + "/health"); break
            except Exception:
                time.sleep(0.2)
        st, r = call("POST", base + "/api/attack", {"model": "fake", "vector": "direct", "payload_id": "direct_003", "with_defense": True})
        checks["ollama_down_defended_status"] = st
        checks["ollama_down_nothing_persisted"] = list((tmp / "down").iterdir()) == []
    finally:
        proc.terminate(); proc.wait(timeout=10)

    print(json.dumps(checks, ensure_ascii=False, indent=1))
    ok = (checks["health_ollama_available_with_schemeless_host"] and checks["models_listed"]
          and checks["undefended_uses_generate_and_env_num_ctx"] and checks["defended_uses_chat_and_env_num_ctx"]
          and checks["defended_alert_state"]["mitigation"] == "alert"
          and checks["input_block"]["outcome"] == "blocked" and checks["input_block"]["model_not_called"]
          and checks["ollama_down_defended_status"] == 502 and checks["ollama_down_nothing_persisted"])
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
