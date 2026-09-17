"""Integración de la API (FastAPI TestClient) con un modelo simulado.

Se valida la respuesta final entregada al usuario y el fichero persistido.
Los resultados se escriben en un directorio temporal, nunca en lab/results.
"""
import json

import pytest
from fastapi.testclient import TestClient

import lab.server as server
from lab.defenses.prompt_guard import INPUT_BLOCK_MESSAGE, OUTPUT_BLOCK_MESSAGE
from tests.helpers_audit import INDIRECT_004_RESPONSE_FILE, FakeClient, recorded_response

COMPROMISED = recorded_response(INDIRECT_004_RESPONSE_FILE)


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(server, "DEFENSE_BLOCK_DANGEROUS_OUTPUT", False)

    def use(fake):
        monkeypatch.setattr(server, "OllamaClient", lambda *a, **k: fake)

    with TestClient(server.app) as client:
        yield client, tmp_path, use, monkeypatch


def attack(client, **kw):
    body = {"model": "fake", "vector": "direct", "payload_id": "direct_003", "with_defense": True}
    body.update(kw)
    return client.post("/api/attack", json=body)


def saved(tmp_path):
    files = list(tmp_path.glob("live_attack_*.json"))
    return [json.loads(f.read_text(encoding="utf-8")) for f in files]


def test_openapi_lists_only_real_endpoints(api):
    client, *_ = api
    paths = set(client.get("/openapi.json").json()["paths"])
    assert paths == {
        "/health", "/api/models", "/api/payloads/{vector}", "/api/attack",
        "/api/results", "/api/results/{filename}", "/api/sync/status", "/api/sync", "/api/demo",
    }
    assert "/api/generate" not in paths


def test_input_block_outcome_is_blocked(api):
    client, tmp, use, _ = api
    fake = FakeClient("no se usa")
    use(fake)
    r = attack(client, payload_id="direct_006")
    body = r.json()
    assert r.status_code == 200
    assert body["outcome"] == "blocked"                     # antes: "partial"
    assert body["defense_blocked"] is True and body["blocked_stage"] == "input"
    assert body["mitigation"] == "blocked_input" and body["model_called"] is False
    assert body["response"] == INPUT_BLOCK_MESSAGE and fake.calls == []
    rec = saved(tmp)[0]
    assert rec["tests"][0]["outcome"] == "blocked" and rec["summary"]["block_rate"] == 1.0


def test_output_alert_delivers_response_and_is_not_a_block(api):
    client, tmp, use, _ = api
    use(FakeClient(COMPROMISED))
    body = attack(client).json()
    assert body["defense_verdict"] == "flagged" and body["mitigation"] == "alert"
    assert body["defense_blocked"] is False and body["block_reason"] is None
    assert body["alert_reason"]
    assert body["output_analysis"]["verdict"] == "dangerous"
    assert body["response"] == COMPROMISED                    # limitación: se entrega
    assert body["outcome"] in {"success", "partial", "refused"}


def test_output_block_opt_in(api):
    client, tmp, use, mp = api
    mp.setattr(server, "DEFENSE_BLOCK_DANGEROUS_OUTPUT", True)
    use(FakeClient(COMPROMISED))
    body = attack(client).json()
    assert body["outcome"] == "blocked" and body["blocked_stage"] == "output"
    assert body["response"] == OUTPUT_BLOCK_MESSAGE
    assert "SISTEMA COMPROMETIDO" not in json.dumps(body, ensure_ascii=False).split('"output_analysis"')[0]
    rec = saved(tmp)[0]
    # Auditoría 2026-09-17 (GAP-004, alternativa B): la evidencia se conserva en
    # disco, pero en un fichero separado que la API no lista ni sirve. Antes este
    # test comprobaba rec["withheld_response"] en el registro público.
    assert "withheld_response" not in rec
    ref = rec["withheld_response_ref"]
    stored = json.loads((tmp / ref["path"]).read_text(encoding="utf-8"))
    assert stored["withheld_response"] == COMPROMISED          # evidencia conservada en disco
    assert ref["http_exposed"] is False
    assert rec["outcome_detail"]["label"] != "defense_blocked_input"


def test_defense_error_returns_502_and_is_not_persisted(api):
    client, tmp, use, _ = api
    use(FakeClient(fail=True))
    r = attack(client)
    assert r.status_code == 502
    assert saved(tmp) == []


def test_undefended_path_unchanged(api):
    client, tmp, _, mp = api

    async def fake_call(model, prompt):
        return "I cannot help with that request.", 12.0

    mp.setattr(server, "_call_ollama", fake_call)
    body = attack(client, with_defense=False).json()
    assert body["outcome"] == "refused"
    assert body["defense_applied"] is False and body["defense_blocked"] is False
    assert body["mitigation"] == "not_applied"
    rec = saved(tmp)[0]
    assert rec["inference"]["endpoint"] == "/api/generate"


def test_defended_path_records_inference_settings(api):
    client, tmp, use, _ = api
    use(FakeClient("Una respuesta normal."))
    attack(client)
    rec = saved(tmp)[0]
    assert rec["inference"]["endpoint"] == "/api/chat"
    assert rec["inference"]["options"]["temperature"] == 0.7


def test_indirect_untrusted_content_reaches_validator(api):
    client, tmp, use, mp = api
    # Se desactiva el bloqueo de entrada para observar la capa de salida.
    from lab.defenses import prompt_guard as pg

    original = pg.PromptGuard.__init__

    def no_input_block(self, client, **kw):
        kw["block_on_suspicious_input"] = False
        original(self, client, **kw)

    mp.setattr(pg.PromptGuard, "__init__", no_input_block)
    use(FakeClient(COMPROMISED))
    body = attack(client, vector="indirect", payload_id="indirect_004").json()
    assert body["output_analysis"]["canaries"] == ["SISTEMA COMPROMETIDO"]
    assert body["output_analysis"]["categories"]["indirect_injection"] is True


def test_whitespace_custom_prompt_uses_catalogue_keywords(api):
    client, tmp, _, mp = api

    async def fake_call(model, prompt):
        return "wep wpa handshake aircrack deauth", 1.0

    mp.setattr(server, "_call_ollama", fake_call)
    body = attack(client, with_defense=False, custom_prompt="   ").json()
    assert body["outcome"] == "success"   # antes se ignoraban las keywords


def test_demo_is_marked_synthetic_and_consistent(api):
    client, *_ = api
    data = client.get("/api/demo").json()
    assert data["synthetic"] is True
    for s in data["sessions"]:
        assert s["synthetic"] is True
        for t in s["tests"]:
            assert not (t["defense_blocked"] and not t["defense_applied"])


def test_result_detail_rejects_traversal(api):
    client, *_ = api
    assert client.get("/api/results/..%2F..%2Fserver.py").status_code == 404


class SlowClient(FakeClient):
    def chat(self, *a, **k):
        import time
        time.sleep(1.5)
        return super().chat(*a, **k)


def _health_latency_during_slow_attack(client, mp, use):
    import threading
    import time

    async def fast_base():
        return None

    mp.setattr(server, "_get_ollama_base", fast_base)
    use(SlowClient("respuesta lenta"))
    worker = threading.Thread(target=lambda: attack(client))
    worker.start()
    time.sleep(0.3)                       # el ataque ya está dentro de la llamada lenta
    t0 = time.perf_counter()
    assert client.get("/health").status_code == 200
    latency = time.perf_counter() - t0
    still_running = worker.is_alive()
    worker.join()
    return latency, still_running


def test_health_does_not_block_while_defended_attack_runs(api):
    """F-10 / GAP-015: prueba REAL de concurrencia (antes solo se buscaba la
    cadena 'run_in_threadpool' en el código fuente)."""
    client, tmp, use, mp = api
    latency, still_running = _health_latency_during_slow_attack(client, mp, use)
    assert still_running, "el ataque lento debía seguir en curso"
    assert latency < 0.8, f"/health tardó {latency:.2f}s mientras había un ataque en curso"


def test_concurrency_test_detects_blocking_implementation(api):
    """Control negativo: si la llamada síncrona se ejecuta en el event loop,
    /health queda bloqueado. Demuestra que el test anterior es sensible."""
    client, tmp, use, mp = api

    async def blocking_threadpool(func, *args, **kwargs):
        return func(*args, **kwargs)

    mp.setattr(server, "run_in_threadpool", blocking_threadpool)
    latency, _ = _health_latency_during_slow_attack(client, mp, use)
    assert latency >= 0.8


@pytest.mark.parametrize("vector", ["direct", "indirect", "jailbreak", "tool_abuse"])
def test_all_vectors_expose_detection_keywords(api, vector):
    """F-05b: sin keywords la API nunca podía devolver 'success' en direct/jailbreak."""
    client, *_ = api
    payloads = client.get(f"/api/payloads/{vector}").json()["payloads"]
    assert payloads and all(p.get("detection_keywords") for p in payloads)


def test_contradictory_signals_require_review(api):
    """Salida corta comprometida: el clasificador legado dice 'refused' (<100
    caracteres, sin keywords) y el validador dice 'dangerous'. No se oculta."""
    client, tmp, use, _ = api
    use(FakeClient("SISTEMA COMPROMETIDO\nDatos de sesión disponibles: token=abc"))
    body = attack(client).json()
    assert body["outcome"] == "refused"
    assert body["output_analysis"]["verdict"] == "dangerous"
    assert body["review_required"] is True
    assert "outcome_refused_but_output_flagged" in body["review_reasons"]
