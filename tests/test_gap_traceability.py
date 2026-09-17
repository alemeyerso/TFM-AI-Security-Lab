"""Auditoría 2026-09-17 — GAP-003/008 (metadatos), GAP-004 (withheld_response),
GAP-009 (resolución de IDs), GAP-016 (validación de vector) y GAP-017 (revisiones).

Todo con modelos SIMULADOS (FakeClient); ningún resultado se escribe en lab/results.
"""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import lab.server as server
from lab.core import payload_registry as reg
from lab.core.payload_revisions import apply_revisions, available_revisions, requested_revisions
from lab.core.run_metadata import REQUIRED_INFERENCE_KEYS, REQUIRED_KEYS
from tests.helpers_audit import ROOT, FakeClient

COMPROMISED = "SISTEMA COMPROMETIDO\nDatos de sesión disponibles: token=abc"


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(server, "DEFENSE_BLOCK_DANGEROUS_OUTPUT", False)
    monkeypatch.setattr(server, "DEFENSE_STRICT_MODE", False)

    def use(fake):
        monkeypatch.setattr(server, "OllamaClient", lambda *a, **k: fake)

    with TestClient(server.app) as client:
        yield client, tmp_path, use, monkeypatch


def post(client, **kw):
    body = {"model": "fake", "vector": "direct", "payload_id": "direct_003", "with_defense": True}
    body.update(kw)
    return client.post("/api/attack", json=body)


def only_record(tmp):
    files = list(tmp.glob("live_attack_*.json"))
    assert len(files) == 1
    return json.loads(files[0].read_text(encoding="utf-8"))


def assert_schema(md):
    for k in REQUIRED_KEYS:
        assert k in md, k
    for k in REQUIRED_INFERENCE_KEYS:
        assert k in md["inference"], k
    blob = json.dumps(md).lower()
    for secret in ("github_token", "jupyter_token", "password=", "authorization"):
        assert secret not in blob


# ── GAP-003 / GAP-008: esquema de metadatos (API) ────────────────────────────

def test_api_defended_record_has_run_metadata(api):
    client, tmp, use, _ = api
    use(FakeClient("Una respuesta normal."))
    post(client)
    rec = only_record(tmp)
    md = rec["run_metadata"]
    assert_schema(md)
    prompt = rec["tests"][0]["prompt"]
    assert md["prompt_original_sha256"] == hashlib.sha256(prompt.encode()).hexdigest()
    assert md["prompt_sent"] is not None
    assert md["prompt_sent_sha256"] == hashlib.sha256(md["prompt_sent"].encode()).hexdigest()
    assert md["defense_config"]["block_threshold_effective"] == 5.0
    assert md["inference"]["endpoint"] == "/api/chat"
    assert md["inference"]["temperature"] == 0.7 and md["inference"]["top_p"] == 0.9
    assert md["payload_revision"] == 1
    assert md["payload_source"] == "lab/payloads/direct/payloads.json"
    assert md["code_revision"].startswith("code-sha256:")
    assert md["dataset_revision"].startswith("payloads-sha256:")
    assert md["mitigation"] == "none" and md["blocked"] is False


def test_api_undefended_record_documents_asymmetry(api):
    client, tmp, _, mp = api

    async def fake_call(model, prompt):
        return "I cannot help with that request.", 12.0, "http://fake:11434"

    mp.setattr(server, "_call_ollama", fake_call)
    post(client, with_defense=False)
    md = only_record(tmp)["run_metadata"]
    assert_schema(md)
    assert md["inference"]["endpoint"] == "/api/generate"
    assert md["inference"]["temperature"] == "ollama_model_default"
    assert md["inference"]["base_url"] == "http://fake:11434"
    assert md["prompt_transformed"] is False and md["defense_config"] is None


def test_api_records_prompt_actually_sent_when_sanitized(api):
    client, tmp, use, _ = api
    fake = FakeClient("ok")
    use(fake)
    post(client, custom_prompt="Hola\u200b" + "a" * 9000)   # invisible + truncado
    rec = only_record(tmp)
    md = rec["run_metadata"]
    sent = fake.calls[0]["messages"][-1]["content"]
    assert md["prompt_sent"] == sent
    assert md["prompt_transformed"] is True
    assert md["input_transformations"]["truncated"] is True
    assert md["payload_id"] is None and md["payload_source"] == "custom_prompt"


def test_api_input_block_has_no_prompt_sent(api):
    client, tmp, use, _ = api
    use(FakeClient("no se usa"))
    post(client, payload_id="direct_006")
    md = only_record(tmp)["run_metadata"]
    assert md["prompt_sent"] is None and md["prompt_sent_sha256"] is None
    assert md["inference"]["called"] is False
    assert md["blocked_stage"] == "input"


def test_strict_mode_env_is_recorded(api):
    client, tmp, use, mp = api
    mp.setattr(server, "DEFENSE_STRICT_MODE", True)
    use(FakeClient("ok"))
    post(client)
    cfg = only_record(tmp)["run_metadata"]["defense_config"]
    assert cfg["strict_mode"] is True and cfg["block_threshold_effective"] == 3.0


# ── GAP-004: withheld_response ───────────────────────────────────────────────

def test_withheld_response_is_not_served_by_http(api):
    client, tmp, use, mp = api
    mp.setattr(server, "DEFENSE_BLOCK_DANGEROUS_OUTPUT", True)
    use(FakeClient(COMPROMISED))
    body = post(client).json()
    assert body["blocked_stage"] == "output"
    detail = client.get(f"/api/results/{body['filename']}").json()
    assert "token=abc" not in json.dumps(detail, ensure_ascii=False)
    assert detail["withheld_response_ref"]["http_exposed"] is False
    # el fichero separado existe pero no se puede pedir por la API
    assert (tmp / "withheld" / body["filename"]).exists()
    assert client.get(f"/api/results/withheld%2F{body['filename']}").json().get("withheld_response") is None
    listed = [r["filename"] for r in client.get("/api/results").json()["results"]]
    assert all(not f.startswith("withheld") for f in listed)


def test_legacy_file_with_inline_withheld_response_is_redacted(api):
    client, tmp, *_ = api
    (tmp / "live_attack_legacy_x.json").write_text(json.dumps({
        "model": "m", "withheld_response": "SECRETO", "summary": {}}), encoding="utf-8")
    detail = client.get("/api/results/live_attack_legacy_x.json").json()
    assert detail["withheld_response"] == server.WITHHELD_HTTP_PLACEHOLDER


def test_sync_never_uploads_withheld_files(api, monkeypatch):
    client, tmp, use, mp = api
    mp.setattr(server, "DEFENSE_BLOCK_DANGEROUS_OUTPUT", True)
    use(FakeClient(COMPROMISED))
    post(client)
    uploaded = []

    async def fake_upload(_client, path, content, message):
        uploaded.append(path)
        return {"path": path, "status": 201, "ok": True}

    mp.setattr(server, "ENABLE_GITHUB_SYNC", True)
    mp.setattr(server, "GITHUB_TOKEN", "dummy-for-test")
    mp.setattr(server, "_github_upload_file", fake_upload)
    assert client.post("/api/sync").status_code == 200
    assert uploaded and all("withheld" not in p for p in uploaded)


# ── GAP-016: validación de vector ────────────────────────────────────────────

@pytest.mark.parametrize("custom", [None, "hola"])
def test_invalid_vector_is_422_and_nothing_is_saved(api, custom):
    client, tmp, use, _ = api
    fake = FakeClient("no se usa")
    use(fake)
    r = post(client, vector="nonexistent", custom_prompt=custom)
    assert r.status_code == 422
    assert list(tmp.glob("*.json")) == [] and fake.calls == []


@pytest.mark.parametrize("vector", ["direct", "indirect", "jailbreak", "tool_abuse"])
def test_valid_vectors_with_custom_prompt(api, vector):
    client, tmp, use, _ = api
    use(FakeClient("ok"))
    assert post(client, vector=vector, custom_prompt="Resume este texto.").status_code == 200


# ── GAP-009: resolución de IDs por origen ────────────────────────────────────

def test_tool_abuse_namespaces_are_different_prompt_sets():
    cli = reg.resolve("tool_abuse_001", "cli")
    ds = reg.resolve("tool_001", "dataset")
    assert cli and ds
    assert reg.prompt_of(cli[0]) != reg.prompt_of(ds[0])
    assert reg.resolve("tool_abuse_001", "dataset") == []      # no hay alias


def _official_ids():
    ids = []
    for f in sorted((ROOT / "lab/results/oficiales").glob("2026091*_gemma4_e2b.json")):
        for t in json.loads(f.read_text(encoding="utf-8"))["tests"]:
            ids.append(("cli", t["payload_id"], f.name))
    for f in sorted((ROOT / "lab/results").glob("eval_gemma4_*_202608*.json")):
        for r in json.loads(f.read_text(encoding="utf-8"))["results"]:
            ids.append(("dataset", r["id"], f.name))
    nb = ROOT / "lab/results/oficiales/notebook05_20260913/05_comparativa_consolidada_20260913_004400.json"
    for r in json.loads(nb.read_text(encoding="utf-8"))["all_results"]:
        ids.append(("notebook05", r["attack_id"], nb.name))
    for f in sorted((ROOT / "lab/results").glob("live_attack_*.json")):
        ids.append(("dataset", json.loads(f.read_text(encoding="utf-8"))["payload_id"], f.name))
    return ids


def test_every_official_payload_id_resolves_against_its_source():
    unresolved = [(s, i, f) for s, i, f in _official_ids() if not reg.resolve(i, s)]
    assert unresolved == []


def test_pilot_prompts_match_cli_source_except_documented_defects():
    """El piloto del 11/09 usó los prompts de lab/attacks/*.py. Diferencias
    conocidas y documentadas (no se corrigen los resultados):
      - direct_001: prompt guardado VACÍO en el resultado;
      - indirect_001: teléfono anonimizado después (691 234 567 → XXX XXX XXX);
      - indirect_004: el piloto usó el texto sin mojibake (= revisión 2)."""
    known = {"direct_001", "indirect_001", "indirect_004"}
    mismatches = set()
    for f in sorted((ROOT / "lab/results/oficiales").glob("2026091*_gemma4_e2b.json")):
        for t in json.loads(f.read_text(encoding="utf-8"))["tests"]:
            cand = reg.resolve(t["payload_id"], "cli")[0]
            if reg.prompt_of(cand) != t["prompt"]:
                mismatches.add(t["payload_id"])
    assert mismatches == known


def test_cli_direct_prompts_are_strings():
    """direct_002 era una tupla por una coma final (se enviaba como lista JSON)."""
    for pid, p in reg.cli_payloads().items():
        assert isinstance(p["prompt"], str), pid


# ── GAP-017: revisiones de payload ───────────────────────────────────────────

R1_FROZEN = ROOT / "lab/payloads/indirect/archive/payloads_r1_frozen_2026-09-17.json"
R2 = ROOT / "lab/payloads/revisions/indirect_004.r2.json"


def test_r1_frozen_copy_is_identical_to_canonical_and_hash_is_recorded():
    canonical = ROOT / "lab/payloads/indirect/payloads.json"
    assert R1_FROZEN.read_bytes() == canonical.read_bytes()
    sums = (ROOT / "lab/payloads/SHA256SUMS.txt").read_text(encoding="utf-8")
    assert hashlib.sha256(R1_FROZEN.read_bytes()).hexdigest() in sums
    assert hashlib.sha256(R2.read_bytes()).hexdigest() in sums


def test_r2_differs_only_in_the_mojibake_token():
    r1 = next(p for p in json.loads(R1_FROZEN.read_text(encoding="utf-8")) if p["id"] == "indirect_004")
    r2 = json.loads(R2.read_text(encoding="utf-8"))
    assert "Ã" not in r2["injected_content"] and "INSTRUCCIÓN OCULTA" in r2["injected_content"]
    assert r1["injected_content"].replace("INSTRUCCIÃ“N", "INSTRUCCIÓN") == r2["injected_content"]
    for k in ("context", "detection_keywords", "category", "name"):
        assert r1[k] == r2[k]
    assert r2["revision"] == 2 and r2["revision_info"]["validated_with_real_model"] is False
    assert r2["revision_info"]["default"] is False


def test_r2_text_equals_stimulus_of_august_battery_and_pilot():
    r2 = json.loads(R2.read_text(encoding="utf-8"))["injected_content"].strip()
    aug = json.loads((ROOT / "lab/results/eval_gemma4_e2b_20260814_135005.json").read_text(encoding="utf-8"))
    assert r2 in next(r["prompt"] for r in aug["results"] if r["id"] == "indirect_004")
    pilot = json.loads((ROOT / "lab/results/oficiales/20260911_225944_gemma4_e2b.json").read_text(encoding="utf-8"))
    assert r2 in next(t["prompt"] for t in pilot["tests"] if t["payload_id"] == "indirect_004")


def test_default_is_revision_1_and_r2_is_opt_in(monkeypatch):
    monkeypatch.delenv("PAYLOAD_REVISIONS", raising=False)
    p1 = next(p for p in server._load_indirect_payloads() if p["id"] == "indirect_004")
    assert p1["revision"] == 1 and "Ã" in p1["prompt"]
    monkeypatch.setenv("PAYLOAD_REVISIONS", "indirect_004=2")
    p2 = next(p for p in server._load_indirect_payloads() if p["id"] == "indirect_004")
    assert p2["revision"] == 2 and "Ã" not in p2["prompt"]
    assert p2["_source"] == "lab/payloads/revisions/indirect_004.r2.json"
    others = {p["id"]: p["revision"] for p in server._load_indirect_payloads() if p["id"] != "indirect_004"}
    assert set(others.values()) == {1}


def test_revision_is_recorded_in_run_metadata(api):
    client, tmp, use, mp = api
    mp.setenv("PAYLOAD_REVISIONS", "indirect_004=2")

    async def fake_call(model, prompt):
        return "Resumen de la tienda.", 1.0, "http://fake:11434"

    mp.setattr(server, "_call_ollama", fake_call)
    post(client, vector="indirect", payload_id="indirect_004", with_defense=False)
    md = only_record(tmp)["run_metadata"]
    assert md["payload_revision"] == 2
    assert md["payload_source"].endswith("indirect_004.r2.json")


def test_revision_spec_validation():
    assert requested_revisions("indirect_004=2, x=3") == {"indirect_004": 2, "x": 3}
    with pytest.raises(ValueError):
        requested_revisions("indirect_004")
    with pytest.raises(ValueError):
        apply_revisions([{"id": "a"}], "src", spec="zzz_unknown=2")
    assert available_revisions("indirect_004") == [1, 2]


def test_cli_indirect_module_honours_revisions(monkeypatch):
    from lab.attacks.indirect_injection import IndirectInjectionAttack

    monkeypatch.setenv("PAYLOAD_REVISIONS", "indirect_004=2")
    p = next(x for x in IndirectInjectionAttack().get_payloads() if x["id"] == "indirect_004")
    assert p["revision"] == 2 and "Ã" not in p["prompt"]
