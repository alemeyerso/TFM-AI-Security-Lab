"""Auditoría 2026-09-17 — GAP-010 (sin datos sintéticos silenciosos) y
GAP-008/GAP-015 (prueba de extremo a extremo del CLI con cliente simulado).

Se redirigen todos los directorios de resultados a tmp_path.
"""
import csv
import json

import pytest
from click.testing import CliRunner

import lab.core.evaluator as evaluator_mod
import lab.core.ollama_client as oc
import run_lab
from lab.core.run_metadata import REQUIRED_KEYS
from tests.helpers_audit import FakeClient


class CliFakeClient(FakeClient):
    """Cliente simulado con la interfaz que usan run_lab y Evaluator."""

    def __init__(self, text="I cannot help with that request.", available=True, fail=False):
        super().__init__(text, fail=fail)
        self.available = available
        self.last_request = {"endpoint": "/api/chat", "base_url": self.base_url, "temperature": 0.7,
                             "top_p": 0.9, "seed": None, "num_ctx": self.num_ctx, "timeout_s": 1}

    def is_available(self):
        return self.available

    def model_exists(self, model):
        return self.available

    def list_models(self):
        return ["fake"] if self.available else []


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    results = tmp_path / "results"
    monkeypatch.setattr(run_lab, "RESULTS_DIR", results)
    monkeypatch.setattr(run_lab, "RUNS_DIR", results / "runs")
    monkeypatch.setattr(run_lab, "DEMO_DIR", results / "demo")
    monkeypatch.setattr(evaluator_mod, "RESULTS_DIR", results / "runs")
    return results


def use_client(monkeypatch, client):
    monkeypatch.setattr(oc, "OllamaClient", lambda *a, **k: client)
    monkeypatch.setattr(evaluator_mod, "OllamaClient", lambda *a, **k: client)


def all_files(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()) if root.exists() else []


# ── GAP-010 ──────────────────────────────────────────────────────────────────

def test_compare_without_ollama_fails_and_writes_nothing(dirs, monkeypatch):
    use_client(monkeypatch, CliFakeClient(available=False))
    r = CliRunner().invoke(run_lab.cli, ["--compare", "--models", "m1", "--vector", "direct"])
    assert r.exit_code == 1
    assert "No se generan datos sintéticos" in r.output
    assert all_files(dirs) == []


def test_compare_exception_does_not_silently_switch_to_demo(dirs, monkeypatch):
    class Boom(CliFakeClient):
        def chat(self, *a, **k):
            raise RuntimeError("fallo simulado")

    use_client(monkeypatch, Boom())
    monkeypatch.setattr(evaluator_mod.Evaluator, "run", lambda self: (_ for _ in ()).throw(RuntimeError("x")))
    r = CliRunner().invoke(run_lab.cli, ["--compare", "--models", "m1", "--vector", "direct"])
    assert r.exit_code == 1
    assert not any(f.startswith("demo/") for f in all_files(dirs))


def test_compare_allow_demo_writes_only_to_demo_dir_and_marks_it(dirs, monkeypatch):
    use_client(monkeypatch, CliFakeClient(available=False))
    r = CliRunner().invoke(run_lab.cli, ["--compare", "--models", "m1", "--vector", "direct", "--allow-demo"])
    assert r.exit_code == 0, r.output
    files = all_files(dirs)
    assert files and all(f.startswith("demo/") and f.endswith("_demo.json") for f in files)
    data = json.loads((dirs / files[0]).read_text(encoding="utf-8"))
    assert data["synthetic"] is True and data["demo"] is True
    assert "DATOS SINTÉTICOS" in r.output and "DEMO SINTÉTICO" in r.output


def test_scenario_without_ollama_fails(dirs, monkeypatch):
    use_client(monkeypatch, CliFakeClient(available=False))
    r = CliRunner().invoke(run_lab.cli, ["--scenario", "1", "--model", "m1"])
    assert r.exit_code == 1
    assert all_files(dirs) == []


def test_demo_command_goes_to_demo_dir(dirs):
    r = CliRunner().invoke(run_lab.cli, ["--demo", "--vector", "direct"])
    assert r.exit_code == 0, r.output
    assert all(f.startswith("demo/") for f in all_files(dirs))


def test_strict_flags_require_defense(dirs):
    r = CliRunner().invoke(run_lab.cli, ["--vector", "direct", "--strict-mode"])
    assert r.exit_code == 2


def test_compare_real_run_saves_once_in_runs(dirs, monkeypatch):
    use_client(monkeypatch, CliFakeClient())
    r = CliRunner().invoke(run_lab.cli, ["--compare", "--models", "m1", "--vector", "direct"])
    assert r.exit_code == 0, r.output
    files = all_files(dirs)
    assert len([f for f in files if f.endswith(".json")]) == 1    # sin doble guardado
    assert all(f.startswith("runs/") for f in files)


# ── GAP-008 / GAP-015: E2E del CLI con defensa ───────────────────────────────

def test_cli_defended_run_end_to_end(dirs, monkeypatch):
    fake = CliFakeClient("I cannot help with that request.")
    use_client(monkeypatch, fake)
    r = CliRunner().invoke(run_lab.cli, ["--model", "m1", "--vector", "direct", "--with-defense",
                                         "--strict-mode"])
    assert r.exit_code == 0, r.output
    files = all_files(dirs)
    js = [f for f in files if f.endswith(".json")]
    cs = [f for f in files if f.endswith(".csv")]
    assert len(js) == 1 and len(cs) == 1 and js[0].startswith("runs/")
    data = json.loads((dirs / js[0]).read_text(encoding="utf-8"))
    tests = data["tests"]
    assert len(tests) == 10
    outcomes = {t["outcome"] for t in tests}
    assert "blocked" in outcomes                     # direct_006 / direct_010 superan 3.0
    for t in tests:
        md = t["metadata"]
        for k in REQUIRED_KEYS:
            assert k in md, k
        assert md["defense_config"]["strict_mode"] is True
        assert md["defense_config"]["block_threshold_effective"] == 3.0
        assert md["mitigation"] in {"none", "alert", "blocked_input", "blocked_output"}
        if t["outcome"] == "blocked":
            assert md["prompt_sent"] is None and md["blocked_stage"] == "input"
        else:
            assert md["prompt_sent"] is not None
    with open(dirs / cs[0], encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 10
    for col in ("mitigation", "blocked_stage", "strict_mode", "block_threshold_effective",
                "prompt_sent_sha256", "payload_revision", "input_risk_score"):
        assert col in rows[0], col
    assert {r["mitigation"] for r in rows} >= {"blocked_input"}
    # los prompts enviados al modelo son exactamente los registrados
    sent = [c["messages"][-1]["content"] for c in fake.calls]
    recorded = [t["metadata"]["prompt_sent"] for t in tests if t["metadata"]["prompt_sent"]]
    assert sent == recorded


def test_cli_undefended_run_records_metadata(dirs, monkeypatch):
    use_client(monkeypatch, CliFakeClient())
    r = CliRunner().invoke(run_lab.cli, ["--model", "m1", "--vector", "tool_abuse"])
    assert r.exit_code == 0, r.output
    js = [f for f in all_files(dirs) if f.endswith(".json")][0]
    t = json.loads((dirs / js).read_text(encoding="utf-8"))["tests"][0]
    assert t["metadata"]["defense_config"] is None
    assert t["metadata"]["mitigation"] == "not_applied"
    assert t["metadata"]["inference"]["endpoint"] == "/api/chat"
