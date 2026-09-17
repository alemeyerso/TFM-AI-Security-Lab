"""Auditoría 2026-09-17: el evaluador falla de forma explícita (AUD-34/35/36)."""
import pytest

from lab.core.evaluator import Evaluator


def test_invalid_vector_raises():
    with pytest.raises(ValueError):
        Evaluator(model="x", vectors=["direct", "direkt"])


def test_empty_vectors_raises():
    with pytest.raises(ValueError):
        Evaluator(model="x", vectors=[])


def test_defense_init_failure_raises(monkeypatch):
    import lab.defenses.prompt_guard as pg

    def boom(*a, **k):
        raise ImportError("simulado")

    monkeypatch.setattr(pg, "PromptGuard", boom)
    with pytest.raises(RuntimeError):
        Evaluator(model="x", vectors=["direct"], with_defense=True)


def test_missing_module_raises(monkeypatch):
    ev = Evaluator(model="x", vectors=["direct"])
    monkeypatch.setattr(ev, "_load_attack_module", lambda v: None)
    with pytest.raises(RuntimeError):
        ev._run_vector("direct")
