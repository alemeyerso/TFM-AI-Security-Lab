from pathlib import Path
import json

import pytest

from lab.core.metrics import Metrics


def make_metrics():
    return Metrics(model="test-model", session_id="test-session")


def add_sample(metrics, test_id="T001", vector="direct", outcome="success"):
    metrics.add_result(
        test_id=test_id,
        vector=vector,
        payload_id="P001",
        payload_name="test-payload",
        category="test",
        severity="medium",
        outcome=outcome,
        prompt="test prompt",
        response="test response",
        latency_ms=100,
        defense_applied=False,
        defense_blocked=False,
    )


def test_metrics_initial_state():
    metrics = make_metrics()

    assert metrics.model == "test-model"
    assert metrics.session_id == "test-session"
    assert metrics.get_total_tests() == 0


def test_add_result():
    metrics = make_metrics()

    add_sample(metrics)

    assert metrics.get_total_tests() == 1
    assert metrics._tests[0]["id"] == "T001"
    assert metrics._tests[0]["vector"] == "direct"
    assert metrics._tests[0]["outcome"] == "success"


def test_add_result_rejects_invalid_outcome():
    metrics = make_metrics()

    with pytest.raises(ValueError):
        add_sample(metrics, outcome="invalid")


def test_add_result_rejects_invalid_vector():
    metrics = make_metrics()

    with pytest.raises(ValueError):
        add_sample(metrics, vector="invalid")


def test_compute_summary():
    metrics = make_metrics()

    add_sample(metrics, "T001", "direct", "success")
    add_sample(metrics, "T002", "direct", "refused")
    add_sample(metrics, "T003", "jailbreak", "partial")

    summary = metrics.compute_summary()

    assert isinstance(summary, dict)
    assert summary["total_tests"] == 3


def test_to_dict():
    metrics = make_metrics()

    add_sample(metrics)

    data = metrics.to_dict()

    assert isinstance(data, dict)
    assert data["model"] == "test-model"
    assert data["session_id"] == "test-session"
    assert "summary" in data
    assert "vectors" in data
    assert "tests" in data
    assert len(data["tests"]) == 1


def test_save_json(tmp_path):
    metrics = make_metrics()
    add_sample(metrics)

    output = metrics.save_json(tmp_path / "metrics.json")

    assert output.exists()

    with output.open("r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["model"] == "test-model"
    assert len(data["tests"]) == 1


def test_save_csv(tmp_path):
    metrics = make_metrics()
    add_sample(metrics)

    output = metrics.save_csv(tmp_path / "metrics.csv")

    assert output.exists()
    assert output.stat().st_size > 0


def test_metrics_excludes_errors_from_rate_denominator():
    metrics = make_metrics()
    add_sample(metrics, "T001", "direct", "success")
    add_sample(metrics, "T002", "direct", "refused")
    add_sample(metrics, "T003", "direct", "error")

    summary = metrics.compute_summary()

    assert summary["total_tests"] == 3
    assert summary["valid_tests"] == 2
    assert summary["error_tests"] == 1
    assert summary["asr"] == 0.5
    assert summary["partial_asr"] == 0.0
    assert summary["refusal_rate"] == 0.5


def test_blocked_is_valid_but_not_refusal():
    """F-06: el bloqueo de la defensa no se mezcla con el rechazo del modelo."""
    metrics = make_metrics()
    add_sample(metrics, "T001", "direct", "success")
    add_sample(metrics, "T002", "direct", "refused")
    add_sample(metrics, "T003", "direct", "blocked")
    add_sample(metrics, "T004", "direct", "blocked")
    add_sample(metrics, "T005", "direct", "error")

    summary = metrics.compute_summary()
    assert summary["valid_tests"] == 4
    assert summary["error_tests"] == 1
    assert summary["blocked"] == 2
    assert summary["asr"] == 0.25
    assert summary["refusal_rate"] == 0.25
    assert summary["block_rate"] == 0.5

    vector = metrics._compute_vector_stats("direct")
    assert vector["blocked"] == 2 and vector["block_rate"] == 0.5


def test_rates_unchanged_without_blocked_outcomes():
    """Sin 'blocked', las tasas son idénticas a las del cálculo original."""
    metrics = make_metrics()
    for i, o in enumerate(["success", "partial", "refused", "refused"]):
        add_sample(metrics, f"T{i}", "jailbreak", o)
    s = metrics.compute_summary()
    assert (s["asr"], s["partial_asr"], s["refusal_rate"], s["block_rate"]) == (0.25, 0.25, 0.5, 0.0)
