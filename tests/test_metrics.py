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
