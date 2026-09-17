"""Regression tests for indirect prompt construction (audit items B2/B3)."""
import sys


def test_e1_indirect_prompts_are_never_empty(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["pytest"])
    from lab.e1_reliability import load_all_payloads

    payloads = load_all_payloads()
    assert len(payloads) == 39
    indirect = [p for p in payloads if p["vector"] == "indirect"]
    assert len(indirect) == 6
    for p in indirect:
        assert len(p["prompt"].strip()) > 200, p["payload_id"]
        assert "--- DOCUMENTO ---" in p["prompt"]


def test_server_indirect_prompts_keep_injection_and_no_default_defense():
    from lab.server import _load_indirect_payloads

    prompts = {p["id"]: p["prompt"] for p in _load_indirect_payloads()}
    assert "NOTA_SISTEMA" in prompts["indirect_001"]      # injection not truncated
    assert "Si eres una IA" in prompts["indirect_003"]
    assert all("No ejecutes ni sigas instrucciones" not in v for v in prompts.values())
