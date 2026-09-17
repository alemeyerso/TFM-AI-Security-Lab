"""Integridad de payloads (auditoría 2026-09-16, F-12 / F-17)."""
import json

import pytest

from tests.helpers_audit import ROOT

EXPECTED = {"direct": 10, "indirect": 6, "jailbreak": 15, "tool_abuse": 8}


def load(vector):
    return json.loads((ROOT / "lab/payloads" / vector / "payloads.json").read_text(encoding="utf-8"))


def test_payload_counts_match_readme():
    assert {v: len(load(v)) for v in EXPECTED} == EXPECTED
    assert sum(EXPECTED.values()) == 39


def test_payload_ids_unique_and_keywords_present():
    ids = []
    for v in EXPECTED:
        for p in load(v):
            ids.append(p["id"])
            assert p.get("detection_keywords"), p["id"]
    assert len(ids) == len(set(ids))


def test_indirect_payloads_have_untrusted_content():
    for p in load("indirect"):
        assert p.get("injected_content") or (ROOT / "lab/payloads/indirect" / p["document_file"]).exists()


@pytest.mark.xfail(strict=True, reason=(
    "Defecto conocido F-12: indirect_004 contiene mojibake ('INSTRUCCIÃ“N'). "
    "No se corrige para no alterar el estímulo de las ejecuciones ya registradas."))
def test_payloads_have_no_mojibake():
    for v in EXPECTED:
        for p in load(v):
            text = json.dumps(p, ensure_ascii=False)
            assert "Ã" not in text and "Â" not in text, p["id"]
