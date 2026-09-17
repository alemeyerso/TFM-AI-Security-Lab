"""F-08: normalización de OLLAMA_HOST y NUM_CTX."""
import pytest

from lab.core.config import normalize_ollama_url, num_ctx_from_env, ollama_base_url
from lab.core.ollama_client import OllamaClient, OllamaConnectionError


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, "http://localhost:11434"),
        ("", "http://localhost:11434"),
        ("host.docker.internal:11434", "http://host.docker.internal:11434"),
        ("http://host.docker.internal:11434/", "http://host.docker.internal:11434"),
        ("https://ollama.example.org:443", "https://ollama.example.org:443"),
        ("0.0.0.0:11434", "http://127.0.0.1:11434"),
        ("0.0.0.0", "http://127.0.0.1:11434"),
        ("myhost", "http://myhost:11434"),
    ],
)
def test_normalize_ollama_url(value, expected):
    assert normalize_ollama_url(value) == expected


def test_client_reads_environment_at_instantiation(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "host.docker.internal:11434")
    monkeypatch.setenv("NUM_CTX", "8192")
    client = OllamaClient()
    assert client.base_url == "http://host.docker.internal:11434"
    assert client.num_ctx == 8192
    assert ollama_base_url() == "http://host.docker.internal:11434"


def test_explicit_arguments_override_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://elsewhere:1")
    client = OllamaClient(base_url="http://localhost:11434", num_ctx=2048)
    assert client.base_url == "http://localhost:11434"
    assert client.num_ctx == 2048


def test_invalid_num_ctx_falls_back(monkeypatch):
    monkeypatch.setenv("NUM_CTX", "not-a-number")
    assert num_ctx_from_env(127000) == 127000


def test_unreachable_host_raises_connection_error_not_raw_requests_error():
    # Antes: requests.exceptions.InvalidSchema sin capturar con un host sin esquema.
    # Auditoría 2026-09-17 (GAP-015): puerto libre reservado en el momento
    # (antes se asumía que el puerto 9 estaba cerrado).
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    client = OllamaClient(base_url=f"127.0.0.1:{free_port}", timeout=1)
    with pytest.raises(OllamaConnectionError):
        client.chat(model="x", messages=[{"role": "user", "content": "hola"}])


def test_experiment_scripts_do_not_hardcode_localhost():
    from tests.helpers_audit import ROOT

    for rel in ["lab/e1_reliability.py", "lab/e2_mini.py", "lab/e3_factorial.py",
                "lab/reeval_indirect.py", "lab/reeval_indirect_canary.py",
                "lab/run_benign_battery.py", "presentacion/demo_record.py"]:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert '"http://localhost:11434/api/generate"' not in text, rel
        assert "OLLAMA_HOST" in text, rel
