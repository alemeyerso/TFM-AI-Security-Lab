"""
audit/check_doc_consistency.py — validación documental (SOLO INFORMA)
======================================================================
Auditoría 2026-09-17 (GAP-012). Compara afirmaciones de la documentación con
la fuente de verdad (código, ficheros de resultados y
``docs/ESTADO_VERIFICACION.md``). NO modifica ningún documento.

Uso:
    python audit/check_doc_consistency.py            # usa las cifras de ESTADO_VERIFICACION.md
    python audit/check_doc_consistency.py --pytest   # además ejecuta pytest y compara el conteo

Salida: lista de comprobaciones OK / DISCREPANCIA y código 1 si hay discrepancias.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DOCS_WITH_CURRENT_CLAIMS = ["README.md", "docs/reproducibilidad.md", "lab/results/README_RESULTS.md"]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def state_counts() -> dict:
    if not (ROOT / "docs/ESTADO_VERIFICACION.md").exists():
        return {}
    text = read("docs/ESTADO_VERIFICACION.md")
    m = re.search(r"Resultado de la suite:\s*`(\d+) passed, (\d+) xfailed", text)
    return {"passed": int(m.group(1)), "xfailed": int(m.group(2))} if m else {}


def pytest_counts() -> dict:
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"],
                         cwd=ROOT, capture_output=True, text=True).stdout
    m = re.search(r"(\d+) passed(?:, (\d+) xfailed)?", out)
    return {"passed": int(m.group(1)), "xfailed": int(m.group(2) or 0)} if m else {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pytest", action="store_true")
    args = ap.parse_args(argv)
    checks: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    # 1. Conteo de tests: fuente de verdad única
    truth = state_counts()
    check("ESTADO_VERIFICACION.md declara el conteo de tests", bool(truth), str(truth))
    if args.pytest:
        real = pytest_counts()
        check("Conteo real de pytest == ESTADO_VERIFICACION.md", real == truth, f"real={real} doc={truth}")
    if truth:
        claim = f"{truth['passed']} passed, {truth['xfailed']} xfailed"
        for doc in ("README.md",):
            check(f"{doc} cita el conteo vigente ({claim})", claim in read(doc))
    for doc in DOCS_WITH_CURRENT_CLAIMS:
        for m in re.finditer(r"(\d+) passed, (\d+) xfailed", read(doc)):
            found = {"passed": int(m.group(1)), "xfailed": int(m.group(2))}
            ctx = read(doc)[max(0, m.start() - 120):m.start()]
            historical = any(w in ctx.lower() for w in ("históric", "antes", "2026-09-16", "anterior"))
            check(f"{doc}: conteo '{m.group(0)}' vigente o marcado como histórico",
                  found == truth or historical, "")
    trail = read("docs/audit_trail.md")
    for m in re.finditer(r"20/20", trail):
        ctx = trail[max(0, m.start() - 160):m.end() + 60].lower()
        check("audit_trail.md: '20/20' marcado como histórico", "histórico" in ctx or "superad" in ctx)

    # 2. SHA256SUMS de resultados
    sums = [l for l in read("lab/results/SHA256SUMS.txt").splitlines() if l and not l.startswith("#")]
    n = len(sums)
    for doc in DOCS_WITH_CURRENT_CLAIMS:
        for m in re.finditer(r"SHA256SUMS\.txt`?[^\n]{0,40}?(\d+)/(\d+)", read(doc)):
            check(f"{doc}: SHA256SUMS {m.group(1)}/{m.group(2)} == {n}/{n}",
                  int(m.group(1)) == int(m.group(2)) == n)

    # 3. Cifra success|safe de la regresión del 16/09
    reg = json.loads(read("audit/regression_stored_data_2026-09-16.json"))
    success_safe = next((v for k, v in reg["after_verdict_por_outcome_guardado"].items()
                         if k == "success|safe"), None)
    readme = read("README.md")
    m = re.search(r"(\d+) respuestas guardadas\s+con\s+`?outcome=success`?", readme)
    check("README: nº de respuestas success analizadas como safe == regresión",
          m and int(m.group(1)) == success_safe, f"README={m and m.group(1)} fuente={success_safe}")

    # 4. Endpoints documentados vs OpenAPI
    import lab.server as server
    paths = set(server.app.openapi()["paths"])
    documented = set(re.findall(r"\|\s*(?:GET|POST)\s*\|\s*`([^`]+)`", readme))
    check("README: tabla de endpoints == OpenAPI", documented == paths,
          f"solo_doc={documented - paths} solo_api={paths - documented}")

    # 5. Recuento de payloads
    counts = {v: len(json.loads(read(f"lab/payloads/{v}/payloads.json")))
              for v in ("direct", "indirect", "jailbreak", "tool_abuse")}
    for v, c in counts.items():
        check(f"README: vector {v} = {c}", re.search(rf"`{v}`\s*\|\s*{c}\s*\|", readme) is not None)

    # 6. Umbrales documentados
    from lab.defenses.output_validator import DANGEROUS_THRESHOLD, STRICT_DANGEROUS_THRESHOLD
    from lab.defenses.prompt_guard import STRICT_MAX_BLOCK_THRESHOLD
    check("README menciona el umbral estricto de entrada", f"{STRICT_MAX_BLOCK_THRESHOLD}" in readme)
    check("README menciona el umbral estricto de salida", f"{STRICT_DANGEROUS_THRESHOLD}" in readme)
    check("README menciona el umbral normal de salida", f"{DANGEROUS_THRESHOLD}" in readme)

    # 7. withheld_response: el README no debe afirmar lo contrario del código
    check("README describe withheld/ y que no se sirve por HTTP",
          "lab/results/withheld/" in readme and "withheld_response" in readme)

    bad = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(("OK           " if ok else "DISCREPANCIA ") + name + (f"  [{detail}]" if detail and not ok else ""))
    print(f"\n{len(checks) - len(bad)}/{len(checks)} comprobaciones OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
