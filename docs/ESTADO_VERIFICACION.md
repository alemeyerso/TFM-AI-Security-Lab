# Estado de verificación — fuente única de las cifras vigentes

Última actualización: **2026-09-17** (auditoría de gaps GAP-001…GAP-019).
Cualquier otro documento que cite el conteo de tests debe coincidir con este
o indicar que la cifra es histórica. `audit/check_doc_consistency.py` lo
comprueba.

## Suite automatizada

Resultado de la suite: `288 passed, 4 xfailed, 1 warning` (292 tests recogidos).

- Comando: `python -m pytest -q -p no:cacheprovider tests`
- Fecha: 2026-09-17.
- Entornos: Python 3.12.3 (Linux) con fastapi 0.115.0, starlette 0.38.6,
  pydantic 2.9.2, httpx 0.27.0, requests 2.31.0, click 8.1.7 y pytest 7.4.0.
  Mismo resultado en un entorno de trabajo y en un entorno virtual creado
  desde cero con `pip install -r requirements.txt`.
- `xfail` estrictos (4): mojibake de `indirect_004` revisión 1 (F-12) y tres
  evasiones léxicas documentadas (GAP-018).
- *Warning* (1): `DeprecationWarning` de `starlette.testclient`.
- Ningún test llama a un modelo real ni escribe en `lab/results/`.

## Integridad de los resultados

- `lab/results/SHA256SUMS.txt`: 21/21 OK (`sha256sum -c lab/results/SHA256SUMS.txt`, desde la raíz).
- `lab/payloads/SHA256SUMS.txt`: 10/10 OK (`sha256sum -c lab/payloads/SHA256SUMS.txt`, desde la raíz).
- Manifiesto SHA-256 de **todo** `lab/results/` idéntico antes y después de
  la auditoría del 17/09.

## Comprobaciones adicionales ejecutadas (sin Ollama)

| Comprobación | Resultado | Evidencia |
|---|---|---|
| `python audit/integration_http_check.py` | PASS | `audit/integration_http_after_2026-09-17.json` |
| `python audit/repro_findings.py` | salida idéntica a la evidencia guardada | `audit/repro_after_2026-09-17.json` |
| `python audit/gap002_before_after.py` | salida idéntica a la evidencia «después» | `audit/gap002_before_2026-09-17.json`, `audit/gap002_after_2026-09-17.json` |
| `python lab/audit_label_reproducibility.py` | solo lectura; mismas cifras al repetirlo | `audit/label_reproducibility_2026-09-17.json` |
| `python audit/check_doc_consistency.py --pytest` | sin discrepancias | salida en consola |
| `docker compose -f docker/docker-compose.yml config --quiet` (con token de prueba) | OK | — |

## No verificado

- Ningún modelo real ni servidor Ollama (versión y *digest* en
  `run_metadata` solo probados con clientes simulados).
- Construcción y arranque de las imágenes Docker (usuario no root, montaje
  en solo lectura).
- Dashboard en navegador.
- Revisión 2 de `indirect_004` con un modelo real.
- Revisión manual de los 24 casos del notebook 05: hecha por un asistente IA,
  **pendiente de confirmación humana**.

## Cifras históricas (no vigentes)

| Fecha | Suite |
|---|---|
| antes del 16/09 | 21 tests (en `audit_trail.md` figuraba «20/20») |
| 2026-09-16 | `128 passed, 1 xfailed` |
| 2026-09-17 (paquete recibido) | `142 passed, 1 xfailed` |
