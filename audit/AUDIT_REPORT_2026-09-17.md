# Informe de corrección y validación — auditoría de gaps 2026-09-17

Referencia: `AUDITORIA_GAPS_2026-09-17.md` (GAP-001…GAP-018, riesgos R-01…R-10).
Base: paquete `TFM-AI-Security-Lab-PARA-CLAUDE-2026-09-17.zip` (copia de seguridad íntegra antes de tocar nada).
Autor de los cambios: Claude (asistente IA), a petición del equipo. **Ningún cambio se ha probado con un modelo real ni con Docker en ejecución.**

---

## A. Resumen ejecutivo

- Se han tratado los 18 gaps y un hallazgo nuevo (GAP-019). Estado: 10 «Corregido y verificado», 5 «Mitigado parcialmente», 2 «Documentado como limitación», 1 «No verificable en el entorno actual» y el nuevo GAP-019 corregido y verificado.
- **Resultados históricos intactos:** el manifiesto SHA-256 de todo `lab/results/` es idéntico antes y después; `lab/results/SHA256SUMS.txt` 21/21 OK. No se ha recalculado ni sustituido ninguna etiqueta publicada.
- **Suite:** `288 passed, 4 xfailed, 1 warning` (antes: `142 passed, 1 xfailed`). Mismo resultado en el entorno de trabajo y en un entorno virtual limpio (Python 3.12.3). Ningún test llama a un modelo real ni escribe en `lab/results/`.
- **Decisiones aplicadas** (tomadas como «entrega ante tribunal»):
  - GAP-002 → política B: detección sobre el original y la forma canónica; se mantiene la separación detección/riesgo/sospecha/bloqueo. Se mitigó el caso reproducido bajo las condiciones evaluadas.
  - GAP-003 → **no** se unifican las rutas con y sin defensa (cambiaría las condiciones experimentales). Se documenta y se registra `prompt_sent` e inferencia.
  - F-12/GAP-017 → opción D: r1 congelada, r2 corregida y opt-in, `xfail` histórico mantenido porque r2 no se ha validado con un modelo real.
- **Requieren decisión del equipo:** confirmar la revisión humana de los 24 casos del notebook 05; aceptar los cambios de texto de la memoria y el `.docx` regenerado; montajes de Jupyter en escritura; validar r2 con modelo real; **rotar el `JUPYTER_TOKEN`** que viajó en el primer ZIP.

## B. Archivos modificados

Nuevos ficheros: ver la lista al final de la tabla. `docker/.env` no existe en el paquete y no se ha creado.

| Ruta | Cambio | Motivo | Riesgo de regresión | Tests |
|---|---|---|---|---|
| `lab/defenses/input_sanitizer.py` | Detección sobre original + forma canónica (invisibles, NFKC, confusables en palabras mixtas); invisibles benignos por contexto; `transformations`; saneado con informe; base64 exige UTF-8 legible y patrón de ataque; `strict_mode` documentado; `TypeError` con entradas no `str` | GAP-001, 002, 011, 013 | Medio: cambia `risk_score` de entradas con invisibles/homoglifos (sube) y de base64 benigno (baja). No afecta a resultados guardados | `test_gap_strict_unicode.py`, suites previas |
| `lab/defenses/output_validator.py` | Umbral `dangerous` 4.0 en modo estricto; `thresholds` y `strict_mode` en el resultado | GAP-001 | Bajo: modo normal sin cambios (5.0) | `test_gap_strict_unicode.py` |
| `lab/defenses/prompt_guard.py` | `describe_config()`; traza de `prompt_sent`, hashes, transformaciones e inferencia; solo se sustituye el **último** mensaje de usuario por el saneado (antes se sustituían todos); docstring de `strict_mode` | GAP-001, 003, 008, 013 | Bajo-medio: la corrección de mensajes cambia conversaciones multi-turno | `test_gap_traceability.py`, `test_gap_cli.py` |
| `lab/core/run_metadata.py` (nuevo) | Esquema `run-metadata/1`: hashes, inferencia, defensa, revisiones de código/payload, Ollama | GAP-008 | Bajo | `test_gap_traceability.py` |
| `lab/core/ollama_client.py` | `last_request` en `chat`/`generate`; `server_info()` (versión y *digest*, best effort) | GAP-008 | Bajo | ídem |
| `lab/core/payload_revisions.py` (nuevo) | Revisiones opt-in (`PAYLOAD_REVISIONS`); por defecto r1 | GAP-017 | Bajo | ídem |
| `lab/core/payload_registry.py` (nuevo) | Resolución de IDs por fuente (dataset, CLI, notebook 05) sin alias | GAP-009 | Bajo | ídem |
| `lab/core/outcome.py` | Añadido `classify_outcome_v2` y `echo_ratio`; `classify_outcome` **sin cambios** | GAP-006 | Nulo sobre lo existente | `test_outcome_v2.py` |
| `lab/core/evaluator.py` | Resultados nuevos a `lab/results/runs/`; `strict_mode` y bloqueo de salida; metadatos por test | GAP-008, 019 | Medio: cambia la carpeta de salida del CLI | `test_gap_cli.py` |
| `lab/core/metrics.py` | Columnas de metadatos añadidas **al final** del CSV | GAP-008 | Bajo (columnas previas sin cambios) | `test_gap_cli.py` |
| `lab/server.py` | Validación de `vector` (422); `withheld/` separado y redacción de valores antiguos; `run_metadata`; `DEFENSE_STRICT_MODE`; revisiones de payload; `_call_ollama` devuelve también el host | GAP-004, 008, 016, 001 | Medio: `schema_version` nuevo; campo `withheld_response` ya no va en línea | `test_server_api.py`, `test_gap_traceability.py` |
| `lab/attacks/direct_injection.py` | Quitada una coma final que convertía el prompt de `direct_002` en una tupla | Hallazgo nuevo | Bajo: el CLI enviaba una tupla | `test_gap_traceability.py` |
| `lab/attacks/indirect_injection.py` | Aplica revisiones opt-in | GAP-017 | Bajo (r1 por defecto) | ídem |
| `run_lab.py` | Sin *fallback* silencioso a demo; `--allow-demo` → `lab/results/demo/`; sin doble guardado; `--strict-mode`, `--block-dangerous-output` | GAP-010, 008, 019 | Medio: `--compare` sin Ollama ahora sale con código 1 | `test_gap_cli.py` |
| `lab/audit_label_reproducibility.py` (nuevo) | Recalcula etiquetas en paralelo, solo lectura | GAP-005 | Nulo | `test_outcome_v2.py` |
| `lab/payloads/indirect/archive/payloads_r1_frozen_2026-09-17.json` (nuevo) | Copia byte a byte de r1 | GAP-017 | Nulo | hash en test |
| `lab/payloads/revisions/indirect_004.r2.json` (nuevo) | r2 corregida, `validated_with_real_model: false`, historial del estímulo | GAP-017 | Nulo (opt-in) | `test_gap_traceability.py` |
| `lab/payloads/SHA256SUMS.txt` (nuevo) | Hashes de los 10 ficheros de payloads | GAP-017 | Nulo | `sha256sum -c` |
| `docker/Dockerfile.api` | Usuario no root (`labapi`, uid 1000) | GAP-014 | **No verificado** (sin build) | — |
| `docker/docker-compose.yml` | `lab/` en solo lectura para la API (salvo `lab/results/`); nuevas variables | GAP-014 | **No verificado** en ejecución; `config --quiet` OK | — |
| `docker/.env.example` | `JUPYTER_TOKEN` vacío (compose no arranca sin token propio); nuevas variables | GAP-014 | Fricción: también bloquea `up api` sin token | — |
| `docs/generate_tfm.py` | Conclusiones del notebook 05 con n=1 y hallazgo manual DI-01 de Qwen; canario 5/28; sin «casi determinista/nunca/siempre» sin cifras; §5.2 sin afirmar evaluación | GAP-007, 012 | Afecta al texto de la memoria: **requiere aceptación del equipo** | revisión de diff |
| `docs/TFM_Final.docx` | Regenerado con el generador corregido; versión previa en `docs/historico/` | GAP-007 | ídem | diff de texto: solo los cambios previstos |
| `README.md` | §2–§9: modo estricto, forma canónica, `withheld/`, 17 (no 18), 21/21, CLI, variables, GAP-018, tabla de gaps, cifras vigentes | GAP-012, 004, 018 | Nulo | `check_doc_consistency.py` |
| `docs/audit_trail.md` | «20/20» marcado como histórico; sección 2026-09-17 | GAP-012 | Nulo | ídem |
| `docs/reproducibilidad.md` | Metadatos, revisiones, origen de etiquetas por conjunto, `invalid`, directorios nuevos | GAP-005, 008 | Nulo | — |
| `docs/ESTADO_VERIFICACION.md` (nuevo) | Fuente única de las cifras vigentes | GAP-012 | Nulo | ídem |
| `tests/test_server_api.py` | Test real de concurrencia + control negativo; `test_output_block_opt_in` busca la evidencia en `withheld/` | GAP-015, 004 | Nulo | — |
| `tests/test_config.py` | Puerto libre reservado en lugar del 9 | GAP-015 | Nulo | — |
| `tests/test_gap_*.py`, `tests/test_outcome_v2.py` (nuevos) | 148 tests nuevos (más 1 control negativo en `test_server_api.py`) | varios | Nulo | — |
| `audit/*_2026-09-17.*`, `audit/check_doc_consistency.py`, `audit/gap002_before_after.py` (nuevos) | Evidencia y comprobadores | — | Nulo | — |

No se modificó `lab/results/README_RESULTS.md` para mantener idéntico el manifiesto de `lab/results/`; su contenido nuevo está en `docs/reproducibilidad.md`.

## C. Correcciones por gap

| Gap | Estado | Qué se hizo | Evidencia |
|---|---|---|---|
| GAP-001 `strict_mode` | Corregido y verificado | Efecto en las tres clases (sospecha con 1 señal débil; bloqueo mín(conf, 3.0); `dangerous` 4.0); `risk_score` independiente del modo; configuración efectiva registrada | `test_gap_strict_unicode.py`, `test_gap_cli.py` (umbral efectivo 3.0 en metadatos) |
| GAP-002 invisibles/homoglifo | Mitigado parcialmente | Política B. Antes: riesgo 1.5 (ancho cero) y 1.0 (homoglifo), nunca bloqueado, homoglifo enviado al modelo. Después: 4.0 y 3.5, sospechoso en ambos modos, **bloqueado en modo estricto** sin llamar al modelo; en modo normal se envía el texto limpio. El emoji con ZWJ ya no se marca. Se mitigó el caso reproducido bajo las condiciones evaluadas | `audit/gap002_before_2026-09-17.json` / `_after_` (cliente simulado) |
| GAP-003 rutas no comparables | Documentado como limitación | No se unifican: la memoria no compara ASR con/sin defensa y unificar cambiaría condiciones experimentales. Se registran endpoint, muestreo y `prompt_sent` | README §6.4, `test_gap_traceability.py` |
| GAP-004 respuesta retenida por HTTP | Corregido y verificado | Fichero aparte en `withheld/`, no listado, no servido, no sincronizado; `withheld_response_ref` con hash; redacción de registros antiguos | `test_gap_traceability.py` |
| GAP-005 etiquetas no reproducibles | Mitigado parcialmente | Script de solo lectura y origen documentado por conjunto. Iguales/total: batería 78/117, piloto 76/78, notebook 05 20/24 (no concluyente por truncado), live 47/70, E1 390/390, E2 60/60, E3 240/240. Las discrepancias no se resuelven: no se sabe cuál es la correcta | `audit/label_reproducibility_2026-09-17.json`, `.csv` |
| GAP-006 keywords en el prompt / `refuse_kw` | Mitigado parcialmente | `classify_outcome_v2` paralelo (eco, keywords solo del prompt, resistencia, señales mixtas). Revisión de 24 casos: 12 coinciden, 6 discrepan, 6 no verificables. **Hecha por IA, pendiente de confirmación humana** | `test_outcome_v2.py`, `audit/notebook05_manual_review_2026-09-17.csv` |
| GAP-007 conclusiones notebook 05 | Mitigado parcialmente | Texto reformulado con n=1 y con el hallazgo manual DI-01 de Qwen; `.docx` regenerado y anterior archivado. Pendiente de aceptación del equipo | diff del generador y del texto del `.docx` |
| GAP-008 registro insuficiente | Corregido y verificado | `run_metadata` en API y CLI; columnas en CSV. Verificado con clientes simulados; la captura de versión/*digest* de Ollama no se ha probado con un servidor real | `test_gap_traceability.py`, `test_gap_cli.py` |
| GAP-009 IDs `tool_abuse` | Corregido y verificado | Premisa corregida: no son alias, son prompts distintos. Registro por fuente; todos los IDs oficiales resuelven; discrepancias del piloto = {direct_001, indirect_001, indirect_004} y explicadas | `test_gap_traceability.py` |
| GAP-010 *fallback* a demo | Corregido y verificado | Código 1 sin ficheros; `--allow-demo` → `demo/` marcado | `test_gap_cli.py` |
| GAP-011 base64 benigno | Corregido y verificado | Exige texto legible y patrón de ataque | `test_gap_strict_unicode.py` |
| GAP-012 cifras contradictorias | Corregido y verificado | 18→17, 15/15→21/21, «20/20» histórico, conteo único en `ESTADO_VERIFICACION.md` | `audit/check_doc_consistency.py --pytest`: 20/20 OK |
| GAP-013 docstrings | Corregido y verificado | Docstrings alineados; comportamientos descritos cubiertos por tests | `test_gap_strict_unicode.py` |
| GAP-014 Docker | No verificable en el entorno actual | Usuario no root, `lab/` en solo lectura para la API, token sin valor por defecto. Solo `docker compose config --quiet` (OK con token de prueba; falla sin token, como se pretende). Build/run imposible: el registro de imágenes estaba bloqueado. Jupyter sigue en escritura | — |
| GAP-015 tests débiles | Corregido y verificado | Concurrencia real (`/health` < 0,8 s con ataque lento de 1,5 s) + control negativo; puerto reservado; E2E del CLI | `test_server_api.py`, `test_gap_cli.py` |
| GAP-016 `vector` libre | Corregido y verificado | 422 para vectores no soportados | `test_gap_traceability.py` |
| GAP-017 mojibake F-12 | Mitigado parcialmente | r1 congelada (SHA-256 `8462cb82…`), r2 opt-in con `payload_revision` registrado; historial del estímulo reconstruido (canario: **inferido**). `xfail` histórico mantenido; sin test normal de r2 con modelo porque no se ha validado | `test_gap_traceability.py`, `lab/payloads/SHA256SUMS.txt` |
| GAP-018 evasiones léxicas | Documentado como limitación | 3 casos fijados como `xfail` estricto; README §6.4 | `test_gap_strict_unicode.py` |
| GAP-019 (nuevo) CLI escribía en la raíz de `lab/results/` | Corregido y verificado | Salida a `runs/` | `test_gap_cli.py` |

Otros hallazgos nuevos: `direct_002` era una tupla en el CLI (corregido); el piloto guardó un prompt vacío en `direct_001`; `indirect_001` tiene el teléfono anonimizado de forma distinta entre fuentes; el JSON del notebook 05 trunca respuestas (500) y payloads (200); `PromptGuard` sustituía todos los mensajes de usuario (corregido). Los datos guardados no se han tocado.

## D. Pruebas ejecutadas

Todas desde la raíz del proyecto, con `PYTHONDONTWRITEBYTECODE=1`.

| Comando | Resultado |
|---|---|
| `python -m pytest -q -p no:cacheprovider tests` (entorno de trabajo, Python 3.12.3) | `288 passed, 4 xfailed, 1 warning` |
| ídem en entorno limpio (`python -m venv` + `pip install -r requirements.txt`) | `288 passed, 4 xfailed, 1 warning`; instalación OK (aviso: `aiofiles 23.2.0` está *yanked*) |
| `python audit/check_doc_consistency.py --pytest` | 20/20 comprobaciones OK |
| `python audit/integration_http_check.py` | `RESULT: PASS` (idéntico a `audit/integration_http_after_2026-09-17.json`) |
| `python audit/repro_findings.py` | JSON idéntico a `audit/repro_after_2026-09-17.json` |
| `python audit/gap002_before_after.py` | JSON idéntico a `audit/gap002_after_2026-09-17.json` (el «antes» se generó sobre la copia de seguridad) |
| `python lab/audit_label_reproducibility.py --out <tmp> --csv <tmp>` | mismas cifras y CSV idéntico a los guardados; `lab/results/` sin cambios |
| `sha256sum -c lab/results/SHA256SUMS.txt` | 21/21 OK |
| `sha256sum -c lab/payloads/SHA256SUMS.txt` | 10/10 OK |
| manifiesto `find lab/results -type f \| sort \| xargs sha256sum` frente al de antes | idéntico |
| `python -m py_compile` sobre `lab/`, `audit/`, `tests/`, `run_lab.py`, `docs/generate_tfm.py` | OK |
| `JUPYTER_TOKEN=<valor de prueba> docker compose -f docker/docker-compose.yml config --quiet` | OK; sin token, error explícito |
| Batería benigna (15 prompts) con `InputSanitizer(strict_mode=True)` | 0 sospechosos, 0 con riesgo ≥ 3.0 |

## E. Resultados históricos preservados

- Ningún fichero de `lab/results/` se ha creado, modificado, movido ni borrado (manifiesto completo idéntico).
- Payloads: `lab/payloads/indirect/payloads.json` (r1, con mojibake) sin cambios; copia congelada byte a byte en `archive/`.
- Notebooks: sin cambios.
- Etiquetas: las publicadas siguen congeladas; `classify_outcome` intacto; v2 y los recálculos viven en ficheros nuevos de `audit/`.
- Memoria: la versión previa está en `docs/historico/TFM_Final_antes_auditoria_2026-09-17.docx`.
- Informes previos (`audit/*_2026-09-16.*`) sin cambios. `audit_trail.md` solo añade anotaciones y una sección nueva.

## F. Verificaciones no ejecutadas

| Verificación | Motivo |
|---|---|
| Cualquier inferencia con modelo real / Ollama | No disponible en el entorno |
| Captura real de versión y *digest* de Ollama | ídem (solo simulada) |
| Validación de `indirect_004` r2 con modelo | ídem; por eso sigue opt-in y con `xfail` |
| `docker compose build` / `up`, usuario no root, escritura denegada | Registro de imágenes bloqueado por política |
| Dashboard en navegador | No probado |
| Revisión humana de los 24 casos del notebook 05 | Requiere al equipo |
| Tasa de falsos positivos del validador de salida con respuestas benignas reales | No hay corpus etiquetado |

## G. Riesgos residuales

| Riesgo | Clasificación | Nota |
|---|---|---|
| R-01 La v3 difería de la v2 más de lo descrito | Verificado | `diff -r` y verificación del estado real antes de corregir |
| R-02 Versión del servidor usada en la batería de agosto | No verificado | Sin historial git; 78/117 etiquetas coinciden al recalcular |
| R-03 Docker e instalación limpia | Parcialmente verificado | Instalación limpia OK; Docker solo `config` |
| R-04 Comportamiento con modelo real tras los cambios | Pendiente de validación externa | — |
| R-05 Dashboard | Pendiente de validación externa | — |
| R-06 Falsos positivos del validador de salida | Limitación documentada | — |
| R-07 Payload usado por el canario del 13/09 | Parcialmente verificado | r1 **inferido** por la longitud del prompt (588); el JSON no guarda el texto |
| R-08 Total de 924 registros | Verificado | 117 + 24 + 60 + 390 + 240 + 60 + 33 contados en los ficheros |
| R-09 Falsos positivos del modo estricto | Parcialmente verificado | 0/15 en la batería benigna; corpus pequeño |
| R-10 Figuras de la presentación con datos Qwen *live* | No verificado | Origen de `presentacion/img/*gemma_qwen*.png` sin trazar |
| R-11 Jupyter monta `lab/` y notebooks en escritura | Limitación documentada | Decisión del equipo |
| R-12 Cambios de texto en la memoria | Pendiente de validación externa | El equipo es dueño del texto |
| R-13 `JUPYTER_TOKEN` expuesto en el primer ZIP | Pendiente de validación externa | Rotarlo |
| Evasiones léxicas (GAP-018) y envío del texto limpio en modo normal (GAP-002) | Limitación documentada | Se mitigó el caso reproducido bajo las condiciones evaluadas |

## H. Comandos de reproducción

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export PYTHONDONTWRITEBYTECODE=1

python -m pytest -q -p no:cacheprovider tests          # 288 passed, 4 xfailed
python audit/check_doc_consistency.py --pytest         # 20/20 OK
python audit/integration_http_check.py                 # RESULT: PASS
python audit/repro_findings.py > /tmp/repro.json
python audit/gap002_before_after.py > /tmp/gap002.json
python lab/audit_label_reproducibility.py --out /tmp/labels.json --csv /tmp/labels.csv
sha256sum -c lab/results/SHA256SUMS.txt
sha256sum -c lab/payloads/SHA256SUMS.txt

# Con Ollama (no ejecutado en esta auditoría):
python run_lab.py --model gemma4:e2b --vector direct --with-defense --strict-mode
PAYLOAD_REVISIONS=indirect_004=2 python run_lab.py --model gemma4:e2b --vector indirect
# Docker (no ejecutado; requiere docker/.env con un JUPYTER_TOKEN propio):
docker compose -f docker/docker-compose.yml build api && docker compose -f docker/docker-compose.yml up -d api
```
