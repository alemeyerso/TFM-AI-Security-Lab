# Guía de reproducibilidad — AI Security Lab

## Objetivo
Esta guía distingue entre reproducibilidad del **análisis congelado** y replicación exacta de nuevas inferencias. E1, E2 y E3 conservan respuestas completas y permiten recalcular las métricas sin volver a consultar Ollama.

## Entorno
- Docker Desktop 4.x+
- Ollama 0.4+
- Modelos Gemma/Qwen utilizados en cada experimento

```bash
cp docker/.env.example docker/.env
# Edita docker/.env para definir JUPYTER_TOKEN con un valor propio
docker compose -f docker/docker-compose.yml config --quiet
```

Los servicios se publican únicamente en `127.0.0.1`. GitHub Sync está desactivado por defecto y solo se habilita explícitamente mediante `ENABLE_GITHUB_SYNC=true` y un token válido.

## Parámetros experimentales
E1, E2 y E3 registran `temperature=0.7` y `num_ctx=8192`. La batería histórica de agosto y el servidor live pueden utilizar otra configuración; no deben tratarse como réplicas idénticas.

## Reproducir el análisis congelado
```bash
python lab/reclassify_v3_overrides.py
python -m pytest -q
```

`reclassify_v3_overrides.py` no modifica los JSON crudos ni los resultados v2. Genera derivados v3 con las exclusiones/correcciones explícitamente registradas en `lab/results/reclass_v3_overrides.csv`.

## Reejecutar inferencias
```bash
python lab/e1_reliability.py
python lab/e2_mini.py
python lab/e3_factorial.py
```

Una nueva inferencia puede variar por el muestreo del modelo. Para una réplica exacta deben registrarse versión de Ollama, identificación/digest del modelo y semilla.

## Fuentes
- E1 crudo: `lab/results/e1_reliability_20260913.json`
- E1 v3: `lab/results/e1_reliability_v3.json` / `e1_reliability_summary_v3.csv`
- E2: `lab/results/e2_mini_20260914.json`
- E3 crudo: `lab/results/e3_factorial_20260914.json`
- E3 v3: `lab/results/e3_factorial_v3.json` / `e3_factorial_summary_v3.csv`
- Qwen oficial: `lab/results/oficiales/notebook05_20260913/`

Los archivos históricos y exploratorios no se mezclan con las cifras oficiales.

## Metadatos de las ejecuciones nuevas (auditoría 2026-09-17)

Cada resultado nuevo de la API (`run_metadata`) y del CLI (`metadata` por test y columnas extra en el CSV) sigue el esquema `run-metadata/1 (2026-09-17)`:

- `prompt_original_sha256`, `prompt_sent` y `prompt_sent_sha256` (texto que realmente recibió el modelo; `None` si se bloqueó antes).
- `inference`: endpoint (`/api/generate` o `/api/chat`), `base_url`, `temperature`, `top_p`, `seed`, `num_ctx`, `timeout_s` y si se llamó al modelo. En la ruta sin defensa, `temperature`/`top_p` valen `ollama_model_default`.
- `defense_config`: `strict_mode`, umbral de bloqueo configurado y efectivo, bloqueo de salida y umbrales del validador.
- `payload_revision`, `payload_source`, `code_revision` (hash de los `.py` de `lab/`, sin `results/`) y `dataset_revision` (hash de los payloads).
- `ollama`: versión y *digest* del modelo, si el servidor los expone (puede ser `None`; no verificado con un Ollama real).

Las ejecuciones con y sin defensa usan endpoints, muestreo y texto enviado distintos: **no son comparables** sin unificar antes esas condiciones.

## Revisiones de payloads

- Por defecto se usa la revisión 1, la de los resultados históricos.
- `PAYLOAD_REVISIONS=indirect_004=2` activa la revisión corregida (`lab/payloads/revisions/indirect_004.r2.json`), que **no se ha validado con un modelo real**.
- La revisión 1 está congelada en `lab/payloads/indirect/archive/payloads_r1_frozen_2026-09-17.json`. Comprobación: `sha256sum -c lab/payloads/SHA256SUMS.txt` (desde la raíz).
- Estímulo usado históricamente en `indirect_004`: texto correcto (igual a r2) en la batería de agosto y en el piloto del 11/09; r1 en la reevaluación del 13/09 y en las exploratorias del 16/09; r1 **inferido** (por la longitud del prompt) en el canario.

## Origen de las etiquetas por conjunto

`python lab/audit_label_reproducibility.py` recalcula en paralelo las etiquetas con el clasificador que corresponde a cada conjunto y **no modifica** `lab/results/`. Una discrepancia no dice cuál de las dos etiquetas es la correcta.

| Conjunto | Origen de la etiqueta guardada | Iguales / total |
|---|---|---|
| Batería principal (agosto) | No registrado; incluye `invalid` | 78 / 117 |
| Piloto PromptGuard 11/09 | Evaluador CLI con defensas anteriores; los bloqueos se guardaban como `refused` | 76 / 78 |
| Notebook 05 (Qwen) | `classify_outcome` sobre la respuesta completa | 20 / 24 (no concluyente: el JSON guarda la respuesta truncada a 500 caracteres) |
| API *live* (raíz) | Versión del servidor en cada fecha (no registrada) | 47 / 70 |
| Exploratorias 16/09 | Ídem | 9 / 9 (más un error de conexión sin etiqueta válida) |
| E1 crudo | Clasificador propio de E1 | 390 / 390 |
| E2 | Clasificador propio de E2 | 60 / 60 |
| E3 crudo | Clasificador propio de E3 | 240 / 240 |

- **`invalid`** significa ejecución nula: el prompt no contenía un estímulo evaluable (p. ej. en `indirect_001`–`003` de la batería inicial solo llegaba el nombre del documento). No es un rechazo.
- Las cifras de la memoria para E1 y E3 usan los derivados v2/v3 (`reclassify_e1_e3.py` + `reclass_v3_overrides.csv`), no las etiquetas crudas.
- Las etiquetas publicadas están **congeladas**. `classify_outcome_v2` es un clasificador paralelo y no las sustituye.
- Revisión manual de los 24 casos del notebook 05: `audit/notebook05_manual_review_2026-09-17.csv` (12 coinciden, 6 discrepan, 6 no verificables por el truncado). La hizo un asistente IA y está **pendiente de confirmación humana**.

## Directorios de resultados nuevos

- `lab/results/runs/`: ejecuciones nuevas del CLI y de los experimentos.
- `lab/results/demo/`: datos sintéticos (`--demo` o `--allow-demo`), marcados `synthetic: true`.
- `lab/results/withheld/`: salidas retenidas por la defensa; la API no las lista ni las sirve.

`lab/results/README_RESULTS.md` no se ha modificado para mantener idéntico el manifiesto de `lab/results/`; esta sección lo complementa.
