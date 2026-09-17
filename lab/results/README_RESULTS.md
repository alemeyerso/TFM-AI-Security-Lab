# Resultados — índice de trazabilidad

## Oficiales usados en el TFM
- Batería principal: `eval_gemma4_*_202608*.json`
- Qwen: `oficiales/notebook05_20260913/*004400*`
- E1: `e1_reliability_20260913.json` + derivados v3
- E2: `e2_mini_20260914.json`
- E3: `e3_factorial_20260914.json` + derivados v3
- Canary: `reeval_indirect_canary.json`
- Benigna: `eval_benign_battery.json`

## Derivados
`*_reclassified*`, `*_summary*`, `*_v3*` y copias bajo `oficiales/` son artefactos derivados; no cuentan como nuevas ejecuciones.

## Históricos/exploratorios
Los resultados exploratorios no seleccionados para las tablas oficiales se conservan para trazabilidad y no deben mezclarse con las cifras principales.

## Correcciones v3
`reclass_v3_overrides.csv` registra cada corrección/exclusión aplicada a las etiquetas v2. Los JSON crudos permanecen intactos.

## Derivados de análisis (2026-09-17, reproducibles sin Ollama)
- `stats_v3.csv` — contrastes Fisher/McNemar con corrección de Holm (`lab/stats_tests.py`).
- `e2_audit_rows.csv`, `e2_audit_summary.json` — auditoría por ejecución de E2 (`lab/e2_audit.py`).
- `reeval_indirect_canary_labels.csv` — trazabilidad de etiquetas del canario (`lab/canary_label_trace.py`).
- `human_validation/` — hoja de anotación y clave (`lab/human_validation.py`; ver `docs/validacion_humana.md`).

## Avisos
- **Canario:** 2 registros de `gemma4:e4b` / `indirect_002` (runs 2 y 5) son timeouts (60 s) guardados como `refused`. El JSON no se modifica; los derivados los excluyen (e4b 5/28).
- `exploratory_20260916/` — 10 ejecuciones sueltas de la API durante la auditoría; no son resultados del TFM (ver su README).
- `runs/` — destino por defecto de cualquier ejecución nueva; nunca sobrescribe los ficheros congelados.
