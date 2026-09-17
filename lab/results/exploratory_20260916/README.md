# Ejecuciones exploratorias del 16/09/2026 (NO forman parte de los resultados del TFM)

10 ejecuciones sueltas de `gemma4:e2b` lanzadas desde la API durante la auditoría
del 16/09, con la versión reescrita de las defensas. Se conservan solo porque
los tests y `audit/repro_findings.py` usan dos de sus respuestas reales como
evidencia (mojibake de `indirect_004` y validador de salida).

- No están en `SHA256SUMS.txt` ni se usan en ninguna cifra de la memoria.
- `live_attack_gemma4_e2b_20260916_185152_62d16fce.json` es un **error de
  conexión** guardado como `partial` por una versión anterior del servidor.
  No es una observación válida. El servidor actual devuelve HTTP 502 y no
  guarda estos casos.
- n=1 por payload: no permiten estimar tasas.
