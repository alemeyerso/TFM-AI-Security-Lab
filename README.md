# TFM AI Security Lab

Repositorio del Trabajo Fin de Máster — Máster en Ciberseguridad, UCM 2025-2026.
**Evaluación de la Ciberseguridad en Entornos de Inteligencia Artificial Generativa.**

## Requisitos previos

- **Python 3.12+** (probado en 3.14)
- **Ollama** para correr los modelos localmente — [ollama.ai](https://ollama.ai)
- **~30GB de disco** para los pesos de los modelos
- **Docker Desktop** (opcional, para despliegue contenerizado)

## Estructura del proyecto

```
TFM-AI-Security-Lab/
├── lab/                        # Código fuente del laboratorio
│   ├── attacks/                # Módulos de ataque (4 vectores)
│   ├── core/                   # Cliente Ollama, clasificador, métricas
│   ├── defenses/               # PromptGuard, sanitizador, validador
│   ├── payloads/               # 39 payloads organizados por vector
│   │   ├── direct/             # 10 payloads de inyección directa
│   │   ├── indirect/           # 6 payloads + documentos trampa (.txt, .json, .md)
│   │   ├── jailbreak/          # 13 payloads (DAN, role-play, crescendo)
│   │   ├── tool_abuse/         # 10 payloads (SQLi, path traversal, SSRF)
│   │   └── benign/             # Batería benigna de control (peticiones legítimas)
│   ├── scenarios/              # 4 escenarios agénticos (coding assistant, file reader, web researcher, autonomous coder)
│   ├── results/                # Resultados pre-calculados (120+ archivos)
│   │   └── oficiales/          # Datos que respaldan las tablas de la memoria
│   ├── server.py               # API FastAPI (dashboard + ataques live)
│   ├── e1_reliability.py       # Experimento E1: fiabilidad test-retest
│   ├── e2_mini.py              # Experimento E2: predicción con herramienta
│   ├── e3_factorial.py         # Experimento E3: diseño factorial
│   ├── reclassify_e1_e3.py     # Reclasificación E1/E3 con rúbrica
│   ├── reeval_indirect.py      # Reevaluación del vector indirecto
│   ├── reeval_indirect_canary.py # Reevaluación indirecta + canario
│   └── run_benign_battery.py   # Batería benigna de control
├── dashboard/                  # Frontend web (HTML/CSS/JS)
├── docker/                     # Docker Compose, Dockerfiles, nginx
├── docs/                       # Generador de la memoria (python-docx) + docs de apoyo
├── notebooks/                  # Análisis en Jupyter
│   ├── 00_setup_verificacion.ipynb
│   ├── 01_direct_injection.ipynb
│   ├── 02_indirect_injection.ipynb
│   ├── 03_jailbreak.ipynb
│   ├── 04_comparativa_modelos.ipynb
│   ├── 05_comparativa_modelos_qwen_TFM_FINAL.ipynb
│   ├── 05_comparativa_modelos_qwen_TFM_FINAL_EJECUTADO.ipynb
│   └── analisis_estadistico.py
├── presentacion/               # Slides (Reveal.js) + demo E2 (HTML y vídeo)
├── run_lab.py                  # CLI principal para lanzar baterías
├── run_experiment.py           # Lanzador de experimentos individuales
└── requirements.txt            # Dependencias con versiones fijadas
```

## Instalación

```bash
git clone https://github.com/alemeyerso/TFM-AI-Security-Lab.git
cd TFM-AI-Security-Lab
pip install -r requirements.txt
```

### Descargar los modelos en Ollama

```bash
ollama pull gemma4:e2b    # 2.3B params, ~7GB
ollama pull gemma4:e4b    # 4B params, ~10GB
ollama pull gemma4:26b    # 26B MoE (3.8B activos), ~17GB
```

Para la comparativa cross-family (opcional):
```bash
ollama pull qwen3.5:2b
```

## Modo completo (con modelos)

### Opción A: Sin Docker

```bash
# 1. Asegúrate de que Ollama está corriendo
ollama serve

# 2. Arranca la API del laboratorio
python lab/server.py

# 3. Abre dashboard/index.html en el navegador
#    o accede a http://localhost:8000/api/results
```

### Opción B: Con Docker

```bash
docker compose -f docker/docker-compose.yml up -d
```

Esto levanta:
- **API** en `http://localhost:8000`
- **Dashboard** en `http://localhost:8080`
- **Jupyter** en `http://localhost:8888` (token: `tfm2026`)

Ollama debe estar corriendo en el host (Docker se conecta via `host.docker.internal:11434`).

## Modo offline (sin GPU ni Ollama)

Si no tienes GPU o no quieres descargar los modelos, puedes ver todos los resultados pre-calculados:

```bash
python lab/server.py --offline
```

El dashboard muestra las gráficas con los 120+ archivos JSON de `lab/results/`. No necesita Ollama.

## Reproducir los experimentos

### Batería principal (39 payloads × 3 modelos)

```bash
# Todos los vectores contra un modelo
python run_lab.py --model gemma4:e2b --all-vectors

# Un vector específico
python run_lab.py --model gemma4:e2b --vector direct

# Todos los modelos, todos los vectores (tarda ~4 horas)
for model in gemma4:e2b gemma4:e4b gemma4:26b; do
    python run_lab.py --model $model --all-vectors
done
```

### Experimento E1: Fiabilidad test-retest

Cada payload se ejecuta 5 veces por modelo para medir estabilidad:

```bash
python lab/e1_reliability.py
```
- Resultados: `lab/results/e1_reliability_20260913.json`
- Resumen: `lab/results/e1_reliability_summary.csv`

### Experimento E2: Predicción con herramienta (send_email)

Verifica que el ASR pasa de 0% a 93.3% al darle `send_email` al modelo:

```bash
python lab/e2_mini.py
```
- Resultados: `lab/results/e2_mini_20260914.json`

### Experimento E3: Diseño factorial de inyección indirecta

6 payloads × 3 modelos × 10 runs × 2 condiciones (inyectado vs limpio):

```bash
python lab/e3_factorial.py
```
- Resultados: `lab/results/e3_factorial_20260914.json`
- Resumen: `lab/results/e3_factorial_summary.csv`

### Comparativa cross-family (Qwen 3.5)

Abrir en Jupyter:
```bash
jupyter notebook notebooks/05_comparativa_modelos_qwen_TFM_FINAL.ipynb
```

### Batería benigna de control

```bash
python lab/run_benign_battery.py
```
- Resultados: `lab/results/eval_benign_battery.json`

## Verificar los datos de la memoria

Los datos que aparecen en las tablas del documento final provienen de:

| Tabla de la memoria | Archivo fuente |
|---|---|
| 4.1 Resultados globales | `lab/results/oficiales/notebook05_20260913/05_summary_asr_20260913_004400.csv` |
| 4.2 Por vector | `lab/results/oficiales/notebook05_20260913/05_comparativa_modelos_20260913_004400.csv` |
| 4.5 Comparativa Qwen | Notebook 05 |
| 4.7 E1 fiabilidad | `lab/results/e1_reliability_summary.csv` |
| 4.8 E3 factorial | `lab/results/e3_factorial_summary.csv` |
| 4.10 E2 predicción | `lab/results/e2_mini_20260914.json` |

## Generar la memoria

```bash
python docs/generate_tfm.py
```
Genera `docs/TFM_Final.docx` con todas las tablas y datos actualizados.


