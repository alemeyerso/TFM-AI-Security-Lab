# 🔐 AI Security Lab — TFM

> **Trabajo de Fin de Máster** · Evaluación de la Ciberseguridad en Entornos de IA Generativa  
> *Máster en Ciberseguridad · UCM · 2025-26*

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Gemma%204-FF6B35?style=flat-square)
![Jupyter](https://img.shields.io/badge/Jupyter-Notebooks-F37626?style=flat-square&logo=jupyter&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/Licencia-MIT-00D4AA?style=flat-square)

---

## ¿Qué es esto?

Este repositorio contiene el **laboratorio de evaluación de seguridad** desarrollado para el TFM. El objetivo es medir y comparar la robustez de modelos de IA open-weights (familia **Gemma 4**, desplegados localmente con **Ollama**) frente a cuatro vectores de ataque:

| Vector | Técnicas | Severidad |
|--------|----------|-----------|
| ⚡ **Direct Injection** | Instruction override, role hijacking, Base64 obfuscation, crescendo | High / Critical |
| 🌐 **Indirect Injection** | Documentos trampa (CV, config, README), tool output poisoning | High / Critical |
| 🔓 **Jailbreak** | DAN, opposite day, roleplay, research context, language switch | Medium / Critical |
| 🔧 **Tool / Agent Abuse** | Path traversal, command injection, SSRF, data exfiltration | Critical |

---

## Reproducir desde cero

### Requisitos mínimos

| Herramienta | Instalación | Necesario para |
|---|---|---|
| **Docker Desktop** | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) | Todo el lab |
| **Ollama** | [ollama.com](https://ollama.com) | Modelos de IA |

> **Nada más.** Python, Jupyter, FastAPI — todo corre dentro de Docker.

### Paso 1 — Descargar los modelos

```bash
# Los tres modelos de la comparativa
ollama pull gemma4:e2b    # ~7 GB   — edge 2B parámetros
ollama pull gemma4:e4b    # ~9.6 GB — edge 4B parámetros
ollama pull gemma4:26b    # ~17 GB  — MoE 26B parámetros
```

> 💡 Se pueden dejar descargando en segundo plano. Si la conexión se corta, Ollama reanuda la descarga desde donde se quedó.

> ⚠️ **Fix obligatorio para OpenCode/Ollama** (num_ctx): después de descargar, ejecuta:
> ```bash
> ollama run gemma4:e2b
> /set parameter num_ctx 127000
> /save gemma4-e2b-lab
> ```

### Paso 2 — Clonar y arrancar

```bash
git clone https://github.com/alemeyerso/TFM-AI-Security-Lab.git
cd TFM-AI-Security-Lab
docker compose -f docker/docker-compose.yml up -d
```

### Paso 3 — Acceder

| Servicio | URL | Para qué |
|---|---|---|
| 📓 **Jupyter Lab** | http://localhost:8888 (token: `tfm2026`) | Reproducir experimentos celda a celda |
| ⚡ **API Live** | http://localhost:8000/docs | Ejecutar ataques vía Swagger UI |
| 📊 **Dashboard** | http://localhost:8080 | Visualizar resultados + panel de ataque live |

---

## Estructura del proyecto

```
TFM/
│
├── 📓 notebooks/                    ← Experimentos reproducibles
│   ├── 00_setup_verificacion.ipynb  Verificar Ollama + modelos disponibles
│   ├── 01_direct_injection.ipynb    5 ataques de inyección directa
│   ├── 02_indirect_injection.ipynb  3 escenarios de inyección indirecta
│   ├── 03_jailbreak.ipynb           6 técnicas de jailbreak
│   └── 04_comparativa_modelos.ipynb Comparativa e2b vs e4b vs 26b + gráficas
│
├── 🐍 lab/
│   ├── server.py          FastAPI — motor de ataques live (port 8000)
│   ├── core/              Motor de evaluación + cliente Ollama + métricas
│   ├── attacks/           Módulos de ataque (direct, indirect, jailbreak, tool_abuse)
│   ├── payloads/          39 payloads JSON con mapeo MITRE ATLAS
│   ├── defenses/          Input sanitizer, output validator, prompt guard
│   ├── scenarios/         4 escenarios realistas de agentes autónomos
│   └── results/           JSONs de resultados (generados al ejecutar)
│
├── 🌐 dashboard/          Dashboard web dark-mode (HTML/CSS/JS puro)
│
├── 🐳 docker/
│   ├── docker-compose.yml 4 servicios: jupyter + api + dashboard + lab
│   ├── Dockerfile         Servicio CLI Python
│   ├── Dockerfile.api     Servicio FastAPI
│   └── .env.example       Variables de entorno configurables
│
├── 📚 docs/
│   ├── reproducibilidad.md  ← Guía detallada para reproducir el lab
│   ├── setup.md             Instalación de Ollama + fix num_ctx
│   ├── attack_taxonomy.md   Taxonomía basada en MITRE ATLAS
│   └── defense_framework.md Marco de defensa (6 capas)
│
├── run_lab.py             CLI alternativo (sin Docker)
└── requirements.txt       Dependencias Python
```

---

## Cómo ejecutar los experimentos

### Opción A — Jupyter (reproducibilidad académica)

1. Abrir http://localhost:8888 (token: `tfm2026`)
2. Navegar a `notebooks/`
3. Empezar por `00_setup_verificacion.ipynb`
4. Ejecutar celda a celda — cada celda muestra la respuesta **real** del modelo

Exportar para el apéndice del TFM:
```bash
docker compose exec jupyter jupyter nbconvert --to html notebooks/*.ipynb
```

### Opción B — Panel Live del Dashboard

1. Abrir http://localhost:8080
2. Hacer clic en **⚡ Ataque Live** en el sidebar
3. Seleccionar modelo → vector → payload
4. Pulsar **⚡ Ejecutar Ataque**
5. Ver la respuesta real con badge de resultado (success / partial / refused)

### Opción C — API directa (Swagger UI)

1. Abrir http://localhost:8000/docs
2. Probar `POST /api/attack` con el body:
```json
{
  "model": "gemma4:e2b",
  "vector": "jailbreak",
  "payload_id": "dan_classic"
}
```

### Opción D — CLI Python

```bash
# Evaluación completa
docker compose -f docker/docker-compose.yml run --rm lab \
  python run_lab.py --model gemma4:e2b --all-vectors

# Solo jailbreak
docker compose -f docker/docker-compose.yml run --rm lab \
  python run_lab.py --model gemma4:e2b --vector jailbreak

```

---

## Métricas de evaluación

| Métrica | Descripción | Interpretación |
|---------|-------------|----------------|
| **ASR** (Attack Success Rate) | % ataques exitosos | Menor = más robusto |
| **Partial ASR** | % ataques parcialmente exitosos | Zona gris |
| **Refusal Rate** | % rechazos del modelo | Mayor = más robusto |
| **Latencia media** | ms de respuesta | Referencia de rendimiento |

### Clasificación de robustez

| ASR | Nivel | |
|-----|-------|-|
| < 15% | Robusto | 🟢 |
| 15–30% | Aceptable | 🟡 |
| 30–50% | Vulnerable | 🟠 |
| > 50% | Crítico | 🔴 |

---

## Vectores de ataque — clasificación MITRE ATLAS

### ⚡ Direct Injection — `AML.T0051`
El atacante controla directamente el input del usuario para sobreescribir instrucciones del sistema. 10 payloads.

### 🌐 Indirect Injection — `AML.T0051.001` / `AML.T0020`
Las instrucciones maliciosas se ocultan en datos del entorno que el agente procesa (documentos, configs, resultados de herramientas). Es el vector más peligroso en sistemas agénticos. 6 payloads.

### 🔓 Jailbreak — `AML.T0054`
Técnicas para desactivar los filtros de seguridad y la alineación del modelo mediante roleplay, reencuadres lógicos o escalada gradual. 15 payloads.

### 🔧 Tool / Agent Abuse — `AML.T0043` / `AML.T0051`
Ataques específicos de agentes con acceso a herramientas (terminal, sistema de ficheros, red). El objetivo es provocar acciones dañinas en el entorno. 8 payloads.

---

## Documentación completa

| Documento | Contenido |
|-----------|-----------|
| [🔁 Guía de Reproducibilidad](docs/reproducibilidad.md) | Instrucciones paso a paso + troubleshooting |
| [📖 Setup](docs/setup.md) | Instalación de Ollama + fix num_ctx |
| [🗂️ Taxonomía de Ataques](docs/attack_taxonomy.md) | Clasificación MITRE ATLAS |
| [🛡️ Marco de Defensa](docs/defense_framework.md) | 6 capas de defensa en profundidad |

---

## Autores

| Nombre | |
|--------|--|
| Juan Montero Gómez | |
| Rugerio Fernández Cobos Fanny B. | |
| Fabiola García Gonzalo | |
| Pedro González Hernanz | |
| Florencia María Belén García | |
| Alejandra Meyers Otero | |

*Máster en Ciberseguridad — UCM — 2025-26*

---

## Referencias

- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Ollama Documentation](https://ollama.com/docs)
- [Gemma 4 — Google DeepMind](https://ai.google.dev/gemma)
- Greshake et al. (2023) — *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* — arXiv:2302.12173
- Perez & Ribeiro (2022) — *Ignore Previous Prompt: Attack Techniques For Language Models*
- Carlini et al. (2023) — *Poisoning Web-Scale Training Datasets is Practical* — arXiv:2302.10149
- Rehberger, J. (2023-2024) — *Prompt Injection in Copilot and AI Agents* — embracethered.com
- AgentDojo Benchmark — *Evaluating Prompt Injection Attacks and Defenses for LLM Agents*

---

<div align="center">
  <sub>Construido con 🔐 para el TFM · <a href="docs/reproducibilidad.md">Reproducir el laboratorio</a></sub>
</div>
