# 🔁 Guía de Reproducibilidad — Laboratorio TFM

> **Evaluación de Robustez de Agentes IA frente a Ataques de Prompt Injection**  
> TFM 2025 · Aleja & Juan

Esta guía permite a cualquier evaluador (profesor, revisor, tribunal) reproducir todos los experimentos del laboratorio en **menos de 15 minutos**, sin necesidad de conocimientos de Python, Node.js ni ningún lenguaje de programación.

---

## Índice

1. [Requisitos Mínimos](#1-requisitos-mínimos)
2. [Descarga de Modelos de IA](#2-descarga-de-modelos-de-ia)
3. [Arranque del Laboratorio (3 pasos)](#3-arranque-del-laboratorio-3-pasos)
4. [Reproducir los Experimentos con Jupyter](#4-reproducir-los-experimentos-con-jupyter)
5. [Demo Live con el Dashboard](#5-demo-live-con-el-dashboard)
6. [Exportar Resultados para el TFM](#6-exportar-resultados-para-el-tfm)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Requisitos Mínimos

| Componente | Versión mínima | Descarga |
|---|---|---|
| **Docker Desktop** | 4.x o superior | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| **Ollama** | 0.4 o superior | [ollama.com/download](https://ollama.com/download) |
| **RAM** | 8 GB (16 GB recomendado para modelos grandes) | — |
| **Disco** | ~25 GB libres (modelos + Docker) | — |

> [!IMPORTANT]
> **No se requiere Python, Node.js, ni ningún otro lenguaje instalado localmente.**  
> Todo corre dentro de Docker. Solo necesitas Docker Desktop + Ollama.

> [!NOTE]
> **Windows**: Docker Desktop incluye WSL2 automáticamente. Actívalo si se solicita durante la instalación.  
> **macOS**: Docker Desktop funciona de forma nativa en Intel y Apple Silicon (M1/M2/M3/M4).  
> **Linux**: Instala Docker Engine + Docker Compose v2 (`apt install docker-compose-plugin`).

---

## 2. Descarga de Modelos de IA

Una vez instalado Ollama, abre una terminal y ejecuta:

```bash
# Modelo pequeño (~2.5 GB) — el más vulnerable, ideal para pruebas rápidas
ollama pull gemma4:e2b

# Modelo mediano (~4.9 GB) — balance entre velocidad y robustez
ollama pull gemma4:e4b

# Modelo grande (~17 GB) — el más robusto, requiere más RAM y tiempo
ollama pull gemma4:26b
```

> [!TIP]
> Para reproducir todos los experimentos del TFM necesitas los tres modelos.  
> Si tienes limitaciones de disco, empieza solo con `gemma4:e2b` (el más ligero).

### Fix del Contexto Ampliado (`num_ctx`)

Los experimentos usan `num_ctx=127000` (ventana de contexto máxima de Gemma 4).  
Si un modelo responde con errores de contexto, aplica este fix:

```bash
# Crear un Modelfile que fije el num_ctx para gemma4:e2b
cat > /tmp/Modelfile_e2b << 'EOF'
FROM gemma4:e2b
PARAMETER num_ctx 127000
EOF

ollama create gemma4:e2b-ctx -f /tmp/Modelfile_e2b

# Repetir para los demás modelos si es necesario
```

**¿Por qué es necesario?** Los ataques de tipo *indirect injection* inyectan documentos externos largos en el contexto del modelo. Sin `num_ctx` elevado, Ollama trunca el prompt y los ataques no se ejecutan correctamente, sesgando los resultados del ASR (Attack Success Rate).

> [!NOTE]
> El servidor FastAPI del laboratorio ya pasa `num_ctx=127000` automáticamente en cada llamada.  
> Este fix manual solo es necesario si usas Ollama directamente desde terminal.

---

## 3. Arranque del Laboratorio (3 pasos)

### Paso 1 — Clonar el repositorio

```bash
git clone https://github.com/[REPO_URL]/TFM.git
cd TFM
```

> Si ya tienes el código (p.ej. en un USB o descargado del aula virtual), simplemente ve al directorio:
> ```bash
> cd /ruta/donde/esta/TFM
> ```

### Paso 2 — Verificar que Ollama está corriendo

```bash
# En Windows/macOS: Ollama se inicia como aplicación de escritorio automáticamente
# En Linux, si no está corriendo:
ollama serve &

# Verificar que responde:
curl http://localhost:11434/api/tags
# Debes ver una lista de modelos en JSON
```

### Paso 3 — Arrancar todos los servicios con Docker

```bash
docker compose -f docker/docker-compose.yml up -d api dashboard jupyter
```

Espera ~60 segundos la primera vez (descarga de imágenes Docker). Luego:

| Servicio | URL | Descripción |
|---|---|---|
| 🖥️ **Dashboard** | http://localhost:8080 | Visualización de resultados (no requiere API) |
| ⚡ **API Live** | http://localhost:8000/docs | FastAPI con Swagger UI interactivo |
| 📓 **Jupyter** | http://localhost:8888 | Notebooks de experimentos (token: `tfm2026`) |

> [!IMPORTANT]
> Si el dashboard muestra "API Lab: Offline", significa que el contenedor `api` aún está arrancando.  
> Espera 15-30 segundos y recarga la página.

---

## 4. Reproducir los Experimentos con Jupyter

### Acceso

1. Abre http://localhost:8888 en tu navegador
2. Introduce el token cuando se solicite: **`tfm2026`**
3. Navega a la carpeta `notebooks/`

### Notebooks disponibles

| Notebook | Descripción | Tiempo estimado |
|---|---|---|
| `01_direct_injection.ipynb` | Ataques de inyección directa sobre los 3 modelos | ~15 min |
| `02_indirect_injection.ipynb` | Inyección indirecta via documentos externos | ~20 min |
| `03_jailbreak.ipynb` | Técnicas de jailbreak (DAN, roleplay, etc.) | ~25 min |
| `04_tool_abuse.ipynb` | Abuso de herramientas (path traversal, SSRF, etc.) | ~15 min |
| `05_defense_evaluation.ipynb` | Evaluación de defensas (input sanitization, etc.) | ~20 min |
| `06_analysis_and_plots.ipynb` | Análisis estadístico y generación de gráficas | ~10 min |

### Ejecución de un notebook

1. Haz doble clic en el notebook deseado
2. En el menú superior: **Kernel → Restart Kernel and Run All Cells**
3. Espera a que todas las celdas completen su ejecución
4. Los resultados se guardan automáticamente en `lab/results/`

> [!TIP]
> Para reproducir **exactamente** los resultados del TFM, ejecuta los notebooks en orden (01 → 06) con el mismo modelo y sin interrupciones. Las semillas aleatorias están fijadas en cada notebook.

> [!WARNING]
> Los notebooks con modelos grandes (`gemma4:26b`) pueden tardar **varios minutos por ataque**.  
> Usa `gemma4:e2b` para pruebas rápidas de reproducibilidad.

---

## 5. Demo Live con el Dashboard

El dashboard en http://localhost:8080 tiene dos modos:

### Modo A — Ver resultados guardados

1. Haz clic en **"Demo Data"** para ver datos de ejemplo
2. O usa **"Cargar JSON"** para abrir cualquier archivo `*.json` de `lab/results/`
3. Navega por las secciones: Sesiones → KPIs → Gráficos → Tests → Comparativa

### Modo B — Ataque Live (requiere API corriendo)

1. Haz clic en **"⚡ Ataque Live"** en el sidebar izquierdo
2. Verifica que el indicador **"API Lab"** muestra **Online** (punto verde)
3. Selecciona:
   - **Modelo**: `gemma4:e2b` (más rápido para demo)
   - **Vector**: p.ej. `direct` o `jailbreak`
   - **Payload**: selecciona uno de la lista desplegable
4. Opcionalmente escribe un prompt personalizado en el área de texto
5. Pulsa **"⚡ Ejecutar Ataque"**
6. Observa el resultado:
   - 🔴 **SUCCESS** — El modelo fue comprometido (ataque exitoso)
   - 🟡 **PARTIAL** — Respuesta parcialmente comprometida
   - 🟢 **REFUSED** — El modelo rechazó el ataque (comportamiento seguro)

> [!NOTE]
> Cada ataque ejecutado se guarda automáticamente en `lab/results/` como un archivo JSON.  
> Puedes cargarlo después en el dashboard con "Cargar JSON" para análisis.

---

## 6. Exportar Resultados para el TFM

### Exportar notebooks a HTML (recomendado para apéndice)

```bash
# Desde el directorio raíz del proyecto:
docker compose -f docker/docker-compose.yml exec jupyter \
  jupyter nbconvert --to html notebooks/*.ipynb

# Los archivos .html aparecerán en la carpeta notebooks/
# Copiarlos al apéndice del TFM como figuras/capturas
```

### Exportar notebooks a PDF (requiere LaTeX)

```bash
# Instalar dependencias LaTeX en el contenedor (solo la primera vez)
docker compose -f docker/docker-compose.yml exec jupyter \
  conda install -y nbconvert texlive-core

# Convertir a PDF
docker compose -f docker/docker-compose.yml exec jupyter \
  jupyter nbconvert --to pdf notebooks/*.ipynb
```

> [!TIP]
> **HTML es más fácil que PDF.** Los HTML incluyen todas las gráficas interactivas  
> y se pueden incluir como capturas en el apéndice del TFM con mejor fidelidad visual.

### Exportar datos CSV para tablas del TFM

```bash
# Desde el dashboard: Exportar CSV → se descarga en tu navegador
# O desde Python (en cualquier terminal):
docker compose -f docker/docker-compose.yml exec jupyter python -c "
import json, csv, glob, pathlib

results = []
for f in pathlib.Path('work/lab/results').glob('*.json'):
    data = json.loads(f.read_text())
    for test in data.get('tests', []):
        test['model'] = data.get('model', '')
        test['session_id'] = data.get('session_id', '')
        results.append(test)

with open('work/lab/results/all_results.csv', 'w', newline='') as f:
    if results:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
        print(f'Exportados {len(results)} tests a all_results.csv')
"
```

---

## 7. Troubleshooting

### ❌ "Ollama no responde" / API muestra "Ollama: Offline"

**Causa**: Ollama no está corriendo en el host.

```bash
# Windows/macOS: Abrir la aplicación Ollama desde el menú de inicio
# Linux:
ollama serve &

# Verificar que funciona:
curl http://localhost:11434/api/tags
```

Si el problema persiste en Docker (especialmente en Linux):
```bash
# Verificar que host.docker.internal resuelve correctamente
docker compose -f docker/docker-compose.yml exec api \
  curl http://host.docker.internal:11434/api/tags
```

---

### ❌ "Puerto ocupado" (bind: address already in use)

**Causa**: Otro proceso usa el mismo puerto.

```bash
# Ver qué proceso usa el puerto (p.ej. 8000):
# Windows:
netstat -ano | findstr :8000
# Linux/macOS:
lsof -i :8000

# Opción 1: Cambiar el puerto en docker-compose.yml
# Cambia "8000:8000" por "8001:8000" en el servicio api

# Opción 2: Matar el proceso que ocupa el puerto
# Windows:
taskkill /PID [PID_del_proceso] /F
# Linux/macOS:
kill -9 [PID_del_proceso]
```

---

### ❌ "Modelo lento" / Los ataques tardan demasiado

**Causa**: `gemma4:26b` es muy grande para el hardware disponible.

**Solución**: Usa `gemma4:e2b` para pruebas de reproducibilidad:
```bash
# En el panel ⚡ Ataque Live:
# Selecciona "gemma4:e2b — Pequeño (más vulnerable)"

# Para los notebooks, edita la celda de configuración:
MODEL = "gemma4:e2b"  # Cambiar de :26b a :e2b
```

---

### ❌ "num_ctx insuficiente" / Respuestas truncadas

**Síntoma**: El modelo responde que no puede procesar el contexto completo.

**Causa**: Ollama usa `num_ctx=2048` por defecto para algunos modelos.

**Solución**:
```bash
# 1. Crear un Modelfile con num_ctx ampliado
cat > /tmp/Modelfile << 'EOF'
FROM gemma4:e2b
PARAMETER num_ctx 127000
EOF

# 2. Crear un nuevo modelo con ese Modelfile
ollama create gemma4:e2b-lab -f /tmp/Modelfile

# 3. En los notebooks, usar el modelo con sufijo -lab
MODEL = "gemma4:e2b-lab"
```

> [!NOTE]
> El servidor FastAPI (`lab/server.py`) ya pasa `num_ctx=127000` en cada llamada.  
> Este fix solo es necesario si llamas a Ollama directamente.

---

### ❌ "docker compose: command not found"

**Causa**: Versión antigua de Docker que usa `docker-compose` (con guión).

```bash
# Prueba con:
docker-compose -f docker/docker-compose.yml up -d api dashboard

# O instala Docker Compose v2:
# https://docs.docker.com/compose/install/
```

---

### ❌ Dashboard muestra "API Lab: Offline" aunque la API está corriendo

**Causa**: El navegador bloquea conexiones cross-origin a localhost (poco común).

**Solución**:
1. Abre http://localhost:8000/health en una **nueva pestaña**
2. Si aparece `{"status": "ok", ...}` → la API funciona
3. Recarga el dashboard con `Ctrl+F5`
4. Si el problema persiste, desactiva extensiones de privacidad/adblock para localhost

---

### ❌ Contenedor api falla al arrancar (error de importación Python)

```bash
# Ver logs detallados:
docker compose -f docker/docker-compose.yml logs api

# Reconstruir la imagen (descarta caché):
docker compose -f docker/docker-compose.yml build --no-cache api
docker compose -f docker/docker-compose.yml up -d api
```

---

### ✅ Verificación rápida del entorno

Ejecuta este script para verificar que todo funciona:

```bash
# 1. Ollama responde
curl -s http://localhost:11434/api/tags | python3 -c "
import json,sys; data=json.load(sys.stdin)
models = [m['name'] for m in data.get('models',[])]
print(f'✅ Ollama online · {len(models)} modelos: {models}')
"

# 2. API responde
curl -s http://localhost:8000/health | python3 -c "
import json,sys; data=json.load(sys.stdin)
print(f'✅ API online · Ollama disponible: {data[\"ollama_available\"]}')
"

# 3. Dashboard responde
curl -s -o /dev/null -w "✅ Dashboard online · HTTP %{http_code}\n" http://localhost:8080

# 4. Jupyter responde
curl -s -o /dev/null -w "✅ Jupyter online · HTTP %{http_code}\n" http://localhost:8888
```

---

*Guía generada para el laboratorio TFM 2025. Para dudas, abrir un issue en el repositorio.*
