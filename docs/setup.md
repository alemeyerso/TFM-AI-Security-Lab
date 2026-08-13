# Guía de Instalación — AI Security Lab

**TFM 2025 · Evaluación de Robustez de Agentes IA frente a Prompt Injection**  
Autores: Aleja & Juan

---

## Índice

1. [Prerrequisitos](#1-prerrequisitos)
2. [Instalación de Ollama en Windows](#2-instalación-de-ollama-en-windows)
3. [Descarga de modelos Gemma 4](#3-descarga-de-modelos-gemma-4)
4. [Fix del num_ctx (problema de contexto)](#4-fix-del-num_ctx)
5. [Instalación de Docker Desktop](#5-instalación-de-docker-desktop)
6. [Configuración del Laboratorio](#6-configuración-del-laboratorio)
7. [Ejecución con Docker Compose](#7-ejecución-con-docker-compose)
8. [Ejecución sin Docker (modo local)](#8-ejecución-sin-docker)
9. [Dashboard Web](#9-dashboard-web)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerrequisitos

### Hardware recomendado

| Componente | Mínimo | Recomendado |
|------------|--------|-------------|
| RAM | 16 GB | 32 GB |
| GPU VRAM | — (CPU) | 8 GB (gemma4:e2b) |
| Disco libre | 20 GB | 60 GB |
| CPU | 4 cores | 8+ cores |

> [!NOTE]
> El laboratorio puede ejecutarse sin GPU. Los modelos e2b y e4b funcionan bien en CPU con 16 GB RAM. El modelo 26b requiere GPU o mucha RAM (>32 GB).

### Software necesario

- **Windows 10/11** (64-bit)
- **Docker Desktop** 4.x o superior
- **Ollama** 0.6.x o superior
- **Python 3.12+** (solo si ejecutas sin Docker)
- **Git** (opcional, para clonar el repositorio)

---

## 2. Instalación de Ollama en Windows

### Paso 1: Descargar Ollama

1. Abre tu navegador y ve a [https://ollama.com/download](https://ollama.com/download)
2. Haz clic en **"Download for Windows"**
3. Ejecuta el instalador `OllamaSetup.exe`
4. Sigue el asistente de instalación (no requiere configuración especial)

### Paso 2: Verificar la instalación

Abre PowerShell o CMD y ejecuta:

```powershell
ollama --version
```

Deberías ver algo como: `ollama version 0.6.x`

### Paso 3: Verificar que el servicio está activo

Ollama se inicia automáticamente como servicio de Windows. Verifica:

```powershell
# Comprobar que la API responde
Invoke-WebRequest -Uri "http://localhost:11434/api/tags" | Select-Object StatusCode
# Debe devolver: 200
```

O abre el navegador en: `http://localhost:11434`

> [!TIP]
> Ollama corre en el puerto `11434` por defecto. Si ves "Ollama is running" en el navegador, todo está bien.

### Configuración del firewall (opcional)

Si Docker no puede conectar al Ollama del host:

1. Abre **Windows Defender Firewall** → **Reglas de entrada**
2. Crea nueva regla → Puerto → TCP → 11434
3. Acción: Permitir la conexión
4. Aplicar a: Redes privadas

---

## 3. Descarga de Modelos Gemma 4

El laboratorio evalúa tres variantes del modelo **Gemma 4** de Google:

| Modelo | Tamaño aprox. | RAM necesaria | Velocidad |
|--------|---------------|----------------|-----------|
| `gemma4:e2b` | ~2 GB | 4-6 GB | Rápido |
| `gemma4:e4b` | ~4 GB | 6-8 GB | Medio |
| `gemma4:26b` | ~16 GB | 20+ GB | Lento |

### Descargar modelos

Abre PowerShell y ejecuta:

```powershell
# Modelo pequeño (e2b) - recomendado para empezar
ollama pull gemma4:e2b

# Modelo mediano (e4b)
ollama pull gemma4:e4b

# Modelo grande (26b) - requiere mucha RAM/VRAM
ollama pull gemma4:26b
```

> [!NOTE]
> La descarga puede tardar varios minutos según tu conexión. Los modelos se guardan en `C:\Users\<usuario>\.ollama\models\`

### Verificar modelos descargados

```powershell
ollama list
```

Deberías ver:
```
NAME            ID              SIZE    MODIFIED
gemma4:e2b      abc123def456    2.1 GB  hace 2 minutos
gemma4:e4b      def456abc789    4.3 GB  hace 5 minutos
```

### Probar un modelo

```powershell
ollama run gemma4:e2b "Hola, ¿puedes presentarte brevemente?"
```

---

## 4. Fix del num_ctx

> [!IMPORTANT]
> Este es uno de los hallazgos clave del laboratorio. Sin este fix, Ollama usa una ventana de contexto muy pequeña (~2048 tokens), lo que distorsiona los resultados de las pruebas.

### El problema

Por defecto, Ollama limita el contexto (`num_ctx`) a un valor pequeño (~2048 tokens) aunque el modelo soporte hasta 128K tokens. Esto provoca:

- Truncado de prompts largos
- Respuestas incorrectas en ataques de overflow
- Resultados no representativos del modelo real

### La solución (fix de Juan)

Al llamar a la API de Ollama, siempre especifica `num_ctx`:

```python
# En el código Python del laboratorio:
response = ollama.chat(
    model="gemma4:e2b",
    messages=[{"role": "user", "content": prompt}],
    options={
        "num_ctx": 127000,  # ← ESTE ES EL FIX
        "temperature": 0.1,
    }
)
```

O en la variable de entorno (ya configurada en `.env.example`):

```bash
NUM_CTX=127000
```

### Verificar el contexto activo

```powershell
# Consulta el modelo y verifica el num_ctx en la respuesta
curl -X POST http://localhost:11434/api/generate `
  -H "Content-Type: application/json" `
  -d '{"model": "gemma4:e2b", "prompt": "test", "options": {"num_ctx": 127000}}'
```

---

## 5. Instalación de Docker Desktop

### Paso 1: Descargar

1. Ve a [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
2. Descarga **Docker Desktop for Windows**
3. Requisito: Windows 10/11 con WSL 2 habilitado

### Paso 2: Habilitar WSL 2 (si no está activo)

Abre PowerShell como Administrador:

```powershell
# Habilitar WSL
wsl --install

# Actualizar a WSL 2
wsl --set-default-version 2
```

Reinicia el equipo si se solicita.

### Paso 3: Instalar Docker Desktop

1. Ejecuta el instalador `Docker Desktop Installer.exe`
2. Marca la opción **"Use WSL 2 instead of Hyper-V"**
3. Completa la instalación y reinicia

### Paso 4: Verificar Docker

```powershell
docker --version
docker compose version
```

Deberías ver:
```
Docker version 26.x.x
Docker Compose version v2.x.x
```

---

## 6. Configuración del Laboratorio

### Paso 1: Obtener el código

```powershell
# Si usas Git:
git clone <url-del-repositorio> C:\Users\aleja\TFM
cd C:\Users\aleja\TFM

# O simplemente descomprime el ZIP en C:\Users\aleja\TFM
```

### Paso 2: Configurar variables de entorno

```powershell
# Copiar el archivo de ejemplo
Copy-Item docker\.env.example docker\.env

# Editar si necesitas cambiar algo (opcional)
notepad docker\.env
```

### Paso 3: Instalar dependencias Python (si ejecutas sin Docker)

```powershell
# Crear entorno virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# Instalar dependencias
pip install -r requirements.txt
```

---

## 7. Ejecución con Docker Compose

### Arrancar el dashboard

```powershell
cd C:\Users\aleja\TFM\docker

# Construir imagen y arrancar dashboard
docker compose up -d dashboard

# Ver el dashboard en el navegador
Start-Process "http://localhost:8080"
```

### Ejecutar una evaluación

```powershell
# Evaluación completa con gemma4:e2b
docker compose run --rm lab python run_lab.py \
  --model gemma4:e2b \
  --vectors all \
  --output /lab/lab/results

# Solo vector de jailbreak
docker compose run --rm lab python run_lab.py \
  --model gemma4:e2b \
  --vectors jailbreak \
  --output /lab/lab/results

# Modo demo (sin Ollama, usa respuestas simuladas)
docker compose run --rm lab python run_lab.py --demo
```

### Comandos útiles de Docker

```powershell
# Ver logs del dashboard
docker compose logs -f dashboard

# Reconstruir imagen tras cambios en código
docker compose build lab

# Parar todos los servicios
docker compose down

# Ver servicios activos
docker compose ps

# Limpiar todo (¡elimina contenedores y volúmenes!)
docker compose down -v --remove-orphans
```

---

## 8. Ejecución sin Docker

Si prefieres ejecutar directamente en Python:

```powershell
# Activar entorno virtual
.venv\Scripts\Activate.ps1

# Ayuda
python run_lab.py --help

# Evaluación con modelo e2b, todos los vectores
python run_lab.py --model gemma4:e2b --vectors all

# Solo direct injection
python run_lab.py --model gemma4:e2b --vectors direct

# Con output personalizado
python run_lab.py --model gemma4:e2b --output lab/results/mi_test.json

# Modo verbose
python run_lab.py --model gemma4:e2b --verbose
```

---

## 9. Dashboard Web

### Opción A: Abrir directamente (sin Docker)

1. Navega a `C:\Users\aleja\TFM\dashboard\`
2. Doble clic en `index.html`
3. El dashboard carga con datos de demo automáticamente

> [!NOTE]
> Al abrirlo como archivo local (`file://`), la verificación del estado de Ollama puede fallar por restricciones CORS. Todo lo demás funciona perfectamente.

### Opción B: Con Docker (recomendado)

```powershell
docker compose -f docker/docker-compose.yml up -d dashboard
# Abrir http://localhost:8080
```

### Cómo usar el dashboard

1. **Cargar JSON** — Carga tus propios resultados desde `lab/results/*.json`
2. **Panel de Sesiones** — Haz clic en una sesión para verla activa
3. **Filtrar tests** — Usa los filtros de Vector/Outcome/Severidad
5. **Ver detalle** — Clic en "Ver" en cualquier test para ver el prompt/respuesta completo
6. **Comparativa** — Con 2+ sesiones cargadas, la sección inferior compara modelos
7. **Exportar** — Descarga los datos en CSV o JSON

---

## 10. Troubleshooting

### ❌ "Ollama is not running" en el dashboard

**Causa:** Ollama no está ejecutándose en el host.

**Solución:**
```powershell
# Iniciar Ollama manualmente
ollama serve

# O verificar el proceso
Get-Process ollama
```

### ❌ Error de conexión desde Docker a Ollama

**Causa:** `host.docker.internal` no se resuelve en Linux.

**Solución para Linux:**
```yaml
# En docker-compose.yml, ya está configurado:
extra_hosts:
  - "host.docker.internal:host-gateway"
```

O usa la IP del bridge Docker:
```bash
# Obtener IP del host desde el contenedor
docker run --rm alpine ip route | awk 'NR==1{print $3}'
# Usar esa IP en OLLAMA_HOST
```

### ❌ El modelo responde muy lento o da timeout

**Causa:** Sin GPU, los modelos grandes son muy lentos.

**Solución:**
```bash
# Usar el modelo más pequeño
--model gemma4:e2b

# Aumentar el timeout
TEST_TIMEOUT=120  # en .env
```

### ❌ "num_ctx" truncando el contexto

**Causa:** Ollama usa el num_ctx por defecto (~2048).

**Solución:** Asegúrate de que `NUM_CTX=127000` está en el `.env` y que el código lo usa en las llamadas.

### ❌ Error "CORS policy" al cargar JSON en el navegador

**Causa:** Los navegadores bloquean `fetch` de `file://` a `file://`.

**Solución:** Usa el botón "Cargar JSON" (file picker) en lugar de fetch directo, o sirve el dashboard con Docker/Nginx.

### ❌ Docker Desktop no arranca en Windows

**Causas comunes:**
- WSL 2 no instalado → `wsl --install` como Admin
- Hyper-V no habilitado → Panel de Control → Características de Windows
- Virtualización deshabilitada en BIOS → Habilitar Intel VT-x o AMD-V

### ❌ "Permission denied" al escribir resultados

**Causa:** El contenedor no tiene permisos en el volumen montado.

**Solución:**
```powershell
# Asegurar que el directorio existe en el host
New-Item -ItemType Directory -Force -Path "lab\results"
# Docker Desktop en Windows maneja permisos automáticamente
```

---

## Estructura del proyecto

```
TFM/
├── dashboard/           # Dashboard web
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
├── docker/              # Infraestructura Docker
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── nginx.conf
│   └── .env.example
├── lab/                 # Código del laboratorio
│   ├── payloads/        # Payloads de ataque
│   ├── results/         # Resultados JSON (generados)
│   └── logs/            # Logs de ejecución
├── docs/                # Documentación
│   ├── setup.md         # Esta guía
│   ├── attack_taxonomy.md
│   └── defense_framework.md
├── requirements.txt
├── run_lab.py
└── README.md
```

---

*Documentación generada para el TFM 2025 · Evaluación de Robustez de Agentes IA frente a Prompt Injection*
