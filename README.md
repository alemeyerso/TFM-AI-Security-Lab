# TFM AI Security Lab 🔐

Repositorio oficial del Trabajo Fin de Máster (Máster en Ciberseguridad, UCM).
El profesor nos pidió que el proyecto fuera perfecta y fácilmente reproducible en cualquier ordenador. Por eso hemos preparado distintas formas de ejecutarlo.

## Requisitos previos

- **Python 3.14+**
- **Ollama** (para correr los modelos localmente) - [Descargar aquí](https://ollama.ai)
- **~30GB de espacio libre** en disco (los modelos pesan lo suyo)
- **Docker Desktop** (opcional, si prefieres aislar todo en contenedores)

## Estructura del proyecto

Aquí tienes un mapa para no perderte:

- `lab/`: Todo el código fuente del laboratorio (servidor, payloads, ataques)
  - `lab/results/`: Archivos JSON con los resultados pre-calculados (¡no los borres, sirven para el modo offline!)
- `docs/`: Documentación y scripts para generar la memoria del TFM
- `dashboard/`: Frontend web (interfaz gráfica)
- `docker/`: Configuración para levantar el proyecto con Docker Compose
- `notebooks/`: Análisis y experimentos celda a celda en Jupyter

## Instalación rápida (sin Docker)

Si no quieres liarte con Docker, esta es la forma más directa de ejecutar el entorno:

```bash
git clone https://github.com/alemeyerso/TFM-AI-Security-Lab.git
cd TFM-AI-Security-Lab
pip install -r requirements.txt

# Descargar los modelos necesarios en Ollama
ollama pull gemma4:e2b
ollama pull gemma4:e4b  
ollama pull gemma4:26b
```

## Modo completo (con modelos y GPU)

Con este modo pruebas todo en directo contra los modelos locales.

1. Arranca el servidor de la API:
   ```bash
   python lab/server.py
   ```
2. (Opcional) Si usas Docker:
   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```
3. Abre el dashboard accediendo al index.html en `dashboard/` o a través del puerto configurado en Docker. Desde ahí puedes lanzar ataques en la pestaña "Ataque Live".

## Modo degradado (sin GPU/Ollama)

¿Tu portátil no tiene GPU potente o no quieres bajarte los 30GB de modelos? No pasa nada. Hemos subido los resultados de nuestras pruebas (más de 120 archivos) al repositorio. 

Ejecuta el servidor en modo offline para ver el dashboard con nuestros resultados pre-calculados:

```bash
python lab/server.py --offline
```
El servidor te avisará con el mensaje: *Modo offline: mostrando resultados pre-calculados (Ollama no requerido)*.

## Ejecutar la batería de ataques

Si quieres replicar nuestros resultados ejecutando toda la batería de payloads de golpe (ojo, esto puede tardar horas dependiendo de tu PC):

```bash
# Para lanzar todos los vectores contra el modelo más ligero
python lab/run_lab.py --model gemma4:e2b --all-vectors

# O si usas docker:
docker compose -f docker/docker-compose.yml run --rm lab python run_lab.py --model gemma4:e2b --all-vectors
```

## Estructura de resultados

Todos los experimentos guardan sus datos en `lab/results/`.
- **Archivos JSON**: Cada archivo es una ejecución individual de un ataque (ej. `live_attack_gemma4_e2b_...json`). Incluyen la latencia, el prompt exacto enviado, la respuesta generada y la clasificación (success/refused/partial).
- El dashboard lee estos archivos automáticamente para generar las gráficas de ASR (Attack Success Rate).

## Generar la memoria

Para generar el documento final de la memoria del TFM:

```bash
python docs/generate_tfm.py
```
Esto junta los datos y exporta la memoria con las tablas y gráficas.

## Presentación

Puedes ver las diapositivas de nuestra presentación y el resumen del proyecto en nuestra página de GitHub Pages:
[https://alemeyerso.github.io/TFM-AI-Security-Lab](https://alemeyerso.github.io/TFM-AI-Security-Lab)
