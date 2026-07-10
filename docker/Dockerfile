FROM python:3.12-slim

# Metadata
LABEL maintainer="Aleja & Juan — TFM 2025"
LABEL description="AI Security Lab: Prompt Injection Evaluation Framework"
LABEL version="1.0.0"

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Ollama corre en el HOST, no en Docker
    # En Windows/Mac usa host.docker.internal
    # En Linux usa la IP del host o extra_hosts
    OLLAMA_HOST=host.docker.internal:11434 \
    DEFAULT_MODEL=gemma4:e2b \
    NUM_CTX=127000 \
    RESULTS_DIR=/lab/lab/results \
    LOG_LEVEL=INFO

# Directorio de trabajo
WORKDIR /lab

# Copiar requirements primero (aprovecha caché de Docker)
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código del laboratorio
COPY lab/ ./lab/
COPY run_lab.py .

# Crear directorios necesarios
RUN mkdir -p lab/results lab/payloads lab/logs

# Crear usuario no-root para seguridad
RUN useradd --create-home --shell /bin/bash labuser && \
    chown -R labuser:labuser /lab

USER labuser

# Healthcheck: verifica que Python está disponible
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

# Por defecto muestra la ayuda
# Sobrescribir con: docker run ... python run_lab.py --model gemma4:e2b
CMD ["python", "run_lab.py", "--help"]
