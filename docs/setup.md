# Setup — AI Security Lab

## 1. Configuración
```bash
cp docker/.env.example docker/.env
docker compose -f docker/docker-compose.yml config --quiet
```
Define un `JUPYTER_TOKEN` propio en `docker/.env`.

## 2. Arranque
```bash
docker compose -f docker/docker-compose.yml up -d api dashboard jupyter
```

Servicios:
- Dashboard: `http://127.0.0.1:8080`
- API: `http://127.0.0.1:8000/docs`
- Jupyter: `http://127.0.0.1:8888`

## 3. CLI
```bash
python run_lab.py --help
python run_lab.py --model gemma4:e2b --all-vectors
python run_lab.py --model gemma4:e2b --vector jailbreak
python run_lab.py --model gemma4:e2b --demo
```

## 4. Experimentos oficiales
```bash
python lab/e1_reliability.py
python lab/e2_mini.py
python lab/e3_factorial.py
python lab/reclassify_v3_overrides.py
```

## 5. Reproducibilidad
Docker reproduce el entorno de software; las inferencias exactas dependen de Ollama, el modelo y la aleatoriedad. Los resultados congelados permiten auditar y recalcular el análisis sin repetir inferencias.
