"""
lab/core/ollama_client.py
=========================
Cliente Python para la API REST de Ollama en localhost:11434.

Características:
- Clase OllamaClient con métodos chat() y generate()
- num_ctx=127000 configurado automáticamente (FIX CRÍTICO para evitar respuestas de 1 token)
- Manejo de errores de conexión con mensajes descriptivos
- Medición de latencia en milisegundos por llamada
- Compatible con cualquier modelo de Ollama (gemma4:e2b, gemma4:e4b, gemma4:26b, etc.)
"""

import time
import json
from typing import Optional
import requests
from rich.console import Console

# Consola rich para logs con color
console = Console()

# URL base de la API de Ollama
OLLAMA_BASE_URL = "http://localhost:11434"

# Valor crítico de contexto: sin esto Ollama puede devolver solo 1 token
NUM_CTX_DEFAULT = 127000

# Timeout en segundos para peticiones a Ollama
REQUEST_TIMEOUT = 300  # 5 minutos para modelos grandes


class OllamaConnectionError(Exception):
    """Excepción lanzada cuando no se puede conectar con Ollama."""
    pass


class OllamaAPIError(Exception):
    """Excepción lanzada cuando la API de Ollama devuelve un error."""
    pass


class OllamaClient:
    """
    Cliente para interactuar con la API REST de Ollama.

    Parámetros
    ----------
    base_url : str
        URL base del servidor Ollama. Por defecto: http://localhost:11434
    num_ctx : int
        Tamaño del contexto. FIX CRÍTICO: debe ser >= 127000 para evitar
        que el modelo devuelva solo 1 token en respuestas largas.
    timeout : int
        Timeout en segundos para las peticiones HTTP.
    verbose : bool
        Si True, imprime información de depuración en la consola.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        num_ctx: int = NUM_CTX_DEFAULT,
        timeout: int = REQUEST_TIMEOUT,
        verbose: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout = timeout
        self.verbose = verbose
        self._session = requests.Session()
        # Cabeceras comunes para todas las peticiones
        self._session.headers.update({"Content-Type": "application/json"})

    # ------------------------------------------------------------------
    # Métodos públicos principales
    # ------------------------------------------------------------------

    def chat(
        self,
        model: str,
        messages: list[dict],
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        top_p: float = 0.9,
        max_tokens: Optional[int] = None,
    ) -> dict:
        """
        Envía una petición de chat a Ollama usando /api/chat.

        Parámetros
        ----------
        model : str
            Nombre del modelo Ollama, p.ej. "gemma4:e2b".
        messages : list[dict]
            Lista de mensajes con formato [{"role": "user", "content": "..."}].
        system_prompt : str, opcional
            Prompt de sistema. Si se proporciona, se añade al principio de messages.
        temperature : float
            Temperatura de generación (0.0 = determinista, 1.0 = muy creativo).
        top_p : float
            Nucleus sampling.
        max_tokens : int, opcional
            Límite de tokens en la respuesta. None = sin límite.

        Retorna
        -------
        dict con claves:
            - content: str — texto de la respuesta
            - model: str — modelo usado
            - latency_ms: int — latencia en milisegundos
            - prompt_tokens: int — tokens de entrada (si disponible)
            - completion_tokens: int — tokens de respuesta (si disponible)
            - raw: dict — respuesta completa de la API
        """
        # Construir lista de mensajes final
        final_messages = []
        if system_prompt:
            final_messages.append({"role": "system", "content": system_prompt})
        final_messages.extend(messages)

        # Opciones del modelo — num_ctx es el FIX CRÍTICO
        options = {
            "num_ctx": self.num_ctx,
            "temperature": temperature,
            "top_p": top_p,
        }
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload = {
            "model": model,
            "messages": final_messages,
            "stream": False,  # Respuesta completa, no streaming
            "options": options,
        }

        if self.verbose:
            console.print(
                f"[dim]→ POST /api/chat | model={model} | messages={len(final_messages)} | num_ctx={self.num_ctx}[/dim]"
            )

        # Medir latencia y hacer la petición
        start_time = time.time()
        response_data = self._post("/api/chat", payload)
        latency_ms = int((time.time() - start_time) * 1000)

        if self.verbose:
            console.print(f"[dim]← Respuesta recibida en {latency_ms} ms[/dim]")

        # Extraer el contenido del mensaje de respuesta
        content = ""
        if "message" in response_data:
            content = response_data["message"].get("content", "")

        # Extraer estadísticas de tokens si están disponibles
        prompt_tokens = response_data.get("prompt_eval_count", 0)
        completion_tokens = response_data.get("eval_count", 0)

        return {
            "content": content,
            "model": response_data.get("model", model),
            "latency_ms": latency_ms,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "raw": response_data,
        }

    def generate(
        self,
        model: str,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        top_p: float = 0.9,
        max_tokens: Optional[int] = None,
    ) -> dict:
        """
        Genera texto usando /api/generate (modo completion).

        Parámetros
        ----------
        model : str
            Nombre del modelo Ollama.
        prompt : str
            Prompt de usuario.
        system_prompt : str, opcional
            Prompt de sistema.
        temperature : float
            Temperatura de generación.
        top_p : float
            Nucleus sampling.
        max_tokens : int, opcional
            Límite de tokens en la respuesta.

        Retorna
        -------
        dict con las mismas claves que chat().
        """
        options = {
            "num_ctx": self.num_ctx,
            "temperature": temperature,
            "top_p": top_p,
        }
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if system_prompt:
            payload["system"] = system_prompt

        if self.verbose:
            console.print(
                f"[dim]→ POST /api/generate | model={model} | num_ctx={self.num_ctx}[/dim]"
            )

        start_time = time.time()
        response_data = self._post("/api/generate", payload)
        latency_ms = int((time.time() - start_time) * 1000)

        if self.verbose:
            console.print(f"[dim]← Respuesta recibida en {latency_ms} ms[/dim]")

        content = response_data.get("response", "")
        prompt_tokens = response_data.get("prompt_eval_count", 0)
        completion_tokens = response_data.get("eval_count", 0)

        return {
            "content": content,
            "model": response_data.get("model", model),
            "latency_ms": latency_ms,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "raw": response_data,
        }

    def list_models(self) -> list[str]:
        """
        Lista los modelos disponibles en el servidor Ollama.

        Retorna
        -------
        list[str] — Lista de nombres de modelos disponibles.
        """
        try:
            resp = self._session.get(
                f"{self.base_url}/api/tags", timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except requests.exceptions.ConnectionError:
            raise OllamaConnectionError(
                f"No se puede conectar con Ollama en {self.base_url}. "
                "Asegúrate de que Ollama está ejecutándose con: ollama serve"
            )
        except Exception as exc:
            raise OllamaAPIError(f"Error al listar modelos: {exc}") from exc

    def is_available(self) -> bool:
        """
        Comprueba si el servidor Ollama está disponible.

        Retorna
        -------
        bool — True si Ollama responde, False si no.
        """
        try:
            resp = self._session.get(
                f"{self.base_url}/api/tags", timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    def model_exists(self, model: str) -> bool:
        """
        Comprueba si un modelo específico está disponible en Ollama.

        Parámetros
        ----------
        model : str
            Nombre del modelo a comprobar.

        Retorna
        -------
        bool — True si el modelo existe.
        """
        try:
            available = self.list_models()
            # Comprobación flexible: acepta "gemma4:e2b" o "gemma4"
            return any(model in m or m in model for m in available)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Métodos privados auxiliares
    # ------------------------------------------------------------------

    def _post(self, endpoint: str, payload: dict) -> dict:
        """
        Realiza una petición POST al endpoint de Ollama.

        Parámetros
        ----------
        endpoint : str
            Ruta de la API, p.ej. "/api/chat".
        payload : dict
            Cuerpo de la petición en formato dict (se serializa a JSON).

        Retorna
        -------
        dict — Respuesta de la API deserializada.

        Lanza
        -----
        OllamaConnectionError si no se puede conectar.
        OllamaAPIError si la API devuelve un error HTTP.
        """
        url = f"{self.base_url}{endpoint}"
        try:
            response = self._session.post(
                url,
                data=json.dumps(payload),
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            raise OllamaConnectionError(
                f"No se puede conectar con Ollama en {self.base_url}.\n"
                "Soluciones:\n"
                "  1. Ejecuta: ollama serve\n"
                "  2. Comprueba que el puerto 11434 está libre\n"
                "  3. Verifica que Ollama está instalado"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise OllamaConnectionError(
                f"Timeout al conectar con Ollama ({self.timeout}s). "
                "Considera aumentar el parámetro timeout."
            ) from exc

        # Manejar errores HTTP de la API
        if response.status_code != 200:
            try:
                error_detail = response.json().get("error", response.text)
            except Exception:
                error_detail = response.text
            raise OllamaAPIError(
                f"Error de API Ollama [{response.status_code}]: {error_detail}"
            )

        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise OllamaAPIError(
                f"Respuesta de Ollama no es JSON válido: {response.text[:200]}"
            ) from exc


# ------------------------------------------------------------------
# Demo rápida si se ejecuta directamente
# ------------------------------------------------------------------
if __name__ == "__main__":
    client = OllamaClient(verbose=True)

    console.print("[bold cyan]Probando conexión con Ollama...[/bold cyan]")

    if not client.is_available():
        console.print("[bold red]✗ Ollama no está disponible en localhost:11434[/bold red]")
        console.print("Ejecuta: [bold]ollama serve[/bold]")
    else:
        console.print("[bold green]✓ Ollama está disponible[/bold green]")
        modelos = client.list_models()
        console.print(f"Modelos disponibles: {modelos}")

        if modelos:
            modelo = modelos[0]
            console.print(f"\nProbando chat con {modelo}...")
            resultado = client.chat(
                model=modelo,
                messages=[{"role": "user", "content": "Di 'Hola' en una sola palabra."}],
            )
            console.print(f"Respuesta: {resultado['content']}")
            console.print(f"Latencia: {resultado['latency_ms']} ms")
