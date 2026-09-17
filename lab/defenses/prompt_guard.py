"""
lab/defenses/prompt_guard.py
==============================
Módulo PromptGuard: wrapper de defensa que combina InputSanitizer
y OutputValidator para proteger llamadas al modelo LLM.

Aplica defensa en dos capas:
  1. Pre-LLM: InputSanitizer analiza el prompt antes de enviarlo
  2. Post-LLM: OutputValidator analiza la respuesta del modelo

Registra todos los intentos (bloqueados y permitidos) y genera
estadísticas de efectividad de la defensa.

Semántica de estados (auditoría 2026-09-16, F-02)
-------------------------------------------------
- Detección (``output_analysis.flags``): un patrón coincidió. No implica acción.
- Alerta (``defense_verdict="flagged"``, ``mitigation="alert"``): la salida es
  ``warning`` o ``dangerous``; la respuesta se ENTREGA SIN MODIFICAR y se
  registra ``alert_reason``. ``blocked`` es False porque no hubo bloqueo.
- Bloqueo preventivo de entrada (``blocked_stage="input"``): el modelo no se
  llama; ``mitigation="blocked_input"``.
- Bloqueo de salida (``blocked_stage="output"``): SOLO si
  ``block_on_dangerous_output=True`` (desactivado por defecto) y la salida es
  ``dangerous``. La respuesta del modelo se retiene y se sustituye por un aviso.
  ``warning`` nunca se bloquea: la heurística tiene falsos positivos.
- Rechazo del modelo: no lo decide PromptGuard; se mide con el clasificador de
  outcomes sobre la respuesta.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

from lab.core.ollama_client import OllamaClient
from lab.core.run_metadata import sha256_text
from lab.defenses.input_sanitizer import InputSanitizer
from lab.defenses.output_validator import OutputValidator

# Umbral máximo de bloqueo de entrada en modo estricto (GAP-001)
STRICT_MAX_BLOCK_THRESHOLD = 3.0

# Logger para registrar intentos de ataque
logger = logging.getLogger("prompt_guard")

INPUT_BLOCK_MESSAGE = (
    "⚠️ [DEFENSA ACTIVADA] Este mensaje ha sido bloqueado por el sistema de seguridad "
    "porque contiene patrones asociados con ataques de inyección de prompts."
)
OUTPUT_BLOCK_MESSAGE = (
    "⚠️ [DEFENSA ACTIVADA] La respuesta generada ha sido retenida por el sistema de "
    "seguridad porque el validador de salida la clasificó como peligrosa."
)


class PromptGuard:
    """
    Wrapper de defensa para el cliente Ollama.

    Combina InputSanitizer y OutputValidator para proporcionar
    protección en dos capas. Registra estadísticas de efectividad
    y genera logs de todos los intentos de ataque.

    Parámetros
    ----------
    client : OllamaClient
        Cliente Ollama subyacente para llamadas al modelo.
    block_on_suspicious_input : bool
        Si True, bloquea el prompt sin enviarlo al modelo cuando el
        risk_score del input alcanza el umbral efectivo (ver strict_mode).
    block_threshold : float
        Umbral de risk_score del input para bloquear (default: 5.0).
    log_file : Path, opcional
        Archivo donde guardar los logs de intentos. Si None, no guarda.
    strict_mode : bool
        Si True, aplica un umbral máximo de bloqueo de 3.0.
        Si block_threshold es menor, se respeta ese valor.
        Además se propaga a InputSanitizer (una sola señal débil vuelve la
        entrada sospechosa) y a OutputValidator (umbral ``dangerous`` 4.0 en
        lugar de 5.0). No cambia el risk_score.
    block_on_dangerous_output : bool
        Si True, retiene las respuestas con veredicto ``dangerous`` (bloqueo
        real de salida). Por defecto False: la capa de salida solo alerta.
    """

    def __init__(
        self,
        client: OllamaClient,
        block_on_suspicious_input: bool = True,
        block_threshold: float = 5.0,
        log_file: Optional[Path] = None,
        strict_mode: bool = False,
        block_on_dangerous_output: bool = False,
    ):
        self.client = client
        self.block_on_dangerous_output = block_on_dangerous_output
        self.block_on_suspicious_input = block_on_suspicious_input
        self.block_threshold = block_threshold
        self.log_file = log_file
        self.strict_mode = strict_mode

        # En modo estricto, el umbral máximo de bloqueo es 3.0.
        # Se respeta cualquier umbral configurado manualmente inferior.
        self.effective_block_threshold = (
            min(self.block_threshold, STRICT_MAX_BLOCK_THRESHOLD)
            if self.strict_mode
            else self.block_threshold
        )

        # Inicializar módulos de análisis
        self.input_sanitizer = InputSanitizer(strict_mode=strict_mode)
        self.output_validator = OutputValidator(strict_mode=strict_mode)

        # Estadísticas de defensa
        self._stats = {
            "total_calls": 0,
            "blocked_by_input": 0,
            "blocked_by_output": 0,
            "flagged_by_output": 0,
            "clean_passed": 0,
            "errors": 0,
            "input_detections": {},  # contador por tipo de detección
            "output_detections": {},
        }

        # Historial de intentos (para análisis)
        self._attempts: list[dict] = []

    def describe_config(self) -> dict[str, Any]:
        """Configuración efectiva de la defensa (se registra en cada ejecución)."""
        return {
            "strict_mode": self.strict_mode,
            "block_on_suspicious_input": self.block_on_suspicious_input,
            "block_threshold_configured": self.block_threshold,
            "block_threshold_effective": self.effective_block_threshold,
            "block_on_dangerous_output": self.block_on_dangerous_output,
            "output_warning_threshold": self.output_validator.warning_threshold,
            "output_dangerous_threshold": self.output_validator.dangerous_threshold,
            "input_max_length": self.input_sanitizer.max_length,
        }

    # ------------------------------------------------------------------
    # Método principal de evaluación
    # ------------------------------------------------------------------

    def evaluate_with_defense(
        self,
        model: str,
        prompt: str,
        system_prompt: Optional[str] = None,
        messages: Optional[list[dict]] = None,
        untrusted_content: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Evalúa un prompt con defensa completa en dos capas.

        Flujo:
        1. InputSanitizer analiza el prompt
        2. Si risk_score >= umbral efectivo → bloquear (sin llamar al modelo).
           Umbral efectivo = block_threshold en modo normal;
           min(block_threshold, 3.0) en modo estricto.
        3. Si pasa → enviar al modelo el prompt sanitizado (sin invisibles
           sospechosos, NFC, confusables mapeados en palabras mixtas, truncado
           a max_length). El texto enviado se devuelve en ``prompt_sent``.
        4. OutputValidator analiza la respuesta
        5. Retornar resultado con metadatos de defensa

        Parámetros
        ----------
        model : str
            Nombre del modelo Ollama.
        prompt : str
            Prompt del usuario a evaluar.
        system_prompt : str, opcional
            System prompt del agente.
        messages : list[dict], opcional
            Historial de mensajes. Si se proporciona, se usa en lugar de prompt.
        untrusted_content : str, opcional
            Contenido externo no confiable incluido en el prompt (vector
            indirecto). Se pasa al OutputValidator para detección por canario.

        Retorna
        -------
        dict con:
            - blocked (bool): True solo si hubo un bloqueo real (entrada o salida)
            - blocked_stage (str|None): "input" | "output" | None
            - block_reason (str): Razón del bloqueo (si aplica)
            - mitigation (str): "none" | "alert" | "blocked_input" | "blocked_output" | "error"
            - alert_reason (str|None): motivo de la alerta cuando defense_verdict="flagged"
            - model_called (bool): si se llegó a invocar el modelo
            - response_modified (bool): si la respuesta entregada difiere de la del modelo
            - withheld_response (str|None): respuesta del modelo retenida (bloqueo de salida)
            - response (str): Respuesta entregada al usuario
            - latency_ms (int): Latencia de la llamada
            - input_analysis (dict): Análisis del InputSanitizer
            - output_analysis (dict): Análisis del OutputValidator
            - defense_verdict (str): "blocked", "flagged", "passed", "error"
            - defense_config (dict): configuración efectiva (umbral, modo...)
            - prompt_sent / prompt_sent_sha256: texto enviado al modelo (None si no se llamó)
            - input_transformations (dict): cambios de la sanitización
            - inference (dict): endpoint y parámetros reales de la llamada
        """
        self._stats["total_calls"] += 1
        attempt = {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "prompt_preview": prompt[:200],
            "blocked": False,
            "block_reason": None,
            "blocked_stage": None,
            "output_flagged": False,
            "output_verdict": None,
            "defense_verdict": "passed",
        }

        # ── Capa 1: Análisis del input ───────────────────────────────
        input_analysis = self.input_sanitizer.analyze(prompt)
        # Traza del texto: original y el que realmente recibiría el modelo
        self._trace = {
            "prompt_original_sha256": sha256_text(prompt),
            "prompt_sent": None,
            "prompt_sent_sha256": None,
            "transformations": input_analysis.get("transformations", {}),
            "inference": {},
        }

        # Actualizar estadísticas de detección de input
        for flag_name, detected in input_analysis["flags"].items():
            if detected:
                self._stats["input_detections"][flag_name] = (
                    self._stats["input_detections"].get(flag_name, 0) + 1
                )

        # Decidir si bloquear
        if (
            self.block_on_suspicious_input
            and input_analysis["risk_score"] >= self.effective_block_threshold
        ):
            # BLOQUEADO: input demasiado sospechoso
            self._stats["blocked_by_input"] += 1
            attempt["blocked"] = True
            attempt["block_reason"] = (
                f"Input bloqueado (risk_score={input_analysis['risk_score']:.1f}): "
                f"{', '.join(input_analysis['detected_patterns'][:2])}"
            )
            attempt["defense_verdict"] = "blocked"
            attempt["blocked_stage"] = "input"
            self._attempts.append(attempt)
            self._log_attempt(attempt)

            return self._result(
                blocked_stage="input",
                block_reason=attempt["block_reason"],
                response=INPUT_BLOCK_MESSAGE,
                latency_ms=0,
                input_analysis=input_analysis,
                output_analysis={},
                defense_verdict="blocked",
                mitigation="blocked_input",
                model_called=False,
                response_modified=False,
            )

        # ── Usar el input sanitizado ─────────────────────────────────
        sanitized_prompt = input_analysis["sanitized_input"]

        # ── Capa 2: Llamada al modelo ────────────────────────────────
        if messages is not None:
            # Solo se analiza (y por tanto solo se sustituye) el ÚLTIMO mensaje
            # de usuario. Antes se sustituían todos los mensajes de usuario por
            # el mismo texto. Limitación: los turnos anteriores no se analizan.
            final_messages = [dict(m) for m in messages]
            for m in reversed(final_messages):
                if m.get("role") == "user":
                    m["content"] = sanitized_prompt
                    break
        else:
            final_messages = [{"role": "user", "content": sanitized_prompt}]
        self._trace["prompt_sent"] = sanitized_prompt
        self._trace["prompt_sent_sha256"] = sha256_text(sanitized_prompt)

        try:
            api_response = self.client.chat(
                model=model,
                messages=final_messages,
                system_prompt=system_prompt,
            )
            response_text = api_response["content"]
            latency_ms = api_response["latency_ms"]
            self._trace["inference"] = dict(getattr(self.client, "last_request", {}) or {})
        except Exception as e:
            logger.error(f"Error en llamada al modelo: {e}")
            self._stats["errors"] += 1
            # Un error NO es un resultado experimental: quien llama debe
            # comprobar defense_verdict == "error" y no clasificarlo (F-07).
            return self._result(
                blocked_stage=None,
                block_reason=None,
                response=f"ERROR: {e}",
                latency_ms=0,
                input_analysis=input_analysis,
                output_analysis={},
                defense_verdict="error",
                mitigation="error",
                model_called=True,
                response_modified=False,
                error=str(e),
            )

        # ── Capa 3: Validación del output ────────────────────────────
        output_analysis = self.output_validator.validate(
            response_text, untrusted_content=untrusted_content
        )

        # Actualizar estadísticas de detección de output
        for cat_name, detected in output_analysis["categories"].items():
            if detected:
                self._stats["output_detections"][cat_name] = (
                    self._stats["output_detections"].get(cat_name, 0) + 1
                )

        # Determinar veredicto final
        verdict = output_analysis["verdict"]
        flags_summary = "; ".join(output_analysis["flags"][:3]) or None
        attempt["output_verdict"] = verdict

        if verdict == "dangerous" and self.block_on_dangerous_output:
            # Bloqueo REAL de salida (opt-in): la respuesta no se entrega.
            self._stats["blocked_by_output"] += 1
            block_reason = (
                f"Salida bloqueada (risk_score={output_analysis['risk_score']:.1f}): {flags_summary}"
            )
            attempt.update(blocked=True, block_reason=block_reason,
                           blocked_stage="output", defense_verdict="blocked")
            self._attempts.append(attempt)
            self._log_attempt(attempt)
            return self._result(
                blocked_stage="output",
                block_reason=block_reason,
                response=OUTPUT_BLOCK_MESSAGE,
                latency_ms=latency_ms,
                input_analysis=input_analysis,
                output_analysis=output_analysis,
                defense_verdict="blocked",
                mitigation="blocked_output",
                model_called=True,
                response_modified=True,
                withheld_response=response_text,
            )

        if verdict in {"warning", "dangerous"}:
            # Solo alerta: la respuesta se entrega sin modificar.
            self._stats["flagged_by_output"] += 1
            attempt["output_flagged"] = True
            defense_verdict, mitigation = "flagged", "alert"
            alert_reason = f"Salida '{verdict}' (risk_score={output_analysis['risk_score']:.1f}): {flags_summary}"
        else:
            self._stats["clean_passed"] += 1
            defense_verdict, mitigation, alert_reason = "passed", "none", None

        attempt["defense_verdict"] = defense_verdict
        self._attempts.append(attempt)
        self._log_attempt(attempt)

        return self._result(
            blocked_stage=None,
            block_reason=None,
            response=response_text,
            latency_ms=latency_ms,
            input_analysis=input_analysis,
            output_analysis=output_analysis,
            defense_verdict=defense_verdict,
            mitigation=mitigation,
            model_called=True,
            response_modified=False,
            alert_reason=alert_reason,
        )

    def _result(self, *, blocked_stage, block_reason, response, latency_ms,
                input_analysis, output_analysis, defense_verdict, mitigation,
                model_called, response_modified, alert_reason=None,
                withheld_response=None, error=None) -> dict[str, Any]:
        """Construye el resultado con campos coherentes por construcción:
        ``blocked`` se deriva exclusivamente de ``blocked_stage``."""
        trace = getattr(self, "_trace", {}) or {}
        return {
            "defense_config": self.describe_config(),
            "prompt_original_sha256": trace.get("prompt_original_sha256"),
            "prompt_sent": trace.get("prompt_sent") if model_called else None,
            "prompt_sent_sha256": trace.get("prompt_sent_sha256") if model_called else None,
            "input_transformations": trace.get("transformations", {}),
            "inference": trace.get("inference", {}),
            "blocked": blocked_stage is not None,
            "blocked_stage": blocked_stage,
            "block_reason": block_reason,
            "response": response,
            "latency_ms": latency_ms,
            "input_analysis": input_analysis,
            "output_analysis": output_analysis,
            "defense_verdict": defense_verdict,
            "mitigation": mitigation,
            "alert_reason": alert_reason,
            "model_called": model_called,
            "response_modified": response_modified,
            "withheld_response": withheld_response,
            "error": error,
        }

    def chat_protected(
        self,
        model: str,
        messages: list[dict],
        system_prompt: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Wrapper directo para OllamaClient.chat() con defensa aplicada.

        Parámetros
        ----------
        model : str
            Nombre del modelo.
        messages : list[dict]
            Lista de mensajes de la conversación.
        system_prompt : str, opcional
            System prompt del agente.

        Retorna
        -------
        dict — Respuesta del modelo con metadatos de defensa.
        """
        # Analizar el último mensaje del usuario
        last_user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_msg = msg.get("content", "")
                break

        return self.evaluate_with_defense(
            model=model,
            prompt=last_user_msg,
            system_prompt=system_prompt,
            messages=messages,
        )

    # ------------------------------------------------------------------
    # Estadísticas y logging
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """
        Retorna las estadísticas de efectividad de la defensa.

        Retorna
        -------
        dict con métricas de efectividad acumuladas.
        """
        total = self._stats["total_calls"]
        if total == 0:
            return {**self._stats, "block_rate": 0.0, "output_block_rate": 0.0,
                    "flag_rate": 0.0, "pass_rate": 0.0}

        return {
            **self._stats,
            "block_rate": round(self._stats["blocked_by_input"] / total, 3),
            "output_block_rate": round(self._stats["blocked_by_output"] / total, 3),
            "flag_rate": round(self._stats["flagged_by_output"] / total, 3),
            "pass_rate": round(self._stats["clean_passed"] / total, 3),
        }

    def reset_stats(self) -> None:
        """Resetea las estadísticas de la defensa."""
        self._stats = {
            "total_calls": 0,
            "blocked_by_input": 0,
            "blocked_by_output": 0,
            "flagged_by_output": 0,
            "clean_passed": 0,
            "errors": 0,
            "input_detections": {},
            "output_detections": {},
        }
        self._attempts = []

    def print_stats(self) -> None:
        """Imprime estadísticas de la defensa en la terminal con Rich."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box

            console = Console()
            stats = self.get_stats()
            total = stats["total_calls"]

            table = Table(
                title="🛡️ Estadísticas de PromptGuard",
                box=box.ROUNDED,
                header_style="bold blue",
            )
            table.add_column("Métrica", style="cyan")
            table.add_column("Valor", justify="right")
            table.add_column("Porcentaje", justify="right")

            table.add_row("Total de llamadas", str(total), "100%")
            table.add_row(
                "Bloqueados (input)",
                str(stats["blocked_by_input"]),
                f"{stats['block_rate']:.1%}",
            )
            table.add_row(
                "Alertas en output (warning/dangerous, no bloqueados)",
                str(stats["flagged_by_output"]),
                f"{stats['flag_rate']:.1%}",
            )
            table.add_row(
                "Bloqueados (output, opt-in)",
                str(stats["blocked_by_output"]),
                f"{stats['output_block_rate']:.1%}",
            )
            table.add_row(
                "Pasaron limpiamente",
                str(stats["clean_passed"]),
                f"{stats['pass_rate']:.1%}",
            )

            console.print(table)

            if stats["input_detections"]:
                console.print("\n[bold]Tipos de detecciones en input:[/bold]")
                for detection, count in stats["input_detections"].items():
                    console.print(f"  • {detection}: {count}")

            if stats["output_detections"]:
                console.print("\n[bold]Tipos de problemas en output:[/bold]")
                for detection, count in stats["output_detections"].items():
                    console.print(f"  • {detection}: {count}")

        except ImportError:
            # Si Rich no está disponible, imprimir en texto plano
            stats = self.get_stats()
            print(f"\n=== Estadísticas de PromptGuard ===")
            print(f"Total de llamadas: {stats['total_calls']}")
            print(f"Bloqueados: {stats['blocked_by_input']} ({stats['block_rate']:.1%})")
            print(f"Marcados: {stats['flagged_by_output']} ({stats['flag_rate']:.1%})")
            print(f"Limpios: {stats['clean_passed']} ({stats['pass_rate']:.1%})")

    def _log_attempt(self, attempt: dict) -> None:
        """
        Registra un intento en el logger y opcionalmente en archivo.

        Parámetros
        ----------
        attempt : dict
            Datos del intento a registrar.
        """
        if attempt["blocked"]:
            logger.warning(
                f"BLOQUEADO ({attempt.get('blocked_stage')}) | {attempt['model']} | "
                f"Razón: {attempt.get('block_reason', 'N/A')[:100]}"
            )
        elif attempt["output_flagged"]:
            logger.warning(
                f"ALERTA OUTPUT ({attempt.get('output_verdict')}) | {attempt['model']} | "
                f"Preview: {attempt['prompt_preview'][:50]}"
            )

        if self.log_file:
            try:
                log_path = Path(self.log_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(attempt, ensure_ascii=False) + "\n")
            except Exception as e:
                logger.error(f"No se pudo guardar en log: {e}")

    def get_attempts_log(self) -> list[dict]:
        """
        Retorna el historial completo de intentos registrados.

        Retorna
        -------
        list[dict] — Lista de todos los intentos.
        """
        return self._attempts.copy()
