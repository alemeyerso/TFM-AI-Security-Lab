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
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

from lab.core.ollama_client import OllamaClient
from lab.defenses.input_sanitizer import InputSanitizer
from lab.defenses.output_validator import OutputValidator

# Logger para registrar intentos de ataque
logger = logging.getLogger("prompt_guard")


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
        input es sospechoso (risk_score >= 5.0).
    block_threshold : float
        Umbral de risk_score del input para bloquear (default: 5.0).
    log_file : Path, opcional
        Archivo donde guardar los logs de intentos. Si None, no guarda.
    strict_mode : bool
        Si True, usa umbral más bajo para detección.
    """

    def __init__(
        self,
        client: OllamaClient,
        block_on_suspicious_input: bool = True,
        block_threshold: float = 5.0,
        log_file: Optional[Path] = None,
        strict_mode: bool = False,
    ):
        self.client = client
        self.block_on_suspicious_input = block_on_suspicious_input
        self.block_threshold = block_threshold
        self.log_file = log_file
        self.strict_mode = strict_mode

        # Inicializar módulos de análisis
        self.input_sanitizer = InputSanitizer(strict_mode=strict_mode)
        self.output_validator = OutputValidator(strict_mode=strict_mode)

        # Estadísticas de defensa
        self._stats = {
            "total_calls": 0,
            "blocked_by_input": 0,
            "flagged_by_output": 0,
            "clean_passed": 0,
            "input_detections": {},  # contador por tipo de detección
            "output_detections": {},
        }

        # Historial de intentos (para análisis)
        self._attempts: list[dict] = []

    # ------------------------------------------------------------------
    # Método principal de evaluación
    # ------------------------------------------------------------------

    def evaluate_with_defense(
        self,
        model: str,
        prompt: str,
        system_prompt: Optional[str] = None,
        messages: Optional[list[dict]] = None,
    ) -> dict[str, Any]:
        """
        Evalúa un prompt con defensa completa en dos capas.

        Flujo:
        1. InputSanitizer analiza el prompt
        2. Si risk_score >= block_threshold → bloquear (sin llamar al modelo)
        3. Si pasa → enviar al modelo con el prompt sanitizado
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

        Retorna
        -------
        dict con:
            - blocked (bool): True si el ataque fue bloqueado
            - block_reason (str): Razón del bloqueo (si aplica)
            - response (str): Respuesta del modelo (vacía si bloqueado)
            - latency_ms (int): Latencia de la llamada
            - input_analysis (dict): Análisis del InputSanitizer
            - output_analysis (dict): Análisis del OutputValidator
            - defense_verdict (str): "blocked", "flagged", "passed"
        """
        self._stats["total_calls"] += 1
        attempt = {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "prompt_preview": prompt[:200],
            "blocked": False,
            "block_reason": None,
            "output_flagged": False,
            "defense_verdict": "passed",
        }

        # ── Capa 1: Análisis del input ───────────────────────────────
        input_analysis = self.input_sanitizer.analyze(prompt)

        # Actualizar estadísticas de detección de input
        for flag_name, detected in input_analysis["flags"].items():
            if detected:
                self._stats["input_detections"][flag_name] = (
                    self._stats["input_detections"].get(flag_name, 0) + 1
                )

        # Decidir si bloquear
        if (
            self.block_on_suspicious_input
            and input_analysis["risk_score"] >= self.block_threshold
        ):
            # BLOQUEADO: input demasiado sospechoso
            self._stats["blocked_by_input"] += 1
            attempt["blocked"] = True
            attempt["block_reason"] = (
                f"Input bloqueado (risk_score={input_analysis['risk_score']:.1f}): "
                f"{', '.join(input_analysis['detected_patterns'][:2])}"
            )
            attempt["defense_verdict"] = "blocked"
            self._attempts.append(attempt)
            self._log_attempt(attempt)

            return {
                "blocked": True,
                "block_reason": attempt["block_reason"],
                "response": (
                    "⚠️ [DEFENSA ACTIVADA] Este mensaje ha sido bloqueado por el sistema de seguridad "
                    "porque contiene patrones asociados con ataques de inyección de prompts."
                ),
                "latency_ms": 0,
                "input_analysis": input_analysis,
                "output_analysis": {},
                "defense_verdict": "blocked",
            }

        # ── Usar el input sanitizado ─────────────────────────────────
        sanitized_prompt = input_analysis["sanitized_input"]

        # ── Capa 2: Llamada al modelo ────────────────────────────────
        if messages is not None:
            # Usar lista de mensajes personalizada
            final_messages = messages
        else:
            final_messages = [{"role": "user", "content": sanitized_prompt}]

        try:
            api_response = self.client.chat(
                model=model,
                messages=final_messages,
                system_prompt=system_prompt,
            )
            response_text = api_response["content"]
            latency_ms = api_response["latency_ms"]
        except Exception as e:
            logger.error(f"Error en llamada al modelo: {e}")
            return {
                "blocked": False,
                "block_reason": None,
                "response": f"ERROR: {e}",
                "latency_ms": 0,
                "input_analysis": input_analysis,
                "output_analysis": {},
                "defense_verdict": "error",
            }

        # ── Capa 3: Validación del output ────────────────────────────
        output_analysis = self.output_validator.validate(response_text)

        # Actualizar estadísticas de detección de output
        for cat_name, detected in output_analysis["categories"].items():
            if detected:
                self._stats["output_detections"][cat_name] = (
                    self._stats["output_detections"].get(cat_name, 0) + 1
                )

        # Determinar veredicto final
        if output_analysis["verdict"] == "dangerous":
            self._stats["flagged_by_output"] += 1
            attempt["output_flagged"] = True
            attempt["defense_verdict"] = "flagged"
            defense_verdict = "flagged"
        else:
            self._stats["clean_passed"] += 1
            defense_verdict = "passed"

        attempt["defense_verdict"] = defense_verdict
        self._attempts.append(attempt)
        self._log_attempt(attempt)

        return {
            "blocked": False,
            "block_reason": None,
            "response": response_text,
            "latency_ms": latency_ms,
            "input_analysis": input_analysis,
            "output_analysis": output_analysis,
            "defense_verdict": defense_verdict,
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
            return {**self._stats, "block_rate": 0.0, "flag_rate": 0.0, "pass_rate": 0.0}

        return {
            **self._stats,
            "block_rate": round(self._stats["blocked_by_input"] / total, 3),
            "flag_rate": round(self._stats["flagged_by_output"] / total, 3),
            "pass_rate": round(self._stats["clean_passed"] / total, 3),
        }

    def reset_stats(self) -> None:
        """Resetea las estadísticas de la defensa."""
        self._stats = {
            "total_calls": 0,
            "blocked_by_input": 0,
            "flagged_by_output": 0,
            "clean_passed": 0,
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
                "Marcados como peligrosos (output)",
                str(stats["flagged_by_output"]),
                f"{stats['flag_rate']:.1%}",
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
                f"BLOQUEADO | {attempt['model']} | "
                f"Razón: {attempt.get('block_reason', 'N/A')[:100]}"
            )
        elif attempt["output_flagged"]:
            logger.warning(
                f"OUTPUT PELIGROSO | {attempt['model']} | "
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
