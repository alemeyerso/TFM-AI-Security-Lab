"""
lab/core/metrics.py
===================
Módulo de métricas para el laboratorio de seguridad de agentes IA.

Registra resultados de cada test, calcula ASR (Attack Success Rate),
partial_asr, refusal_rate, latencias y exporta en formato JSON/CSV.
También genera resúmenes visuales en terminal usando Rich.
"""

import json
import csv
import uuid
from datetime import datetime
from typing import Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class Metrics:
    """
    Clase principal de métricas para el laboratorio de seguridad.

    Registra cada test ejecutado, calcula estadísticas por vector
    y globales, y exporta los resultados al formato JSON definido.

    Parámetros
    ----------
    model : str
        Nombre del modelo evaluado, p.ej. "gemma4:e2b".
    session_id : str, opcional
        UUID de sesión. Si no se proporciona, se genera automáticamente.
    """

    # Resultados válidos para cada test
    VALID_OUTCOMES = {"success", "partial", "refused", "error"}

    # Vectores de ataque soportados
    VALID_VECTORS = {"direct", "indirect", "jailbreak", "tool_abuse"}

    def __init__(self, model: str, session_id: Optional[str] = None):
        self.model = model
        self.session_id = session_id or str(uuid.uuid4())
        self.timestamp = datetime.now().isoformat()
        self._tests: list[dict] = []  # Lista de resultados de tests individuales

    # ------------------------------------------------------------------
    # Registro de resultados
    # ------------------------------------------------------------------

    def add_result(
        self,
        test_id: str,
        vector: str,
        payload_id: str,
        payload_name: str,
        category: str,
        severity: str,
        outcome: str,
        prompt: str,
        response: str,
        latency_ms: int,
        defense_applied: bool = False,
        defense_blocked: bool = False,
        metadata: Optional[dict] = None,
    ) -> None:
        """
        Registra el resultado de un test individual.

        Parámetros
        ----------
        test_id : str
            Identificador único del test, p.ej. "direct_001".
        vector : str
            Vector de ataque: "direct", "indirect", "jailbreak", "tool_abuse".
        payload_id : str
            ID del payload usado, p.ej. "ignore_previous".
        payload_name : str
            Nombre legible del payload.
        category : str
            Categoría del ataque, p.ej. "instruction_override".
        severity : str
            Severidad: "low", "medium", "high", "critical".
        outcome : str
            Resultado: "success", "partial", "refused", "error".
        prompt : str
            Prompt completo enviado al modelo.
        response : str
            Respuesta completa del modelo.
        latency_ms : int
            Latencia de la llamada en milisegundos.
        defense_applied : bool
            True si se aplicó defensa antes de enviar el prompt.
        defense_blocked : bool
            True si la defensa bloqueó el ataque (sin enviar al modelo).
        metadata : dict, opcional
            Datos adicionales específicos del test.
        """
        if outcome not in self.VALID_OUTCOMES:
            raise ValueError(
                f"outcome '{outcome}' no válido. Usa: {self.VALID_OUTCOMES}"
            )
        if vector not in self.VALID_VECTORS:
            raise ValueError(
                f"vector '{vector}' no válido. Usa: {self.VALID_VECTORS}"
            )

        record = {
            "id": test_id,
            "vector": vector,
            "payload_id": payload_id,
            "payload_name": payload_name,
            "category": category,
            "severity": severity,
            "outcome": outcome,
            "prompt": prompt,
            "response": response,
            "latency_ms": latency_ms,
            "defense_applied": defense_applied,
            "defense_blocked": defense_blocked,
        }
        if metadata:
            record["metadata"] = metadata

        self._tests.append(record)

    # ------------------------------------------------------------------
    # Cálculo de estadísticas
    # ------------------------------------------------------------------

    def _compute_vector_stats(self, vector: str) -> dict:
        """
        Calcula estadísticas para un vector de ataque específico.

        Parámetros
        ----------
        vector : str
            Nombre del vector de ataque.

        Retorna
        -------
        dict con métricas del vector.
        """
        tests = [t for t in self._tests if t["vector"] == vector]
        total = len(tests)

        if total == 0:
            return {
                "total": 0,
                "successful": 0,
                "partial": 0,
                "refused": 0,
                "asr": 0.0,
                "partial_asr": 0.0,
                "refusal_rate": 0.0,
                "avg_latency_ms": 0,
            }

        successful = sum(1 for t in tests if t["outcome"] == "success")
        partial = sum(1 for t in tests if t["outcome"] == "partial")
        refused = sum(1 for t in tests if t["outcome"] == "refused")
        latencies = [t["latency_ms"] for t in tests if t["latency_ms"] > 0]
        avg_latency = int(sum(latencies) / len(latencies)) if latencies else 0

        return {
            "total": total,
            "successful": successful,
            "partial": partial,
            "refused": refused,
            "asr": round(successful / total, 3),
            "partial_asr": round(partial / total, 3),
            "refusal_rate": round(refused / total, 3),
            "avg_latency_ms": avg_latency,
        }

    def compute_summary(self) -> dict:
        """
        Calcula el resumen global de todos los tests.

        Retorna
        -------
        dict con métricas globales.
        """
        total = len(self._tests)
        if total == 0:
            return {
                "total_tests": 0,
                "successful_attacks": 0,
                "partial_attacks": 0,
                "refused": 0,
                "asr": 0.0,
                "partial_asr": 0.0,
                "refusal_rate": 0.0,
                "avg_latency_ms": 0,
            }

        successful = sum(1 for t in self._tests if t["outcome"] == "success")
        partial = sum(1 for t in self._tests if t["outcome"] == "partial")
        refused = sum(1 for t in self._tests if t["outcome"] == "refused")
        latencies = [t["latency_ms"] for t in self._tests if t["latency_ms"] > 0]
        avg_latency = int(sum(latencies) / len(latencies)) if latencies else 0

        return {
            "total_tests": total,
            "successful_attacks": successful,
            "partial_attacks": partial,
            "refused": refused,
            "asr": round(successful / total, 3),
            "partial_asr": round(partial / total, 3),
            "refusal_rate": round(refused / total, 3),
            "avg_latency_ms": avg_latency,
        }

    # ------------------------------------------------------------------
    # Exportación de resultados
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Exporta todos los resultados al formato JSON definido en el esquema.

        Retorna
        -------
        dict con el esquema completo de resultados.
        """
        summary = self.compute_summary()
        vectors = {
            v: self._compute_vector_stats(v) for v in self.VALID_VECTORS
        }

        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "model": self.model,
            "summary": summary,
            "vectors": vectors,
            "tests": self._tests,
        }

    def save_json(self, output_path: Path) -> Path:
        """
        Guarda los resultados en un archivo JSON.

        Parámetros
        ----------
        output_path : Path
            Ruta del archivo de salida.

        Retorna
        -------
        Path — Ruta absoluta del archivo creado.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = self.to_dict()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        console.print(f"[green]✓ Resultados guardados en:[/green] {output_path}")
        return output_path

    def save_csv(self, output_path: Path) -> Path:
        """
        Exporta los resultados individuales de tests en formato CSV.

        Parámetros
        ----------
        output_path : Path
            Ruta del archivo CSV de salida.

        Retorna
        -------
        Path — Ruta absoluta del archivo creado.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not self._tests:
            console.print("[yellow]⚠ No hay tests para exportar a CSV[/yellow]")
            return output_path

        # Columnas para el CSV
        fieldnames = [
            "id", "vector", "payload_id", "payload_name",
            "category", "severity", "outcome",
            "latency_ms", "defense_applied", "defense_blocked",
            # prompt y response se truncan para el CSV
            "prompt_preview", "response_preview",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for test in self._tests:
                row = {k: test.get(k, "") for k in fieldnames
                       if k not in ("prompt_preview", "response_preview")}
                row["prompt_preview"] = str(test.get("prompt", ""))[:200]
                row["response_preview"] = str(test.get("response", ""))[:200]
                writer.writerow(row)

        console.print(f"[green]✓ CSV guardado en:[/green] {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # Visualización en terminal con Rich
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """
        Imprime un resumen visual de los resultados en la terminal usando Rich.
        Muestra tabla por vector y estadísticas globales.
        """
        summary = self.compute_summary()

        # ── Panel de resumen global ──────────────────────────────────
        asr_color = "green" if summary["asr"] < 0.3 else (
            "yellow" if summary["asr"] < 0.6 else "red"
        )
        refusal_color = "green" if summary["refusal_rate"] > 0.6 else (
            "yellow" if summary["refusal_rate"] > 0.3 else "red"
        )

        panel_content = (
            f"[bold]Modelo:[/bold] {self.model}   "
            f"[bold]Sesión:[/bold] {self.session_id[:8]}...\n"
            f"[bold]Tests totales:[/bold] {summary['total_tests']}   "
            f"[{asr_color}][bold]ASR:[/bold] {summary['asr']:.1%}[/{asr_color}]   "
            f"[{refusal_color}][bold]Rechazo:[/bold] {summary['refusal_rate']:.1%}[/{refusal_color}]   "
            f"[bold]Latencia media:[/bold] {summary['avg_latency_ms']} ms"
        )
        console.print(Panel(panel_content, title="[bold cyan]Resumen de Evaluación[/bold cyan]", box=box.DOUBLE))

        # ── Tabla por vector ─────────────────────────────────────────
        table = Table(
            title="Resultados por Vector de Ataque",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Vector", style="cyan", min_width=12)
        table.add_column("Tests", justify="right")
        table.add_column("Éxitos", justify="right", style="red")
        table.add_column("Parciales", justify="right", style="yellow")
        table.add_column("Rechazados", justify="right", style="green")
        table.add_column("ASR", justify="right")
        table.add_column("Refusal", justify="right")
        table.add_column("Latencia (ms)", justify="right")

        vector_labels = {
            "direct": "Inyección Directa",
            "indirect": "Inyección Indirecta",
            "jailbreak": "Jailbreak",
            "tool_abuse": "Abuso de Tools",
        }

        for vector in self.VALID_VECTORS:
            stats = self._compute_vector_stats(vector)
            if stats["total"] == 0:
                continue  # Omitir vectores sin tests

            asr_val = stats["asr"]
            asr_str = f"[red]{asr_val:.1%}[/red]" if asr_val > 0.5 else (
                f"[yellow]{asr_val:.1%}[/yellow]" if asr_val > 0.2 else f"[green]{asr_val:.1%}[/green]"
            )
            refusal_val = stats["refusal_rate"]
            refusal_str = f"[green]{refusal_val:.1%}[/green]" if refusal_val > 0.6 else (
                f"[yellow]{refusal_val:.1%}[/yellow]" if refusal_val > 0.3 else f"[red]{refusal_val:.1%}[/red]"
            )

            table.add_row(
                vector_labels.get(vector, vector),
                str(stats["total"]),
                str(stats["successful"]),
                str(stats["partial"]),
                str(stats["refused"]),
                asr_str,
                refusal_str,
                str(stats["avg_latency_ms"]),
            )

        console.print(table)

        # ── Tests más peligrosos ─────────────────────────────────────
        successful_tests = [t for t in self._tests if t["outcome"] == "success"]
        if successful_tests:
            danger_table = Table(
                title="⚠️  Ataques Exitosos",
                box=box.SIMPLE,
                header_style="bold red",
            )
            danger_table.add_column("ID", style="dim")
            danger_table.add_column("Vector")
            danger_table.add_column("Payload")
            danger_table.add_column("Severidad")
            danger_table.add_column("Latencia (ms)", justify="right")

            severity_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }
            for test in successful_tests[:10]:  # Máximo 10 filas
                sev = test.get("severity", "medium")
                danger_table.add_row(
                    test["id"],
                    test["vector"],
                    test["payload_name"],
                    f"[{severity_colors.get(sev, 'white')}]{sev}[/{severity_colors.get(sev, 'white')}]",
                    str(test["latency_ms"]),
                )
            console.print(danger_table)

    def get_total_tests(self) -> int:
        """Retorna el número total de tests registrados."""
        return len(self._tests)
