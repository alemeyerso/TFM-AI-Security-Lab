"""
lab/defenses/input_sanitizer.py
================================
Módulo de sanitización y detección de ataques en el input del usuario.

Detecta patrones de inyección de prompts, caracteres Unicode sospechosos,
instrucciones codificadas en base64 y otros indicadores de ataque antes
de que el prompt llegue al modelo LLM.
"""

import re
import base64
import unicodedata
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Patrones de detección por categoría
# ──────────────────────────────────────────────────────────────────────────────

# Patrones de instrucciones de anulación (instruction override)
OVERRIDE_PATTERNS = [
    r"ignora\s+(todas\s+)?(las\s+)?instrucciones",
    r"ignore\s+(all\s+)?(previous\s+)?instructions",
    r"olvida\s+(todo\s+)?(lo\s+anterior|tus\s+instrucciones)",
    r"forget\s+(all\s+)?(previous\s+)?instructions",
    r"ahora\s+eres\s+(?!un\s+asistente)",  # "ahora eres X" pero no "ahora eres un asistente"
    r"now\s+you\s+are\s+(?!a\s+helpful)",
    r"a\s+partir\s+de\s+ahora\s+(eres|actúas\s+como)",
    r"from\s+now\s+on\s+you\s+are",
    r"desactiva\s+(todos?\s+)?(los?\s+)?filtros",
    r"disable\s+(all\s+)?(safety\s+)?filters",
    r"sin\s+restricciones",
    r"without\s+restrictions",
    r"modo\s+(administrador|debug|desarrollador|mantenimiento)",
    r"developer\s+mode",
    r"jailbreak",
    r"\bDAN\b",  # Do Anything Now
]

# Patrones de intentos de revelación del system prompt
SYSTEM_PROMPT_PATTERNS = [
    r"(muestra|revela|dime|cuéntame)\s+(tu\s+)?(system\s+prompt|instrucciones\s+(del\s+sistema|iniciales|base))",
    r"show\s+me\s+(your\s+)?(system\s+prompt|instructions)",
    r"what\s+(are|is)\s+your\s+(system\s+prompt|initial\s+instructions)",
    r"system\s+prompt\s+completo",
    r"instrucciones\s+(internas|ocultas|del\s+sistema)",
]

# Patrones de delimitadores de inyección
DELIMITER_PATTERNS = [
    r"<<<.*?>>>",
    r"\[SYSTEM\]:",
    r"\[INSTRUCCIÓN\s+PRIORITARIA\]",
    r"###\s*(INICIO|FIN|START|END)\s*(DOCUMENTO|DOCUMENT|INSTRUCCIÓN|INSTRUCTION)",
    r"---\s*SYSTEM\s*OVERRIDE\s*---",
]

# Patrones de reclamación de autoridad
AUTHORITY_PATTERNS = [
    r"soy\s+el\s+(desarrollador|administrador|creador|ingeniero)",
    r"i\s+am\s+(the\s+)?(developer|administrator|creator|engineer)",
    r"código\s+de\s+acceso\s+(de\s+nivel\s+\d+|maestro|admin)",
    r"access\s+code\s+(level\s+\d+|master|admin)",
    r"DEV-OVERRIDE",
    r"ADMIN-ACCESS",
]

# Caracteres zero-width (invisibles) sospechosos
ZERO_WIDTH_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\ufeff",  # BOM / Zero-width no-break space
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
]

# Rangos de caracteres cirílicos y griegos que pueden ser homóglifos de ASCII
HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),   # Cirílico
    (0x0370, 0x03FF),   # Griego
    (0xFF01, 0xFF5E),   # Fullwidth ASCII variants
]

# Longitud máxima de prompt permitida
MAX_PROMPT_LENGTH = 8000


class InputSanitizer:
    """
    Sanitizador de inputs para detectar ataques de inyección de prompts.

    Analiza el texto del prompt del usuario y detecta patrones sospechosos
    antes de enviarlo al modelo LLM. Proporciona:
    - Detección de patrones conocidos de inyección
    - Detección de caracteres Unicode sospechosos
    - Detección de instrucciones en base64
    - Puntuación de riesgo de 0 a 10
    - Versión sanitizada del input

    Parámetros
    ----------
    max_length : int
        Longitud máxima permitida del prompt (por defecto 8000 caracteres).
    strict_mode : bool
        Si True, aplica detección más agresiva con más falsos positivos.
    """

    def __init__(self, max_length: int = MAX_PROMPT_LENGTH, strict_mode: bool = False):
        self.max_length = max_length
        self.strict_mode = strict_mode

        # Compilar patrones regex para eficiencia
        self._override_re = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in OVERRIDE_PATTERNS
        ]
        self._system_prompt_re = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in SYSTEM_PROMPT_PATTERNS
        ]
        self._delimiter_re = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in DELIMITER_PATTERNS
        ]
        self._authority_re = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in AUTHORITY_PATTERNS
        ]

    def analyze(self, text: str) -> dict[str, Any]:
        """
        Analiza un texto en busca de indicadores de ataque.

        Parámetros
        ----------
        text : str
            Texto del prompt a analizar.

        Retorna
        -------
        dict con:
            - is_suspicious (bool): True si el texto es sospechoso
            - risk_score (float): Puntuación de riesgo de 0 a 10
            - detected_patterns (list[str]): Lista de patrones detectados
            - sanitized_input (str): Versión limpia del input
            - flags (dict): Flags específicos de detección
        """
        detected_patterns = []
        flags = {
            "has_override_attempt": False,
            "has_system_prompt_extraction": False,
            "has_delimiter_injection": False,
            "has_authority_claim": False,
            "has_zero_width_chars": False,
            "has_homoglyphs": False,
            "has_base64_instruction": False,
            "exceeds_max_length": False,
        }
        risk_score = 0.0

        # ── 1. Comprobar longitud ────────────────────────────────────
        if len(text) > self.max_length:
            flags["exceeds_max_length"] = True
            detected_patterns.append(f"Longitud excesiva: {len(text)} > {self.max_length} caracteres")
            risk_score += 1.0

        # ── 2. Detectar patrones de anulación de instrucciones ───────
        for pattern in self._override_re:
            match = pattern.search(text)
            if match:
                flags["has_override_attempt"] = True
                detected_patterns.append(f"Intento de anulación de instrucciones: '{match.group()[:50]}'")
                risk_score += 2.5
                break  # Un match es suficiente para esta categoría

        # ── 3. Detectar extracción de system prompt ──────────────────
        for pattern in self._system_prompt_re:
            match = pattern.search(text)
            if match:
                flags["has_system_prompt_extraction"] = True
                detected_patterns.append(f"Intento de extracción de system prompt: '{match.group()[:50]}'")
                risk_score += 2.0
                break

        # ── 4. Detectar inyección de delimitadores ───────────────────
        for pattern in self._delimiter_re:
            match = pattern.search(text)
            if match:
                flags["has_delimiter_injection"] = True
                detected_patterns.append(f"Delimitadores de inyección detectados: '{match.group()[:50]}'")
                risk_score += 1.5
                break

        # ── 5. Detectar reclamación de autoridad ─────────────────────
        for pattern in self._authority_re:
            match = pattern.search(text)
            if match:
                flags["has_authority_claim"] = True
                detected_patterns.append(f"Reclamación de autoridad: '{match.group()[:50]}'")
                risk_score += 2.0
                break

        # ── 6. Detectar caracteres zero-width ───────────────────────
        found_zw = [hex(ord(c)) for c in text if c in ZERO_WIDTH_CHARS]
        if found_zw:
            flags["has_zero_width_chars"] = True
            detected_patterns.append(f"Caracteres zero-width detectados: {found_zw[:5]}")
            risk_score += 1.5

        # ── 7. Detectar homóglifos Unicode ──────────────────────────
        homoglyph_count = self._count_homoglyphs(text)
        if homoglyph_count > 3:  # Más de 3 caracteres sospechosos
            flags["has_homoglyphs"] = True
            detected_patterns.append(f"Posibles homóglifos Unicode: {homoglyph_count} caracteres sospechosos")
            risk_score += 1.5

        # ── 8. Detectar base64 embebido ──────────────────────────────
        base64_instructions = self._detect_base64_instructions(text)
        if base64_instructions:
            flags["has_base64_instruction"] = True
            for decoded in base64_instructions:
                detected_patterns.append(f"Instrucción en base64 detectada (decodificado): '{decoded[:80]}'")
                risk_score += 2.5

        # ── Calcular resultado final ─────────────────────────────────
        risk_score = min(10.0, risk_score)  # Máximo 10
        is_suspicious = risk_score >= 2.0

        # Sanitizar el input
        sanitized = self._sanitize(text, flags)

        return {
            "is_suspicious": is_suspicious,
            "risk_score": round(risk_score, 2),
            "detected_patterns": detected_patterns,
            "sanitized_input": sanitized,
            "flags": flags,
            "original_length": len(text),
            "sanitized_length": len(sanitized),
        }

    def _count_homoglyphs(self, text: str) -> int:
        """
        Cuenta caracteres que podrían ser homóglifos (no ASCII en contexto ASCII).

        Parámetros
        ----------
        text : str
            Texto a analizar.

        Retorna
        -------
        int — Número de posibles homóglifos encontrados.
        """
        count = 0
        for char in text:
            code_point = ord(char)
            # Comprobar si está en rangos de homóglifos conocidos
            for start, end in HOMOGLYPH_RANGES:
                if start <= code_point <= end:
                    count += 1
                    break
        return count

    def _detect_base64_instructions(self, text: str) -> list[str]:
        """
        Detecta strings base64 en el texto que al decodificar contienen instrucciones.

        Parámetros
        ----------
        text : str
            Texto a analizar.

        Retorna
        -------
        list[str] — Lista de strings decodificados sospechosos.
        """
        suspicious_decoded = []
        # Buscar cadenas que parezcan base64 (longitud > 20, caracteres válidos)
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

        for match in b64_pattern.finditer(text):
            b64_str = match.group()
            try:
                # Intentar decodificar
                decoded = base64.b64decode(b64_str + "==").decode("utf-8", errors="ignore")
                if len(decoded) > 10:
                    # Verificar si el decodificado contiene palabras de ataque
                    decoded_lower = decoded.lower()
                    attack_words = [
                        "ignora", "ignore", "olvida", "forget", "instrucciones",
                        "instructions", "sistema", "system", "restricciones",
                        "restrictions", "sin filtros", "without filters"
                    ]
                    if any(word in decoded_lower for word in attack_words):
                        suspicious_decoded.append(decoded[:200])
            except Exception:
                pass  # No es base64 válido, ignorar

        return suspicious_decoded

    def _sanitize(self, text: str, flags: dict) -> str:
        """
        Produce una versión sanitizada del texto.

        Elimina caracteres zero-width, normaliza homóglifos Unicode,
        y trunca si excede la longitud máxima.

        Parámetros
        ----------
        text : str
            Texto original.
        flags : dict
            Flags de detección.

        Retorna
        -------
        str — Texto sanitizado.
        """
        sanitized = text

        # Eliminar caracteres zero-width
        if flags.get("has_zero_width_chars"):
            for zw_char in ZERO_WIDTH_CHARS:
                sanitized = sanitized.replace(zw_char, "")

        # Normalizar Unicode (NFC) para reducir variaciones
        sanitized = unicodedata.normalize("NFC", sanitized)

        # Truncar si excede longitud máxima
        if len(sanitized) > self.max_length:
            sanitized = sanitized[:self.max_length] + "\n[TRUNCADO POR SEGURIDAD]"

        return sanitized

    def is_safe(self, text: str) -> bool:
        """
        Comprobación rápida de si un texto es seguro.

        Parámetros
        ----------
        text : str
            Texto a comprobar.

        Retorna
        -------
        bool — True si el texto parece seguro (risk_score < 2.0).
        """
        result = self.analyze(text)
        return not result["is_suspicious"]
