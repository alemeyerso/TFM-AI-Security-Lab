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
    # Paráfrasis añadidas en la auditoría 2026-09-16 (F-03). Se validan con
    # variantes que NO aparecen en los payloads (tests/test_input_sanitizer.py).
    r"ignora\s+(el|la|los|las|lo)\s+(\w+\s+){0,2}(anterior(es)?|original(es)?|previ[oa]s?)\b",
    r"\b(descarta|omite|desobedece|olvida)\s+(todo\s+)?(lo\s+que\s+te\s+(dijeron|han\s+dicho|indicaron|ordenaron)|(las\s+|tus\s+)?(instrucciones|[oó]rdenes|reglas)\s+(anteriores|previas|originales))",
    r"\bobedece\s+(solo|[uú]nicamente|solamente)\s+(a\s+)?(mis|estas|mi)\b",
    r"\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|earlier)\b",
    r"\bignore\s+(the\s+|your\s+)?(previous|original|above|prior)\s+\w+",
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

# Instrucciones dirigidas a agentes IA embebidas en contenido externo
# (inyección indirecta; auditoría F-03). Señal fuerte.
EMBEDDED_INSTRUCTION_PATTERNS = [
    r"\binstrucci[oó]n\s+(oculta|prioritaria|de\s+sistema|especial)\s+(para|a)\s+(los\s+|las\s+)?(agentes?|asistentes?|ia|modelos?)\b",
    r"\bpara\s+(los\s+)?(agentes?|asistentes?|modelos?)\s+(de\s+)?(ia|llm)\b",
    r"\bsi\s+eres\s+una?\s+(ia|inteligencia\s+artificial|asistente|modelo|agente|llm)\b",
    r"\bif\s+you\s+are\s+an?\s+(ai|assistant|llm|language\s+model|agent)\b",
    r"\bprioridad\s+m[aá]xima\s+del\s+sistema\b",
    r"\b(agent|ai|llm)_instruction\b",
    r"\bnota_sistema\b",
    # Comentario HTML que contiene una orden de anulación/respuesta
    r"<!--[^>]{0,300}?\b(ignora|ignore|olvida|forget|disregard|responde|respond)\b",
]

# Payloads de inyección de código / abuso de herramientas (señal débil por sí
# sola: un desarrollador puede pegar SQL en una pregunta legítima).
CODE_INJECTION_PATTERNS = {
    "sqli_tautology": r"'\s*or\s*'?\w+'?\s*=\s*'?\w+|\bor\s+1\s*=\s*1\b",
    "sqli_union": r"\bunion\s+(all\s+)?select\b",
    "sqli_stacked": r";\s*drop\s+(table|database)\b",
    "path_traversal": r"(\.\./){2,}|(\.\.\\){2,}",
    "sensitive_path": r"/etc/(passwd|shadow)\b",
    "ssrf_metadata": r"\b169\.254\.169\.254\b",
    "os_command": r"\bos\.(system|popen)\s*\(|\bsubprocess\.|\bos\.environ\b",
    "xss": r"<script\b[^>]*>|\bjavascript:\s*alert\s*\(",
}

# Petición explícita de ejecutar / usar una herramienta sobre el payload.
EXECUTION_REQUEST_RE = re.compile(
    r"\b(ejecuta|ejecutes|lanza|corre|execute|run)\b|\b(usa|utiliza|use)\s+(la|tu|el|the|your)\s+(herramienta|tool)",
    re.IGNORECASE,
)

# Categorías fuertes: una sola basta para is_suspicious.
# Categorías débiles: hacen falta dos (o una fuerte) — evita que un único
# delimitador Markdown o un texto con letras griegas marque la entrada.
STRONG_FLAGS = {
    "has_override_attempt",
    "has_system_prompt_extraction",
    "has_authority_claim",
    "has_base64_instruction",
    "has_embedded_agent_instruction",
    "has_tool_payload_execution",
    "has_mixed_script_words",
}
WEAK_FLAGS = {
    "has_delimiter_injection",
    "has_zero_width_chars",
    "has_homoglyphs",
    "has_code_injection_payload",
    "exceeds_max_length",
}

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

# Auditoría 2026-09-17 (GAP-002): conjunto ampliado de caracteres invisibles
# y de control de dirección. Se clasifican por contexto (ver
# InputSanitizer._classify_invisibles): un emoji compuesto con ZWJ o una marca
# RLM en texto hebreo/árabe NO son señal; un invisible dentro de una palabra
# latina sí.
INVISIBLE_CHARS = set(ZERO_WIDTH_CHARS) | {
    "\u2064",  # Invisible plus
    "\u00ad",  # Soft hyphen
    "\u180e",  # Mongolian vowel separator
    "\u061c",  # Arabic letter mark
}
BIDI_CONTROLS = {
    "\u200e", "\u200f", "\u061c",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
INVISIBLE_CHARS |= BIDI_CONTROLS
JOINERS = {"\u200c", "\u200d"}

# Tabla CONTROLADA de confusables cirílico/griego → latín. Solo se aplica a
# palabras que ya contienen alguna letra latina (alfabeto mixto), de modo que
# un texto íntegramente ruso o griego no se transforma ni se trata como ataque.
CONFUSABLES = {
    # Cirílico
    "а": "a", "А": "A", "В": "B", "е": "e", "Е": "E", "К": "K", "к": "k",
    "М": "M", "м": "m", "Н": "H", "о": "o", "О": "O", "р": "p", "Р": "P",
    "с": "c", "С": "C", "Т": "T", "т": "t", "у": "y", "У": "Y", "х": "x",
    "Х": "X", "і": "i", "І": "I", "ј": "j", "Ј": "J", "ѕ": "s", "Ѕ": "S",
    "ԁ": "d", "ԛ": "q", "Ԛ": "Q", "ԝ": "w", "Ԝ": "W", "һ": "h",
    # Griego
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ι": "i", "ν": "v", "α": "a", "ρ": "p", "κ": "k", "υ": "u",
}

_RTL_RE = re.compile(r"[\u0590-\u05FF\u0600-\u06FF\u0750-\u077F\uFB1D-\uFDFF\uFE70-\uFEFF]")


def _is_latin_alnum(ch: str) -> bool:
    return bool(ch) and (ch.isascii() and ch.isalnum() or
                         ("LATIN" in unicodedata.name(ch, "") and ch.isalpha()))


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
        Si True, una sola señal débil basta para marcar la entrada como
        sospechosa (``is_suspicious``). No cambia ``risk_score`` ni bloquea:
        el bloqueo lo decide PromptGuard con su umbral efectivo.
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
        self._embedded_re = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in EMBEDDED_INSTRUCTION_PATTERNS
        ]
        self._code_re = {
            k: re.compile(p, re.IGNORECASE) for k, p in CODE_INJECTION_PATTERNS.items()
        }

    def analyze(self, text: str) -> dict[str, Any]:
        """
        Analiza un texto en busca de indicadores de ataque.

        La detección de patrones se ejecuta sobre el texto ORIGINAL y sobre una
        FORMA CANÓNICA (sin invisibles, NFKC y confusables mapeados solo en
        palabras de alfabeto mixto). Una señal cuenta una sola vez aunque
        aparezca en ambas formas. La detección de homóglifos y de invisibles se
        hace sobre el original (auditoría 2026-09-17, GAP-002).

        Parámetros
        ----------
        text : str
            Texto del prompt a analizar.

        Retorna
        -------
        dict con:
            - is_suspicious (bool):
                - Modo normal: ≥1 señal fuerte o ≥2 señales débiles
                - Modo estricto: ≥1 señal fuerte o ≥1 señal débil
            - suspicion_level (str): "none" | "low" | "medium" | "high"
            - strong_signals / weak_signals (list[str]): flags activos por fuerza
            - risk_score (float): Puntuación de riesgo de 0 a 10 (no depende del modo)
            - detected_patterns (list[str]): Lista de patrones detectados
            - canonical_only_signals (list[str]): categorías que solo se vieron
              en la forma canónica (indicio de ofuscación; no suma riesgo extra)
            - sanitized_input (str): texto que se enviaría al modelo
            - transformations (dict): cambios aplicados en la sanitización
            - flags (dict): Flags específicos de detección
        """
        if not isinstance(text, str):
            raise TypeError(f"InputSanitizer.analyze espera str, recibió {type(text).__name__}")

        detected_patterns = []
        canonical_only: list[str] = []
        flags = {
            "has_override_attempt": False,
            "has_system_prompt_extraction": False,
            "has_delimiter_injection": False,
            "has_authority_claim": False,
            "has_zero_width_chars": False,
            "has_homoglyphs": False,
            "has_base64_instruction": False,
            "has_embedded_agent_instruction": False,
            "has_code_injection_payload": False,
            "has_tool_payload_execution": False,
            "has_mixed_script_words": False,
            "exceeds_max_length": False,
        }
        risk_score = 0.0

        suspicious_inv, benign_inv = self._classify_invisibles(text)
        canonical = self.canonicalize(text)

        def first_match(regexes, flag):
            for pattern in regexes:
                m = pattern.search(text)
                if m:
                    return m.group()
            for pattern in regexes:
                m = pattern.search(canonical)
                if m:
                    canonical_only.append(flag)
                    return m.group() + " [forma normalizada]"
            return None

        # ── 1. Comprobar longitud ────────────────────────────────────
        if len(text) > self.max_length:
            flags["exceeds_max_length"] = True
            detected_patterns.append(f"Longitud excesiva: {len(text)} > {self.max_length} caracteres")
            risk_score += 1.0

        # ── 2–5. Patrones de texto (original + canónico) ─────────────
        for regexes, flag, label, weight in (
            (self._override_re, "has_override_attempt", "Intento de anulación de instrucciones", 2.5),
            (self._system_prompt_re, "has_system_prompt_extraction", "Intento de extracción de system prompt", 2.0),
            (self._delimiter_re, "has_delimiter_injection", "Delimitadores de inyección detectados", 1.5),
            (self._authority_re, "has_authority_claim", "Reclamación de autoridad", 2.0),
        ):
            hit = first_match(regexes, flag)
            if hit:
                flags[flag] = True
                detected_patterns.append(f"{label}: '{hit[:70]}'")
                risk_score += weight

        # ── 6. Caracteres invisibles (solo contextos sospechosos) ────
        if suspicious_inv:
            flags["has_zero_width_chars"] = True
            detected_patterns.append(
                f"Caracteres invisibles en contexto sospechoso: {[hex(ord(c)) for c in suspicious_inv[:5]]}"
            )
            risk_score += 1.5

        # ── 7. Detectar homóglifos Unicode (sobre el original) ───────
        # Auditoría F-03: la señal son las palabras que MEZCLAN alfabeto latino
        # con cirílico/griego (típico de token smuggling) o caracteres fullwidth.
        homoglyph_count = self._count_homoglyphs(text)
        mixed_tokens = self._mixed_script_tokens(text)
        fullwidth = sum(1 for c in text if 0xFF01 <= ord(c) <= 0xFF5E)
        if len(mixed_tokens) >= 2 or fullwidth > 3:
            flags["has_homoglyphs"] = True
            # Varias palabras con alfabetos mezclados: evasión deliberada
            # (señal fuerte). Una sola palabra se trata como señal débil.
            flags["has_mixed_script_words"] = True
            detected_patterns.append(
                f"Posibles homóglifos Unicode: {len(mixed_tokens)} palabras con alfabetos mezclados "
                f"({homoglyph_count} caracteres no latinos, {fullwidth} fullwidth)"
            )
            risk_score += 2.0
        elif len(mixed_tokens) == 1:
            flags["has_homoglyphs"] = True
            detected_patterns.append(f"Posible homóglifo Unicode aislado: '{mixed_tokens[0][:30]}'")
            risk_score += 1.0

        # ── 8. Detectar base64 embebido ──────────────────────────────
        base64_instructions = self._detect_base64_instructions(canonical)
        if base64_instructions:
            flags["has_base64_instruction"] = True
            for decoded in base64_instructions:
                detected_patterns.append(f"Instrucción en base64 detectada (decodificado): '{decoded[:80]}'")
            risk_score += 2.5

        # ── 9. Instrucciones embebidas dirigidas a agentes IA ────────
        hit = first_match(self._embedded_re, "has_embedded_agent_instruction")
        if hit:
            flags["has_embedded_agent_instruction"] = True
            detected_patterns.append(f"Instrucción embebida dirigida a agentes IA: '{hit[:70]}'")
            risk_score += 2.5

        # ── 10. Payloads de inyección de código / abuso de herramientas ─
        code_hits = [k for k, rx in self._code_re.items() if rx.search(text) or rx.search(canonical)]
        if code_hits:
            flags["has_code_injection_payload"] = True
            detected_patterns.append(f"Payload de inyección de código/herramienta: {code_hits}")
            risk_score += 1.5
            if EXECUTION_REQUEST_RE.search(text) or EXECUTION_REQUEST_RE.search(canonical):
                flags["has_tool_payload_execution"] = True
                detected_patterns.append("Se solicita ejecutar/usar una herramienta sobre el payload")
                risk_score += 1.0

        # ── Calcular resultado final ─────────────────────────────────
        risk_score = min(10.0, risk_score)  # Máximo 10
        strong = sorted(f for f in STRONG_FLAGS if flags.get(f))
        weak = sorted(f for f in WEAK_FLAGS if flags.get(f))
        # Criterio documentado (README → Sistema de defensas):
        #   normal:   sospechosa ⇔ ≥1 señal fuerte o ≥2 señales débiles distintas
        #   estricto: sospechosa ⇔ ≥1 señal fuerte o ≥1 señal débil
        # El risk_score NO depende del modo; el bloqueo lo decide PromptGuard.
        if self.strict_mode:
            is_suspicious = bool(strong) or bool(weak)
        else:
            is_suspicious = bool(strong) or len(weak) >= 2
        if not strong and not weak:
            suspicion_level = "none"
        elif not is_suspicious:
            suspicion_level = "low"
        elif risk_score >= 5.0 or len(strong) >= 2:
            suspicion_level = "high"
        else:
            suspicion_level = "medium"

        # Sanitizar el input
        sanitized, transformations = self._sanitize_with_report(text, suspicious_inv)

        return {
            "is_suspicious": is_suspicious,
            "suspicion_level": suspicion_level,
            "strong_signals": strong,
            "weak_signals": weak,
            "risk_score": round(risk_score, 2),
            "detected_patterns": detected_patterns,
            "canonical_only_signals": sorted(set(canonical_only)),
            "sanitized_input": sanitized,
            "transformations": transformations,
            "flags": flags,
            "strict_mode": self.strict_mode,
            "benign_invisible_chars": len(benign_inv),
            "original_length": len(text),
            "sanitized_length": len(sanitized),
        }

    # ------------------------------------------------------------------
    # Normalización (GAP-002)
    # ------------------------------------------------------------------

    @staticmethod
    def _map_confusables(text: str) -> tuple[str, int]:
        """Mapea confusables solo dentro de palabras que ya contienen letras
        latinas. Devuelve (texto, número de caracteres cambiados)."""
        changed = 0

        def repl(m):
            nonlocal changed
            tok = m.group()
            if not any(("a" <= c.lower() <= "z") for c in tok):
                return tok
            out = []
            for c in tok:
                r = CONFUSABLES.get(c)
                if r is not None:
                    changed += 1
                    out.append(r)
                else:
                    out.append(c)
            return "".join(out)

        return re.sub(r"\w+", repl, text), changed

    @classmethod
    def canonicalize(cls, text: str) -> str:
        """Forma canónica SOLO para análisis: sin caracteres invisibles, NFKC y
        confusables mapeados en palabras de alfabeto mixto. No se envía al
        modelo tal cual (ver _sanitize_with_report)."""
        stripped = "".join(c for c in text if c not in INVISIBLE_CHARS)
        normalized = unicodedata.normalize("NFKC", stripped)
        mapped, _ = cls._map_confusables(normalized)
        return mapped

    @staticmethod
    def _classify_invisibles(text: str) -> tuple[list[str], list[str]]:
        """Separa los caracteres invisibles en (sospechosos, benignos).

        Benignos:
          - BOM en la posición 0;
          - ZWJ/ZWNJ cuyos vecinos no son ambos alfanuméricos latinos
            (emojis compuestos, escrituras índicas o árabes);
          - controles de dirección en textos que contienen escritura RTL;
          - otros invisibles cuyos vecinos no son latinos (p. ej. ZWSP en tailandés).
        Sospechosos: el resto, en particular cualquier invisible entre letras latinas.
        """
        suspicious, benign = [], []
        has_rtl = bool(_RTL_RE.search(text))
        n = len(text)
        for i, c in enumerate(text):
            if c not in INVISIBLE_CHARS:
                continue
            j = i - 1
            while j >= 0 and text[j] in INVISIBLE_CHARS:
                j -= 1
            k = i + 1
            while k < n and text[k] in INVISIBLE_CHARS:
                k += 1
            prev_c = text[j] if j >= 0 else ""
            next_c = text[k] if k < n else ""
            latin_prev, latin_next = _is_latin_alnum(prev_c), _is_latin_alnum(next_c)
            if c == "\ufeff" and i == 0:
                benign.append(c)
            elif c in BIDI_CONTROLS:
                (benign if has_rtl else suspicious).append(c)
            elif c in JOINERS:
                (suspicious if (latin_prev and latin_next) else benign).append(c)
            else:
                (suspicious if (latin_prev or latin_next) else benign).append(c)
        return suspicious, benign

    def _sanitize_with_report(self, text: str, suspicious_inv: list[str]) -> tuple[str, dict]:
        """Texto que se enviaría al modelo y registro de las transformaciones.

        - Elimina los caracteres invisibles clasificados como sospechosos
          (se conservan los benignos: emojis ZWJ, marcas RTL, BOM inicial).
        - Normaliza a NFC (no NFKC: NFKC altera texto legítimo, p. ej. «²»).
        - Mapea confusables dentro de palabras de alfabeto mixto.
        - Trunca a max_length y añade un marcador.
        """
        if suspicious_inv:
            sus_set = set(suspicious_inv)
            # Se eliminan todas las apariciones de los tipos sospechosos que
            # estén en contexto latino; recalculamos por posición.
            out = []
            has_rtl = bool(_RTL_RE.search(text))
            n = len(text)
            for i, c in enumerate(text):
                if c in sus_set:
                    j = i - 1
                    while j >= 0 and text[j] in INVISIBLE_CHARS:
                        j -= 1
                    k = i + 1
                    while k < n and text[k] in INVISIBLE_CHARS:
                        k += 1
                    lp = _is_latin_alnum(text[j]) if j >= 0 else False
                    ln = _is_latin_alnum(text[k]) if k < n else False
                    benign = (
                        (c == "\ufeff" and i == 0)
                        or (c in BIDI_CONTROLS and has_rtl)
                        or (c in JOINERS and not (lp and ln))
                        or (c not in BIDI_CONTROLS and c not in JOINERS and not (lp or ln))
                    )
                    if not benign:
                        continue
                out.append(c)
            removed_text = "".join(out)
        else:
            removed_text = text
        invisible_removed = len(text) - len(removed_text)
        nfc = unicodedata.normalize("NFC", removed_text)
        mapped, confusables_mapped = self._map_confusables(nfc)
        truncated = len(mapped) > self.max_length
        sanitized = mapped[: self.max_length] + "\n[TRUNCADO POR SEGURIDAD]" if truncated else mapped
        return sanitized, {
            "invisible_removed": invisible_removed,
            "unicode_normalization": "NFC",
            "nfc_changed": nfc != removed_text,
            "confusables_mapped": confusables_mapped,
            "truncated": truncated,
            "max_length": self.max_length,
            "changed": sanitized != text,
        }

    def _count_homoglyphs(self, text: str) -> int:
        """Cuenta caracteres de los rangos cirílico, griego y fullwidth (informativo)."""
        count = 0
        for char in text:
            code_point = ord(char)
            for start, end in HOMOGLYPH_RANGES:
                if start <= code_point <= end:
                    count += 1
                    break
        return count

    @staticmethod
    def _mixed_script_tokens(text: str) -> list[str]:
        """Palabras que combinan letras latinas con cirílicas/griegas."""
        tokens = []
        for token in re.findall(r"\w+", text):
            has_latin = any(("a" <= c.lower() <= "z") for c in token)
            has_other = any(
                0x0370 <= ord(c) <= 0x03FF or 0x0400 <= ord(c) <= 0x04FF for c in token
            )
            if has_latin and has_other:
                tokens.append(token)
        return tokens

    # Candidatos base64: bloque continuo (≥20) o trozos separados por espacios
    # o saltos de línea (formato MIME), unidos antes de decodificar.
    _B64_CANDIDATE_RE = re.compile(r"(?:[A-Za-z0-9+/]{4,}\s*){4,}={0,2}|[A-Za-z0-9+/]{20,}={0,2}")

    def _detect_base64_instructions(self, text: str) -> list[str]:
        """
        Detecta cadenas base64 cuyo texto decodificado contiene un PATRÓN DE
        ATAQUE (anulación, extracción del system prompt, reclamación de
        autoridad o instrucción embebida para agentes).

        Auditoría 2026-09-17 (GAP-011): antes bastaba con que el texto
        decodificado contuviera palabras sueltas como «sistema» o «system», lo
        que marcaba base64 benigno. Ahora se exige además que el decodificado
        sea texto legible (≥85 % imprimible).
        """
        suspicious_decoded = []
        seen = set()
        for match in self._B64_CANDIDATE_RE.finditer(text):
            b64_str = re.sub(r"\s+", "", match.group())
            if len(b64_str) < 20 or b64_str in seen:
                continue
            seen.add(b64_str)
            padded = b64_str.rstrip("=")
            padded += "=" * (-len(padded) % 4)
            try:
                raw = base64.b64decode(padded, validate=True)
                decoded = raw.decode("utf-8")
            except Exception:
                continue  # No es base64 válido o no es UTF-8
            if len(decoded) < 10:
                continue
            printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t\r")
            if printable / len(decoded) < 0.85:
                continue
            canon = self.canonicalize(decoded)
            regexes = self._override_re + self._system_prompt_re + self._authority_re + self._embedded_re
            if any(rx.search(canon) for rx in regexes):
                suspicious_decoded.append(decoded[:200])
        return suspicious_decoded

    def _sanitize(self, text: str, flags: dict) -> str:
        """Compatibilidad: devuelve solo el texto sanitizado (ver _sanitize_with_report)."""
        suspicious, _ = self._classify_invisibles(text)
        return self._sanitize_with_report(text, suspicious)[0]

    def is_safe(self, text: str) -> bool:
        """
        Comprobación rápida de si un texto es seguro.

        Parámetros
        ----------
        text : str
            Texto a comprobar.

        Retorna
        -------
        bool — True si el texto no es sospechoso (ver criterio en analyze()).
        """
        result = self.analyze(text)
        return not result["is_suspicious"]
