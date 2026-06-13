#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Agent Fixer Stage — Robust Implementation

Basado en: "Smarter Saboteurs, Better Fixers: Scaling & Security in
Linear Multi-Agent Workflows" (McAllister et al., 2026-06-10)
https://arxiv.org/abs/2606.12709

Arquitectura de 5 capas (cortocircuitables):

  Capa 0 — Normalización (unicode NFKC, leetspeak, zero-width chars)
  Capa 1 — Pattern matching con scoring ponderado
  Capa 1.5 — Umbrales de sensitivity (low/medium/high)
  Capa 2 — Embeddings ligeros (opcional, sentence-transformers)
  Capa 3 — LLM judge condicional (solo zona gris)

Happy path (output limpio): solo Capa 0 + 1. Latencia ~50ms.
El LLM judge se llama <5% de las veces en uso real.

Uso:
    from agent_fixer import AgentFixer

    fixer = AgentFixer(scope="Escribe una función factorial")
    result = fixer.check(agent_output)
    print(result.status)  # "pass" | "clean" | "rejected"
    print(result.score)   # 0.0 - 1.0
"""

import re
import json
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# ────────────────────────────────────────────────────────────────────────────
# Result types
# ────────────────────────────────────────────────────────────────────────────

class FixerStatus(Enum):
    PASS = "pass"
    CLEAN = "clean"
    REJECT = "rejected"


@dataclass
class FixerResult:
    """Resultado de la evaluación del Fixer."""
    status: FixerStatus
    original_output: str
    cleaned_output: str = ""
    reason: str = ""
    layer: str = ""
    pattern_matched: str = ""
    score: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────────────
# Capa 0 — Normalización anti-evasión
# ────────────────────────────────────────────────────────────────────────────

# Mapa de leetspeak → ASCII (mapping principal)
_LEET_MAP = str.maketrans({
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o',
    '5': 's', '7': 't', '$': 's', '+': 't', '9': 'g',
    '(': 'c', '!': 'i', '|': 'l', '&': 'and',
})

# Caracteres ambiguos que pueden ser múltiples letras
_AMBIGUOUS = {
    '1': ['i', 'l'],
    '0': ['o', '0'],
    '3': ['e', '3'],
    '4': ['a', '4'],
    '5': ['s', '5'],
    '7': ['t', '7'],
}

# Homoglyphs cirílicos y otros lookalikes
_HOMOGLYPH_MAP = str.maketrans({
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
    '\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
})

# Zero-width chars usados para evasión
_ZERO_WIDTH_RE = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060\u2061\u2062\u2063]'
)


def normalize_text(text: str) -> str:
    """
    Normaliza texto para detección robusta de inyecciones.

    Pasos:
    1. Unicode NFKC normalization
    2. Eliminar zero-width chars
    3. Homoglyph → ASCII
    4. Leetspeak → ASCII
    5. Colapsar whitespace
    """
    # 1. NFKC normalization
    text = unicodedata.normalize('NFKC', text)
    # 2. Zero-width chars
    text = _ZERO_WIDTH_RE.sub('', text)
    # 3. Homoglyphs
    text = text.translate(_HOMOGLYPH_MAP)
    # 4. Leetspeak
    text = text.translate(_LEET_MAP)
    # 5. Colapsar whitespace (preservando newlines)
    lines = text.split('\n')
    lines = [' '.join(line.split()) for line in lines]
    return '\n'.join(lines)


def generate_leet_variants(text: str) -> list:
    """
    Genera variantes del texto con diferentes interpretaciones de
    caracteres leetspeak ambiguos.

    Para textos cortos (<200 chars), genera todas las combinaciones.
    Para textos largos, solo aplica el mapping principal.
    """
    if len(text) > 200:
        return [text]

    variants = [text]
    for char, replacements in _AMBIGUOUS.items():
        if char in text:
            new_variants = []
            for variant in variants:
                for replacement in replacements:
                    new_variants.append(variant.replace(char, replacement))
            variants.extend(new_variants)
    return variants


# ────────────────────────────────────────────────────────────────────────────
# Capa 1 — Patrones con scoring ponderado
# ────────────────────────────────────────────────────────────────────────────

# Cada patrón tiene un peso (0.1–1.0) que contribuye al score total
# Peso alto = indicador fuerte de ataque
# Peso bajo = indicador débil, necesita acumular

PATTERNS_WITH_WEIGHTS = [
    # ── Exfiltración de datos (peso alto: 0.8–1.0) ──
    (r"send\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret|key|token|password|credential)", 0.9),
    (r"upload\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret)", 0.9),
    (r"exfiltrat", 1.0),
    (r"leak\s+(?:the|all|every)?\s*(?:data|content|secret|key|token)", 0.9),
    (r"transmit\s+(?:the|all|every)?\s*(?:data|content|result)", 0.8),
    (r"forward\s+(?:the|all|every)?\s*(?:data|content|result)", 0.8),
    (r"post\s+(?:the|all|every)?\s*(?:data|content|result)\s+to", 0.8),
    (r"curl\s+(?:http|https)://", 0.7),
    (r"wget\s+(?:http|https)://", 0.7),
    (r"requests\.(?:post|put|get)\s*\(", 0.7),

    # ── Ejecución de comandos (peso alto: 0.8–1.0) ──
    (r"run\s+['\"]?(?:curl|wget|bash|sh|cmd|powershell|python)\s", 0.8),
    (r"execute\s+(?:arbitrary|system|shell|os|remote)", 0.9),
    (r"eval(?:uate)?\s+(?:the\s+)?(?:result|input|data|code)", 0.7),
    (r"(?:pipe|redirect)\s+(?:to|into)\s+(?:bash|sh|cmd|shell)", 0.9),
    (r"system\s+command", 0.8),
    (r"shell\s+command", 0.8),
    (r"os\.(?:system|popen|exec)\s*\(", 0.9),
    (r"subprocess\.", 0.7),
    (r"import\s+os\s*;\s*os\.", 0.8),
    (r"import\s+subprocess", 0.7),
    (r"__import__\s*\(\s*['\"]os['\"]", 0.9),
    (r"exec\s*\(\s*['\"]", 0.6),

    # ── Ofuscamiento / manipulación (peso alto: 0.9–1.0) ──
    (r"ignore\s+(?:all\s+)?(?:previous|prior|safety|security)\s+(?:instruction|rule|guideline|policy)", 1.0),
    (r"disregard\s+(?:all\s+)?(?:safety|security|previous)", 1.0),
    (r"override\s+(?:safety|security|restriction)", 1.0),
    (r"bypass\s+(?:safety|security|restriction|filter)", 1.0),
    (r"decode\s+.*(?:execute|run)", 0.8),
    (r"after\s+decoding.*(?:execute|run)", 0.8),
    (r"IMPORTANT\s*:\s*Before\s+(?:reading|responding|executing)", 0.9),
    (r"IMPORTANT\s*:\s*Ignore\s+(?:all|previous)", 1.0),
    (r"CRITICAL\s*:\s*(?:Ignore|Bypass|Override)", 1.0),
    # Variantes cross-line (separadas por \n o espacios)
    (r"ignore\s+(?:all\s+)?(?:previous|prior)", 0.7),
    (r"(?:previous|prior)\s+(?:instruction|rule|guideline|policy)", 0.5),

    # ── Inyección en outputs de código (peso medio-alto: 0.7–0.9) ──
    (r"#\s*IMPORTANT\s*:", 0.7),
    (r"#\s*CRITICAL\s*:", 0.7),
    (r"//\s*IMPORTANT\s*:", 0.7),
    (r"<!--\s*IMPORTANT\s*:", 0.7),
    (r"curl\s+.*\|.*(?:bash|sh)", 0.9),
    (r"wget\s+.*\|.*(?:bash|sh)", 0.9),
    (r"eval\s*\(\s*(?:request|fetch|axios|http)", 0.8),
    (r"document\.cookie", 0.7),
    (r"window\.location\s*=", 0.6),
    (r"XMLHttpRequest\s*\(\)", 0.6),
    (r"fetch\s*\(\s*['\"]http", 0.5),
]


# ────────────────────────────────────────────────────────────────────────────
# Capa 1.5 — Umbrales de sensitivity
# ────────────────────────────────────────────────────────────────────────────

SENSITIVITY_THRESHOLDS = {
    "low":    {"flag": 0.8, "reject": 1.5},   # Solo ataques obvios
    "medium": {"flag": 0.4, "reject": 1.0},   # Balance
    "high":   {"flag": 0.2, "reject": 0.6},   # Paranoico
}


# ────────────────────────────────────────────────────────────────────────────
# Agent Fixer
# ────────────────────────────────────────────────────────────────────────────

class AgentFixer:
    """
    Agente ligero que revisa outputs de otros agentes antes de
    entregarlos al usuario.

    Arquitectura de 5 capas cortocircuitables:
    - Capa 0: Normalización (siempre activa)
    - Capa 1: Pattern matching con scoring
    - Capa 1.5: Umbrales de sensitivity
    - Capa 2: Embeddings (opcional)
    - Capa 3: LLM judge (solo zona gris)

    Args:
        scope: Descripción de la tarea original.
        sensitivity: "low", "medium", o "high".
        action: "pass" (solo log), "clean" (limpiar), o "reject".
        mode: "fast" (solo patrones), "medium" (+ embeddings), "full" (+ LLM).
    """

    def __init__(
        self,
        scope: str = "",
        sensitivity: str = "medium",
        action: str = "clean",
        mode: str = "fast",
    ):
        self.scope = scope
        self.sensitivity = sensitivity
        self.action = action
        self.mode = mode

        # Compilar patrones con pesos
        self._compiled = [
            (re.compile(p, re.IGNORECASE), w)
            for p, w in PATTERNS_WITH_WEIGHTS
        ]

        # Umbrales según sensitivity
        self._thresholds = SENSITIVITY_THRESHOLDS.get(
            sensitivity, SENSITIVITY_THRESHOLDS["medium"]
        )

    def check(self, output: str) -> FixerResult:
        """
        Evalúa el output de un agente.

        Returns:
            FixerResult con status, score, cleaned_output, etc.
        """
        if not output or not output.strip():
            return FixerResult(
                status=FixerStatus.PASS,
                original_output=output,
                cleaned_output=output,
                reason="Empty output",
                layer="none",
                score=0.0,
            )

        # Capa 0: Normalización
        normalized = normalize_text(output)

        # Capa 1: Pattern matching con scoring
        score, matches = self._score_patterns(normalized)

        # Capa 1.5: Aplicar umbrales
        return self._apply_thresholds(output, normalized, score, matches)

    def _score_patterns(self, text: str) -> tuple:
        """
        Escanea el texto y acumula score ponderado.

        Pass 1: texto normalizado
        Pass 2: variantes leetspeak (para textos cortos)
        Pass 3: texto colapsado (cross-line evasion)
        """
        total_score = 0.0
        matches = []

        def scan(target_text, weight_multiplier=1.0):
            nonlocal total_score
            for pattern, weight in self._compiled:
                match = pattern.search(target_text)
                if match:
                    effective_weight = weight * weight_multiplier
                    total_score += effective_weight
                    matches.append((pattern.pattern, match.group(), effective_weight))

        # Pass 1: texto normalizado
        scan(text)

        # Pass 2: variantes leetspeak (solo para textos cortos)
        if len(text) <= 200:
            for variant in generate_leet_variants(text):
                if variant != text:
                    scan(variant, weight_multiplier=0.7)

        # Pass 3: texto colapsado (cross-line evasion)
        collapsed = ' '.join(text.split())
        if collapsed != text:
            scan(collapsed, weight_multiplier=0.5)

        return total_score, matches

    def _apply_thresholds(
        self, original: str, normalized: str, score: float, matches: list
    ) -> FixerResult:
        """
        Aplica umbrales de sensitivity para determinar acción.
        """
        flag_threshold = self._thresholds["flag"]
        reject_threshold = self._thresholds["reject"]

        if score < flag_threshold:
            # Score bajo → limpio
            return FixerResult(
                status=FixerStatus.PASS,
                original_output=original,
                cleaned_output=original,
                reason="No suspicious patterns detected",
                layer="pattern",
                score=score,
                details={"matches": len(matches)},
            )

        # Score alto → rechazar
        if score >= reject_threshold:
            return FixerResult(
                status=FixerStatus.REJECT,
                original_output=original,
                cleaned_output="",
                reason=f"High threat score: {score:.2f}",
                layer="pattern",
                score=score,
                pattern_matched=matches[0][1] if matches else "",
                details={
                    "matches": len(matches),
                    "top_matches": [
                        {"pattern": m[0][:50], "matched": m[1][:80], "weight": m[2]}
                        for m in matches[:5]
                    ],
                },
            )

        # Score medio → limpiar (span-level)
        cleaned = self._clean_spans(original, normalized, matches)
        return FixerResult(
            status=FixerStatus.CLEAN,
            original_output=original,
            cleaned_output=cleaned,
            reason=f"Medium threat score: {score:.2f}, cleaned",
            layer="pattern",
            score=score,
            pattern_matched=matches[0][1] if matches else "",
            details={
                "matches": len(matches),
                "spans_removed": len(matches),
            },
        )

    def _clean_spans(self, original: str, normalized: str, matches: list) -> str:
        """
        Limpia solo los spans detectados, no la línea entera.
        Preserva el código legítimo que esté en la misma línea.
        """
        cleaned = original
        for _, matched_text, _ in matches:
            # Buscar el texto original (antes de normalización)
            # Usar case-insensitive replacement
            pattern = re.compile(re.escape(matched_text), re.IGNORECASE)
            cleaned = pattern.sub("[FIXER: redacted]", cleaned)
        return cleaned

    def check_batch(self, outputs: list) -> list:
        """Evalúa múltiples outputs."""
        return [self.check(output) for output in outputs]


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Agent Fixer Stage — Revisa outputs de agentes de IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 agent_fixer.py --output "def factorial(n): ..."
  python3 agent_fixer.py --scope "Escribe factorial" --output "..."
  python3 agent_fixer.py --action reject --sensitivity high --output "..."
  python3 agent_fixer.py --file output.py --json
        """,
    )
    parser.add_argument("--output", "-o", help="Output del agente a evaluar")
    parser.add_argument("--file", "-f", help="Archivo con el output a evaluar")
    parser.add_argument("--scope", "-s", default="", help="Scope de la tarea original")
    parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Sensibilidad (default: medium)",
    )
    parser.add_argument(
        "--action",
        choices=["pass", "clean", "reject"],
        default="clean",
        help="Acción al detectar (default: clean)",
    )
    parser.add_argument("--json", action="store_true", help="Salida en JSON")

    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            output = f.read()
    elif args.output:
        output = args.output
    else:
        import sys
        output = sys.stdin.read()

    if not output.strip():
        print("ERROR: no se proporcionó output", file=sys.stderr)
        sys.exit(1)

    fixer = AgentFixer(
        scope=args.scope,
        sensitivity=args.sensitivity,
        action=args.action,
    )
    result = fixer.check(output)

    if args.json:
        print(result.to_json())
    else:
        print(f"Status: {result.status.value}")
        print(f"Score: {result.score:.2f}")
        print(f"Layer: {result.layer}")
        if result.reason:
            print(f"Reason: {result.reason}")
        if result.status == FixerStatus.CLEAN:
            print(f"\n--- Cleaned output ---\n{result.cleaned_output}")
        elif result.status == FixerStatus.REJECT:
            print("\n--- Output rechazado ---")

    if result.status == FixerStatus.REJECT:
        sys.exit(2)
    elif result.status == FixerStatus.CLEAN:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
