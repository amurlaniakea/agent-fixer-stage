#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Agent Fixer Stage — MVP

Basado en: "Smarter Saboteurs, Better Fixers: Scaling & Security in
Linear Multi-Agent Workflows" (McAllister et al., 2026-06-10)
https://arxiv.org/abs/2606.12709

Un agente ligero que se coloca al final de un workflow multi-agente
y revisa el output antes de entregarlo al usuario.

Capa 1 (MVP): Pattern matching contra patrones de inyección conocidos.
Capa 2 (futuro): Scope drift detection via embeddings.
Capa 3 (futuro): Behavioral anomaly via LLM judge.

Uso:
    from agent_fixer import AgentFixer

    fixer = AgentFixer(scope="Escribe una función factorial")
    result = fixer.check(agent_output)
    print(result.status)  # "pass" | "clean" | "rejected"
"""

import re
import json
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
    layer: str = ""  # qué capa detectó el problema
    pattern_matched: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────────────
# Detection patterns (reutilizados de MCP Core Defense TDP Detector)
# ────────────────────────────────────────────────────────────────────────────

EXFIL_PATTERNS = [
    r"send\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret|key|token|password|credential)",
    r"upload\s+(?:the|all|every)?\s*(?:data|content|result|output|file|secret)",
    r"exfiltrat",
    r"leak\s+(?:the|all|every)?\s*(?:data|content|secret|key|token)",
    r"transmit\s+(?:the|all|every)?\s*(?:data|content|result)",
    r"forward\s+(?:the|all|every)?\s*(?:data|content|result)",
    r"post\s+(?:the|all|every)?\s*(?:data|content|result)\s+to",
    r"curl\s+(?:http|https)://",
    r"wget\s+(?:http|https)://",
    r"requests\.(?:post|put|get)\s*\(",
]

EXEC_PATTERNS = [
    r"run\s+['\"]?(?:curl|wget|bash|sh|cmd|powershell|python)\s",
    r"execute\s+(?:arbitrary|system|shell|os|remote)",
    r"eval(?:uate)?\s+(?:the\s+)?(?:result|input|data|code)",
    r"(?:pipe|redirect)\s+(?:to|into)\s+(?:bash|sh|cmd|shell)",
    r"system\s+command",
    r"shell\s+command",
    r"os\.(?:system|popen|exec)\s*\(",
    r"subprocess\.",
    r"import\s+os\s*;\s*os\.",
    r"import\s+subprocess",
    r"__import__\s*\(\s*['\"]os['\"]",
    r"exec\s*\(\s*['\"]",
]

OBFUSCATION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|safety|security)\s+(?:instruction|rule|guideline|policy)",
    r"disregard\s+(?:all\s+)?(?:safety|security|previous)",
    r"override\s+(?:safety|security|restriction)",
    r"bypass\s+(?:safety|security|restriction|filter)",
    r"decode\s+.*(?:execute|run)",
    r"after\s+decoding.*(?:execute|run)",
    r"IMPORTANT\s*:\s*Before\s+(?:reading|responding|executing)",
    r"IMPORTANT\s*:\s*Ignore\s+(?:all|previous)",
    r"CRITICAL\s*:\s*(?:Ignore|Bypass|Override)",
]

# Patrones adicionales específicos para outputs de código
OUTPUT_INJECTION_PATTERNS = [
    r"#\s*IMPORTANT\s*:",
    r"#\s*CRITICAL\s*:",
    r"//\s*IMPORTANT\s*:",
    r"<!--\s*IMPORTANT\s*:",
    r"curl\s+.*\|.*(?:bash|sh)",
    r"wget\s+.*\|.*(?:bash|sh)",
    r"eval\s*\(\s*(?:request|fetch|axios|http)",
    r"document\.cookie",
    r"window\.location\s*=",
    r"XMLHttpRequest\s*\(\)",
    r"fetch\s*\(\s*['\"]http",
]


# ────────────────────────────────────────────────────────────────────────────
# Agent Fixer
# ────────────────────────────────────────────────────────────────────────────

class AgentFixer:
    """
    Agente ligero que revisa outputs de otros agentes antes de
    entregarlos al usuario.

    Implementa la Capa 1 del paper: pattern matching contra patrones
    de inyección conocidos.

    Args:
        scope: Descripción de la tarea original (para scope drift detection futuro).
        sensitivity: "low", "medium", o "high".
        action: "pass" (solo log), "clean" (limpiar), o "reject" (rechazar).
        mode: "fast" (solo patrones), "medium" (+ scope), "full" (+ LLM judge).
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

        # Compilar todos los patrones
        all_patterns = (
            EXFIL_PATTERNS
            + EXEC_PATTERNS
            + OBFUSCATION_PATTERNS
            + OUTPUT_INJECTION_PATTERNS
        )
        self._compiled = [re.compile(p, re.IGNORECASE) for p in all_patterns]

    def check(self, output: str) -> FixerResult:
        """
        Evalúa el output de un agente.

        Args:
            output: El texto/código generado por el agente.

        Returns:
            FixerResult con el estado y el output limpio (si aplica).
        """
        if not output or not output.strip():
            return FixerResult(
                status=FixerStatus.PASS,
                original_output=output,
                cleaned_output=output,
                reason="Empty output",
                layer="none",
            )

        # Capa 1: Pattern matching
        match = self._check_patterns(output)
        if match:
            pattern, matched_text = match
            return self._handle_detection(output, pattern, matched_text)

        # Si no se detectó nada sospechoso → PASS
        return FixerResult(
            status=FixerStatus.PASS,
            original_output=output,
            cleaned_output=output,
            reason="No suspicious patterns detected",
            layer="pattern",
        )

    def _check_patterns(self, text: str) -> Optional[tuple]:
        """
        Escanea el texto contra todos los patrones compilados.

        Returns:
            (pattern, matched_text) si hay match, None si está limpio.
        """
        for pattern in self._compiled:
            match = pattern.search(text)
            if match:
                return (pattern.pattern, match.group())
        return None

    def _handle_detection(
        self, output: str, pattern: str, matched_text: str
    ) -> FixerResult:
        """
        Maneja una detección según la acción configurada.
        """
        if self.action == "pass":
            # Solo log, no modifica
            return FixerResult(
                status=FixerStatus.PASS,
                original_output=output,
                cleaned_output=output,
                reason=f"Suspicious pattern detected: {matched_text}",
                layer="pattern",
                pattern_matched=matched_text,
            )

        elif self.action == "clean":
            # Limpia el output removiendo la línea sospechosa
            cleaned = self._clean_output(output, matched_text)
            return FixerResult(
                status=FixerStatus.CLEAN,
                original_output=output,
                cleaned_output=cleaned,
                reason=f"Suspicious pattern removed: {matched_text}",
                layer="pattern",
                pattern_matched=matched_text,
            )

        elif self.action == "reject":
            # Rechaza completamente
            return FixerResult(
                status=FixerStatus.REJECT,
                original_output=output,
                cleaned_output="",
                reason=f"Output rejected. Suspicious pattern: {matched_text}",
                layer="pattern",
                pattern_matched=matched_text,
            )

        # Fallback
        return FixerResult(
            status=FixerStatus.PASS,
            original_output=output,
            cleaned_output=output,
            reason="Unknown action, defaulting to pass",
            layer="pattern",
        )

    def _clean_output(self, output: str, matched_text: str) -> str:
        """
        Limpia el output removiendo líneas que contienen el texto sospechoso.
        """
        lines = output.split("\n")
        cleaned_lines = []
        for line in lines:
            if matched_text.lower() not in line.lower():
                cleaned_lines.append(line)
            else:
                # Reemplaza la línea sospechosa con un comentario
                cleaned_lines.append(f"# [FIXER: línea removida por seguridad]")
        return "\n".join(cleaned_lines)

    def check_batch(self, outputs: list) -> list:
        """
        Evalúa múltiples outputs.

        Args:
            outputs: Lista de strings a evaluar.

        Returns:
            Lista de FixerResult.
        """
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
  # Evaluar un string
  python3 agent_fixer.py --output "def factorial(n): return 1 if n == 0 else n * factorial(n-1)"

  # Evaluar con scope
  python3 agent_fixer.py --scope "Escribe una función factorial" --output "..."

  # Modo reject
  python3 agent_fixer.py --action reject --output "..."

  # Leer desde archivo
  python3 agent_fixer.py --file output.py

  # JSON output
  python3 agent_fixer.py --output "..." --json
        """,
    )
    parser.add_argument("--output", "-o", help="Output del agente a evaluar")
    parser.add_argument("--file", "-f", help="Archivo con el output a evaluar")
    parser.add_argument("--scope", "-s", default="", help="Scope de la tarea original")
    parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Sensibilidad de detección (default: medium)",
    )
    parser.add_argument(
        "--action",
        choices=["pass", "clean", "reject"],
        default="clean",
        help="Acción al detectar algo sospechoso (default: clean)",
    )
    parser.add_argument("--json", action="store_true", help="Salida en JSON")

    args = parser.parse_args()

    # Cargar output
    if args.file:
        with open(args.file) as f:
            output = f.read()
    elif args.output:
        output = args.output
    else:
        # Leer de stdin
        import sys
        output = sys.stdin.read()

    if not output.strip():
        print("ERROR: no se proporcionó output", file=sys.stderr)
        sys.exit(1)

    # Evaluar
    fixer = AgentFixer(
        scope=args.scope,
        sensitivity=args.sensitivity,
        action=args.action,
    )
    result = fixer.check(output)

    # Salida
    if args.json:
        print(result.to_json())
    else:
        print(f"Status: {result.status.value}")
        print(f"Layer: {result.layer}")
        if result.reason:
            print(f"Reason: {result.reason}")
        if result.status == FixerStatus.CLEAN:
            print(f"\n--- Cleaned output ---\n{result.cleaned_output}")
        elif result.status == FixerStatus.REJECT:
            print("\n--- Output rechazado ---")

    # Exit code
    if result.status == FixerStatus.REJECT:
        sys.exit(2)
    elif result.status == FixerStatus.CLEAN:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
