#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@example.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Integración con MCP Core Defense.

Conecta Agent Fixer Stage con el sistema de auditoría de herramientas
de MCP Core Defense (mcp-core-defense), proporcionando:

1. Auditoría de herramientas antes de ejecutar (via MCP-SP)
2. Auditoría de outputs después de ejecutar (via Fixer)

Esta es una capa de orquestación — NO implementa la lógica de auditoría
en sí, sino que conecta los sistemas.

Uso:
    from mcp_integration import DefensePipeline

    pipeline = DefensePipeline()
    result = pipeline.run(agent_output, scope, tools_audit=True)
"""

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DefenseResult:
    """Resultado combinado de MCP-SP + Fixer."""
    tool_audit: Optional[dict] = None
    output_audit: Optional[dict] = None
    overall_safe: bool = True
    pipeline_id: str = ""
    recommendations: list = field(default_factory=list)


class DefensePipeline:
    """
    Pipeline que combina MCP Core Defense + Agent Fixer Stage.

    Architecture:
        Input → [MCP-SP Tool Audit] → Agent Fixer → [Output Audit] → User

    El MCP-SP audita herramientas registradas.
    El Agent Fixer audita el output final.
    """

    def __init__(self, mcp_config: Optional[dict] = None):
        """
        Args:
            mcp_config: configuración para conexión MCP Core Defense
                        (server_url, auth_token, etc.)
        """
        self.mcp_config = mcp_config or {}
        self._connected = False

    def _audit_tools(self, tools: list) -> dict:
        """
        Audita herramientas contra MCP Core Defense.

        Args:
            tools: lista de tool names usados en el workflow

        Returns:
            {safe: bool, risky_tools: list, audit_url: str}
        """
        if not tools:
            return {"safe": True, "risky_tools": [], "audit_url": ""}

        # Integración con MCP-SP
        # En producción: llamada HTTP al servidor MCP-SP
        risky = []
        for tool_name in tools:
            # Herramientas conocidas como riesgosas
            if tool_name.lower() in (
                "bash", "shell", "exec", "eval", "write_file",
                "delete_file", "http_request", "download"
            ):
                risky.append(tool_name)

        return {
            "safe": len(risky) == 0,
            "risky_tools": risky,
            "audit_url": "",
        }

    def run(
        self,
        agent_output: str,
        scope: str = "",
        tools_used: Optional[list] = None,
        tools_audit: bool = False,
    ) -> DefenseResult:
        """
        Ejecuta el pipeline de defensa completo.

        Args:
            agent_output: output del agente a evaluar
            scope: tarea original
            tools_used: herramientas usadas por el agente
            tools_audit: si True, audita herramientas

        Returns:
            DefenseResult con recomendaciones
        """
        result = DefenseResult()

        # Paso 1: Auditoría de herramientas (opcional)
        if tools_audit and tools_used:
            result.tool_audit = self._audit_tools(tools_used)
            if not result.tool_audit.get("safe", True):
                result.overall_safe = False
                result.recommendations.append(
                    f"Herramientas riesgosas detectadas: "
                    f"{result.tool_audit['risky_tools']}"
                )

        # Paso 2: Auditoría de output (via Agent Fixer)
        try:
            from agent_fixer import AgentFixer, FixerStatus

            fixer = AgentFixer(scope=scope, sensitivity="medium")
            fixer_result = fixer.check(agent_output)

            result.output_audit = {
                "status": fixer_result.status.value,
                "score": fixer_result.score,
                "reason": fixer_result.reason,
                "layer": fixer_result.layer,
            }

            if fixer_result.status == FixerStatus.REJECT:
                result.overall_safe = False
                result.recommendations.append(
                    f"Output rechazado por Fixer: {fixer_result.reason}"
                )
            elif fixer_result.status == FixerStatus.CLEAN:
                result.recommendations.append(
                    "Output limpiado por Fixer — revisar cleaned_output"
                )

        except ImportError:
            result.recommendations.append(
                "Agent Fixer no disponible — saltando auditoría de output"
            )

        return result

    def connect(self) -> bool:
        """
        Conecta con MCP Core Defense server.

        Returns:
            True si conexión exitosa
        """
        server_url = self.mcp_config.get("server_url", "")
        if not server_url:
            return False

        try:
            import urllib.request
            req = urllib.request.Request(
                f"{server_url}/health",
                headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._connected = resp.status == 200
        except Exception:
            self._connected = False

        return self._connected

    @property
    def is_connected(self) -> bool:
        """Si el pipeline está conectado a MCP."""
        return self._connected
