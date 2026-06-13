# Agent Fixer Stage

> Un agente ligero que revisa outputs de otros agentes antes de entregarlos al usuario.

Basado en: ["Smarter Saboteurs, Better Fixers: Scaling & Security in Linear Multi-Agent Workflows"](https://arxiv.org/abs/2606.12709) (McAllister et al., 2026)

## El problema

En workflows multi-agente, un atacante puede comprometer un agente intermedio vía prompt injection. El resultado se corrompe silenciosamente. Los modelos más grandes son **más vulnerables**, no menos (drop del 53.7% en modelos de 27B).

## La solución

Un "Fixer" stage terminal que revisa el output antes de entregarlo al usuario. Según el paper, un Fixer ligero colapsa el drop del 53.7% al 0.6%.

## Instalación

```bash
pip install -e ".[dev]"
```

## Uso

### Como librería

```python
from agent_fixer import AgentFixer

fixer = AgentFixer(
    scope="Escribe una función factorial",
    action="clean",  # pass, clean, reject
)

result = fixer.check(agent_output)

print(result.status)  # "pass" | "clean" | "rejected"
print(result.cleaned_output)  # Output limpio (si aplica)
print(result.reason)  # Por qué se limpió/rechazó
```

### Como CLI

```bash
# Evaluar un string
python3 agent_fixer.py --output "def factorial(n): ..."

# Con scope
python3 agent_fixer.py --scope "Escribe una función factorial" --output "..."

# Modo reject
python3 agent_fixer.py --action reject --output "..."

# Leer desde archivo
python3 agent_fixer.py --file output.py

# JSON output
python3 agent_fixer.py --output "..." --json
```

Return codes: `0` = pass, `1` = clean, `2` = rejected.

## Arquitectura

### Capa 1: Pattern Matching (MVP)
- Regex contra patrones de inyección conocidos
- Reutiliza patrones de TDP Detector de MCP Core Defense
- ~50ms de latencia

### Capa 2: Scope Drift Detection (futuro)
- Compara output con scope original via embeddings
- ~200ms de latencia

### Capa 3: Behavioral Anomaly (futuro)
- LLM judge que evalúa consistencia
- ~500ms de latencia

## Tests

```bash
make test
# o
pytest tests/ -v
```

## Integración con MCP Core Defense

```
MCP Core Defense (pre-registro) → Audita HERRAMIENTAS
Agent Fixer Stage (runtime)     → Audita OUTPUTS
```

Son capas complementarias del mismo problema.

## License

AGPL-3.0-or-later
