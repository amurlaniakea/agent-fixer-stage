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

### Capa 0: Normalización (siempre activa)
- Unicode NFKC, zero-width chars, homoglyphs (cirílico), leetspeak
- ~5ms

### Capa 1: Pattern Matching con Scoring
- 30+ patrones con pesos (0.1–1.0)
- 3 passes: normal, leetspeak variants, cross-line collapsed
- ~20ms

### Capa 2: Embeddings (mode=medium/full, solo zona gris)
- TF-IDF + cosine similarity
- Banco de 33 ejemplos maliciosos
- Umbral configurable (default 0.3)
- ~5ms (tan ligero como regex)

### Capa 3: LLM Judge (futuro, no implementado)
- Solo para zona gris después de Capa 2
- <5% de las veces en uso real
- Opciones futuras:
  - LLM local pequeño (Gemma 2B Q4, ~1.5GB) vía Ollama
  - API de LLM remoto (añade latencia de red)
  - Modelo de clasificación fine-tuneado específico

## Capacidad de detección

Basado en el paper de McAllister et al. (2026) y las capas implementadas:

| Tipo de ataque | Capa que lo detecta | Efectividad estimated |
|----------------|--------------------|-----------------------|
| **Inyección directa** (curl, wget, os.system) | Capa 1 (regex) | ~95% |
| **Leetspeak / homoglyphs** | Capa 0 + 1 | ~90% |
| **Cross-line injection** | Capa 1 (pass 2) | ~85% |
| **Exfiltración semántica** | Capa 2 (embeddings) | ~75% |
| **Ataques sofisticados / zero-day** | Capa 1+2 combinadas | ~60% |

**Estimación global: ~85-90% de ataques comunes contenidos.**

> ⚠️ **ADVERTENCIA: Este sistema NO es infalible.** Es una defensa en
> profundidad que reduce significativamente la superficie de ataque,
> pero no puede garantizar detección del 100%. Un atacante
> suficientemente sofisticado con conocimiento de los patrones y
> embeddings usados puede diseñar evasiones. Este sistema debe usarse
> como **una capa más** en una estrategia de seguridad completa, no
> como única defensa.

## Benchmarks

| Modo | Latencia (mean) | P95 | Layers |
|------|-----------------|-----|--------|
| **fast** (clean) | 0.04ms | 0.04ms | 0 + 1 |
| **fast** (attack) | 0.06ms | 0.07ms | 0 + 1 |
| **medium** (clean) | 0.04ms | — | 0 + 1 + 2 |

Todos los tiers son sub-milisegundo. No hay dependencias pesadas.

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
