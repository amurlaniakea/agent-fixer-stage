# Changelog

All notable changes to Agent Fixer Stage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-28

### Added
- **Scope Drift Detection (Capa 2.5)** — Nuevo módulo `scope_drift.py` que compara el output con el scope original via TF-IDF + cosine similarity. Detecta cuando el agente hace algo no relacionado con la tarea.
- **LLM Judge (Capa 3)** — Nuevo módulo `llm_judge.py` con soporte para Ollama (local) y API OpenAI-compatible (remoto). Evalúa consistencia scope→output usando un LLM.
- **MCP Integration** — Nuevo módulo `mcp_integration.py` con `DefensePipeline` que conecta Agent Fixer con MCP Core Defense para auditoría de herramientas y outputs.
- **Multi-language patterns** — 42 nuevos patrones en español (28), francés (3), alemán (3), italiano (3), portugués (3), reverse shell (6), jailbreak (3). Total: 80 patrones.
- **Leetspeak isolation** — Separación de `_LEET_MAP_DETECT` (agresivo para scoring) y `_LEET_MAP_CLEAN` (no corrompe sintaxis de código).
- **Span offset tracking** — `_score_patterns` registra (start, end) offsets; `_clean_spans` aplica por posición en vez de substring match.
- **Action override real** — `action='reject'` fuerza REJECT, `action='pass'` eleva threshold, `action='clean'` = comportamiento estándar.
- **Match deduplication** — Elimina matches duplicados entre passes (Pass 1 vs Pass 3 cross-line).
- **Dataset downloads** — 5 datasets de HuggingFace descargados (~11,871 ejemplos): deepset/prompt-injections, yanismiraoui/prompt_injections, reshabhs/SPML, rikka-snow/multilingual, darkknight25/Reverse_Shell.
- **pyproject.toml** actualizado para empaquetado pip (version 0.2.0, classifiers, URLs).

### Fixed
- **Bug crítico: leetspeak corrupting code** — `(` → `c` convertía `os.system(cmd)` en `os.systemccmd)`, rompiendo el regex de detección. Fix: mapa de detección separado.
- **Bug crítico: span cleaning silent failure** — `_clean_spans` buscaba texto normalizado en original sin normalizar. Fix: usar offsets registrados.
- **Bug crítico: action parameter vestigial** — `self.action` se asignaba pero nunca se leía. Fix: implementar override real.
- **False positive: subprocess.run legítimo** — Código Python válido daba score=2.0 (REJECT). Fix: deduplicación de matches + pesos recalibrados.
- **False positive: import subprocess** — Score 0.7 solo por importar. Fix: peso reducido a 0.1, solo import sin uso peligroso no suma.

### Detection Performance (updated)

| Attack Type | Layer | Estimated Effectiveness |
|-------------|-------|----------------------|
| Direct injection (curl, wget, os.system) | Layer 1 (regex) | ~95% |
| Leetspeak / homoglyphs | Layer 0 + 1 | ~95% |
| Cross-line injection | Layer 1 (pass 2) | ~85% |
| Semantic exfiltration | Layer 2 (embeddings) | ~75% |
| Spanish attacks | Layer 1 (ES patterns) | ~85% |
| French/German/Italian/Portuguese | Layer 1 (EU patterns) | ~75% |
| Reverse shell payloads | Layer 1 (RCE patterns) | ~90% |
| Scope drift | Layer 2.5 (TF-IDF) | ~70% |
| Sophisticated / zero-day | Layer 1+2+2.5+3 combined | ~65% |

**Global estimate: ~90-95% of common attacks contained (multi-language).**

### Architecture (updated)

```
Agent Fixer Stage v0.2.0
├── Capa 0: Normalización (NFKC, zero-width, homoglyphs, leetspeak)
├── Capa 1: Pattern Matching (80 patterns, 5 idiomas, 3 passes)
├── Capa 1.5: Umbrales de sensibilidad (low/medium/high)
├── Capa 2: Embeddings TF-IDF (banco de 33 ejemplos maliciosos)
├── Capa 2.5: Scope Drift Detection (TF-IDF cosine similarity) [NUEVO]
├── Capa 3: LLM Judge (Ollama/API remota) [NUEVO]
└── MCP Integration (DefensePipeline) [NUEVO]
```

## [0.1.0] - 2026-06-22

### Added
- Layer 0: Normalization — Unicode NFKC, zero-width chars, homoglyphs (Cyrillic), leetspeak
- Layer 1: Pattern Matching with Scoring — 30+ patterns with weights (0.1–1.0), 3 passes
- Layer 2: Embeddings — TF-IDF + cosine similarity, 33 malicious example bank
- Layer 3: LLM Judge — Documented as future work (not implemented)
- CLI — `python3 agent_fixer.py` with `--scope`, `--action`, `--file`, `--json` flags
- 42 tests
- Makefile with standard targets
- ruff, mypy, black configuration
- Coverage configuration (minimum 80%)
- SECURITY.md and CHANGELOG.md
- CI/CD via GitHub Actions (Python 3.10, 3.11, 3.12)

### Detection Performance

| Attack Type | Layer | Estimated Effectiveness |
|-------------|-------|----------------------|
| Direct injection (curl, wget, os.system) | Layer 1 (regex) | ~95% |
| Leetspeak / homoglyphs | Layer 0 + 1 | ~90% |
| Cross-line injection | Layer 1 (pass 2) | ~85% |
| Semantic exfiltration | Layer 2 (embeddings) | ~75% |
| Sophisticated / zero-day | Layer 1+2 combined | ~60% |

**Global estimate: ~85-90% of common attacks contained.**

### Benchmarks

| Mode | Latency (mean) | P95 | Layers |
|------|----------------|-----|--------|
| fast (clean) | 0.04ms | 0.04ms | 0 + 1 |
| fast (attack) | 0.06ms | 0.07ms | 0 + 1 |
| medium (clean) | 0.04ms | — | 0 + 1 + 2 |
