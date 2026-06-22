# Changelog

All notable changes to Agent Fixer Stage will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
