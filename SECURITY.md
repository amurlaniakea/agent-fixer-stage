# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.0   | Yes       |
| 0.1.0   | Yes       |

## Reporting a Security Vulnerability

If you discover a security vulnerability in Agent Fixer Stage, please report it responsibly.

**Do NOT open a public GitHub Issue for security vulnerabilities.**

Instead, report via email:
- **Email:** amurlaniakea@gmail.com
- **Subject:** `[SECURITY] Agent Fixer Stage vulnerability`

You will receive a response within 48 hours.

## Security Considerations

Agent Fixer Stage is a defense tool, but has limitations:

### Layers (v0.2.0)
- **Layer 0 (Normalization):** Unicode NFKC + homoglyph detection + leetspeak map. Covers common evasion techniques.
- **Layer 1 (Pattern Matching):** 80 patterns (EN, ES, FR, DE, IT, PT) with weighted scoring. 3 passes (normal, leetspeak variants, cross-line).
- **Layer 2 (Embeddings):** TF-IDF + cosine similarity with 33 malicious examples. Semantic detection.
- **Layer 2.5 (Scope Drift):** TF-IDF cosine similarity between scope and output. Detects off-topic outputs.
- **Layer 3 (LLM Judge):** Optional LLM-based consistency check (Ollama or remote API).
- **MCP Integration:** DefensePipeline for tool audit + output audit combination.

### Estimated Detection
- **Global: ~90-95% of common attacks** (multi-language, multi-layer).
- **Not 100%** — sophisticated attackers with knowledge of patterns can design evasions.

### Known Limitations
- TF-IDF embeddings are less precise than transformer-based models for semantic similarity.
- LLM Judge requires Ollama running locally or API key for remote.
- Scope Drift Detection may produce false positives on short/vague scopes.
- Pattern matching only covers known attack signatures in 5 languages.

**Use Agent Fixer Stage as one layer in a defense-in-depth strategy. It is not a silver bullet.**

## Dependencies

No runtime dependencies (Python stdlib only).
Dev: `pytest`, `black`, `ruff`, `mypy`, `pytest-cov`
Optional: `requests` (for LLM judge remote mode)
