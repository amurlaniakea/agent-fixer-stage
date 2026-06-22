# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
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

- **Layer 0 (Normalization):** Unicode NFKC + homoglyph detection covers common evasion techniques but not all.
- **Layer 1 (Pattern Matching):** 30+ patterns with weighted scoring. Novel injection techniques may evade detection.
- **Layer 2 (Embeddings):** TF-IDF + cosine similarity with 33 malicious examples. Limited by the example bank.
- **Layer 3 (LLM Judge):** Not yet implemented. Only documented as future work.
- **Estimated global detection: ~85-90% of common attacks.** Not 100%.

**Use Agent Fixer Stage as one layer in a defense-in-depth strategy. It is not a silver bullet.**

## Dependencies

No runtime dependencies (Python stdlib only).
Dev: `pytest`, `black`, `ruff`, `mypy`, `pytest-cov`
