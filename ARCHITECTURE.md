# chaincanary — Architecture

> A Python supply-chain attack scanner that detects malicious packages
> *before* installation. Pure offline static analysis — no Docker, no sandbox,
> no cloud.
>
> **Origin story:** Born from the LiteLLM 1.82.7/.8 supply chain attack
> (2026-03-24), where TeamPCP injected a malicious `.pth` file that executed
> on every Python startup.

---

## Design Principles

1. **Zero false negatives on known attacks** — Must catch LiteLLM 1.82.7 demo case
2. **Developer UX first** — Beautiful terminal output, one-command install
3. **Non-blocking by default** — Warn, don't break CI unless configured to block
4. **Layered detection** — Static first (fast), dynamic sandbox later (v0.3)
5. **Version diffing** — Compare against previous version behavior to highlight *changes*
6. **Nothing leaves your machine** — Pure offline static analysis, no cloud, no account

---

## Analysis Pipeline

`AnalysisEngine.analyze()` in `engine.py` orchestrates the detection pipeline:

```
chaincanary check <package>==<version>
        │
        ▼
┌────────────────────────────────────────┐
│  Step 0: Safety Checks (no download)   │
│  ──────────────────────────────────── │
│  • Typosquatting (Levenshtein)         │
│  • Dependency confusion                │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Step 1: Download .whl (or --local)    │
│  ──────────────────────────────────── │
│  • PyPI download with SHA256 verify    │
│  • Retry with exponential backoff      │
│  • 200 MB hard cap                     │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Step 2: Attestation (PEP 740)         │
│  ──────────────────────────────────── │
│  • Query PyPI Integrity API            │
│  • Sigstore publisher metadata         │
│  • INFO-only, no score impact          │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Step 3: Static Analysis  (~2s)        │
│  ──────────────────────────────────── │
│  • Zip safety (traversal, bomb)        │
│  • .pth semantic classifier            │
│  • AST deep scan (obfuscation)         │
│  • setup.py / install hook analysis    │
│  • DNS exfiltration patterns           │
│  • Known malicious hash DB lookup      │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Step 4: Version Diff                  │
│  ──────────────────────────────────── │
│  • Compare file lists vs prev version  │
│  • Flag new .pth files as CRITICAL     │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Step 5: Safe Version Lookup           │
│  ──────────────────────────────────── │
│  • If HIGH_RISK/MALICIOUS: scan up     │
│    to 3 prior versions for rollback    │
└────────┬───────────────────────────────┘
         ▼
┌────────────────────────────────────────┐
│  Risk Report                           │
│  ──────────────────────────────────── │
│  • Score 0-10                          │
│  • Verdict: SAFE / LOW_RISK /          │
│    HIGH_RISK / MALICIOUS               │
│  • Safe version recommendation         │
└────────────────────────────────────────┘
```

---

## Risk Score Calculation

```python
SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH":     2.5,
    "MEDIUM":   1.0,
    "LOW":      0.3,
    "INFO":     0.0,
}

# Score thresholds:
# 0.0 - 2.0  → SAFE
# 2.0 - 4.0  → LOW_RISK
# 4.0 - 7.0  → HIGH_RISK
# 7.0+       → MALICIOUS

# Severity floor overrides (prevents score gaming):
# 1× CRITICAL  → minimum HIGH_RISK
# 2+ CRITICAL  → minimum MALICIOUS
# 3+ HIGH      → minimum HIGH_RISK

# LOW findings capped at 8 contributors to prevent noise inflation
```

---

## .pth Semantic Classifier

The core differentiator. A `.pth` file in `site-packages` runs on **every
Python startup** — not just at install time. Other scanners miss this entirely.

| .pth content | Classification | Finding |
|---|---|---|
| Empty | Normal | silent |
| `/usr/local/lib/...` | Path-only | silent |
| setuptools distutils shim | Safe code | LOW |
| `subprocess.Popen(['curl', ...])` | **Dangerous** | CRITICAL |

---

## Project Structure

```
chaincanary/
├── chaincanary/
│   ├── __init__.py              # Version metadata
│   ├── engine.py                # Pipeline orchestrator
│   ├── models.py                # Finding, RiskReport, Severity, scoring
│   ├── analyzer/
│   │   ├── __init__.py          # Exports StaticAnalyzer, DynamicAnalyzer
│   │   ├── static.py            # Static analysis coordinator
│   │   ├── ast_deep.py          # AST obfuscation detection
│   │   ├── pth_analyzer.py      # .pth semantic classifier
│   │   ├── differ.py            # Version file-list diff
│   │   ├── dynamic.py           # Docker sandbox (optional, v0.3)
│   │   ├── rules.py             # Rule definitions (static + dynamic + attestation)
│   │   ├── _file_checks.py      # Structure checks, .pth detection
│   │   ├── _wheel_safety.py     # Zip bomb / path traversal
│   │   ├── _hash_check.py       # Malicious hash lookup
│   │   ├── _patterns.py         # Regex patterns (network, DNS, obfuscation)
│   │   ├── _deep_visitor.py     # AST visitor for code inspection
│   │   └── _sdist.py            # Source distribution fallback
│   ├── cli/
│   │   ├── __init__.py          # Re-exports + backward compat
│   │   ├── _main.py             # Click group definition
│   │   ├── _helpers.py          # Shared CLI utilities
│   │   ├── check_cmd.py         # `check` subcommand
│   │   ├── audit_cmd.py         # `audit` subcommand
│   │   ├── diff_cmd.py          # `diff` subcommand
│   │   ├── install_cmd.py       # `install` subcommand
│   │   └── update_cmd.py        # `update` subcommand
│   ├── db/
│   │   └── known_malicious.json # SHA256 hash database
│   ├── attestation.py           # PEP 740 attestation via PyPI Integrity API
│   ├── downloader.py            # PyPI wheel download + version resolution
│   ├── hashfeed.py              # Remote hash feed (cache: ~/.chaincanary)
│   ├── lockfile.py              # Parse requirements.txt / pyproject.toml / Pipfile.lock
│   ├── reporter.py              # Rich terminal output
│   ├── safety_checks.py         # Typosquatting, dependency confusion, git deps
│   ├── sarif.py                 # SARIF v2.1.0 output
│   └── pre_commit.py            # Git pre-commit hook entry point
├── tests/
│   ├── fixtures/                # Mock wheel builders + malicious packages
│   └── test_*.py                # 17 test modules, 375+ tests
├── .github/workflows/
│   ├── ci.yml                   # CI: Python 3.9-3.12 matrix
│   └── release.yml              # PyPI trusted publishing (OIDC)
├── pyproject.toml               # hatchling build, deps, tool config
└── LICENSE                      # Apache 2.0
```

---

## Tech Stack

| Component | Choice | Reason |
|-----------|--------|--------|
| CLI framework | `click` + `rich` | Beautiful output, industry standard |
| Package parsing | `zipfile` (stdlib) | No extra deps for wheel inspection |
| Hash DB | Local JSON + GitHub-hosted remote feed | Simple, updatable via `chaincanary update` |
| Build backend | `hatchling` | Modern, fast Python packaging |
| Attestation | PyPI Integrity API (PEP 740 / Sigstore) | Standard, no extra infra |
| Output formats | Rich terminal, JSON, SARIF v2.1.0 | Human + CI + GitHub Security tab |
