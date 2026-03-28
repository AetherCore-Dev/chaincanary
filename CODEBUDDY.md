# CODEBUDDY.md

This file provides guidance to CodeBuddy Code when working with code in this repository.

## Project Overview

chaincanary is a Python supply-chain attack scanner that detects malicious packages *before* installation. It performs pure offline static analysis on `.whl` files — no Docker, no sandbox, no cloud. Born from the LiteLLM 1.82.7/.8 attack (March 2026).

Current version: **0.2.0**

## Build & Development Commands

```bash
# Install in dev mode (editable + dev dependencies)
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v --tb=short

# Run a single test file
pytest tests/test_static.py -v

# Run a single test
pytest tests/test_review_fixes.py::test_typosquatting_detection -v

# Lint (matches CI — only E, F, I rules)
ruff check chaincanary/ --select E,F,I

# Type check
mypy chaincanary/

# Build wheel
pip install build && python -m build

# Self-scan (dogfooding — used in CI)
pip freeze | grep -E "^(click|requests|rich|packaging)==" > /tmp/runtime_deps.txt
chaincanary audit /tmp/runtime_deps.txt --fail-on MALICIOUS
```

## Architecture

### Analysis Pipeline

`AnalysisEngine.analyze()` in `engine.py` orchestrates the detection pipeline sequentially:

1. **Typosquatting check** (`safety_checks.py`) — Levenshtein distance against top-200 PyPI packages, no download needed
2. **Dependency confusion check** (`safety_checks.py`) — detects internal name collisions
3. **Download** (`downloader.py`) — fetches `.whl` from PyPI into a temp dir (or uses `--local`). Retry strategy: 3 attempts with exponential backoff. SHA256 verified. Max 200 MB. Default timeout 30s.
4. **Attestation check** (`attestation.py`) — queries PyPI Integrity API (PEP 740) for Sigstore attestations; INFO-only, no score impact
5. **Static analysis** (`analyzer/static.py`) — the core: zip safety, `.pth` semantic classifier, AST analysis, obfuscation detection, hash DB lookup, DNS exfiltration patterns
6. **Version diff** (`analyzer/differ.py`) — compares file lists between current and previous version; flags new `.pth` files as CRITICAL
7. **Safe version lookup** — if HIGH_RISK/MALICIOUS, scans up to 3 prior versions to find a clean rollback candidate

### Scoring System (`models.py`)

Raw score is sum of severity weights (CRITICAL=4, HIGH=2.5, MEDIUM=1, LOW=0.3, INFO=0), capped at 10. Severity floors prevent gaming: 1 CRITICAL → minimum HIGH_RISK, 2+ CRITICAL → MALICIOUS, 3+ HIGH → HIGH_RISK.

Score thresholds: 0-2.0 SAFE, 2.0-4.0 LOW_RISK, 4.0-7.0 HIGH_RISK, 7.0+ MALICIOUS.

`RiskReport` dataclass accumulates findings; `calculate_score()` recomputes verdict from scratch each time — reports are immutable once scored.

### Key Design Decisions

- **`.pth` semantic classifier** (`analyzer/static.py`): 4 categories — empty, path-only, safe-code (setuptools shim), dangerous (network/subprocess). This is the core differentiator from other scanners.
- **No mutation of downloaded packages**: everything happens in `tempfile.TemporaryDirectory`, wheel is never installed.
- Rich console for all terminal output (stderr for progress, stdout for results).
- JSON output mode (`--json-output`) on every command for CI/pipeline use.

### CLI Commands

Click-based CLI. Entry point: `chaincanary.cli:main` (defined in `cli/_main.py`, subcommands in `cli/` submodules).

| Command | Module | Purpose |
|---------|--------|---------|
| `check` | `cli/check_cmd.py` | Scan a single package without installing |
| `install` | `cli/install_cmd.py` | Scan then pip-install if safe |
| `audit` | `cli/audit_cmd.py` | Scan all deps in a lockfile (parallel via ThreadPoolExecutor) |
| `diff` | `cli/diff_cmd.py` | Compare two versions for file-level changes |
| `update` | `cli/update_cmd.py` | Refresh hash database from remote feed |

Second entry point: `chaincanary-pre-commit` → `chaincanary.pre_commit:main` for git pre-commit hook integration.

## Project Structure

```
chaincanary/
├── chaincanary/
│   ├── __init__.py              # Version, author metadata
│   ├── engine.py                # Orchestrator — wires analyzers together
│   ├── models.py                # Finding, RiskReport, Severity, scoring logic
│   ├── analyzer/
│   │   ├── __init__.py          # Exports StaticAnalyzer, DynamicAnalyzer
│   │   ├── static.py            # Static analysis coordinator
│   │   ├── dynamic.py           # Docker sandbox analysis (optional)
│   │   ├── ast_deep.py          # AST obfuscation detection (string concat, chr(), encoded exec)
│   │   ├── differ.py            # File-list diff between versions
│   │   ├── pth_analyzer.py      # Deep .pth file semantic classification
│   │   ├── rules.py             # Rule definitions (STATIC_RULES, DYNAMIC_RULES)
│   │   ├── _file_checks.py      # Structure checks, .pth detection, Python file AST scanning
│   │   ├── _wheel_safety.py     # Zip bomb detection, path traversal protection
│   │   ├── _hash_check.py       # Known malicious hash lookup from local db
│   │   ├── _patterns.py         # Regex patterns for network calls, DNS exfil, obfuscation
│   │   ├── _deep_visitor.py     # AST visitor for deep code inspection
│   │   └── _sdist.py            # Source distribution analysis fallback
│   ├── cli/
│   │   ├── __init__.py          # Re-exports commands + helpers + backward compat
│   │   ├── _main.py             # Click group definition
│   │   ├── _helpers.py          # Shared CLI utilities
│   │   ├── check_cmd.py         # `check` subcommand
│   │   ├── audit_cmd.py         # `audit` subcommand
│   │   ├── diff_cmd.py          # `diff` subcommand
│   │   ├── install_cmd.py       # `install` subcommand
│   │   └── update_cmd.py        # `update` subcommand
│   ├── db/
│   │   └── known_malicious.json # SHA256 hash database of known malware
│   ├── attestation.py           # PEP 740 attestation verification via PyPI Integrity API
│   ├── downloader.py            # PyPI wheel download, version resolution
│   ├── hashfeed.py              # Remote hash feed management (cache TTL: 24h, dir: ~/.chaincanary)
│   ├── lockfile.py              # Parse requirements.txt / pyproject.toml / Pipfile.lock
│   ├── reporter.py              # Rich terminal output formatting
│   ├── safety_checks.py         # Typosquatting detection, dependency confusion, git dep flagging
│   ├── sarif.py                 # SARIF v2.1.0 output generation for GitHub Code Scanning
│   └── pre_commit.py            # Git pre-commit hook entry point
├── tests/
│   ├── fixtures/
│   │   ├── make_mock_wheel.py   # Utility to create test wheels
│   │   └── mock_packages.py     # Mock package definitions
│   ├── test_static.py           # Static analysis basics
│   ├── test_ast_deep.py         # AST obfuscation detection
│   ├── test_pth_and_edge_cases.py # .pth file semantic analysis
│   ├── test_integration.py      # End-to-end integration tests
│   ├── test_review_fixes.py     # Multi-angle security review fixes
│   ├── test_dep_confusion.py    # Dependency confusion detection
│   ├── test_hash_db.py          # Known malicious hash database
│   ├── test_hashfeed.py         # Remote hash feed caching/updates
│   ├── test_sarif.py            # SARIF output generation
│   ├── test_sarif_edge_cases.py # SARIF edge cases
│   ├── test_offline.py          # Offline mode with local wheels
│   ├── test_offline_edge_cases.py # Offline edge cases
│   ├── test_attestation.py      # PyPI attestation verification
│   ├── test_pre_commit.py       # Pre-commit hook integration
│   ├── test_skip.py             # Package skip patterns
│   └── test_timeout.py          # Download timeout handling
└── .github/workflows/
    ├── ci.yml                   # CI: Python 3.9-3.12 matrix, lint on 3.11
    └── release.yml              # PyPI publish via trusted publishing (OIDC)
```

## Conventions

- Python 3.9+ minimum — use `from __future__ import annotations` for modern type hints
- `ruff` for linting (line-length 100, rules E/F/I/UP, E501 ignored)
- `hatchling` build backend
- Workers capped at 16 for PyPI rate-limit protection
- Internal analyzer helpers are `_`-prefixed modules (e.g., `_patterns.py`, `_file_checks.py`)
- CLI subcommands each live in their own module under `cli/`

## Testing

- 17 test modules, CI matrix: Python 3.9, 3.10, 3.11, 3.12
- Lint runs only on Python 3.11 in CI
- Test fixtures in `tests/fixtures/` include mock wheel builders and mock malicious packages
- No separate `conftest.py` — pytest config is in `pyproject.toml`: `testpaths=["tests"]`, `addopts="-v"`
