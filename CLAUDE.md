# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

chaincanary is a Python supply-chain attack scanner that detects malicious packages *before* installation. It performs pure offline static analysis on `.whl` files — no Docker, no sandbox, no cloud. Born from the LiteLLM 1.82.7/.8 attack (March 2026).

Current version: **0.2.0** (v0.2 shipped — SARIF, offline mode, AST deep scan, hash feed, dep confusion detection, PEP 740 attestation verification).

## Build & Development Commands

```bash
# Install in dev mode (editable + dev dependencies)
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v --tb=short

# Run a single test file / single test
pytest tests/test_static.py -v
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

`AnalysisEngine.analyze()` in `engine.py` orchestrates sequential steps:

1. **Typosquatting check** (`safety_checks.py`) — Levenshtein distance against top-200 PyPI packages, no download needed
2. **Download** (`downloader.py`) — fetches `.whl` from PyPI into a temp dir (or uses `--local`)
3. **Attestation check** (`attestation.py`) — queries PyPI Integrity API (PEP 740) for Sigstore attestations; INFO-only, no score impact
4. **Static analysis** (`analyzer/static.py`) — the core: zip safety, `.pth` semantic classifier, AST analysis, obfuscation detection, hash DB lookup, DNS exfiltration patterns
5. **Version diff** (`analyzer/differ.py`) — compares file lists between current and previous version; flags new `.pth` files as CRITICAL
6. **Dynamic analysis** (`analyzer/dynamic.py`) — Docker-based sandbox (optional, skipped by default in practice)
7. **Safe version lookup** — if HIGH_RISK/MALICIOUS, scans up to 3 prior versions to find a clean rollback candidate

### Key Design Decisions

- **Scoring with severity floors** (`models.py`): Raw score is sum of severity weights (CRITICAL=4, HIGH=2.5, MEDIUM=1, LOW=0.3), capped at 10. But severity floors prevent gaming: 1 CRITICAL → minimum HIGH_RISK, 2+ CRITICAL → MALICIOUS, 3+ HIGH → HIGH_RISK.
- **`.pth` semantic classifier** (`analyzer/static.py`): 4 categories — empty, path-only, safe-code (setuptools shim), dangerous (network/subprocess). This is the unique differentiator.
- **Immutable reports**: `RiskReport` dataclass accumulates findings; `calculate_score()` recomputes verdict from scratch each time.
- **No mutation of downloaded packages**: everything happens in `tempfile.TemporaryDirectory`, wheel is never installed.

### CLI Commands (Click-based, entry point: `cli.py`)

| Command | Purpose |
|---------|---------|
| `check` | Scan a package without installing |
| `install` | Scan then pip-install if safe |
| `audit` | Scan all deps in a lockfile (parallel via ThreadPoolExecutor) |
| `diff` | Compare two versions for file-level changes |

### File Roles

| File | Role |
|------|------|
| `engine.py` | Orchestrator — wires analyzers together |
| `analyzer/static.py` | Core static analysis + `.pth` classifier (~800 lines, largest file) |
| `analyzer/dynamic.py` | Docker sandbox analysis (optional) |
| `analyzer/rules.py` | Rule definitions for static patterns |
| `analyzer/pth_analyzer.py` | Deep `.pth` file classification |
| `analyzer/differ.py` | File-list diff between versions |
| `models.py` | `Finding`, `RiskReport`, `Severity`, scoring logic |
| `safety_checks.py` | Typosquatting detection, git dep flagging |
| `attestation.py` | PEP 740 attestation verification via PyPI Integrity API |
| `downloader.py` | PyPI wheel download, version resolution |
| `lockfile.py` | Parse requirements.txt / pyproject.toml |
| `reporter.py` | Rich terminal output formatting |
| `sarif.py` | SARIF v2.1.0 output generation |
| `db/known_malicious.json` | SHA256 hash database of known malware |

## Testing

- Test files: `tests/test_static.py`, `tests/test_integration.py`, `tests/test_pth_and_edge_cases.py`, `tests/test_review_fixes.py`, `tests/test_sarif.py`, `tests/test_sarif_edge_cases.py`, `tests/test_offline.py`, `tests/test_offline_edge_cases.py`, `tests/test_attestation.py`
- 375 tests total, all passing
- Fixtures in `tests/fixtures/` include a mock malicious LiteLLM wheel
- CI matrix: Python 3.9, 3.10, 3.11, 3.12
- Lint runs only on 3.11 in CI

## Conventions

- Python 3.9+ minimum — use `from __future__ import annotations` for modern type hints
- `ruff` for linting (line-length 100, rules E/F/I/UP, E501 ignored)
- `hatchling` build backend
- Rich console for all terminal output (stderr for progress, stdout for results)
- JSON output mode (`--json-output`) on every command for CI/pipeline use
- Workers capped at 16 for PyPI rate-limit protection

## Roadmap Context (v0.2 planned)

Key planned features: remote hash feed, ~~SARIF output~~, ~~`--offline` mode~~, `--timeout` flag, `--skip` patterns, pre-commit hook, Rich progress bar for audit, dependency confusion detection, `__init__.py` AST deep scan. See `ROADMAP.md` for full details.

### Implemented in v0.2 (dev)
- **SARIF output** (`--sarif-output`): Generates SARIF v2.1.0 JSON for GitHub Code Scanning. Uses Package URL (purl) for artifact URIs, SHA-256 fingerprints for dedup. Module: `sarif.py`.
- **Offline mode** (`--offline`): Disables all network calls. `check --offline` requires `--local`. `audit --offline` requires `--wheel-dir`. Engine skips version diff and safe version lookup.
