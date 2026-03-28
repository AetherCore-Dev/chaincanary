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

### CLI Commands (Click-based, entry point: `cli/_main.py`)

| Command | Purpose |
|---------|---------|
| `check` | Scan a package without installing |
| `install` | Scan then pip-install if safe |
| `audit` | Scan all deps in a lockfile (parallel via ThreadPoolExecutor) |
| `diff` | Compare two versions for file-level changes |
| `update` | Refresh hash database from remote feed |

### File Roles

| File | Role |
|------|------|
| `engine.py` | Orchestrator — wires analyzers together |
| `analyzer/static.py` | Core static analysis + `.pth` classifier |
| `analyzer/ast_deep.py` | AST obfuscation detection |
| `analyzer/pth_analyzer.py` | Deep `.pth` file classification |
| `analyzer/differ.py` | File-list diff between versions |
| `analyzer/dynamic.py` | Docker sandbox analysis (optional) |
| `analyzer/rules.py` | Rule definitions (static, dynamic, attestation) |
| `analyzer/_file_checks.py` | Structure checks, .pth detection |
| `analyzer/_wheel_safety.py` | Zip bomb / path traversal protection |
| `analyzer/_hash_check.py` | Known malicious hash lookup |
| `analyzer/_patterns.py` | Regex patterns (network, DNS exfil, obfuscation) |
| `analyzer/_deep_visitor.py` | AST visitor for code inspection |
| `models.py` | `Finding`, `RiskReport`, `Severity`, scoring logic |
| `safety_checks.py` | Typosquatting, dependency confusion, git dep flagging |
| `attestation.py` | PEP 740 attestation verification via PyPI Integrity API |
| `downloader.py` | PyPI wheel download, version resolution |
| `hashfeed.py` | Remote hash feed management (cache: `~/.chaincanary`) |
| `lockfile.py` | Parse requirements.txt / pyproject.toml / Pipfile.lock |
| `reporter.py` | Rich terminal output formatting |
| `sarif.py` | SARIF v2.1.0 output generation |
| `pre_commit.py` | Git pre-commit hook entry point |
| `db/known_malicious.json` | SHA256 hash database of known malware |

## Testing

- Test files: `tests/test_static.py`, `tests/test_integration.py`, `tests/test_pth_and_edge_cases.py`, `tests/test_review_fixes.py`, `tests/test_sarif.py`, `tests/test_sarif_edge_cases.py`, `tests/test_offline.py`, `tests/test_offline_edge_cases.py`, `tests/test_attestation.py`, `tests/test_ast_deep.py`, `tests/test_dep_confusion.py`, `tests/test_hash_db.py`, `tests/test_hashfeed.py`, `tests/test_pre_commit.py`, `tests/test_skip.py`, `tests/test_timeout.py`
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

## Roadmap Context

v0.2 shipped. See `ROADMAP.md` for v0.3 plans (lightweight sandbox, package reputation, npm/cargo/go support).
