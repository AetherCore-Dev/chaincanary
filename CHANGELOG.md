# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

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

### Detection coverage (v0.1.0)

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

### Not yet implemented (coming soon)

- Docker sandbox for dynamic analysis
- `--watch` mode for continuous monitoring
- SBOM integration (CycloneDX, SPDX)
- Slack / webhook alerts
