# Roadmap

This document tracks what's done, what's in progress, and where chaincanary is going.

---

## ✅ v0.1.0 — shipped (2026-03-25)

Core detection engine built in response to the LiteLLM 1.82.7 supply chain attack.

- Static wheel analysis (no Docker, no sandbox)
- `.pth` semantic classifier (the LiteLLM attack vector)
- Version diff — detect what changed between two releases
- Lockfile audit — scan all dependencies in parallel
- GitHub Action — drop-in CI integration
- CLI: `check`, `audit`, `diff`, `install`
- JSON output for pipeline integration

---

## 🔧 Unreleased — post-0.1.0 hardening (in dev)

Fixes identified during multi-angle security review:

- [x] **Scoring bug** — `1×CRITICAL` was `LOW_RISK`. Fixed with severity floor rules.
- [x] **DNS exfiltration** — `socket.getaddrinfo()` / `gethostbyname()` as DNS tunnel
- [x] **`sys.modules` bypass** — indirect module access to evade import detection
- [x] **Typosquatting** — Levenshtein distance check against 100+ popular packages
- [x] **Git dependency flagging** — `git+https://` in requirements bypasses PyPI review
- [x] **`safe_version` validation** — scan rollback candidates before recommending them
- [x] **workers rate-limit cap** — `--workers` capped at 16 to avoid PyPI 429s
- [x] **README accuracy** — removed dangerous `alias pip` suggestion, improved comparison table

---

## ✅ v0.2.0 — shipped (2026-03-27)

**Theme: better signal, fewer false positives, real-world usability**

### Detection improvements
- [x] **Hash feed** — remote JSON feed with auto-update (`hashfeed.py`)
- [x] **Dependency confusion detection** — flag internal package name collisions
- [x] **`__init__.py` AST deep scan** — catches `getattr(obj, "g"+"et")` style obfuscation (`ast_deep.py`)

### Usability
- [x] **`--timeout` flag** — per-package download timeout (default 30s)
- [x] **`--offline` mode** — scan local `.whl` files with zero network calls
- [x] **`chaincanary update`** — refresh hash database from remote feed
- [x] **`--skip` patterns** — ignore known-safe packages
- [x] **Rich progress bar** — per-package status during `audit`

### CI/CD
- [x] **SARIF output** — `--sarif-output` for GitHub Security tab integration

### Still planned (backlog)
- [x] **PEP 740 attestation verification** — query PyPI Integrity API for Sigstore attestations (`attestation.py`)
- [x] **Pre-commit hook** — `chaincanary-pre-commit` entry point + `.pre-commit-hooks.yaml`
- [ ] **Docker image** — `ghcr.io/allenenli/chaincanary:latest`

---

## 🔭 v0.3.0 — longer term

**Theme: from scanner to platform**

### Dynamic analysis
- [ ] **Lightweight sandbox** — run `python -c "import pkg"` in a restricted environment
  (seccomp, no network) and capture syscalls. No Docker required.
- [ ] **Install-time behavior** — run `pip install --dry-run` equivalent and capture
  what `setup.py`/`pyproject.toml` hooks would execute
- [ ] **Import-time behavior** — detect actual network connections, file writes,
  process spawns that happen on `import`

### Intelligence
- [ ] **Package reputation score** — age, download count, maintainer history,
  recent maintainer changes (common pre-attack signal)
- [ ] **Typosquatting graph** — automated detection of new packages that appear
  1-2 edits from any top-1000 package
- [ ] **Diff history** — track behavioral changes across all versions of a package,
  not just two explicit versions

### Ecosystem
- [ ] **npm/cargo/go modules support** — extend beyond Python
- [ ] **VS Code extension** — highlight risky imports inline
- [ ] **Slack/webhook alerts** — notify when a package you use gets flagged

---

## 🚫 Known Limitations (honest)

These are things chaincanary **cannot** currently detect well.
Be aware of them when interpreting results.

### False negatives (things we miss)

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **C extensions (`.so`/`.pyd`)** | Malicious native code is invisible to static analysis | Lightweight sandbox in v0.3 |
| **Advanced obfuscation** | AST deep scan covers many patterns but not all (e.g., nested lambda chains) | Ongoing improvement |
| **No CVE database** | Won't catch vulnerabilities in known-safe packages | Use alongside `pip-audit` |
| **No dynamic sandbox** | `import pkg` side effects not executed | Lightweight sandbox in v0.3 |
| **Git deps not fully analyzed** | Flagged as HIGH_RISK but not deep-scanned | Planned |
| **Private PyPI mirrors** | Can't download from non-public registries | Use `--offline --wheel-dir` |
| **Multi-stage payloads** | Pkg downloads payload at runtime, nothing suspicious at install | Runtime monitoring (v0.3+) |

### False positives (things we over-flag)

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **Legitimate network in `__init__`** | Analytics/telemetry packages flagged MEDIUM | Use `--skip` flag |
| **`sys.modules` in testing code** | Test utilities sometimes use indirect imports | Scope detection to non-test files |
| **socket in server libraries** | HTTP servers legitimately use socket | DNS_EXFIL only fires in `__init__` |
| **Typosquatting on short names** | Short package names have high similarity by chance | Tuned thresholds (≤2 edit dist + ≥0.75 similarity) |

### Architecture constraints

| Constraint | Why | Future fix |
|------------|-----|------------|
| **Hash DB is static** | Bundled DB stale after release | Use `chaincanary update` to refresh from remote feed |
| **No code signing** | DB updates not authenticated | Sigstore-signed feed (v0.2) |
| **Single-pass analysis** | No cross-file call graph | AST call graph (v0.3) |
| **No Windows installer hooks** | `.exe` post-install scripts not analyzed | Planned |

---

## Star growth strategy 🌟

The short-term goal is developer awareness. Here's the plan:

1. **Launch anchor** — LiteLLM 1.82.7 is a real, recent, high-profile attack.
   `chaincanary check litellm 1.82.7` demonstrating `MALICIOUS` in 2 seconds is
   the killer demo. Make every article/post lead with this.

2. **Show HN post** — "Show HN: chaincanary — I built a Python supply chain scanner
   after LiteLLM 1.82.7". Lead with the demo GIF. Target: 50+ upvotes.

3. **GitHub Action** — The easiest star trigger is a CI badge. If developers can add
   `uses: allenenli/chaincanary@v0.1.0` in 30 seconds, they'll star when it catches something.

4. **Twitter/X thread** — Walk through the LiteLLM attack anatomy + how chaincanary catches it.
   Tag the security community (e.g., @SwisskyRepo, @LiveOverflow).

5. **Dev.to / hashnode post** — Long-form "How .pth files became a supply chain weapon"
   with chaincanary as the solution. Good for SEO.

6. **PyPI page** — Make `pip install chaincanary` the first thing people try.
   First run should feel magical (instant demo output).
