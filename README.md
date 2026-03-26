# chaincanary

**Stop supply-chain attacks before they execute. The only scanner with semantic `.pth` analysis.**

> Caught LiteLLM 1.82.8 as MALICIOUS at publish time — before any advisory existed. No cloud. No account. Nothing leaves your machine.

![chaincanary demo](demo.gif)

**Try it now — zero install:**

```bash
pipx run chaincanary check requests==2.28.0
```

Or scan the real LiteLLM attack (uses local mock wheel — no network):

```bash
git clone https://github.com/AetherCore-Dev/chaincanary && cd chaincanary
pip install -e .
chaincanary check litellm==1.82.8 --local tests/fixtures/litellm-1.82.8-py3-none-any.whl
```

---

**Why developers use chaincanary:**

- **Catches what others miss** — semantic `.pth` classifier detects attacks that run on every Python startup, not just at install time
- **Zero config** — `pip install chaincanary && chaincanary check <package>`, done
- **Nothing leaves your machine** — pure offline static analysis, no cloud, no account, no proxy
- **CI-ready** — GitHub Action blocks malicious packages on every push
- **Audit entire projects** — scan all dependencies in `requirements.txt` or `pyproject.toml` in one command
- **Version diffing** — see exactly what changed between releases
- **Works in China** — no proxy needed, unlike socket.dev / Safety

[![PyPI version](https://badge.fury.io/py/chaincanary.svg)](https://pypi.org/project/chaincanary/)
[![CI](https://github.com/AetherCore-Dev/chaincanary/actions/workflows/ci.yml/badge.svg)](https://github.com/AetherCore-Dev/chaincanary/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

---

## Install

```bash
pip install chaincanary
```

Or try without installing: `pipx run chaincanary check <package>`

---

## Usage

### Scan a single package

```bash
chaincanary check requests==2.28.0
chaincanary check litellm==1.82.8

# Scan a local .whl file (no network needed)
chaincanary check litellm==1.82.8 --local ./litellm-1.82.8-py3-none-any.whl
```

### Audit your entire project

```bash
chaincanary audit requirements.txt
chaincanary audit pyproject.toml --fail-on HIGH_RISK
```

### Compare two versions

```bash
chaincanary diff litellm 1.82.6 1.82.8
```

### Safe install (scan before installing)

```bash
chaincanary install requests==2.32.0
chaincanary install litellm==1.82.8   # blocked — MALICIOUS
```

### JSON output (for pipelines)

```bash
chaincanary check litellm==1.82.8 --json-output | jq '.verdict'
# "MALICIOUS"
```

### SARIF output (for GitHub Code Scanning)

```bash
# Single package → SARIF
chaincanary check litellm==1.82.8 --local ./litellm-1.82.8-py3-none-any.whl --sarif-output > results.sarif

# Audit lockfile → SARIF
chaincanary audit requirements.txt --sarif-output > chaincanary.sarif
```

Upload to GitHub Security tab in your CI workflow:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: chaincanary.sarif
```

### Offline mode (air-gapped / CI cache)

```bash
# Download wheels first (standard pip)
pip download -r requirements.txt -d ./wheels/

# Scan without any network calls
chaincanary audit requirements.txt --offline --wheel-dir ./wheels/

# Single package offline
chaincanary check mypackage==1.0.0 --offline --local ./mypackage-1.0.0-py3-none-any.whl
```

---

## GitHub Action — drop-in CI protection

```yaml
# .github/workflows/security.yml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AetherCore-Dev/chaincanary@v0.1.0
        with:
          requirements: requirements.txt
          fail-on: MALICIOUS   # or HIGH_RISK for stricter mode
          sarif-output: chaincanary.sarif  # optional: upload to GitHub Security tab
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: chaincanary.sarif
```

Fails your build if any dependency matches a known attack pattern. Zero config.

---

## Why chaincanary catches what others miss

A `.pth` file in Python's `site-packages` runs **on every Python startup** — not just at install time. Other scanners only check `setup.py` install hooks and miss this entirely.

chaincanary has a **semantic `.pth` classifier** with 4 categories:

| .pth content | Classification | Finding |
|---|---|---|
| Empty | Normal | silent |
| `/usr/local/lib/...` | Path-only | silent |
| setuptools distutils shim | Safe code | LOW |
| `subprocess.Popen(['curl', ...])` | **Dangerous** | CRITICAL |

> LiteLLM 1.82.8 was flagged MALICIOUS by chaincanary at publish time.
> Other tools missed it entirely, or flagged it only after manual rule updates.

---

## What chaincanary detects

| Attack vector | Location | Severity |
|---|---|---|
| `.pth` file with network/subprocess | `site-packages/*.pth` | CRITICAL |
| Network call during `pip install` | `setup.py` | HIGH |
| Shell command during `pip install` | `setup.py` | HIGH |
| `exec(base64.decode(...))` obfuscation | anywhere | HIGH |
| DNS exfiltration via `socket.getaddrinfo` | `__init__.py` | HIGH |
| Network call on every `import` | `__init__.py` | MEDIUM |
| SSH / AWS credential access | anywhere | HIGH |
| Path traversal in wheel zip | `.whl` structure | CRITICAL |
| Known malicious SHA256 hash | `.whl` file | CRITICAL |
| Typosquatting (Levenshtein distance) | package name | MEDIUM |

---

## Comparison

| | **chaincanary** | pip-audit | Trivy | socket.dev | Safety |
|---|---|---|---|---|---|
| `.pth` semantic analysis | **4-category classifier** | -- | -- | no static classifier | -- |
| Detects LiteLLM 1.82.8 at publish time | **offline, no rules needed** | -- | -- | only after manual rule update | -- |
| No account / cloud needed | yes | yes | yes | no (GitHub App) | no (account) |
| Nothing leaves your machine | yes | yes | yes | no (uploads metadata) | yes |
| Offline capable | yes | partial | yes | no | no |
| China mainland access (no proxy) | yes | yes | yes | no (403) | no (403) |
| Open source | yes | yes | yes | no (SaaS) | partial |

> chaincanary is not a CVE scanner — use it alongside `pip-audit` for vulnerability advisory coverage.

---

## The LiteLLM attack — what happened

<details>
<summary><strong>March 24, 2026: TeamPCP hijacked LiteLLM on PyPI</strong></summary>

Threat actor **TeamPCP** hijacked the LiteLLM maintainer's PyPI account and published two malicious versions:

| Version | Attack vector | Trigger |
|---------|--------------|---------|
| **1.82.7** | Payload injected into `litellm/proxy/proxy_server.py` | `import litellm.proxy` |
| **1.82.8** | Hidden `.pth` file (`litellm_init.pth`, 34 KB) | **Every Python startup — no import needed** |

The `.pth` attack in 1.82.8:

```python
# litellm_init.pth — executes on every Python startup, silently, forever
import os, subprocess, sys
subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('...'))"])
```

The payload collects SSH keys, env vars, AWS/GCP/K8s credentials, crypto wallets, CI secrets — encrypts with AES-256 + RSA-4096 and exfiltrates to `https://models.litellm.cloud/` (a fake domain registered the day before).

This runs **every time you start Python** — not just during `pip install`. LiteLLM was downloaded ~95 million times per month. chaincanary flagged **both versions MALICIOUS** at publish time — without any advisory, rule update, or cloud lookup.

</details>

---

## How it works

```
chaincanary check <package>
        |
        v
Download wheel (no install, no execute)
        |
        v
Static analysis:
  - Zip safety (path traversal, zip bomb)
  - .pth semantic classifier (4 categories)
  - AST analysis of setup.py / install hooks
  - Obfuscation detection (base64, eval, exec)
  - __init__.py delayed-trigger scan
  - DNS exfiltration patterns
  - SHA256 malicious hash database
  - Typosquatting distance check
        |
        v
Score 0-10 -> Verdict: SAFE / LOW_RISK / HIGH_RISK / MALICIOUS
        |
        v
Block or proceed
```

No sandboxing. No Docker. No kernel modules. Pure Python static analysis in seconds.

---

## Add chaincanary badge to your project

Show that your project is scanned for supply-chain attacks:

```markdown
[![chaincanary](https://img.shields.io/badge/scanned%20by-chaincanary-blue)](https://github.com/AetherCore-Dev/chaincanary)
```

[![chaincanary](https://img.shields.io/badge/scanned%20by-chaincanary-blue)](https://github.com/AetherCore-Dev/chaincanary)

---

## Known Limitations

chaincanary is a **static behavioral scanner**, not a magic bullet:

| Gap | Mitigation |
|-----|------------|
| No C extension analysis (`.so`/`.pyd`) | Sandbox mode in v0.3 |
| No CVE database | Use alongside `pip-audit` |
| No dynamic sandbox | Static signals only (for now) |
| Multi-stage payloads (download at runtime) | Runtime monitoring in v0.3 |

---

## Roadmap

| Version | Theme | Status |
|---------|-------|--------|
| **v0.1** | Core engine: `.pth` classifier, audit, diff, GitHub Action | shipped |
| **v0.2** | SARIF output, offline mode, hash feed, pre-commit hook | **in progress** |
| **v0.3** | Lightweight sandbox, package reputation, npm/cargo | later |

Full plan: [ROADMAP.md](ROADMAP.md)

---

## Contributing

```bash
git clone https://github.com/AetherCore-Dev/chaincanary
cd chaincanary
pip install -e ".[dev]"
pytest tests/
```

PRs welcome — especially:
- New malicious hash signatures
- Detection rules for new attack patterns
- False positive reports

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

*Built after the [LiteLLM supply chain attack](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign), March 2026.*
