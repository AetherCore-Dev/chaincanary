# pipguard 🛡️

**A pip installation security sandbox that detects supply chain attacks before they compromise your system.**

[![PyPI version](https://badge.fury.io/py/pipguard.svg)](https://badge.fury.io/py/pipguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

---

## Why pipguard exists

On **2026-03-24**, the `litellm` package (9.5M downloads/month) was compromised in a supply chain attack. Versions `1.82.7` and `1.82.8` contained a malicious `.pth` file — `litellm_init.pth` — that **executed attacker code on every Python startup**, even after removal.

No existing tool caught this before install. Snyk needed a CVE. Dependabot needed a GitHub Advisory. By the time those existed, millions of developers had already been compromised.

**pipguard is different.** It catches the attack *before* it happens — by running the install in a sandbox and watching what it actually does.

---

## Demo

```
$ pipguard check litellm==1.82.7

🔍 pipguard — Analyzing litellm==1.82.7 ...

  → Downloading package (not installing)...
  → Downloaded: litellm-1.82.7-py3-none-any.whl
  → Running static analysis...
  → Running sandbox analysis (Docker)...

╭─────────────────────────────────────────────────────────╮
│           Findings for litellm==1.82.7                  │
├──────────┬──────────────────────┬───────────────────────┤
│ Severity │ Rule                 │ Title                 │
├──────────┼──────────────────────┼───────────────────────┤
│ CRITICAL │ PTH_FILE_INSTALL     │ .pth file installed — │
│          │                      │ executes on every     │
│          │                      │ Python startup        │
│ HIGH     │ OUTBOUND_NETWORK     │ Outbound network      │
│          │                      │ connection during     │
│          │                      │ install               │
│ HIGH     │ NETWORK_IN_SETUP     │ Network request in    │
│          │                      │ install hooks         │
╰──────────┴──────────────────────┴───────────────────────╯

╭─ litellm==1.82.7 ──────────────────────────────────────╮
│                                                         │
│  ☠️  MALICIOUS   Risk Score: 9.2 / 10                  │
│                                                         │
│  ● 1 CRITICAL finding(s)                               │
│  ● 2 HIGH finding(s)                                   │
│                                                         │
│  💡 Safe version available: litellm==1.82.6            │
│                                                         │
│  🚫 Installation BLOCKED. Use --force to override.     │
│                                                         │
╰─────────────────────────────────────────────────────────╯

Error: Installation of litellm==1.82.7 was BLOCKED.
Consider: pip install litellm==1.82.6
```

---

## Installation

```bash
pip install pipguard
```

For full sandbox analysis (recommended), install Docker:
```bash
# Docker required for dynamic analysis
# https://docs.docker.com/get-docker/
```

---

## Usage

### Check before installing

```bash
# Check a specific version
pipguard check litellm==1.82.7

# Check latest version
pipguard check requests

# JSON output (for CI)
pipguard check litellm==1.82.7 --json-output
```

### Safe install (analyze then install)

```bash
# Analyze and install if safe
pipguard install litellm==1.82.7

# Block on HIGH_RISK too (not just MALICIOUS)
pipguard install litellm==1.82.7 --block-on HIGH_RISK

# Force install even if malicious (not recommended)
pipguard install litellm==1.82.7 --force
```

### Options

```
--skip-dynamic    Skip Docker sandbox (static analysis only, faster)
--verbose / -v    Show detailed evidence for each finding
--json-output     Output results as JSON
--block-on        Block on HIGH_RISK or MALICIOUS (default: MALICIOUS)
--force           Install even if blocked
```

---

## How it works

pipguard uses a **two-layer detection approach**:

### Layer 1: Static Analysis (fast, ~2s)

Unpacks the wheel without executing any code and inspects:

| Check | What it catches |
|-------|-----------------|
| `.pth` file detection | LiteLLM-style persistence via Python startup hooks |
| `sitecustomize.py` | Alternative persistence mechanism |
| AST analysis of install hooks | `exec()`, `eval()`, obfuscated code |
| Pattern matching | Network imports, subprocess calls, sensitive path writes |
| Known malicious hash DB | Exact match against threat intelligence database |

### Layer 2: Dynamic Sandbox (thorough, ~15s)

Runs the actual install inside a Docker container with `--network=none` and `strace` monitoring:

| Check | What it catches |
|-------|-----------------|
| Network connection attempts | Phone-home, C2 beacons, data exfiltration |
| File writes outside package dir | Persistence mechanisms, config tampering |
| `.pth` file writes (confirmed) | Persistence confirmed by sandbox |
| Subprocess spawning | Unexpected child processes |
| Credential file access | `~/.aws/credentials`, `~/.ssh/id_rsa`, etc. |
| Env var + network correlation | Credential exfiltration pattern |

### Risk Scoring

```
Score   Verdict     Action
0-2     SAFE        Install
2-4     LOW_RISK    Warn, install
4-7     HIGH_RISK   Warn, require --force or reconsider
7-10    MALICIOUS   Block (require --force to override)
```

---

## Use in CI/CD

### GitHub Actions

```yaml
- name: Check pip dependencies
  uses: actions/setup-python@v4
  with:
    python-version: '3.11'

- name: Install pipguard
  run: pip install pipguard

- name: Audit new dependencies
  run: |
    pipguard check litellm==1.82.7 --json-output --skip-dynamic
  # Exit code 1 if MALICIOUS, 0 if safe
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pipguard
        name: pipguard — check requirements.txt
        entry: pipguard check
        language: system
        files: requirements.*\.txt$
```

---

## Detection Coverage

| Attack Type | Static | Dynamic | Example |
|-------------|--------|---------|---------|
| `.pth` persistence | ✅ | ✅ | LiteLLM 1.82.7 |
| `sitecustomize.py` persistence | ✅ | ✅ | - |
| C2 beacon on install | ✅ | ✅ | LiteLLM 1.82.7 |
| Credential exfiltration | ✅ | ✅ | Various |
| Obfuscated backdoor | ✅ | ✅ | Various |
| Known malicious hash | ✅ | - | DB-backed |
| Network-only attack | - | ✅ | - |
| Filesystem persistence | ✅ | ✅ | - |

---

## Roadmap

- [ ] **v0.2** — CI/CD workflow scanner (GitHub Actions security)
- [ ] **v0.3** — AI API Key leak detection in codebases
- [ ] **v0.4** — AI-generated code security audit (Copilot/Cursor patterns)
- [ ] **v1.0** — VS Code / Cursor plugin
- [ ] **Enterprise** — Private deployment, SBOM generation, compliance reports

---

## Contributing

```bash
git clone https://github.com/allenenli/pipguard
cd pipguard
pip install -e ".[dev]"
pytest tests/
```

PRs welcome. See [ARCHITECTURE.md](ARCHITECTURE.md) for internals.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built in response to the LiteLLM 1.82.7 supply chain attack (TeamPCP, 2026-03-24).*
*Because the best time to check a package is before it runs on your machine.*
