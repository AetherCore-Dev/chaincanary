# chaincanary — Architecture

> A pip package installation security sandbox that detects supply chain attacks
> before they compromise your system.
>
> **Origin story:** Born from the LiteLLM 1.82.7 supply chain attack (2026-03-24),
> where TeamPCP injected a malicious `.pth` file that executed on every Python startup.

---

## One-liner

```
chaincanary is a pip installation sandbox that helps AI developers avoid
supply chain attacks like LiteLLM 1.82.7.
```

---

## Design Principles

1. **Zero false negatives on known attacks** — Must catch LiteLLM 1.82.7 demo case
2. **Developer UX first** — Beautiful terminal output, one-command install
3. **Non-blocking by default** — Warn, don't break CI unless configured to block
4. **Layered detection** — Static first (fast), dynamic sandbox second (accurate)
5. **Version diffing** — Compare against previous version behavior to highlight *changes*

---

## Architecture Overview

```
chaincanary install <package>==<version>
        │
        ▼
┌───────────────────┐
│  1. Static Analysis│  (fast, ~2s)
│  ─────────────────│
│  • Unpack wheel   │
│  • Scan for .pth  │
│  • AST analysis   │
│  • setup.py hooks │
│  • Known malware  │
│    hash DB        │
└────────┬──────────┘
         │ risk_score > 3 or suspicious?
         ▼
┌───────────────────┐
│  2. Dynamic       │  (thorough, ~15s)
│     Sandbox       │
│  ─────────────────│
│  • Docker/        │
│    bubblewrap     │
│  • strace monitor │
│  • Network calls  │
│  • File writes    │
│  • Subprocess     │
│  • Env var reads  │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  3. Version Diff  │
│  ─────────────────│
│  • Compare vs     │
│    prev version   │
│  • Highlight new  │
│    behaviors      │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  4. Risk Report   │
│  ─────────────────│
│  • Score 0-10     │
│  • Findings list  │
│  • Safe version   │
│    recommendation │
│  • Block / Warn / │
│    Allow          │
└───────────────────┘
```

---

## Detection Rules

### Static Rules (always run)
| Rule | Severity | Description |
|------|----------|-------------|
| `pth_file_write` | CRITICAL | Package installs a `.pth` file → executes on every Python startup |
| `setup_exec` | HIGH | `setup.py` calls `exec()`, `eval()`, or `os.system()` |
| `obfuscated_code` | HIGH | base64 decode + exec pattern |
| `network_in_setup` | HIGH | Network requests during `setup.py` |
| `subprocess_in_setup` | MEDIUM | Subprocess calls during install hooks |
| `sensitive_path_write` | HIGH | Writes to `~/.ssh`, `~/.aws`, `/etc` |
| `known_malicious_hash` | CRITICAL | SHA256 matches known malware database |

### Dynamic Rules (run in sandbox)
| Rule | Severity | Description |
|------|----------|-------------|
| `outbound_network` | HIGH | Any network connection during install |
| `file_write_homedir` | HIGH | Writes files outside package directory |
| `env_var_exfil` | CRITICAL | Reads env vars then makes network call |
| `persistent_hook` | CRITICAL | Installs `.pth`, `.pth`-like, or sitecustomize |
| `subprocess_spawn` | MEDIUM | Spawns child processes |
| `credential_read` | CRITICAL | Reads `~/.netrc`, `~/.aws/credentials`, etc. |

---

## MVP Scope (Day 1-3)

### Day 1: Core Engine
- [ ] `chaincanary/analyzer/static.py` — static analysis
- [ ] `chaincanary/analyzer/dynamic.py` — Docker sandbox
- [ ] `chaincanary/analyzer/rules.py` — detection rules
- [ ] `chaincanary/models.py` — RiskReport, Finding, Severity

### Day 2: CLI + UX
- [ ] `chaincanary/cli.py` — Click-based CLI
- [ ] `chaincanary/reporter.py` — Rich terminal output
- [ ] `chaincanary/diff.py` — version behavior comparison
- [ ] Demo: `chaincanary install litellm==1.82.7` → catches attack

### Day 3: Polish + Publish
- [ ] `chaincanary/integrations/github_actions.py` — GHA integration
- [ ] `README.md` — full docs with demo GIF
- [ ] `pyproject.toml` — publish to PyPI
- [ ] GitHub Actions CI for chaincanary itself

---

## Tech Stack

| Component | Choice | Reason |
|-----------|--------|--------|
| CLI framework | `click` + `rich` | Beautiful output, industry standard |
| Sandbox (MVP) | Docker SDK | Cross-platform, fastest to ship |
| Sandbox (v2) | `bubblewrap` | Linux-native, lighter, CI-friendly |
| System monitoring | `strace` → `eBPF` | strace for MVP, eBPF for production |
| Package parsing | `pip`, `pkginfo`, `zipfile` | Standard library |
| Hash DB | Local JSON + GitHub-hosted | Simple, updatable |

---

## Project Structure

```
chaincanary/
├── chaincanary/
│   ├── __init__.py
│   ├── cli.py              # Entry point
│   ├── models.py           # RiskReport, Finding, Severity
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── static.py       # Static analysis (AST, file inspection)
│   │   ├── dynamic.py      # Dynamic sandbox (Docker/strace)
│   │   ├── rules.py        # Detection rule definitions
│   │   └── differ.py       # Version behavior diff
│   ├── reporter.py         # Rich terminal output
│   ├── downloader.py       # Fetch wheel from PyPI without installing
│   ├── integrations/
│   │   ├── github_actions.py
│   │   └── pre_commit.py
│   └── db/
│       └── known_malicious.json  # Known malware hashes
├── tests/
│   ├── test_static.py
│   ├── test_dynamic.py
│   └── fixtures/           # Test packages (including mock malicious)
├── .github/
│   └── workflows/
│       └── ci.yml
├── README.md
├── ARCHITECTURE.md
├── pyproject.toml
└── LICENSE                 # MIT
```

---

## Risk Score Calculation

```python
SEVERITY_WEIGHTS = {
    "CRITICAL": 4.0,
    "HIGH":     2.5,
    "MEDIUM":   1.0,
    "LOW":      0.3,
}

def calculate_score(findings: list[Finding]) -> float:
    raw = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return min(10.0, raw)

# Score interpretation:
# 0.0 - 2.0  → SAFE (green)
# 2.1 - 4.0  → LOW RISK (yellow)
# 4.1 - 7.0  → HIGH RISK (orange)  → Warn + ask
# 7.1 - 10.0 → MALICIOUS (red)     → Block by default
```

---

## Future Roadmap (post-MVP)

- **v0.2:** CI/CD workflow scanner (GitHub Actions, GitLab CI)
- **v0.3:** AI API Key leak detection
- **v0.4:** AI-generated code security audit (Copilot/Cursor patterns)
- **v1.0:** VS Code / Cursor plugin
- **Enterprise:** Private deployment, SBOM generation, compliance reports
