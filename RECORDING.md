# Recording the Demo GIF

## Quick start (Mac)

```bash
# 1. Clone & install
git clone https://github.com/AetherCore-Dev/chaincanary
cd chaincanary
pip install -e .

# 2. Install VHS (GIF recorder)
brew install vhs

# 3. Verify the scan works (should print MALICIOUS)
python3 chaincanary-demo-scan.py

# 4. Record
vhs chaincanary-demo.tape
# → outputs: demo.gif
```

## What you'll see

```
🔍 chaincanary — Analyzing litellm==1.82.8 ...

  Downloading package...
  Running static analysis...
  ...

╭────────────┬──────────────────────────────┬───────────────────────╮
│ Severity   │ Rule                         │ Title                 │
├────────────┼──────────────────────────────┼───────────────────────┤
│ CRITICAL   │ PTH_FILE_INSTALL             │ .pth file installs    │
│ CRITICAL   │ PTH_NETWORK_BEACON           │ phone-home on startup │
│ CRITICAL   │ PTH_SUBPROCESS               │ subprocess on startup │
╰────────────┴──────────────────────────────┴───────────────────────╯

  ☠️   MALICIOUS   Risk Score: 10.0 / 10
  🚫 Installation BLOCKED.
```

## Files

| File | Purpose |
|------|---------|
| `chaincanary-demo-scan.py` | Scans mock wheel, prints full output |
| `chaincanary-demo.tape` | VHS script → records `demo.gif` |
| `tests/fixtures/litellm-1.82.8-py3-none-any.whl` | Mock wheel (safe, no real payload) |
| `tests/fixtures/make_mock_wheel.py` | Regenerates the mock wheel if needed |

## After recording

Replace the placeholder in README.md:

```
<!-- GIF_PLACEHOLDER: replace the line below with your terminal demo GIF -->
<!-- ![chaincanary demo](demo.gif) -->
```

→ change to:

```
![chaincanary demo](demo.gif)
```
