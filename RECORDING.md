# Recording the Demo GIF

## Quick start (Mac)

```bash
# 1. Clone & install
git clone https://github.com/AetherCore-Dev/chaincanary
cd chaincanary
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. Install VHS (GIF recorder)
brew install vhs

# 3. Verify the scan works (should print MALICIOUS)
chaincanary check litellm==1.82.8 --local tests/fixtures/litellm-1.82.8-py3-none-any.whl

# 4. Record
vhs chaincanary-demo.tape
# → outputs: demo.gif
```

## What you'll see

```
🔍 chaincanary — Analyzing litellm==1.82.8 ...

╭────────────┬──────────────────────────────┬──────────────────────────────────────────────────────────────────────┬──────────╮
│ Severity   │ Rule                         │ Title                                                                │ Source   │
├────────────┼──────────────────────────────┼──────────────────────────────────────────────────────────────────────┼──────────┤
│ CRITICAL   │ PTH_FILE_INSTALL             │ .pth file installs dangerous code that runs on every Python startup  │ static   │
│ CRITICAL   │ PTH_NETWORK_BEACON           │ .pth file makes network call on every Python startup (phone-home)    │ static   │
│ CRITICAL   │ PTH_SUBPROCESS               │ .pth file spawns subprocess on every Python startup                  │ static   │
╰────────────┴──────────────────────────────┴──────────────────────────────────────────────────────────────────────┴──────────╯

  ☠️   MALICIOUS   Risk Score: 10.0 / 10
  🚫 Installation BLOCKED.
```

## Files

| File | Purpose |
|------|---------|
| `chaincanary-demo.tape` | VHS script → records `demo.gif` |
| `chaincanary-demo-scan.py` | Standalone demo (scans mock wheel without CLI install) |
| `tests/fixtures/litellm-1.82.8-py3-none-any.whl` | Mock wheel (safe, no real payload) |
| `tests/fixtures/make_mock_wheel.py` | Regenerates the mock wheel if needed |

## Customizing the recording

Edit `chaincanary-demo.tape` to change:
- **Terminal size**: `Set Width` / `Set Height`
- **Font size**: `Set FontSize`
- **Theme**: `Set Theme` (Dracula, Catppuccin Mocha, etc.)
- **Typing speed**: `Set TypingSpeed`

The tape uses `--local` flag to scan the bundled mock wheel offline — no PyPI download needed.
