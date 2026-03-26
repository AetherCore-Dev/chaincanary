# chaincanary-demo.tape
# VHS recording script — generates demo.gif
#
# Prerequisites (Mac):
#   brew install vhs
#   brew install ttyd  # VHS dependency on Mac
#   cd chaincanary/
#   pip install -e .   # or: pip install chaincanary
#
# Run:
#   vhs chaincanary-demo.tape
#   # outputs: demo.gif  (drop into README to replace the placeholder)

Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1100
Set Height 650
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Padding 20
Set WindowBar Colorful
Set WindowBarSize 40
Set LoopOffset 70%
Set CursorBlink false

# ── Setup: activate venv + clean prompt ──
Hide
Type "cd /Users/allenenli/Documents/chaincanary && source .venv/bin/activate && export PS1='$ '"
Enter
Sleep 2000ms
Type "clear"
Enter
Sleep 500ms
Show

# ── Scene 1: Context — what happened ──

Type "# LiteLLM 1.82.8 was a supply-chain attack (March 2026)"
Sleep 500ms
Enter
Type "# A hidden .pth file exfiltrated SSH keys, AWS creds & crypto wallets"
Sleep 500ms
Enter
Type "# Let's scan it with chaincanary..."
Sleep 500ms
Enter
Sleep 1000ms

# ── Scene 2: Run the real CLI command ──

Type "chaincanary check litellm==1.82.8 --local tests/fixtures/litellm-1.82.8-py3-none-any.whl"
Sleep 400ms
Enter
Sleep 4500ms

# ── Scene 3: Let the viewer read the MALICIOUS verdict ──
Sleep 6000ms

# ── Scene 4: Safe rollback ──
Enter
Type "# Blocked! Safe rollback:"
Sleep 300ms
Enter
Type "# pip install litellm==1.82.6"
Sleep 600ms
Enter
Sleep 3500ms
