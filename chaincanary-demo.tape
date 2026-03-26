# chaincanary-demo.tape
# VHS recording script — generates demo.gif
#
# Prerequisites (Mac):
#   brew install vhs
#   brew install ttyd  # VHS dependency on Mac
#   cd chaincanary/
#   pip install chaincanary  # or: pip install -e .
#
# Run:
#   vhs chaincanary-demo.tape
#   # outputs: demo.gif  (drop into README to replace the placeholder)

Output demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 520
Set Theme "Dracula"
Set TypingSpeed 50ms
Set Padding 20

# ── Scene 1: headline ──
Type "# LiteLLM 1.82.8 was a supply chain attack — let's scan it"
Sleep 800ms
Enter
Sleep 500ms
Enter

# ── Scene 2: scan the mock wheel (instant, no network) ──
Type "python3 chaincanary-demo-scan.py"
Sleep 700ms
Enter
Sleep 6000ms

# pause so viewer can read the MALICIOUS verdict
Sleep 3000ms

# ── Scene 3: what would safe rollback look like? ──
Enter
Type "# Safe version: pip install litellm==1.82.6"
Sleep 1000ms
Enter
Sleep 1000ms
