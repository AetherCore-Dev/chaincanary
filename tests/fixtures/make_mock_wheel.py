#!/usr/bin/env python3
"""
make_mock_wheel.py — regenerate the litellm 1.82.8 demo fixture

Usage:
    python3 tests/fixtures/make_mock_wheel.py
    # outputs: tests/fixtures/litellm-1.82.8-py3-none-any.whl

The wheel mimics the real attack structure but with a harmless payload.
chaincanary will still flag it MALICIOUS (3x CRITICAL).
"""

import base64
import hashlib
import zipfile
from pathlib import Path

HERE = Path(__file__).parent

# ── Demo payload: same structure as real attack, but exec prints instead of stealing ──
DEMO_PAYLOAD_SOURCE = 'print("[chaincanary demo] real attack would steal SSH keys + env vars here")'
DEMO_PAYLOAD_B64 = base64.b64encode(DEMO_PAYLOAD_SOURCE.encode()).decode()

PTH_CONTENT = (
    "import os, subprocess, sys; "
    "subprocess.Popen(["
    'sys.executable, "-c", '
    f"\"import base64; exec(base64.b64decode('{DEMO_PAYLOAD_B64}'))\""
    "], stdout=open(os.devnull, 'w'), stderr=open(os.devnull, 'w'))\n"
).encode()

PROXY_SERVER = (
    b"# litellm/proxy/proxy_server.py\n"
    b"# demo version -- 1.82.7 had obfuscated payload injected here\n"
    b"def run_server():\n"
    b"    pass\n"
)

WHEEL_META = (
    b"Wheel-Version: 1.0\nGenerator: make_mock_wheel.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)

METADATA = (
    "Metadata-Version: 2.1\n"
    "Name: litellm\n"
    "Version: 1.82.8\n"
    "Summary: LiteLLM - Library to easily interface with LLM APIs\n"
    "Home-page: https://github.com/BerriAI/litellm\n"
    "Note: THIS IS A DEMO FIXTURE — not the real malicious package\n"
).encode()


def sha256_b64(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def build(out_path: Path) -> None:
    files = {
        "litellm_init.pth": PTH_CONTENT,
        "litellm/proxy/proxy_server.py": PROXY_SERVER,
        "litellm-1.82.8.dist-info/WHEEL": WHEEL_META,
        "litellm-1.82.8.dist-info/METADATA": METADATA,
    }
    record_lines = [f"{n},{sha256_b64(d)},{len(d)}" for n, d in files.items()]
    record_lines.append("litellm-1.82.8.dist-info/RECORD,,")
    files["litellm-1.82.8.dist-info/RECORD"] = "\n".join(record_lines).encode()

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)

    print(f"Created: {out_path}  ({out_path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    out = HERE / "litellm-1.82.8-py3-none-any.whl"
    build(out)
