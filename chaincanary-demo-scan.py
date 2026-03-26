#!/usr/bin/env python3
"""
chaincanary-demo-scan.py

Scan the local litellm-1.82.8 mock wheel and display results,
exactly as if you ran: chaincanary check litellm==1.82.8

Usage (from repo root):
    python3 chaincanary-demo-scan.py

Or: install chaincanary then run this script for the GIF demo.
"""

import shutil
import sys
import tempfile
from pathlib import Path

# ── locate the mock wheel ──
SCRIPT_DIR = Path(__file__).parent
WHL = SCRIPT_DIR / "tests/fixtures/litellm-1.82.8-py3-none-any.whl"

if not WHL.exists():
    print(f"[error] mock wheel not found at {WHL}")
    print("Run: python3 tests/fixtures/make_mock_wheel.py")
    sys.exit(1)

sys.path.insert(0, str(SCRIPT_DIR))

# noqa: E402 — imports must follow sys.path setup above
from chaincanary import downloader as _dl  # noqa: E402
from chaincanary import engine as _engine  # noqa: E402
from chaincanary import reporter  # noqa: E402
from chaincanary.engine import AnalysisEngine  # noqa: E402


# ── monkey-patch downloader so engine uses local file instead of PyPI ──
def _local_download(package, version, target_dir=None, verify_hash=True):  # noqa: ARG001
    """Return the mock wheel instead of fetching from PyPI."""
    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix="chaincanary_"))
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / WHL.name
    shutil.copy2(WHL, dest)
    return dest


# monkey-patch version listing so safe-version lookup works offline
def _local_get_all_versions(package):
    return ["1.82.0", "1.82.2", "1.82.4", "1.82.6", "1.82.7", "1.82.8"]


def _local_get_latest_safe(package, current):
    return "1.82.6"


# patch both the module and the engine's local reference
_dl.download_wheel = _local_download
_dl.get_all_versions = _local_get_all_versions
_dl.get_latest_safe_version = _local_get_latest_safe
_engine.download_wheel = _local_download
_engine.get_latest_safe_version = _local_get_latest_safe

# ── run the scan ──
engine = AnalysisEngine()
package, version = "litellm", "1.82.8"

reporter.print_scanning(package, version)

report = engine.analyze(
    package,
    version,
    on_progress=lambda msg: print(f"  {msg}"),
)

reporter.print_report(report)

# exit with non-zero if malicious (useful for CI)
if report.verdict == "MALICIOUS":
    sys.exit(1)
