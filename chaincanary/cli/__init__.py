"""
CLI entry point for chaincanary.

Registers all sub-commands and re-exports ``main`` so that
``from chaincanary.cli import main`` and the entry-point
``chaincanary.cli:main`` both keep working.
"""

from __future__ import annotations

# Import command modules to trigger @main.command() registration.
from chaincanary.cli import audit_cmd as audit_cmd  # noqa: F401
from chaincanary.cli import check_cmd as check_cmd  # noqa: F401
from chaincanary.cli import diff_cmd as diff_cmd  # noqa: F401
from chaincanary.cli import install_cmd as install_cmd  # noqa: F401
from chaincanary.cli import update_cmd as update_cmd  # noqa: F401

# Backward-compat: expose helpers at package level so existing patches
# like ``@patch("chaincanary.cli.AnalysisEngine")`` still resolve.
from chaincanary.cli._helpers import (  # noqa: F401
    _parse_package_spec,
    _resolve_version,
    _run_analysis,
    console,
    err_console,
)
from chaincanary.cli._main import main
from chaincanary.engine import AnalysisEngine as AnalysisEngine  # noqa: F401

__all__ = ["main"]

if __name__ == "__main__":
    main()
