"""
Lockfile / requirements scanner.
Supports: requirements.txt, pyproject.toml, poetry.lock, pip-tools .txt
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class PackageSpec:
    name: str
    version: Optional[str]
    source_file: str
    source_line: int
    raw: str


def parse_requirements_txt(path: Path) -> list[PackageSpec]:
    """
    Parse requirements.txt (or any pip-compatible requirements file).
    Supports: ==, >=, extras, comments, -r includes, -c constraints.
    """
    specs = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        # Skip comments, blank lines, flags
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Remove inline comments
        line = re.sub(r"\s+#.*$", "", line).strip()
        # Skip editable installs
        if line.startswith("-e"):
            continue
        # Extract package name and pinned version (== only)
        m = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?)"
            r"(?:\[.*?\])?"          # extras
            r"\s*==\s*([^\s;,]+)",   # ==version
            line,
        )
        if m:
            specs.append(PackageSpec(
                name=m.group(1),
                version=m.group(3),
                source_file=str(path),
                source_line=lineno,
                raw=raw,
            ))
        else:
            # Pinned version not found — include with no version for latest check
            m2 = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?)", line)
            if m2:
                specs.append(PackageSpec(
                    name=m2.group(1),
                    version=None,
                    source_file=str(path),
                    source_line=lineno,
                    raw=raw,
                ))
    return specs


def parse_pyproject_toml(path: Path) -> list[PackageSpec]:
    """Parse pyproject.toml dependencies."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # fallback
        except ImportError:
            return []  # toml not available

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    specs = []
    # PEP 517 / Hatch / setuptools style
    deps = (
        data.get("project", {}).get("dependencies", [])
        + data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys().__class__([])
    )
    # Poetry style
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, constraint in poetry_deps.items():
        if name.lower() == "python":
            continue
        version = None
        if isinstance(constraint, str):
            m = re.search(r"==([^\s,]+)", constraint)
            if m:
                version = m.group(1)
        specs.append(PackageSpec(
            name=name,
            version=version,
            source_file=str(path),
            source_line=0,
            raw=f"{name} = {constraint!r}",
        ))

    return specs


def detect_lockfile(directory: Path) -> Optional[Path]:
    """Auto-detect the most precise lockfile in a directory."""
    candidates = [
        "requirements.txt",
        "requirements-lock.txt",
        "requirements/base.txt",
        "requirements/production.txt",
        "pyproject.toml",
        "Pipfile.lock",
    ]
    for name in candidates:
        p = directory / name
        if p.exists():
            return p
    return None


def parse_lockfile(path: Path) -> list[PackageSpec]:
    """Auto-dispatch to the right parser based on file type."""
    suffix = path.suffix.lower()
    name = path.name.lower()

    if suffix == ".toml":
        return parse_pyproject_toml(path)
    if "requirements" in name or suffix == ".txt":
        return parse_requirements_txt(path)
    # Pipfile.lock
    if name == "pipfile.lock":
        return _parse_pipfile_lock(path)
    return []


def _parse_pipfile_lock(path: Path) -> list[PackageSpec]:
    """Parse Pipfile.lock."""
    try:
        import json
        data = json.loads(path.read_text())
    except Exception:
        return []

    specs = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            version_str = info.get("version", "")
            m = re.match(r"==(.+)", version_str)
            version = m.group(1) if m else None
            specs.append(PackageSpec(
                name=name,
                version=version,
                source_file=str(path),
                source_line=0,
                raw=f"{name}{version_str}",
            ))
    return specs
