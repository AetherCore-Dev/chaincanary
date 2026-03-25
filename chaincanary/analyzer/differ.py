"""
Version behavior differ — compare behaviors between two versions.
Highlights NEW behaviors that appeared in a specific version.
This is the key feature that would have caught LiteLLM 1.82.7:
the .pth file was NOT in 1.82.6 but appeared in 1.82.7.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from chaincanary.models import BehaviorSnapshot


@dataclass
class BehaviorDiff:
    """What changed between prev_version and current_version."""
    package: str
    prev_version: str
    curr_version: str

    # New behaviors (appeared in curr, not in prev)
    new_pth_files: list[str] = field(default_factory=list)
    new_network_calls: list[str] = field(default_factory=list)
    new_file_writes: list[str] = field(default_factory=list)
    new_subprocesses: list[str] = field(default_factory=list)

    # Removed behaviors (in prev but not curr)
    removed_pth_files: list[str] = field(default_factory=list)
    removed_network_calls: list[str] = field(default_factory=list)

    @property
    def has_new_suspicious_behavior(self) -> bool:
        return bool(
            self.new_pth_files
            or self.new_network_calls
            or self.new_subprocesses
        )

    @property
    def summary(self) -> str:
        parts = []
        if self.new_pth_files:
            parts.append(f"{len(self.new_pth_files)} new .pth file(s)")
        if self.new_network_calls:
            parts.append(f"{len(self.new_network_calls)} new network call(s)")
        if self.new_subprocesses:
            parts.append(f"{len(self.new_subprocesses)} new subprocess(es)")
        if self.new_file_writes:
            parts.append(f"{len(self.new_file_writes)} new file write(s)")
        return ", ".join(parts) if parts else "no behavioral changes"


def diff_behaviors(
    prev: BehaviorSnapshot,
    curr: BehaviorSnapshot,
) -> BehaviorDiff:
    """Compare two behavior snapshots and return the diff."""
    result = BehaviorDiff(
        package=curr.package,
        prev_version=prev.version,
        curr_version=curr.version,
    )

    # Sets for comparison
    prev_pth = set(prev.pth_files)
    curr_pth = set(curr.pth_files)
    result.new_pth_files = list(curr_pth - prev_pth)
    result.removed_pth_files = list(prev_pth - curr_pth)

    prev_net = set(_normalize_calls(prev.network_calls))
    curr_net = set(_normalize_calls(curr.network_calls))
    result.new_network_calls = list(curr_net - prev_net)
    result.removed_network_calls = list(prev_net - curr_net)

    prev_writes = set(prev.file_writes)
    curr_writes = set(curr.file_writes)
    result.new_file_writes = list(curr_writes - prev_writes)

    prev_procs = set(prev.subprocesses)
    curr_procs = set(curr.subprocesses)
    result.new_subprocesses = list(curr_procs - prev_procs)

    return result


def _normalize_calls(calls: list[str]) -> list[str]:
    """Normalize call strings for comparison (strip line numbers, etc.)."""
    normalized = []
    for c in calls:
        # Keep just the domain/path part for network calls
        import re
        m = re.search(r'([\w\-\.]+\.[\w]{2,})', c)
        if m:
            normalized.append(m.group(1))
        else:
            normalized.append(c[:80])
    return normalized


def diff_from_static(
    prev_files: list[str],  # filenames in prev wheel
    curr_files: list[str],  # filenames in curr wheel
) -> dict:
    """
    Quick static diff: which files were ADDED between versions.
    This is the fastest way to spot .pth injection.
    """
    prev_set = set(prev_files)
    curr_set = set(curr_files)

    added = curr_set - prev_set
    removed = prev_set - curr_set

    new_pth = [f for f in added if f.endswith(".pth")]
    new_suspicious = [f for f in added if any(
        keyword in f.lower()
        for keyword in ["hook", "inject", "loader", "init", "startup", "sitecustomize"]
    )]

    return {
        "added_files": sorted(added),
        "removed_files": sorted(removed),
        "new_pth_files": new_pth,
        "new_suspicious_files": new_suspicious,
    }
