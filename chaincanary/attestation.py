"""
PyPI attestation verification via PEP 740 Integrity API.

Checks whether a package has digital attestations (Sigstore-backed)
on PyPI. Does NOT perform full Sigstore verification — PyPI verifies
at upload time. We detect presence and extract publisher metadata.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import requests  # type: ignore[import-untyped]

from chaincanary.models import Finding, Severity

_log = logging.getLogger(__name__)

INTEGRITY_URL = (
    "https://pypi.org/integrity/{project}/{version}/{filename}/provenance"
)
ACCEPT_HEADER = "application/vnd.pypi.integrity.v1+json"

# Input validation (PEP 440 version chars + PEP 503 package names)
_SAFE_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,200}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9_.\-+!]{1,64}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+\.(whl|tar\.gz|zip)$")

# Cap response body to prevent memory exhaustion from malformed responses
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB


def _normalize_package_name(name: str) -> str:
    """Normalize package name per PEP 503 (lowercase, hyphens)."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class AttestationResult:
    """Immutable result from an attestation check."""

    has_attestation: bool
    publisher_kind: str | None = None
    repository: str | None = None
    workflow_ref: str | None = None
    error: str | None = None


def check_attestation(
    package: str,
    version: str,
    filename: str,
    timeout: int = 30,
) -> AttestationResult:
    """
    Query PyPI Integrity API for attestations on a specific wheel file.

    Returns AttestationResult — never raises.  Network errors are
    captured in the ``error`` field so the caller can silently skip.
    """
    # Input validation — reject anything that could cause URL path injection
    if not _SAFE_PACKAGE_RE.match(package):
        return AttestationResult(has_attestation=False, error="Invalid package name")
    if not _SAFE_VERSION_RE.match(version):
        return AttestationResult(has_attestation=False, error="Invalid version string")
    if not _SAFE_FILENAME_RE.match(filename):
        return AttestationResult(has_attestation=False, error="Invalid filename")

    normalized = _normalize_package_name(package)
    url = INTEGRITY_URL.format(
        project=normalized,
        version=version,
        filename=filename,
    )
    try:
        resp = requests.get(
            url,
            headers={"Accept": ACCEPT_HEADER},
            timeout=(10, timeout),  # (connect_timeout, read_timeout)
            stream=True,
        )
    except requests.exceptions.Timeout:
        return AttestationResult(has_attestation=False, error="Request timed out")
    except requests.exceptions.ConnectionError:
        return AttestationResult(has_attestation=False, error="Connection error")
    except Exception as exc:
        _log.debug("Attestation check failed: %s", exc)
        return AttestationResult(has_attestation=False, error="Network error")

    if resp.status_code == 404:
        resp.close()
        return AttestationResult(has_attestation=False)

    if resp.status_code != 200:
        resp.close()
        return AttestationResult(
            has_attestation=False,
            error=f"Unexpected status {resp.status_code}",
        )

    # Read body with size cap to prevent memory exhaustion
    try:
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > _MAX_RESPONSE_BYTES:
                resp.close()
                return AttestationResult(
                    has_attestation=False, error="Response too large",
                )
        resp.close()
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return AttestationResult(
            has_attestation=False, error="Invalid JSON response",
        )
    except Exception:
        return AttestationResult(
            has_attestation=False, error="Response read error",
        )

    return _parse_attestation_response(data)


def _parse_attestation_response(
    data: dict[str, Any],
) -> AttestationResult:
    """Extract publisher metadata from the Integrity API response.

    Only the first attestation bundle is inspected.
    """
    bundles = data.get("attestation_bundles", [])
    if not bundles:
        return AttestationResult(has_attestation=False)

    first_bundle = bundles[0]
    publisher = first_bundle.get("publisher", {})
    claims = publisher.get("claims", {})

    return AttestationResult(
        has_attestation=True,
        publisher_kind=publisher.get("kind"),
        repository=claims.get("repository"),
        workflow_ref=claims.get("workflow_ref"),
    )


def attestation_to_findings(
    result: AttestationResult,
    package: str,
    version: str,
) -> list[Finding]:
    """Convert an AttestationResult into Finding objects for the report."""
    if result.error:
        return []

    if result.has_attestation:
        evidence_parts = [
            f"Publisher: {result.publisher_kind or 'unknown'}",
        ]
        if result.repository:
            evidence_parts.append(f"Repository: {result.repository}")
        if result.workflow_ref:
            evidence_parts.append(f"Workflow: {result.workflow_ref}")

        return [
            Finding(
                rule_id="ATTESTATION_VERIFIED",
                severity=Severity.INFO,
                title=(
                    f"Package has PyPI attestation "
                    f"(publisher: {result.publisher_kind or 'unknown'})"
                ),
                description=(
                    f"'{package}=={version}' has a valid digital attestation "
                    f"on PyPI (PEP 740 / Sigstore). This means the package "
                    f"was built in a verified CI environment and its "
                    f"provenance can be traced."
                ),
                evidence="\n".join(evidence_parts),
                source="attestation",
            ),
        ]

    return [
        Finding(
            rule_id="NO_ATTESTATION",
            severity=Severity.INFO,
            title="No PyPI attestation found",
            description=(
                f"'{package}=={version}' does not have a digital attestation "
                f"on PyPI. Most PyPI packages do not have attestations yet. "
                f"As PEP 740 adoption grows, unsigned packages may warrant "
                f"closer scrutiny."
            ),
            evidence=(
                f"Checked PyPI Integrity API for {package}=={version}"
            ),
            source="attestation",
        ),
    ]
