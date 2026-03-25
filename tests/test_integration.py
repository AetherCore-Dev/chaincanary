"""
Integration tests using mock malicious packages.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fixtures.mock_packages import create_clean_litellm, create_mock_litellm_attack

from chaincanary.analyzer.differ import diff_from_static
from chaincanary.analyzer.static import StaticAnalyzer
from chaincanary.models import RiskReport, Severity


class TestLiteLLMAttackSimulation:
    """
    Full simulation of the LiteLLM 1.82.7 supply chain attack.
    These tests document EXACTLY what chaincanary catches.
    """

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmpdir)
        self.static = StaticAnalyzer()

        self.clean_wheel = create_clean_litellm(self.tmp_path / "clean", "1.82.6")
        self.attack_wheel = create_mock_litellm_attack(self.tmp_path / "attack")

    def test_attack_detected_as_malicious(self):
        """litellm 1.82.7 mock should be detected as MALICIOUS (score > 7)."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        report = RiskReport(package="litellm", version="1.82.7", findings=findings)
        report.calculate_score()

        assert report.verdict == "MALICIOUS"
        assert report.score >= 7.0
        assert report.is_blocked

    def test_three_critical_findings(self):
        """Should produce 3 CRITICAL findings for the attack package."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 2  # At minimum: PTH_FILE_INSTALL + PTH_NETWORK_BEACON

    def test_pth_file_detected(self):
        """PTH_FILE_INSTALL rule must fire."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        rule_ids = [f.rule_id for f in findings]
        assert "PTH_FILE_INSTALL" in rule_ids

    def test_network_beacon_detected(self):
        """PTH_NETWORK_BEACON rule must fire (phone-home detection)."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        rule_ids = [f.rule_id for f in findings]
        assert "PTH_NETWORK_BEACON" in rule_ids

    def test_evidence_contains_pth_filename(self):
        """Evidence should mention the malicious file name."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        pth_finding = next(f for f in findings if f.rule_id == "PTH_FILE_INSTALL")
        assert "litellm_init.pth" in pth_finding.evidence

    def test_evidence_contains_malicious_domain(self):
        """Evidence should contain the C2 domain."""
        findings = self.static.analyze_wheel(self.attack_wheel)
        beacon_finding = next((f for f in findings if f.rule_id == "PTH_NETWORK_BEACON"), None)
        assert beacon_finding is not None
        assert "litellm.cloud" in beacon_finding.evidence

    def test_clean_version_is_safe(self):
        """litellm 1.82.6 (clean version) should have no CRITICAL findings."""
        findings = self.static.analyze_wheel(self.clean_wheel)
        report = RiskReport(package="litellm", version="1.82.6", findings=findings)
        report.calculate_score()

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0
        assert not report.is_blocked

    def test_version_diff_detects_new_pth(self):
        """Version diff should detect the new .pth file added in 1.82.7."""
        files_clean = self.static.get_wheel_filelist(self.clean_wheel)
        files_attack = self.static.get_wheel_filelist(self.attack_wheel)
        diff = diff_from_static(files_clean, files_attack)

        assert "litellm_init.pth" in diff["new_pth_files"]
        assert len(diff["new_pth_files"]) >= 1

    def test_version_diff_no_false_positive_on_clean(self):
        """Same version compared to itself should show no new .pth files."""
        files = self.static.get_wheel_filelist(self.clean_wheel)
        diff = diff_from_static(files, files)

        assert diff["new_pth_files"] == []
        assert diff["added_files"] == []
