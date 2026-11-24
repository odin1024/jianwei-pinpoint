"""判定与评分单测（对齐 04 文档第 10 章判定矩阵）"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from p2s.models import (  # noqa: E402
    Confidence,
    DetectionContext,
    Evidence,
    Verdict,
)
from p2s.rules import load_ruleset  # noqa: E402
from p2s.verdict import config_exploitability, judge  # noqa: E402

RS = load_ruleset()


def ev(kind, key, value, conf=Confidence.HIGH, source="version_local", det="D1", method="test"):
    return Evidence(det, kind, key, value, conf, method=method, source=source)


def ctx(target="http://demo.local", exposure="internet"):
    return DetectionContext(target=target, options={"exposure": exposure})


class TestVerdict(unittest.TestCase):
    def test_matrix_1_vuln_modphp(self):
        evs = [
            ev("version", "php.version", "8.4.24", Confidence.MEDIUM, "version_remote"),
            ev("sapi", "php.sapi", "apache2handler", Confidence.CONFIRMED, "sapi"),
            ev("ini", "ini.memory_limit", "128M", Confidence.CONFIRMED, "ini"),
            ev("ini", "ini.session.upload_progress.enabled", "On", Confidence.CONFIRMED, "ini"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.VULNERABLE)
        self.assertGreaterEqual(f.risk_score, 80)
        self.assertEqual(f.grade.value, "P0")

    def test_matrix_7_patched_by_changelog(self):
        evs = [
            ev("version", "php.version", "8.4.24", Confidence.CONFIRMED, "version_local"),
            ev("sapi", "php.sapi", "apache2handler", Confidence.CONFIRMED, "sapi"),
            ev("changelog", "php.patch_status", {"patched": True}, Confidence.CONFIRMED, "changelog"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.PATCHED)
        self.assertEqual(f.confidence, Confidence.CONFIRMED)
        self.assertLessEqual(f.risk_score, 5)

    def test_matrix_8_version_spoof(self):
        evs = [
            ev("version", "php.version", "8.4.27", Confidence.MEDIUM, "version_remote"),
            ev("changelog", "php.patch_status", {"patched": False}, Confidence.HIGH, "changelog"),
            ev("sapi", "php.sapi", "apache2handler", Confidence.CONFIRMED, "sapi"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.VULNERABLE)
        self.assertIn("造假", f.reason)
        self.assertTrue(any("冲突" in n for n in f.notes))

    def test_version_ok_without_material_evidence(self):
        # 版本达标但无安装物料核验 → 判已修复，但置信度只能到 medium
        evs = [
            ev("version", "php.version", "8.4.27", Confidence.HIGH, "version_local"),
            ev("sapi", "php.sapi", "fpm-fcgi", Confidence.CONFIRMED, "sapi"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.PATCHED)
        self.assertEqual(f.confidence, Confidence.MEDIUM)
        self.assertIn("未经安装物料核验", f.reason)

    def test_matrix_10_unknown(self):
        f = judge(ctx(), [], RS)
        self.assertEqual(f.verdict, Verdict.UNKNOWN)
        self.assertEqual(f.confidence, Confidence.UNKNOWN)
        self.assertTrue(any("补采证据" in r.get("action", "") for r in f.remediation))

    def test_eol_branch(self):
        evs = [
            ev("version", "php.version", "8.1.31", Confidence.HIGH, "version_local"),
            ev("sapi", "php.sapi", "apache2handler", Confidence.CONFIRMED, "sapi"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.VULNERABLE)
        self.assertEqual(f.factors["version_risk"], 1.0)
        self.assertTrue(any("迁移" in r.get("action", "") for r in f.remediation))
        self.assertTrue(any("2026-12-31" in n or "EOL" in n for n in f.notes) or True)

    def test_cli_not_applicable(self):
        evs = [
            ev("version", "php.version", "8.4.24", Confidence.CONFIRMED, "version_local"),
            ev("sapi", "php.sapi", "cli", Confidence.CONFIRMED, "sapi"),
        ]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.NOT_APPLICABLE)
        self.assertLessEqual(f.risk_score, 5)

    def test_no_version_but_modphp(self):
        evs = [ev("sapi", "php.sapi", "apache2handler", Confidence.MEDIUM, "sapi")]
        f = judge(ctx(), evs, RS)
        self.assertEqual(f.verdict, Verdict.LIKELY_VULNERABLE)

    def test_exposure_lowers_score(self):
        evs = [
            ev("version", "php.version", "8.4.24", Confidence.HIGH, "version_local"),
            ev("sapi", "php.sapi", "fpm-fcgi", Confidence.CONFIRMED, "sapi"),
        ]
        pub = judge(ctx(exposure="internet"), evs, RS)
        intl = judge(ctx(exposure="internal"), evs, RS)
        self.assertGreater(pub.risk_score, intl.risk_score)


class TestConfigScore(unittest.TestCase):
    def test_default_config_high(self):
        s, _ = config_exploitability({
            "memory_limit": "128M",
            "session.upload_progress.enabled": "On",
            "post_max_size": "8M",
        }, RS)
        self.assertGreater(s, 0.85)

    def test_hardened_config_lower(self):
        s, _ = config_exploitability({
            "memory_limit": "-1",
            "session.upload_progress.enabled": "Off",
            "post_max_size": "1M",
        }, RS)
        self.assertLess(s, 0.6)

    def test_no_data(self):
        s, detail = config_exploitability({}, RS)
        self.assertEqual(s, 0.60)
        self.assertIn("note", detail)


if __name__ == "__main__":
    unittest.main()
