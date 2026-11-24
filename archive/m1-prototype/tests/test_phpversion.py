"""版本解析与受影响判定单测

运行：python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from p2s.phpversion import (  # noqa: E402
    VersionStatus,
    evaluate,
    fixed_for,
    is_affected,
    parse_version,
    upgrade_path,
)


class TestParse(unittest.TestCase):
    def test_plain(self):
        v = parse_version("8.4.27")
        self.assertEqual((v.major, v.minor, v.patch), (8, 4, 27))
        self.assertFalse(v.is_prerelease)

    def test_debian_suffix(self):
        v = parse_version("8.4.27-1ubuntu1.2")
        self.assertEqual(v.tuple3, (8, 4, 27))
        self.assertEqual(v.suffix, "1ubuntu1.2")

    def test_rhel_suffix(self):
        v = parse_version("8.3.36-1.el9")
        self.assertEqual(v.tuple3, (8, 3, 36))

    def test_kylin_suffix(self):
        v = parse_version("8.1.2-1kylin1.3")
        self.assertEqual(v.tuple3, (8, 1, 2))

    def test_header_form(self):
        v = parse_version("PHP/8.3.14")
        self.assertEqual(v.tuple3, (8, 3, 14))

    def test_prerelease(self):
        v = parse_version("8.4.27RC1")
        self.assertEqual(v.tuple3, (8, 4, 27))
        self.assertTrue(v.is_prerelease)

    def test_garbage(self):
        self.assertIsNone(parse_version("no-version-here"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version(None))


class TestEvaluate(unittest.TestCase):
    def test_vulnerable_84(self):
        st, _ = evaluate("8.4.26")
        self.assertEqual(st, VersionStatus.VULNERABLE)

    def test_patched_84(self):
        st, _ = evaluate("8.4.27")
        self.assertEqual(st, VersionStatus.PATCHED)

    def test_patched_higher(self):
        st, _ = evaluate("8.4.30")
        self.assertEqual(st, VersionStatus.PATCHED)

    def test_vulnerable_85(self):
        self.assertEqual(evaluate("8.5.11")[0], VersionStatus.VULNERABLE)
        self.assertEqual(evaluate("8.5.12")[0], VersionStatus.PATCHED)

    def test_vulnerable_83(self):
        self.assertEqual(evaluate("8.3.35")[0], VersionStatus.VULNERABLE)
        self.assertEqual(evaluate("8.3.36")[0], VersionStatus.PATCHED)

    def test_vulnerable_82(self):
        self.assertEqual(evaluate("8.2.34")[0], VersionStatus.VULNERABLE)
        self.assertEqual(evaluate("8.2.35")[0], VersionStatus.PATCHED)

    def test_eol_branch_regardless_of_patch(self):
        # 8.1 装到该分支最新版仍是漏洞版 —— 这是最容易漏报的场景
        for v in ("8.1.2", "8.1.31", "8.1.35", "8.0.30", "7.4.33", "5.6.40"):
            st, note = evaluate(v)
            self.assertEqual(st, VersionStatus.VULNERABLE_EOL, v)
            self.assertIn("无修复", note)

    def test_prerelease_not_patched(self):
        st, _ = evaluate("8.4.27RC1")
        self.assertEqual(st, VersionStatus.PRERELEASE)

    def test_unknown_branch(self):
        st, _ = evaluate("9.0.1")
        self.assertEqual(st, VersionStatus.UNKNOWN_BRANCH)

    def test_distro_suffix_does_not_matter(self):
        # 回移补丁与否不能靠版本号判断，但版本区间本身应正确
        self.assertEqual(evaluate("8.4.24-1ubuntu1")[0], VersionStatus.VULNERABLE)
        self.assertEqual(evaluate("8.4.27-1ubuntu1")[0], VersionStatus.PATCHED)

    def test_is_affected_tristate(self):
        self.assertTrue(is_affected("8.4.26"))
        self.assertFalse(is_affected("8.4.27"))
        self.assertIsNone(is_affected("9.9.9"))

    def test_fixed_and_upgrade(self):
        v = parse_version("8.4.26")
        self.assertEqual(fixed_for(v), "8.4.27")
        self.assertIn("8.4.27", upgrade_path(v))

    def test_eol_upgrade_is_migration(self):
        v = parse_version("8.1.31")
        self.assertIn("迁移", upgrade_path(v))


if __name__ == "__main__":
    unittest.main()
