"""发行版版本号回归矩阵。

背景：v1.0.4 之前 parse_version 把任何后缀都当作预发布标识，
导致 `-1ubuntu1` / `-1.el9` / `-1kylin1` 这类打包修订号被判成 dev_branch。
在 discovery 的严重度排序里 dev_branch(4) 仅次于 patched(5)，
于是 Ubuntu/RHEL/麒麟 上一台真 vulnerable 的机器被排到几乎「已修复」，
构成优先级层面的漏报。本矩阵锁死该行为。
"""

from __future__ import annotations

import pytest

from p2s.core.versions import Status, classify, parse_version

# (版本串, 期望状态) —— 覆盖 Debian/Ubuntu/RHEL/麒麟/统信 与上游预发布
DISTRO_MATRIX = [
    # 已修复基线 + 各发行版打包后缀
    ("8.2.35", Status.PATCHED),
    ("8.2.35-1", Status.PATCHED),
    ("8.2.35-1ubuntu1", Status.PATCHED),
    ("8.2.35-1ubuntu1.2", Status.PATCHED),
    ("8.2.35+deb12u1", Status.PATCHED),
    ("8.2.35-1.el9", Status.PATCHED),
    ("8.2.35-1kylin1", Status.PATCHED),
    ("8.2.35-1.ky10", Status.PATCHED),
    ("8.3.36-1+deb12u1", Status.PATCHED),
    ("8.4.27-1ubuntu1", Status.PATCHED),
    ("8.5.12-1.el10", Status.PATCHED),
    ("PHP/8.4.27", Status.PATCHED),
    # 未修复 + 发行版后缀：必须仍然是 vulnerable，不能被降级
    ("8.2.34-1ubuntu1", Status.VULNERABLE),
    ("8.4.26-1.el9", Status.VULNERABLE),
    ("8.3.35-1kylin1", Status.VULNERABLE),
    ("8.4.24", Status.VULNERABLE),
    # 真正的上游预发布标识仍应识别为 dev
    ("8.4.27RC1", Status.DEV),
    ("8.4.27-RC1", Status.DEV),
    ("8.4.27-dev", Status.DEV),
    ("8.3.36beta2", Status.DEV),
    ("8.3.36alpha1", Status.DEV),
    # EOL 分支不受后缀影响
    ("8.1.31", Status.EOL_BACKPORT_AVAILABLE),
    ("8.1.31-1ubuntu1", Status.EOL_BACKPORT_AVAILABLE),
    ("7.4.33-1.el9", Status.EOL_BACKPORT_AVAILABLE),
    ("5.6.40", Status.EOL_UNPATCHABLE),
    # 开发分支与无法解析
    ("8.6.0", Status.DEV),
    ("garbage", Status.UNKNOWN),
    ("", Status.UNKNOWN),
]


@pytest.mark.parametrize("raw,expected", DISTRO_MATRIX)
def test_distro_suffix_matrix(raw, expected):
    assert classify(raw).status == expected


def test_patched_distro_pkg_not_ranked_below_vulnerable():
    """真实漏洞机器不能因为带打包后缀而被排到「已修复」附近。"""
    from p2s.core.discovery import _STATUS_RANK

    vuln = classify("8.2.34-1ubuntu1").status
    patched = classify("8.2.35-1ubuntu1").status
    assert _STATUS_RANK[vuln] < _STATUS_RANK[patched]


def test_distro_revision_is_not_prerelease_marker():
    assert parse_version("8.2.35-1ubuntu1")[3] is None
    assert parse_version("8.2.35-1.el9")[3] is None
    assert parse_version("8.2.35RC1")[3] == "RC"


def test_numeric_comparison_not_lexicographic():
    """8.4.100 > 8.4.27，不能按字符串比大小。"""
    assert classify("8.4.100").status == Status.PATCHED
    assert classify("8.4.9").status == Status.VULNERABLE
