"""版本矩阵回归测试：把官方公告的四个分支真值固化成测试。

数据来源：PHP 2026-10-21 安全公告 —— 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12。
真值由云主机靶场实测确认（docker 镜像 8.2.34/8.2.35/8.3.35/8.3.36）。
"""
from __future__ import annotations

import pytest

from p2s.core.versions import Status, classify

#: (版本, 期望状态) —— 每个分支的"修复前一个版本"与"修复版本"
MATRIX = [
    ("8.2.34", Status.VULNERABLE),
    ("8.2.35", Status.PATCHED),
    ("8.3.35", Status.VULNERABLE),
    ("8.3.36", Status.PATCHED),
    ("8.4.26", Status.VULNERABLE),
    ("8.4.27", Status.PATCHED),
    ("8.5.11", Status.VULNERABLE),
    ("8.5.12", Status.PATCHED),
]


@pytest.mark.parametrize("version,expected", MATRIX)
def test_branch_matrix(version: str, expected: str) -> None:
    v = classify(version)
    assert v.status == expected, f"{version} 应为 {expected}，实际 {v.status}（{v.reason}）"


def test_vulnerable_needs_action_patched_does_not():
    assert classify("8.4.26").needs_action is True
    assert classify("8.4.27").needs_action is False


def test_fixed_release_reported():
    v = classify("8.3.35")
    assert v.fixed_release == "8.3.36"
