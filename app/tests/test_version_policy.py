"""版本号规则的测试与守卫。

规则：MAJOR.MINOR.PATCH 每段 0–9，满 10 进位。
"""
from __future__ import annotations

import pytest

from p2s import __version__
from p2s.core import version_policy as VP


def test_current_version_is_valid() -> None:
    assert VP.is_valid(__version__), f"当前版本 {__version__} 不符合规则"
    for part in __version__.split("."):
        assert int(part) <= VP.MAX, f"{__version__} 有段超过 {VP.MAX}"


def test_parse_and_reject() -> None:
    assert VP.parse("1.2.3") == (1, 2, 3)
    with pytest.raises(ValueError):
        VP.parse("1.2")
    with pytest.raises(ValueError):
        VP.parse("v1.2.3")


def test_patch_overflow_bumps_minor() -> None:
    assert VP.bump("1.2.9", "patch") == "1.3.0"


def test_minor_overflow_bumps_major() -> None:
    assert VP.bump("1.9.0", "minor") == "2.0.0"
    assert VP.bump("1.9.9", "patch") == "2.0.0"


def test_normal_bumps() -> None:
    assert VP.bump("1.2.3", "patch") == "1.2.4"
    assert VP.bump("1.2.3", "minor") == "1.3.0"
    assert VP.bump("1.2.3", "major") == "2.0.0"


def test_bump_never_exceeds_max() -> None:
    v = "1.0.0"
    for _ in range(200):                 # 连续递增 200 次，任何时刻都不越界
        v = VP.bump(v, "patch")
        assert VP.is_valid(v), f"递增过程中出现非法版本 {v}"


def test_explain_is_human_readable() -> None:
    text = VP.explain("1.3.2")
    assert "第 1 代" in text and "第 3 个次要版本" in text
