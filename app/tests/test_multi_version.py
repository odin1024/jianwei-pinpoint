"""多版本聚合测试：资产必须报"最差"的 PHP，并保留全部实例。"""
from __future__ import annotations

from p2s.core.discovery import pick_worst_php


def test_worst_is_oldest_vulnerable_branch():
    """8.2.34 比 8.4.26 更该被关注（分支更老、同样未修复）。"""
    inst = [
        {"port": 8082, "version": "8.4.27"},
        {"port": 8083, "version": "8.2.34"},
        {"port": 8081, "version": "8.4.26"},
    ]
    assert pick_worst_php(inst)["version"] == "8.2.34"


def test_vulnerable_beats_patched_regardless_of_number():
    """8.3.35（未修复）比 8.4.27（已修复）更严重，不能按版本号大小选。"""
    inst = [{"port": 1, "version": "8.4.27"}, {"port": 2, "version": "8.3.35"}]
    assert pick_worst_php(inst)["port"] == 2


def test_eol_beats_unknown():
    inst = [{"port": 1, "version": None}, {"port": 2, "version": "7.4.33"}]
    assert pick_worst_php(inst)["port"] == 2


def test_single_instance():
    assert pick_worst_php([{"port": 80, "version": "8.4.26"}])["version"] == "8.4.26"


def test_unknown_version_kept_when_only_option():
    inst = [{"port": 80, "version": None}]
    assert pick_worst_php(inst)["port"] == 80
