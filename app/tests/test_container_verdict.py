"""容器结论测试：版本核实 + 补丁标志（依据云主机实测）。"""
from __future__ import annotations

import pytest

from p2s.core import containers as C


def test_to_dict_carries_patch_fields():
    it = C.ContainerInstall(container="c1", image="php:8.4.27-cli",
                            version="8.4.27", sapi="cli",
                            patch_flag=True, verified=True)
    d = it.to_dict()
    assert d["patch_flag"] is True and d["verified"] is True
    assert d["path"] == "container:c1"


@pytest.mark.parametrize("raw,expect_flag,expect_ver", [
    ("8.4.26|cli|false", False, "8.4.26"),      # 未修复版实测输出
    ("8.4.27|cli|''", True, "8.4.27"),          # 修复版实测输出
    ("8.4.27|cli|NULL", True, "8.4.27"),
])
def test_probe_inside_parses(monkeypatch, raw, expect_flag, expect_ver):
    monkeypatch.setattr(C, "_run", lambda args, timeout=8: (0, raw))
    ver, sapi, flag = C._probe_inside("c1")
    assert ver == expect_ver
    assert sapi == "cli"
    assert flag is expect_flag


def test_probe_inside_failure_returns_none(monkeypatch):
    monkeypatch.setattr(C, "_run", lambda args, timeout=8: (1, ""))
    assert C._probe_inside("c1") == (None, None, None)


def test_scan_containers_uses_exec_when_enabled(monkeypatch):
    monkeypatch.setenv("P2S_CONTAINER_EXEC", "1")
    monkeypatch.setattr(C, "docker_available", lambda: True)
    monkeypatch.setattr(C, "list_containers",
                        lambda: [{"id": "a", "name": "web", "image": "php:8.4.26-cli"}])
    # 桩必须接受 timeout：真实实现会按剩余预算收敛单次 exec 的超时
    monkeypatch.setattr(C, "_probe_inside",
                        lambda name, timeout=10: ("8.4.26", "cli", False))
    items, notes = C.scan_containers()
    assert len(items) == 1
    assert items[0].verified is True
    assert items[0].patch_flag is False
    assert "核实" in items[0].note


def test_scan_containers_without_exec_keeps_tag(monkeypatch):
    monkeypatch.delenv("P2S_CONTAINER_EXEC", raising=False)
    monkeypatch.setattr(C, "docker_available", lambda: True)
    monkeypatch.setattr(C, "list_containers",
                        lambda: [{"id": "a", "name": "web", "image": "php:8.4.27-cli"}])
    items, _ = C.scan_containers()
    assert items[0].version == "8.4.27"
    assert items[0].verified is False
