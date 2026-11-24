"""补丁标记库测试：用**真实二进制**验证判定，不靠构造的假数据。

真实样本从实验场镜像提取过，但仓库不该带 20MB 二进制。
所以这里做两件事：
  1. 用 markers.json 里记录的真实字符串构造最小样本 → 验证判定逻辑；
  2. 校验"三分支全部可区分"这一事实没有被意外破坏。
"""
from __future__ import annotations

import json

from p2s.core import patchmarkers as pm


def test_markers_file_loads() -> None:
    data = pm.load()
    assert data["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert len(pm.markers()) >= 5
    assert len(pm.branches()) == 3


def test_all_branches_distinguishable() -> None:
    """核心保证：每条标记在三个分支上都必须能区分补丁与否。"""
    matrix = pm.verify_matrix()
    assert matrix, "缺少实测矩阵"
    for branch, row in matrix.items():
        for marker, values in row.items():
            assert values["unpatched"] != values["patched"], (
                f"{branch} 分支上 {marker} 无法区分补丁状态 —— 该标记应被移除或降级")
    s = pm.summary()
    assert s["all_branches_distinguishable"] is True


def test_branches_have_provenance() -> None:
    """每个分支都要能追到具体镜像与二进制 sha256，否则等于没证据。"""
    for b in pm.branches():
        for side in ("unpatched", "patched"):
            info = b[side]
            assert info["php_version"] and info["image"]
            assert len(info["binary_sha256"]) == 64


def _blob(needles: list[bytes]) -> bytes:
    """拼一个最小"二进制"：标记之间用空字节隔开。"""
    return b"\x00".join(needles)


def test_match_patched_by_new_instruction_name() -> None:
    blob = _blob([b"MZ\x90\x00", b"memory_hard_limit_percent", b"other stuff"])
    r = pm.match_binary(blob)
    assert r["verdict"] == "patched"
    assert "MK-OOM-CFG-1" in r["hits"]
    assert r["evidence"]


def test_match_unpatched_by_old_oom_message() -> None:
    """只剩旧版 OOM 文案、没有新指令 → 未补丁。"""
    blob = _blob([b"MZ\x90\x00", b"Out of memory (allocated %zu bytes)"])
    r = pm.match_binary(blob)
    assert r["verdict"] == "unpatched"
    assert any("未补丁" in e or "旧版" in e for e in r["evidence"])


def test_match_unknown_when_no_marker() -> None:
    """找不到任何标记时必须是 unknown —— 绝不能默认判成未补丁。"""
    r = pm.match_binary(b"MZ\x00random binary\x00nothing here")
    assert r["verdict"] == "unknown"


def test_match_conflict_when_both_signals() -> None:
    """新旧标记同时命中 → 矛盾，交人工，不猜。"""
    blob = _blob([b"memory_hard_limit_percent", b"Out of memory (allocated %zu bytes)"])
    r = pm.match_binary(blob)
    assert r["verdict"] == "conflict"


def test_match_real_ish_patched_binary() -> None:
    """模拟真实已补丁二进制：同时含全部 4 条"新增"标记，且旧文案已消失。"""
    blob = _blob([
        b"zend_handle_delayed_oom",
        b"zend_set_memory_hard_limit_percent",
        b"memory_hard_limit_percent",
        b"Hard memory limit of %zu bytes exhausted",
    ])
    r = pm.match_binary(blob)
    assert r["verdict"] == "patched"
    assert len(r["hits"]) >= 4


def test_match_real_ish_unpatched_binary() -> None:
    """模拟真实未补丁二进制：无新增标记，但旧 OOM 文案在。"""
    blob = _blob([b"MZ", b"Out of memory (allocated %zu bytes)", b"PHP 8.4.26"])
    r = pm.match_binary(blob)
    assert r["verdict"] == "unpatched"


# ---------------------------------------------------------------- 运行时

def test_runtime_unpatched() -> None:
    r = pm.match_runtime("bool(false)")
    assert r["verdict"] == "unpatched"
    assert "不存在" in r["evidence"][0]


def test_runtime_patched_empty_string() -> None:
    r = pm.match_runtime('string(0) ""')
    assert r["verdict"] == "patched"


def test_runtime_patched_with_value() -> None:
    """显式设置过该指令（如 120）也是已补丁的正向证据。"""
    r = pm.match_runtime('string(3) "120"')
    assert r["verdict"] == "patched"


def test_runtime_unknown() -> None:
    r = pm.match_runtime("NULL")
    assert r["verdict"] == "unknown"


def test_summary_shape() -> None:
    s = pm.summary()
    assert s["binary_markers"] >= 5
    assert s["runtime_probes"] >= 1
    assert {b["branch"] for b in s["branches"]} == {"8.2", "8.3", "8.4"}


def test_markers_json_is_valid_utf8_json() -> None:
    """数据文件必须能被解析（防止手工编辑时漏逗号）。"""
    raw = (pm._DATA).read_text(encoding="utf-8")
    json.loads(raw)
    assert "verification_matrix" in raw