"""基准集结构测试：防止 benchmark.json 被改坏而评测结果失真。

不联网、不需要容器 —— 只校验数据本身的自洽性。
真实评测见 `scripts/run_benchmark.py`（需目标可达）。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parent.parent / "data" / "benchmark.json"


@pytest.fixture(scope="module")
def bench() -> dict:
    if not BENCH.exists():
        pytest.skip("没有基准集文件（需在实验场构建后放入 data/）")
    return json.loads(BENCH.read_text(encoding="utf-8"))


def test_bench_schema(bench) -> None:
    assert bench["cases"], "基准集不能为空"
    for c in bench["cases"]:
        assert {"id", "image", "endpoint", "truth", "access"} <= set(c)
        assert {"php_version", "patched"} <= set(c["truth"])
        assert c["access"]["port"] > 0


def test_bench_is_symmetric(bench) -> None:
    """未补丁与已补丁数量必须对称 —— 否则"全判未补丁"也能拿高分。"""
    vuln = [c for c in bench["cases"] if not c["truth"]["patched"]]
    patched = [c for c in bench["cases"] if c["truth"]["patched"]]
    assert len(vuln) == len(patched), (
        f"未补丁 {len(vuln)} 个 / 已补丁 {len(patched)} 个，不对称会让指标失去意义")


def test_bench_covers_all_branches(bench) -> None:
    """三个分支都要有样本，否则无法发现单分支退化。"""
    branches = {c["truth"]["php_version"].rsplit(".", 1)[0] for c in bench["cases"]}
    assert {"8.2", "8.3", "8.4"} <= branches, f"分支覆盖不全：{branches}"


def test_bench_ids_unique(bench) -> None:
    ids = [c["id"] for c in bench["cases"]]
    assert len(ids) == len(set(ids)), "用例 ID 重复"


def test_truth_matches_known_fixed_releases(bench) -> None:
    """真相必须与版本基线一致：低于基线=未补丁，等于基线=已补丁。"""
    from p2s.core.versions import classify

    for c in bench["cases"]:
        v = classify(c["truth"]["php_version"])
        expected = "patched" if c["truth"]["patched"] else "vulnerable"
        assert v.status == expected, (
            f"{c['id']}: 真相写 patched={c['truth']['patched']}，"
            f"但 {c['truth']['php_version']} 按基线是 {v.status}")