"""本地取证的性能护栏：扫描必须有时间上界。

真实事故（2026-11-26）
----------------------
`scan_artifacts` 对**每个**候选文件都算 SHA-256，之后才判断后缀。
候选来自 `_iter_recent_files`：mtime >= since（默认 2026-10-20）。

GitHub runner 的系统文件（/opt、/var/lib/php 等）mtime 是**镜像构建时间**，
通常就在最近几周 —— 正好晚于 since。于是几千个系统文件全部进入候选，
每个都要读一遍算 SHA-256。该步骤在 runner 上超过 60 秒，
连带把 `test_host_job` 的等待循环一起拖到超时。

这类缺陷在开发机上**永远看不见**（Windows 上 /tmp 之类的目录是空的），
所以必须有门禁把它钉住。

本测试断言的是"上界"，不是"具体耗时"——机器快慢差异很大，
断言上界才能跨环境成立。
"""
from __future__ import annotations

import time
from pathlib import Path

from p2s.core import hostcheck


def test_scan_artifacts_respects_time_budget(tmp_path: Path, monkeypatch) -> None:
    """扫描必须自己收住 —— 传 3 秒预算，就该在几秒内返回。"""
    # 造一批"近期修改"的文件，模拟系统目录里 mtime 较新的文件
    import os

    # tmp_path 不在默认扫描根里，必须替换掉，否则扫不到任何文件
    monkeypatch.setattr(hostcheck, "_scan_dirs", lambda: [tmp_path])
    for i in range(200):
        p = tmp_path / f"f{i}.txt"
        p.write_text("x" * 4096)
        # mtime 必须**晚于** since（since 取自"现在"），否则候选数为 0
        future = time.time() + 60
        os.utime(p, (future, future))

    t0 = time.monotonic()
    hostcheck.scan_artifacts(since=hostcheck.datetime.now(), budget_seconds=3.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 25.0, (
        f"扫描耗时 {elapsed:.1f} 秒，远超 3 秒预算 —— "
        f"说明又退化成'逐文件算哈希'了")


def test_scan_artifacts_truncates_and_reports(tmp_path: Path, monkeypatch) -> None:
    """预算耗尽时必须停下来，并**如实报告**结果不完整。"""
    import os

    monkeypatch.setattr(hostcheck, "_scan_dirs", lambda: [tmp_path])
    # 用足够大的文件，让哈希计算真正耗时 —— 否则 300 个小文件瞬间扫完，
    # 预算根本耗不掉，"截断"分支永远不会执行（就成了假门禁）。
    blob = b"A" * (2 * 1024 * 1024)
    for i in range(40):
        p = tmp_path / f"g{i}.php"
        p.write_bytes(blob)
        future = time.time() + 60
        os.utime(p, (future, future))

    t0 = time.monotonic()
    arts = hostcheck.scan_artifacts(since=hostcheck.datetime.now(), budget_seconds=0.05)
    elapsed = time.monotonic() - t0

    assert elapsed < 20.0, f"扫描未按预算收住：{elapsed:.1f} 秒"
    kinds = {a.kind for a in arts}
    assert "scan_truncated" in kinds, (
        "预算耗尽却没有报告截断 —— 用户会误以为扫描是完整的。"
        f"实际 kinds={kinds}")


def test_scan_artifacts_default_budget_is_bounded() -> None:
    """默认预算必须是有限值（不能是 0 或无穷）。"""
    import inspect

    sig = inspect.signature(hostcheck.scan_artifacts)
    budget = sig.parameters["budget_seconds"].default
    assert isinstance(budget, (int, float))
    assert 0 < budget <= 60, f"默认预算 {budget} 秒不合理"


def test_hash_probe_limit_is_small() -> None:
    """非脚本类文件参与哈希匹配的体积上限必须是有限的小值。"""
    limit = getattr(hostcheck, "_HASH_PROBE_MAX_BYTES", None)
    assert limit is not None, "缺少 _HASH_PROBE_MAX_BYTES"
    assert 0 < limit <= 4 * 1024 * 1024, f"上限 {limit} 太大，哈希开销会失控"


def test_iter_recent_files_has_file_cap() -> None:
    """文件遍历必须有数量上限，不能无界扫描。"""
    import inspect

    src = inspect.getsource(hostcheck._iter_recent_files)
    assert "max_files" in src, "_iter_recent_files 缺少文件数上限"


def test_scan_dirs_is_bounded() -> None:
    """扫描目录列表本身也要有上限 —— 否则目录越多越慢，且无从察觉。"""
    import inspect


    src = inspect.getsource(hostcheck._scan_dirs)
    limit = getattr(hostcheck, "_MAX_SCAN_DIRS", None)
    assert limit is not None, (
        "_scan_dirs 没有目录数上限（缺少 _MAX_SCAN_DIRS）："
        "目录越多，扫描越慢，且没有告警点")
    assert limit > 0 and limit <= 64, f"目录数上限 {limit} 不合理"
    assert "_MAX_SCAN_DIRS" in src, "_scan_dirs 没有实际使用该上限"


def test_scan_dirs_returns_few_paths() -> None:
    """实际返回的目录数应在合理范围（当前实现：个位数）。"""
    dirs = hostcheck._scan_dirs()
    assert len(dirs) <= 24, f"扫描目录过多：{len(dirs)} 个 -> {[str(d) for d in dirs]}"


def test_run_host_check_completes_quickly() -> None:
    """整体本地取证必须在合理时间内完成（含容器/K8s 清点）。"""
    t0 = time.monotonic()
    rep = hostcheck.run_host_check()
    elapsed = time.monotonic() - t0
    assert elapsed < 90.0, (
        f"run_host_check 耗时 {elapsed:.1f} 秒 —— "
        f"在慢机器/CI 上会拖垮整个测试轮次")
    assert rep is not None