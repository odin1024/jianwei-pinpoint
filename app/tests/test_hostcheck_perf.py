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

def test_run_host_check_respects_total_budget(tmp_path: Path, monkeypatch) -> None:
    """整体取证必须受**总预算**约束，不是只有痕迹扫描受约束。

    真实事故：GitHub runner 上 run_host_check 超过 120 秒，
    把 test_host_job 的等待循环一起拖到超时（连挂 4 轮 CI）。
    当时只有 scan_artifacts 有预算，而磁盘遍历本身（os.walk 大目录树）
    就能吃掉绝大部分时间 —— 遍历器也必须看 deadline。
    """
    import os

    # 造一个"runner 规模"的目录：多层 + 大量近期文件
    root = tmp_path / "opt" / "a" / "b" / "c"
    root.mkdir(parents=True)
    future = time.time() + 600
    for i in range(1200):
        d = root / f"d{i % 40}"
        d.mkdir(exist_ok=True)
        p = d / f"f{i}.txt"
        p.write_bytes(b"B" * 4096)
        os.utime(p, (future, future))

    monkeypatch.setattr(hostcheck, "_scan_dirs", lambda: [root])

    t0 = time.monotonic()
    hostcheck.run_host_check(budget_seconds=10.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 45.0, (
        f"run_host_check 在 10 秒预算下耗时 {elapsed:.1f} 秒 —— "
        f"总预算没有真正约束住整个流程（遍历器可能没看 deadline）")


def test_iter_recent_files_honors_deadline(tmp_path: Path) -> None:
    """遍历器自身必须认 deadline —— 大目录树的 os.walk 才是主要开销。"""
    import os

    root = tmp_path / "big"
    root.mkdir()
    future = time.time() + 600
    for i in range(800):
        d = root / f"x{i}"
        d.mkdir()
        for j in range(10):
            p = d / f"f{j}.txt"
            p.write_bytes(b"C" * 1024)
            os.utime(p, (future, future))

    t0 = time.monotonic()
    got = list(hostcheck._iter_recent_files(
        [root], hostcheck.datetime.now(), deadline=time.monotonic() + 0.5))
    elapsed = time.monotonic() - t0

    assert elapsed < 20.0, f"遍历器未认 deadline，耗时 {elapsed:.1f} 秒"
    # 预算 0.5 秒不可能遍历完 8000 个文件，必须提前返回
    assert len(got) < 8000, f"遍历器没有提前停止（取了 {len(got)} 个文件）"


def test_run_host_check_survives_hanging_docker(tmp_path: Path, monkeypatch) -> None:
    """docker/kubectl 卡住时，取证仍必须在总预算内收工。

    真实事故（CI 第 7 轮）：GitHub runner 上装了 docker CLI 但 daemon 没起，
    docker 客户端会反复重连，单个命令就能耗掉十几秒；容器多时线性累加。
    `run_host_check` 的预算当时只覆盖磁盘扫描，没覆盖这段外部命令，
    于是整体耗时 >120 秒，两个用例被 pytest-timeout 判死。
    """
    import shutil as _shutil
    import subprocess

    monkeypatch.setattr(hostcheck, "_scan_dirs", lambda: [tmp_path])

    # 模拟"docker 命令会挂住"：任何 docker/kubectl 调用都睡满整个 timeout
    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if isinstance(cmd, (list, tuple)) and cmd and str(cmd[0]) in {"docker", "kubectl"}:
            tmo = float(kwargs.get("timeout") or 5.0)
            time.sleep(tmo)
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=tmo)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)
    # 让容器扫描认为 docker 可用，从而真的走到外部命令
    monkeypatch.setattr(
        _shutil, "which",
        lambda name: "/usr/bin/docker" if name in {"docker", "kubectl"} else None)

    t0 = time.monotonic()
    rep = hostcheck.run_host_check(budget_seconds=8.0)
    elapsed = time.monotonic() - t0

    assert elapsed < 45.0, (
        f"docker 卡住时取证耗时 {elapsed:.1f} 秒（预算 8 秒）—— "
        f"说明容器清点没拿到 deadline 或没按剩余预算收敛")
    assert rep is not None


def test_scan_containers_accepts_deadline() -> None:
    """容器清点必须能接收截止时刻（否则无法被总预算约束）。"""
    import inspect

    from p2s.core import containers

    assert "deadline" in inspect.signature(containers.scan_containers).parameters, (
        "scan_containers 缺少 deadline 参数")
    assert "deadline" in inspect.signature(containers.scan_kubernetes).parameters, (
        "scan_kubernetes 缺少 deadline 参数")


def test_scan_containers_stops_at_deadline(monkeypatch) -> None:
    """已超过截止时刻时，容器清点必须立刻返回并说明跳过原因。"""
    from p2s.core import containers

    monkeypatch.setattr(containers, "docker_available", lambda: True)
    monkeypatch.setattr(containers, "list_containers",
                        lambda: [{"id": "a", "image": "php:8.2-fpm", "name": "c1"}])
    items, notes = containers.scan_containers(deadline=time.monotonic() - 1)
    assert notes, "超时跳过后必须给出说明"
    assert any("时间预算" in n for n in notes), f"说明里没提预算：{notes}"


def test_single_huge_directory_is_interruptible(tmp_path: Path) -> None:
    """**单个**巨型目录也必须能在预算内被打断。

    这是 CI 挂 4 轮的真正原因：runner 的 /opt 里挂着托管工具缓存，
    单个目录就有几十万个条目。os.walk 在产出第一个结果之前会先把整目录
    读进内存（os.scandir 一次列全），这段没有任何检查点 ——
    20 秒预算照样跑 6 分钟以上。

    改成手动递归 + 逐条目检查预算后，这个场景才有上界。
    """
    import os

    big = tmp_path / "huge"
    big.mkdir()
    future = time.time() + 600
    # 一个目录里塞满文件（不建子目录，专测"单目录过大"）
    for i in range(6000):
        p = big / f"n{i}.log"
        p.write_bytes(b"D")
        os.utime(p, (future, future))

    t0 = time.monotonic()
    got = list(hostcheck._iter_recent_files(
        [big], hostcheck.datetime.now(), deadline=time.monotonic() + 0.3))
    elapsed = time.monotonic() - t0

    assert elapsed < 20.0, (
        f"单个大目录下遍历耗时 {elapsed:.1f} 秒 —— "
        f"说明预算检查点不够细（os.walk 会一次性列全目录）")
    assert len(got) < 6000, f"没有提前停止（取了 {len(got)} 个）"


def test_scan_artifacts_interrupts_in_huge_directory(tmp_path: Path, monkeypatch) -> None:
    """scan_artifacts 在巨型单目录里也要按预算收工，并报告截断。"""
    import os

    monkeypatch.setattr(hostcheck, "_scan_dirs", lambda: [tmp_path])
    big = tmp_path / "cache"
    big.mkdir()
    future = time.time() + 600
    for i in range(3000):
        p = big / f"c{i}.php"
        p.write_bytes(b"<?php echo 1;" * 100)
        os.utime(p, (future, future))

    t0 = time.monotonic()
    arts = hostcheck.scan_artifacts(since=hostcheck.datetime.now(), budget_seconds=1.0)
    elapsed = time.monotonic() - t0

    # 这里断言的是"有界"，**不是**"一定截断"：
    # 快机器上 3000 个文件不到 1 秒就扫完了，此时不截断才是正确行为。
    # 之前写成"必须截断"，在 GitHub runner 上就误报了（0.52 秒扫完，不该有截断）。
    assert elapsed < 30.0, f"scan_artifacts 在巨型目录下耗时 {elapsed:.1f} 秒"
    kinds = {a.kind for a in arts}
    truncated = "scan_truncated" in kinds
    if truncated:
        # 一旦报截断，就必须给出可见的说明（不能是空记录）
        note = next(a for a in arts if a.kind == "scan_truncated")
        assert "预算" in note.detail, f"截断记录缺少说明：{note.detail}"
    else:
        # 没截断就说明真的扫完了 —— 至少要扫到那些 .php 文件
        assert any(a.kind == "recent_script" for a in arts), (
            f"既没截断也没扫到文件，说明遍历逻辑坏了：kinds={kinds}")
