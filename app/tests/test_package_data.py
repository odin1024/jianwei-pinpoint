"""包内数据文件必须被 git 跟踪 —— 防止"本地能跑、clone 下来报错"。

真实事故（2026-11-25 发布时发现）
--------------------------------
`app/.gitignore` 里有一行 `data/`，本意是忽略运行时数据目录，
但它匹配**任意层级的 data 目录**，于是把两个必需文件一并忽略了：

  · app/src/p2s/core/data/markers.json   ← 补丁标记库，patchmarkers.py 启动即读
  · app/data/benchmark.json              ← 基准集

本地一切正常（文件在磁盘上），推到 GitHub 后仓库里根本没有这两个文件，
任何人 clone 下来 `patchmarkers.load()` 会直接 FileNotFoundError。

根因：.gitignore 的 `data/` 匹配规则比作者以为的宽；而**没有任何门禁**
检查"运行时要读的文件是否真的在仓库里"。

本测试补上这一层：只检查运行时按路径读取的数据文件，不误伤新代码文件。
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent          # app/
ROOT = APP.parent                                      # 仓库根
PKG_DATA = APP / "src" / "p2s" / "core" / "data"
BENCH_DATA = APP / "data"


def _git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        pytest.skip(f"git 不可用或不在仓库内：{r.stderr[:120]}")
    return r.stdout


def _tracked() -> set[str]:
    return {line.strip() for line in _git("ls-files").splitlines() if line.strip()}


def _rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


@pytest.mark.parametrize("directory,label", [
    (PKG_DATA, "包内数据目录"),
    (BENCH_DATA, "基准集目录"),
])
def test_data_files_are_tracked(directory: Path, label: str) -> None:
    """数据目录下的每个文件都必须在 git 索引里。"""
    if not directory.exists():
        pytest.skip(f"{label}不存在：{directory}")
    tracked = _tracked()
    missing = [
        _rel(f) for f in sorted(directory.rglob("*"))
        if f.is_file() and f.suffix not in (".pyc",)
        and _rel(f) not in tracked
    ]
    assert not missing, (
        f"{label}里有文件未被 git 跟踪：{missing}\n"
        f"这会让 clone 下来的仓库缺少运行所需数据（本地能跑不代表别人能跑）")


def test_markers_json_not_ignored() -> None:
    """markers.json 不能被 .gitignore 匹配 —— 它是运行时必需的。"""
    target = PKG_DATA / "markers.json"
    if not target.exists():
        pytest.fail(f"缺少补丁标记库：{target}")
    r = subprocess.run(["git", "check-ignore", "-v", _rel(target)],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode != 0, (
        f"markers.json 被 .gitignore 忽略了：{r.stdout.strip()}\n"
        f"patchmarkers 会在 clone 后直接报错")


def test_benchmark_json_not_ignored() -> None:
    target = BENCH_DATA / "benchmark.json"
    if not target.exists():
        pytest.skip("没有基准集文件")
    r = subprocess.run(["git", "check-ignore", "-v", _rel(target)],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode != 0, f"benchmark.json 被 .gitignore 忽略：{r.stdout.strip()}"


def test_package_imports_without_local_data_dir() -> None:
    """标记库必须能从包内部路径加载（而不是依赖当前工作目录）。"""
    from p2s.core import patchmarkers as pm

    data = pm.load()
    assert data["cves"], "标记库应包含 CVE 列表"
    assert pm._DATA.exists(), f"数据文件路径不存在：{pm._DATA}"
    assert pm._DATA.is_relative_to(APP / "src"), "数据文件必须位于包内，随 wheel 分发"