"""文档数字漂移检查：README 声称的指标必须与仓库实际一致。

为什么需要
----------
README 里写着"537 passed（43 个用例文件）"这类数字。代码一改，这些数字就过期，
而**没有任何门禁会发现**——文档开始说谎，读者却以为是真的。
本项目已经踩过：README 曾长期写"134 passed / 版本 1.0.4"，实际早已是 500+。

做法
----
只校验**能静态判定**的项（不跑测试，避免门禁跑测试导致递归/变慢）：
  · 用例文件数
  · 版本号（README / pyproject / __init__ 三者一致）
  · 规则条数
运行 `pytest` 时若 README 写死 passed 数，无法静态核对 ——
所以规定：**README 只写"用例文件数"与"版本号"，不写 passed 数**（会随环境变）。
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT.parent / "README.md"


def _readme() -> str:
    if not README.exists():
        pytest.skip("未找到项目根 README")
    return README.read_text(encoding="utf-8")


def test_test_file_count_matches_readme() -> None:
    """README 里的"N 个用例文件"必须等于实际 test_*.py 数量。"""
    text = _readme()
    m = re.search(r"（(\d+) 个用例文件）", text)
    if not m:
        pytest.skip("README 未声明用例文件数")
    claimed = int(m.group(1))
    actual = len(list((ROOT / "tests").glob("test_*.py")))
    assert claimed == actual, (
        f"README 写 {claimed} 个用例文件，实际 {actual} 个 —— 改了测试请同步 README")


def test_version_consistent() -> None:
    """版本号：__init__.py / pyproject.toml 必须一致（README 允许不写）。"""
    import p2s

    declared = p2s.__version__
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert m, "pyproject.toml 缺少 version"
    assert m.group(1) == declared, (
        f"pyproject {m.group(1)} != __init__ {declared}")


def test_rule_count_matches_readme() -> None:
    """README 若声明规则条数，必须与 rulebook 实际一致。

    首列允许加粗（`| **加固规则库** |`）—— 曾经因为不接受加粗，
    这个门禁静默跳过了，等于没检查。
    """
    text = _readme()
    m = re.search(r"\*{0,2}加固规则库\*{0,2}\s*\|\s*\*\*(\d+) 条\*\*", text)
    if not m:
        pytest.skip("README 未声明规则条数")
    claimed = int(m.group(1))
    from p2s.core import rulebook

    actual = len(rulebook.ALL)
    assert claimed == actual, (
        f"README 写 {claimed} 条规则，实际 {actual} 条")


def test_version_badge_matches_package() -> None:
    """README 顶部的版本徽章必须与包版本一致。

    徽章是静态文本（shields.io 的 `badge/version-X-...`），不会自动更新。
    发版时忘了改，首页就会长期挂着一个旧版本号 —— 这正是"文档说谎"最典型的形态。
    所以把徽章也纳入门禁。
    """
    text = _readme()
    m = re.search(r"badge/version-([0-9]+\.[0-9]+\.[0-9]+)-", text)
    if not m:
        pytest.skip("README 没有版本徽章")
    import p2s

    assert m.group(1) == p2s.__version__, (
        f"README 版本徽章写 {m.group(1)}，实际包版本 {p2s.__version__} —— 发版时请同步徽章")


def test_readme_does_not_hardcode_passed_count() -> None:
    """README 不应写死 passed 数：它随 Python 版本/跳过条件变化，必然漂移。

    允许出现"537 passed"这种形式**仅当**它出现在测试命令的注释里作为示例，
    但正文表格里的"单元测试 | N passed"会误导读者 —— 改为要求写明实测日期。
    """
    text = _readme()
    rows = re.findall(r"\|\s*单元测试\s*\|\s*\*\*(\d+) passed\*\*", text)
    if not rows:
        return  # 没写就不违规
    # 写了就必须注明验证日期，读者才能判断新鲜度
    assert "（2026-" in text or "（20" in text, (
        "README 声明了 passed 数，但未注明验证日期 —— 数字会过期，必须带日期")