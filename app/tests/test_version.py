"""版本号一致性校验：三处必须一致，且 CHANGELOG 有对应条目。

版本号唯一来源是 p2s.__version__；pyproject / CHANGELOG 是它的"投影"。
这条测试的价值在于：发布时漏改任何一处，CI 会直接失败。
"""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = ROOT.parent / "CHANGELOG.md"


def test_version_matches_pyproject():
    from p2s import __version__

    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert m, "pyproject.toml 里找不到 version"
    assert m.group(1) == __version__, (
        f"版本不一致：pyproject={m.group(1)} / __init__={__version__}"
    )


def test_version_in_changelog():
    from p2s import __version__

    assert CHANGELOG.exists(), f"缺少变更记录：{CHANGELOG}"
    text = CHANGELOG.read_text(encoding="utf-8")
    # CHANGELOG 的最新条目必须是当前版本
    headings = re.findall(r"(?m)^## \[([^\]]+)\]", text)
    assert headings, "CHANGELOG 里没有任何版本条目"
    assert headings[0] == __version__, (
        f"CHANGELOG 最新条目是 {headings[0]}，与当前版本 {__version__} 不一致；"
        "改版本号时请同步在 CHANGELOG 顶部加一节"
    )


def test_version_semver_shape():
    from p2s import __version__

    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), f"不是语义化版本：{__version__}"


def test_changelog_has_release_workflow():
    """发布流程必须写在 CHANGELOG 里，避免下一个人靠猜。"""
    text = CHANGELOG.read_text(encoding="utf-8")
    for kw in ("pytest", "ruff", "package_release.py", "verify_console.py"):
        assert kw in text, f"CHANGELOG 发布流程缺少：{kw}"


@pytest.mark.parametrize("fname", ["README.md", "docs/ARCHITECTURE.md", "docs/DETECTION.md"])
def test_docs_exist(fname):
    assert (ROOT / fname).exists(), f"缺少文档：{fname}"
