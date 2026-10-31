"""前端静态资源的结构测试。

起因：抽取样式表时误删了含 `monospace` 的那一行，连带删掉了 `pre{...}` 的闭合 `}`，
导致之后所有规则被 CSS 嵌套吞掉——表格行高从 47px 变成 107px、操作列从横排变竖排。
所有语法检查（ruff / node --check / HTML 配平）都发现不了，只有肉眼看截图才能发现。
"""
from __future__ import annotations

import pathlib
import re

CONSOLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "p2s" / "console"
CSS = CONSOLE / "templates" / "app.css"
TPL = CONSOLE / "templates"


def test_css_braces_balanced() -> None:
    """花括号必须配平：少一个 } 会让后面所有规则失效。"""
    s = CSS.read_text(encoding="utf-8")
    assert s.count("{") == s.count("}"), (
        f"CSS 花括号不配平：{s.count('{')} 开 / {s.count('}')} 闭")


def test_css_never_negative_depth() -> None:
    """不允许出现"多一个 }"——同样会让后面的规则错位。"""
    depth = 0
    for i, line in enumerate(CSS.read_text(encoding="utf-8").splitlines(), 1):
        depth += line.count("{") - line.count("}")
        assert depth >= 0, f"第 {i} 行出现了多余的 }}"


def test_no_control_chars_in_assets() -> None:
    for f in [CSS, *TPL.glob("*.html")]:
        s = f.read_text(encoding="utf-8")
        assert "\r" not in s, f"{f.name} 含回车符，可能被模板转义破坏"


def test_templates_present() -> None:
    for name in ("dashboard.html", "login.html", "app.css"):
        assert (TPL / name).exists(), f"缺少模板 {name}"


def test_no_duplicate_selector_blocks_for_pbar() -> None:
    """.pbar 曾被定义两遍，后写的静默覆盖前面的（踩过一次）。"""
    s = CSS.read_text(encoding="utf-8")
    defs = len(re.findall(r"^\.pbar\{", s, re.M))
    assert defs <= 1, f".pbar 被定义了 {defs} 次，后面的会静默覆盖前面的"
