"""前端静态资源的结构测试。

起因：抽取样式表时按含 'mono' 的行删除，连带删掉了若干续行的 `}` 与选择器行：
  - `pre{...` 少 `}`  → 之后所有规则被 CSS 嵌套吞掉
  - `.evi{...` 少 `}` → 再吞一批
  - `.port{...` 丢选择器行 → 剩下一行孤立属性
结果：表格行高 107px、操作按钮竖排、顶栏按钮掉到视口上方。
花括号总数仍然"配平"（362/362），所以只查数量根本发现不了——必须查结构。
"""
from __future__ import annotations

import pathlib
import re

CONSOLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "p2s" / "console"
CSS = CONSOLE / "templates" / "app.css"
TPL = CONSOLE / "templates"

TOP_LEVEL_OK = (".top-actions", ".kpi", ".pbar", ".modal", ".topbar", ".card")


def _lines() -> list[str]:
    return CSS.read_text(encoding="utf-8").splitlines()


def test_css_braces_balanced() -> None:
    s = CSS.read_text(encoding="utf-8")
    assert s.count("{") == s.count("}"), (
        f"CSS 花括号不配平：{s.count('{')} 开 / {s.count('}')} 闭")


def test_css_depth_never_negative() -> None:
    depth = 0
    for i, line in enumerate(_lines(), 1):
        depth += line.count("{") - line.count("}")
        assert depth >= 0, f"第 {i} 行出现多余的 }}"


def test_css_ends_at_depth_zero() -> None:
    depth = sum(ln.count("{") - ln.count("}") for ln in _lines())
    assert depth == 0, f"文件结束时仍嵌套 {depth} 层，说明有规则没闭合"


def test_cross_line_rules_close_before_next_selector() -> None:
    """跨行规则必须在下一个顶层选择器出现前闭合。

    这是真正能抓到"少一个 } 导致后半段失效"的检查——括号数量平衡时它照样能发现。
    """
    lines = _lines()
    depth = 0
    open_at: int | None = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if depth == 0 and "{" in line and not stripped.startswith(("/*", "*", "@")):
            if line.count("{") > line.count("}"):
                open_at = i
        depth += line.count("{") - line.count("}")
        if open_at and depth == 0:
            open_at = None
        elif open_at and i > open_at and depth >= 1 and line and not line[0].isspace():
            nxt = stripped
            if nxt and "{" in nxt and not nxt.startswith(("/*", "*", "@", "}", ")")):
                raise AssertionError(
                    f"第 {open_at} 行的规则没闭合，第 {i} 行又开始了新规则：{nxt[:60]}")


def test_key_selectors_are_top_level() -> None:
    """关键选择器必须位于顶层；被嵌套就意味着它们不会生效。"""
    depth = 0
    seen: dict[str, int] = {}
    for i, line in enumerate(_lines(), 1):
        if depth == 0:
            for sel in TOP_LEVEL_OK:
                if line.startswith(sel + "{") or line.startswith(sel + " "):
                    seen.setdefault(sel, depth)
        depth += line.count("{") - line.count("}")
    for sel in TOP_LEVEL_OK:
        assert sel in seen or sel in ("",), f"{sel} 没出现在顶层"


def test_no_control_chars_in_assets() -> None:
    for f in [CSS, *TPL.glob("*.html")]:
        assert "\r" not in f.read_text(encoding="utf-8"), f"{f.name} 含回车符"


def test_templates_present() -> None:
    for name in ("dashboard.html", "login.html", "app.css"):
        assert (TPL / name).exists(), f"缺少模板 {name}"


def test_no_duplicate_selector_definitions() -> None:
    """.pbar 曾被定义两遍，后写的静默覆盖前面的。"""
    s = CSS.read_text(encoding="utf-8")
    for sel in (".pbar", ".kpi", ".top-actions"):
        n = len(re.findall(r"^" + re.escape(sel) + r"\{", s, re.M))
        assert n <= 1, f"{sel} 被定义了 {n} 次"
