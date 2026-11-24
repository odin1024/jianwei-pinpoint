"""版本号规则：MAJOR.MINOR.PATCH，每段 0–9，满 10 进位。

为什么要这条规则
----------------
`0.26.0` 这种编号会让客户以为"改了 26 轮还没发布"，也让发布记录难以扫读。
改成三段各 0–9：MINOR 到 9 再加就进 MAJOR，PATCH 到 9 再加就进 MINOR。
这样版本号永远短、永远可读，且仍保留"改了多少次"的信息（进位即累计）。
"""
from __future__ import annotations

import re

PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
MAX = 9


def parse(version: str) -> tuple[int, int, int]:
    m = PATTERN.match(version.strip())
    if not m:
        raise ValueError(f"版本号格式应为 MAJOR.MINOR.PATCH：{version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def is_valid(version: str) -> bool:
    try:
        major, minor, patch = parse(version)
    except ValueError:
        return False
    return all(0 <= x <= MAX for x in (major, minor, patch))


def bump(version: str, kind: str = "patch") -> str:
    """按规则递增。kind: patch | minor | major。满 10 自动进位。"""
    major, minor, patch = parse(version)
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        minor += 1
        if minor > MAX:
            return f"{major + 1}.0.0"
        return f"{major}.{minor}.0"
    patch += 1
    if patch > MAX:
        patch = 0
        minor += 1
        if minor > MAX:
            return f"{major + 1}.0.0"
    return f"{major}.{minor}.{patch}"


def explain(version: str) -> str:
    major, minor, patch = parse(version)
    return (f"第 {major} 代 · 第 {minor} 个次要版本 · 第 {patch} 个修订"
            f"（每段上限 {MAX}，满 {MAX + 1} 进位）")
