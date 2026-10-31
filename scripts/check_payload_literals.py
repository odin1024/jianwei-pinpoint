"""守护检查：源码中不得出现**完整可执行**的 PHP 载荷字面量。

为什么需要这个：
  交付给客户时，工具源码会被杀毒软件 / EDR / 邮件网关扫描。
  如果源码里写死了完整的 webshell 一行式载荷（PHP 开标签 + 危险函数 + 结束标签），
  工具本身会被判定为恶意软件而无法安装、无法上报、无法启动。

规则：
  允许 —— 正则模式、关键字列表、独立片段（如单独的 PHP 开标签）
  禁止 —— 出现 PHP 开标签 + 危险函数 + 结束标签的完整载荷（含跨行写法）

  说明：本检查只覆盖**代码与配置**（.py/.yaml/.json/.conf/.rules/.txt/.html）。
  Markdown 文档需要展示攻击样例，不在本检查范围内（用 --include-docs 可一并检查）。

用法：python scripts/check_payload_literals.py [目录] [--include-docs]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# 危险函数
DANGEROUS = (
    r"(system|exec|shell_exec|passthru|popen|proc_open|eval|assert|"
    r"create_function|pcntl_exec|call_user_func)"
)

# 完整 webshell：开标签（<?php / <?= / <?）... 危险函数 ... 结束标签
# 用 [\s\S] 而不是 . 是为了覆盖跨行写法；限制长度避免把整篇文档串起来。
ONE_LINER = re.compile(
    r"<\?(?:php|=)?"                 # PHP 开标签（长/短/短输出）
    r"(?:(?!\?>)[\s\S]){0,400}?"     # 中间内容，遇到 ?> 立即停
    r"\b" + DANGEROUS + r"\b"
    r"(?:(?!\?>)[\s\S]){0,400}?"
    r"\?>",
    re.IGNORECASE,
)

CODE_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".txt", ".html", ".conf", ".rules", ".ps1", ".sh", ".js"}
DOC_SUFFIXES = {".md"}
SKIP_PARTS = {".venv", ".git", "__pycache__", "node_modules", "reports", "p2s-data", "archive"}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_text(text: str) -> list[str]:
    """返回命中列表（含行号）。整篇扫描，能覆盖跨行拼写的载荷。"""
    hits: list[str] = []
    for m in ONE_LINER.finditer(text):
        snippet = re.sub(r"\s+", " ", text[m.start():m.end()])[:120]
        hits.append(f"L{_line_of(text, m.start())}: {snippet}")
    return hits


def scan_dir(root: Path, include_docs: bool = False) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    suffixes = CODE_SUFFIXES | (DOC_SUFFIXES if include_docs else set())
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in suffixes:
            continue
        if any(part in SKIP_PARTS for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_text(text)
        if hits:
            out[str(p)] = hits
    return out


def _ensure_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    args = list(sys.argv[1:] if argv is None else argv)
    include_docs = "--include-docs" in args
    roots = [Path(a) for a in args if not a.startswith("--")] or [Path(__file__).resolve().parent.parent]

    problems: dict[str, list[str]] = {}
    for r in roots:
        target = r if r.is_dir() else r.parent
        problems.update(scan_dir(target, include_docs=include_docs))

    if not problems:
        print(
            "[OK] 未发现完整 PHP 载荷字面量（代码/配置文件）。"
            "注意：这只覆盖「开标签+危险函数+结束标签」这一种形态，"
            "不构成「不会被杀毒误报」的保证。"
        )
        return 0
    print("[FAIL] 发现完整 PHP 载荷字面量，请改为拼接构造：\n")
    for path, hits in problems.items():
        print(f"  {path}")
        for h in hits:
            print(f"    {h}")
    print("\n参考：tests/test_rules.py 中的 PHP_OPEN / PHP_CLOSE 拼接写法。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
