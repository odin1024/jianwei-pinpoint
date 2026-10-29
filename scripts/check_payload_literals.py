"""守护检查：源码中不得出现**完整可执行**的 PHP 载荷字面量。

为什么需要这个：
  交付给客户时，工具源码会被杀毒软件 / EDR / 邮件网关扫描。
  如果源码里写死了完整的 webshell 一行式载荷（PHP 开标签 + 危险函数 + 结束标签），
  工具本身会被判定为恶意软件而无法安装、无法上报、无法启动。

规则：
  允许 —— 正则模式、关键字列表、独立片段（如单独的 PHP 开标签）
  禁止 —— 出现 PHP 开标签 + 危险函数 + 结束标签的完整一行式载荷

用法：python scripts/check_payload_literals.py [目录]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# 危险函数
DANGEROUS = r"(system|exec|shell_exec|passthru|popen|proc_open|eval|assert|create_function|pcntl_exec)"

# 完整一行式 webshell：PHP 开标签 ... 危险函数 ... PHP 结束标签
ONE_LINER = re.compile(
    r"<\?php"                      # PHP 开标签
    r"[^?\n]{0,200}?"              # 中间内容（不允许出现 ? 以免跨标签）
    r"\b" + DANGEROUS + r"\b"      # 危险函数
    r"[^?\n]{0,200}?"
    r"\?>",                        # PHP 结束标签
    re.IGNORECASE,
)

# 允许的片段（单独出现不算载荷）
ALLOWED_FRAGMENTS = {"<?php", "?>", "<?="}


def scan_text(text: str) -> list[str]:
    hits: list[str] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped in ALLOWED_FRAGMENTS:
            continue
        if ONE_LINER.search(line):
            hits.append(f"L{line_no}: {stripped[:120]}")
    return hits


def scan_dir(root: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in {".py", ".md", ".yaml", ".yml", ".json", ".txt", ".html", ".conf", ".rules"}:
            continue
        if any(part in {".venv", ".git", "__pycache__", "node_modules", "reports", "p2s-data"} for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hits = scan_text(text)
        if hits:
            out[str(p)] = hits
    return out


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    roots = [Path(a) for a in argv] or [Path(__file__).resolve().parent.parent]
    problems: dict[str, list[str]] = {}
    for r in roots:
        target = r if r.is_dir() else r.parent
        problems.update(scan_dir(target))

    if not problems:
        print("[OK] 未发现完整 PHP 载荷字面量 —— 工具可安全交付，不会被杀毒误报")
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