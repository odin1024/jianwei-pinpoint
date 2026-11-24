"""把当前仓库打成两个交付 zip。

    python tools/package_release.py            # 输出到 dist/
    python tools/package_release.py --out D:/out

产出：
  dist/见微Pinpoint-v0.5.1.zip        完整交付包（文档 + 源码 + 样例，不含 .venv/.git/运行时数据）
  dist/php2shell-sentinel-0.5.1.zip   仅源码包（给只要工具的客户）

排除规则是白名单驱动的：只收「应该交付」的目录，避免把 .venv、p2s-data、
缓存、密钥之类打进去。
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _version() -> str:
    """从 p2s.__version__ 读取，避免打包版本号与代码漂移。"""
    src = (ROOT / "app" / "src" / "p2s" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', src, re.MULTILINE)
    if not m:
        raise SystemExit("无法从 app/src/p2s/__init__.py 解析 __version__")
    return m.group(1)


VERSION = _version()

#: 完整交付包收录的顶层目录/文件
BUNDLE = [
    "README.md",
    "app/src", "app/tests", "app/scripts", "app/examples", "app/docs", "app/.github",
    "app/Dockerfile", "app/docker-compose.yml", "app/Makefile", "app/pyproject.toml",
    "app/README.md", "app/.gitignore",
    "docs", "samples",
]

#: 仅源码包收录
CODE = [
    "src", "tests", "scripts", "examples", "docs", ".github",
    "Dockerfile", "docker-compose.yml", "Makefile", "pyproject.toml", "README.md", ".gitignore",
]

SKIP_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
             "p2s-data", "reports", "node_modules", ".run"}
SKIP_SUFFIX = {".pyc", ".pyo", ".tmp"}
SKIP_NAMES = {".p2s-port", "host-report.json"}


def add_path(zf: zipfile.ZipFile, base: Path, rel: str, prefix: str) -> int:
    src = base / rel
    n = 0
    if src.is_file():
        zf.write(src, f"{prefix}{rel}")
        return 1
    if not src.is_dir():
        print(f"  ! 跳过（不存在）: {rel}")
        return 0
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        parts = set(p.relative_to(base).parts)
        if parts & SKIP_DIRS:
            continue
        if p.suffix.lower() in SKIP_SUFFIX or p.name in SKIP_NAMES:
            continue
        arc = prefix + str(p.relative_to(base)).replace("\\", "/")
        zf.write(p, arc)
        n += 1
    return n


def build(out: Path, name: str, entries: list[str], base: Path, prefix: str) -> Path:
    target = out / name
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        total = 0
        for rel in entries:
            total += add_path(zf, base, rel, prefix)
    print(f"  {name}  {total} 文件  {target.stat().st_size / 1024:.0f} KB")
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    args = ap.parse_args(argv)
    out = Path(args.out)
    if not args.out.startswith(str(ROOT)) and not Path(args.out).is_absolute():
        out = ROOT / args.out

    print(f"打包 v{VERSION} → {out}")
    build(out, f"见微Pinpoint-v{VERSION}.zip", BUNDLE, ROOT, "")
    build(out, f"php2shell-sentinel-{VERSION}.zip", CODE, ROOT / "app", "php2shell-sentinel/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
