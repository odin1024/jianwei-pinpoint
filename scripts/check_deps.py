"""依赖与供应链检查（离线可用，不依赖 pip-audit 网络查询）。

做两件事：
  1. **清单审计**：把 requirements / pyproject 的依赖列出来，核对是否有未使用的重依赖
     （本项目历史上删过从未 import 的 jinja2 / pyyaml）；
  2. **可选在线审计**：检测到 pip-audit 时调用它；没有就明确提示，而不是假装检查过。

用法：
    python scripts/check_deps.py            # 只做离线审计
    python scripts/check_deps.py --online   # 有 pip-audit 时联网查 CVE
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "p2s"


def declared_requirements() -> dict[str, str]:
    """从 pyproject 读 dependencies（不引入 tomllib 以兼容 3.9）。"""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", text)
    out: dict[str, str] = {}
    if not block:
        return out
    # 依赖可能写在一行里，也可能分到 [project.optional-dependencies] 各组，统一按引号提取
    chunks = [block.group(1)]
    opt = re.search(r"(?ms)^\[project\.optional-dependencies\](.*?)(?=^\[|\Z)", text)
    if opt:
        chunks.append(opt.group(1))
    for chunk in chunks:
        for raw in re.findall(r'"([^"]+)"', chunk):
            name = re.split(r"[<>=!~\[ ]", raw.strip(), maxsplit=1)[0].strip().lower()
            if name:
                out[name] = ""
    return out


def imported_modules() -> set[str]:
    """扫描源码里实际 import 的顶层模块名。"""
    mods: set[str] = set()
    for p in SRC.rglob("*.py"):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    mods.add(a.name.split(".")[0].lower())
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods.add(node.module.split(".")[0].lower())
    return mods


#: 包名 → 实际 import 名（两者经常不一致）
IMPORT_ALIAS = {
    "python-multipart": "multipart",
    "pydantic": "pydantic",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "httpx": "httpx",
    "cryptography": "cryptography",
    "pytest": "pytest",
    "ruff": "ruff",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true", help="有 pip-audit 时联网查询已知漏洞")
    args = ap.parse_args()

    declared = declared_requirements()
    used = imported_modules()
    print(f"声明依赖 {len(declared)} 个，源码 import 的顶层模块 {len(used)} 个\n")

    #: 由框架间接使用、源码里不会直接 import 的运行时依赖（不能算"未使用"）
    INDIRECT = {"python-multipart"}       # FastAPI 解析 UploadFile 时自己导入
    DEV_TOOLS = {"pytest", "ruff", "coverage"}

    unused, dev_only = [], []
    for pkg in sorted(declared):
        mod = IMPORT_ALIAS.get(pkg, pkg.replace("-", "_"))
        if mod in used or pkg in INDIRECT:
            continue
        (dev_only if pkg in DEV_TOOLS else unused).append(pkg)
    if dev_only:
        print("ℹ️  仅测试/构建使用（预期不在 src 中 import）：", "、".join(dev_only))
    if unused:
        print("⚠️  可能未被使用的依赖（需人工确认，测试/构建工具也会声明在这）：")
        for u in unused:
            print("   -", u)
    else:
        print("✅ 所有运行时依赖都能在源码里找到对应 import")

    if args.online:
        exe = shutil.which("pip-audit")
        if not exe:
            print("\n⚠️  未安装 pip-audit，本次**没有**做漏洞库比对。")
            print("   安装后重试： pip install pip-audit")
        else:
            print("\n运行 pip-audit …")
            rc = subprocess.call([exe, "-r", "pyproject.toml"])
            if rc != 0:
                print("❌ pip-audit 报告了问题（见上方输出）")
                return rc
            print("✅ pip-audit 未发现已知漏洞")
    else:
        print("\n（未加 --online，仅做离线清单审计）")

    return 0


if __name__ == "__main__":
    sys.exit(main())
