"""一致性门禁：前端 api() 调用 vs 后端实际注册的路由。

为什么需要：前端调了一个后端不存在的接口时，表现为"点了没反应"或 404，
而 pytest / ruff / node --check / 验收脚本都发现不了 —— 只有真点下去才知道。
本项目已经踩过两次同类坑（弹窗没加 on、scan_api 漏导入）。

路由来源优先级：运行中服务的 /openapi.json → 退化为扫描 @router 装饰器。
"""
from __future__ import annotations

import http.cookiejar
import json
import pathlib
import re
import sys
import urllib.request as u

BASE = "http://127.0.0.1:18080"
CONSOLE = pathlib.Path(__file__).resolve().parent.parent / "src" / "p2s" / "console"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _console_auth import credentials  # noqa: E402


def frontend_calls() -> set[str]:
    out: set[str] = set()
    files = list((CONSOLE / "ui_pages" / "js").glob("*.js")) + [CONSOLE / "templates" / "dashboard.html"]
    for f in files:
        txt = f.read_text(encoding="utf-8")
        # 捕获后还要看紧跟的字符：若是 + 或模板变量，说明是前缀拼接
        for m in re.finditer(r"""api\(\s*['"`](/api/[^'"`]*)['"`]\s*([+]?)""", txt):
            path, concat = m.group(1), m.group(2)
            out.add(path + "{}" if (concat or path.endswith("/")) else path)
    return out


def backend_paths() -> set[str]:
    cj = http.cookiejar.CookieJar()
    op = u.build_opener(u.HTTPCookieProcessor(cj))
    try:
        op.open(u.Request(f"{BASE}/api/login",
                          data=json.dumps(credentials()).encode(),
                          headers={"Content-Type": "application/json"}, method="POST"),
                timeout=10)
        raw = op.open(f"{BASE}/openapi.json", timeout=15).read()
        return set(json.loads(raw).get("paths", {}))
    except Exception:
        # 兜底：扫描装饰器（覆盖全部 console 模块）
        found: set[str] = set()
        for f in CONSOLE.glob("*.py"):
            for m in re.finditer(r'@router\.(?:get|post|patch|delete|put)\(\s*"([^"]+)"',
                                 f.read_text(encoding="utf-8")):
                found.add(m.group(1))
        return found


def canon(path: str) -> str:
    """把 ${x} / {x} / 具体 ID 统一成 {}；但保留 cancel、export 这类动作名。"""
    p = path.split("?")[0].rstrip("/")
    p = re.sub(r"\$\{[^}]*\}", "{}", p)          # 模板变量
    p = re.sub(r"\{[^}]*\}", "{}", p)            # FastAPI 路径参数
    # 只把"像 ID"的末段归一（含数字、长 hex、带扩展名）
    p = re.sub(r"/[0-9a-fA-F]{6,}$", "/{}", p)
    p = re.sub(r"/\d+$", "/{}", p)
    p = re.sub(r"/[^/{}]+\.(json|md|html|csv)$", "/{}", p)
    return p


def main() -> int:
    calls = frontend_calls()
    paths = backend_paths()
    if not paths:
        print("[SKIP] 拿不到后端路由表，跳过一致性检查")
        return 0

    known = {canon(p) for p in paths}
    known_raw = {p.rstrip("/") for p in paths}
    missing: list[str] = []
    for c in sorted(calls):
        if c.rstrip("/") in known_raw or canon(c) in known:
            continue
        missing.append(c)

    print(f"前端调用 {len(calls)} 个接口 / 后端注册 {len(paths)} 个路由")
    if missing:
        print(f"[FAIL] {len(missing)} 个调用在后端找不到：")
        for m in missing:
            seg = "/".join(m.split("/")[:3])
            near = sorted(p for p in paths if p.startswith(seg))
            print(f"   - {m}" + (f"    同段可用：{near[:3]}" if near else ""))
        return 1
    print("[OK] 前端所有 api() 调用都能在后端找到对应路由")
    return 0


if __name__ == "__main__":
    sys.exit(main())
