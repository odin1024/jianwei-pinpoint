"""控制台验收脚本 —— 一条命令跑完本轮所有关键行为。

    P2S_CONSOLE_PASSWORD=你的口令 python scripts/verify_console.py
    python scripts/verify_console.py --base http://127.0.0.1:18080 --password xxx

覆盖：健康检查、未登录拦截、登录取会话、错误口令、导出格式、日志上传、
后台任务全流程、已删除的同步端点、登出失效。

退出码：0 全通过；1 有失败项。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _console_auth import credentials  # noqa: E402

RESULTS: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    RESULTS.append((bool(ok), name, detail))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:18080")
    # 口令来源：--password > P2S_ADMIN_PASSWORD > P2S_CONSOLE_PASSWORD
    # 1.0.5 起控制台不再有内置默认口令，脚本必须显式拿到凭据（此前这里只认
    # --password，而文档写的是环境变量，导致按文档跑会静默 401、只跑 6 项就退出）
    ap.add_argument("--password", default="")
    ap.add_argument("--sample", default=str(Path(__file__).resolve().parent.parent / "examples" / "access.log.sample"))
    args = ap.parse_args()

    if not args.password:
        args.password = credentials()["password"]

    base = args.base.rstrip("/")
    with httpx.Client(base_url=base, timeout=30.0, follow_redirects=False) as c:
        # 1) 健康检查（无需登录）
        r = c.get("/api/health")
        check(r.status_code == 200, "健康检查可匿名访问", f"{r.status_code} {r.text[:60]}")

        # 2) 未登录拦截
        r = c.get("/api/overview")
        check(r.status_code == 401, "未登录访问 API 返回 401", str(r.status_code))
        r = c.get("/")
        check(r.status_code in (302, 307) and r.headers.get("location") == "/login",
              "未登录访问首页跳转登录页", f"{r.status_code} -> {r.headers.get('location')}")
        r = c.get("/login")
        check(r.status_code == 200 and "见微" in r.text, "登录页可访问", str(r.status_code))

        # 3) 错误口令
        r = c.post("/api/login", json={"password": "definitely-wrong"})
        check(r.status_code == 401, "错误口令被拒绝", str(r.status_code))

        # 4) 正确口令
        r = c.post("/api/login", json={"password": args.password})
        check(r.status_code == 200, "正确口令登录成功", str(r.status_code))
        if r.status_code != 200:
            return report()

        r = c.get("/api/overview")
        check(r.status_code == 200, "登录后可访问 API", str(r.status_code))
        overview = r.json() if r.status_code == 200 else {}
        check(isinstance(overview.get("total_assets"), int), "总览返回资产数",
              f"assets={overview.get('total_assets')} scans={overview.get('scan_count')}")

        # 5) 安全响应头
        r = c.get("/api/health")
        check(r.headers.get("x-content-type-options") == "nosniff", "带 nosniff 安全头")
        check(r.headers.get("x-frame-options") == "SAMEORIGIN", "带 X-Frame-Options")

        # 6) 规则导出
        for fmt, must in (("sigma", "title:"), ("modsecurity", "SecRule"), ("suricata", "alert http")):
            r = c.get(f"/api/rules/export/{fmt}")
            check(r.status_code == 200 and must in r.text, f"规则导出 {fmt}",
                  f"{r.status_code} {len(r.text)}B")
            check("attachment" in r.headers.get("content-disposition", ""),
                  f"规则导出 {fmt} 带下载文件名")

        # 7) CSV 导出
        r = c.get("/api/assets/export")
        check(r.status_code == 200 and r.headers.get("content-type", "").startswith("text/csv"),
              "资产 CSV 导出 MIME 正确", r.headers.get("content-type", ""))
        check(r.content.startswith("\ufeff".encode()), "CSV 带 UTF-8 BOM（Excel 不乱码）")

        # 8) 日志路径白名单
        r = c.post("/api/jobs", json={"kind": "logs", "path": r"C:\Windows\win.ini"})
        check(r.status_code == 403, "白名单外的日志路径被拒绝", str(r.status_code))

        # 9) 上传并分析
        sample = Path(args.sample)
        if sample.exists():
            with sample.open("rb") as fh:
                r = c.post("/api/scan/logs/upload", files={"file": (sample.name, fh, "text/plain")})
            ok = r.status_code == 200 and len(r.json().get("findings", [])) > 0
            check(ok, "上传日志并产出命中",
                  f"{r.status_code} 命中={len(r.json().get('findings', [])) if r.status_code == 200 else '-'}")
            if r.status_code == 200:
                check(bool(r.json().get("finished_at")), "报告结束时间非空",
                      str(r.json().get("finished_at")))
        else:
            check(False, "示例日志存在", str(sample))

        # 10) 后台任务全流程
        r = c.post("/api/jobs", json={"kind": "logs", "path": str(sample)})
        check(r.status_code == 200, "提交后台任务", str(r.status_code))
        if r.status_code == 200:
            jid = r.json()["id"]
            state = ""
            for _ in range(60):
                time.sleep(0.4)
                j = c.get(f"/api/jobs/{jid}").json()
                state = j.get("state", "")
                if state in ("done", "failed", "cancelled"):
                    break
            check(state == "done", "后台任务执行完成", f"state={state} progress={j.get('progress')}")
            check("active" in j, "任务字典含 active 字段（前端 KPI 依赖）", str(j.get("active")))

        # 11) 已删除的同步端点
        for path, payload in (("/api/scan/logs", {"path": "x"}),
                              ("/api/discover", {"hosts": ["127.0.0.1"]}),
                              ("/api/scan/host", {})):
            r = c.post(path, json=payload)
            check(r.status_code in (404, 405), f"同步端点已下线 {path}", str(r.status_code))

        # 12) Agent 上报鉴权
        r = c.post("/api/agent/report", json={"hostname": "verify", "data": {}})
        check(r.status_code == 401, "Agent 上报缺令牌被拒绝", str(r.status_code))

        # 13) 登出
        c.post("/api/logout")
        r = c.get("/api/assets")
        check(r.status_code == 401, "登出后会话失效", str(r.status_code))

    return report()


def report() -> int:
    print()
    width = max(len(n) for _, n, _ in RESULTS)
    failed = 0
    for ok, name, detail in RESULTS:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name:<{width}}  {detail}")
        failed += 0 if ok else 1
    print(f"\n  合计 {len(RESULTS)} 项，通过 {len(RESULTS) - failed}，失败 {failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
