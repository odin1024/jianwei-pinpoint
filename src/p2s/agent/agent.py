"""p2s 轻量 Agent —— 在被检查的主机上运行，执行 L3 主机侧检测并上报。

为什么需要 Agent：
  L3 检测（生效配置、可疑文件、进程、连接）必须在目标主机本地执行，
  靠远程探测拿不到这些信息。

部署（客户主机）：
    pip install p2s            # 或从源码安装
    p2s-agent --console http://console.internal:8080 --interval 3600

    Windows 计划任务 / Linux systemd timer 均可调度。
"""
from __future__ import annotations

import argparse
import os
import platform
import sys
import time
from datetime import datetime

import httpx

from ..core import hostcheck
from ..core.report import ScanResult, to_json


def collect() -> dict:
    rep = hostcheck.run_host_check(deep=True)
    return rep.to_dict()


def post_console(console: str, payload: dict, timeout: float = 30.0) -> None:
    url = console.rstrip("/") + "/api/agent/report"
    with httpx.Client(timeout=timeout) as c:
        r = c.post(url, json={"hostname": platform.node(), "data": payload})
        r.raise_for_status()
        print(f"已上报到 {url} -> {r.status_code}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="p2s-agent", description="p2s 主机侧检测 Agent")
    p.add_argument("--console", help="控制台地址，例如 http://127.0.0.1:8080")
    p.add_argument("--interval", type=int, default=0, help="循环上报间隔（秒），0 表示只跑一次")
    p.add_argument("--out", help="把本地报告同时写入该目录")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args(argv)

    while True:
        payload = collect()
        risk = payload.get("risk")
        print(f"[{datetime.now().isoformat(timespec='seconds')}] "
              f"{payload.get('hostname')} 风险={risk} "
              f"痕迹={len(payload.get('artifacts', []))}")

        if args.out:
            res = ScanResult(scan_id=f"agent-{int(time.time())}", kind="agent",
                             started_at=datetime.now().isoformat(timespec="seconds"))
            res.target_count = 1
            res.host_reports = [payload]
            to_json(res, os.path.join(args.out, "host-report.json"))
            print(f"本地报告已写入 {args.out}")

        if args.console:
            try:
                post_console(args.console, payload, args.timeout)
            except Exception as exc:  # noqa: BLE001
                print(f"上报失败: {exc}", file=sys.stderr)

        if args.interval <= 0:
            break
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
