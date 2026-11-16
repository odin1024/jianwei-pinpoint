"""p2s 轻量 Agent —— 在被检查的主机上运行，执行本地取证并上报。

为什么需要 Agent：
  L3 检测（生效配置、可疑文件、进程、连接）必须在目标主机本地执行，
  靠远程探测拿不到这些信息。

部署（客户主机）：
    pip install p2s
    p2s-agent --console http://console.internal:18080 --token <口令> --interval 3600

    Windows 计划任务 / Linux systemd timer 均可调度。
"""
from __future__ import annotations

import argparse
import os
import platform
import random
import signal
import sys
import time
from datetime import datetime

from ..core import hostcheck
from ..core.httpclient import make_client
from ..core.report import ScanResult, to_json

_STOP = False


def _ensure_utf8() -> None:
    """Windows 控制台默认 GBK，中文输出会乱码或直接 UnicodeEncodeError。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def collect() -> dict:
    return hostcheck.run_host_check(deep=True).to_dict()


def post_console(console: str, payload: dict, token: str = "", timeout: float = 30.0,
                 verify_tls: bool = True, retries: int = 3) -> None:
    """上报到控制台；失败按指数退避重试，避免一次网络抖动就丢掉整轮结果。"""
    url = console.rstrip("/") + "/api/agent/report"
    headers = {"X-P2S-Token": token} if token else {}
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with make_client(timeout=timeout, verify=verify_tls) as c:
                r = c.post(
                    url,
                    json={"hostname": platform.node(), "data": payload},
                    headers=headers,
                )
                r.raise_for_status()
            print(f"已上报到 {url} -> {r.status_code}")
            return
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt < retries:
                wait = min(30.0, 2 ** attempt) + random.uniform(0, 1.5)
                print(f"上报失败（第 {attempt}/{retries} 次）：{exc}；{wait:.1f}s 后重试",
                      file=sys.stderr)
                time.sleep(wait)
    raise RuntimeError(f"上报失败（已重试 {retries} 次）：{last}")


def _handle_stop(signum, frame):  # noqa: ARG001
    global _STOP
    _STOP = True
    print("收到退出信号，当前这一轮结束后停止", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8()
    p = argparse.ArgumentParser(prog="p2s-agent", description="p2s 本地取证 Agent")
    p.add_argument("--console", help="控制台地址，例如 http://127.0.0.1:18080")
    p.add_argument("--token", default=os.environ.get("P2S_AGENT_TOKEN", ""),
                   help="上报令牌（默认取环境变量 P2S_AGENT_TOKEN）")
    p.add_argument("--interval", type=int, default=0, help="循环上报间隔（秒），0 表示只跑一次")
    p.add_argument("--out", help="把本地报告同时写入该目录")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验（自签名内网）")
    args = p.parse_args(argv)

    if args.console and not args.token:
        print("警告：未提供 --token，控制台会以 401 拒绝上报（除非控制台同样没设口令）",
              file=sys.stderr)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_stop)
        except (ValueError, OSError):
            pass

    while True:
        try:
            payload = collect()
        except Exception as exc:  # noqa: BLE001
            # 单轮采集失败不应结束整个循环 —— 上一版直接把 daemon 打死了
            print(f"采集失败：{type(exc).__name__}: {exc}", file=sys.stderr)
            payload = None

        if payload is not None:
            print(f"[{datetime.now().isoformat(timespec='seconds')}] "
                  f"{payload.get('hostname')} 风险={payload.get('risk')} "
                  f"痕迹={len(payload.get('artifacts', []))}")

            if args.out:
                try:
                    res = ScanResult(scan_id=f"agent-{int(time.time())}", kind="agent",
                                     started_at=datetime.now().isoformat(timespec="seconds"))
                    res.target_count = 1
                    res.host_reports = [payload]
                    to_json(res, os.path.join(args.out, "host-report.json"))
                    print(f"本地报告已写入 {args.out}")
                except OSError as exc:
                    print(f"写本地报告失败：{exc}", file=sys.stderr)

            if args.console:
                try:
                    post_console(args.console, payload, args.token, args.timeout,
                                 verify_tls=not args.insecure)
                except Exception as exc:  # noqa: BLE001
                    print(f"上报失败: {exc}", file=sys.stderr)

        if args.interval <= 0 or _STOP:
            break
        # 加抖动：避免整批机器同一秒打向控制台
        time.sleep(max(1.0, args.interval + random.uniform(-5, 5)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
