"""命令行入口

    p2s scan <target...>
    p2s hunt --log <path>
    p2s rules
    p2s version
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from urllib.parse import urlsplit

from . import __version__
from .detectors import d6_hunt
from .engine import Engine
from .report import (
    enable_ansi,
    render_json,
    render_markdown,
    render_terminal,
)
from .rules import load_ruleset

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

BANNER = r"""
  ____  _____ ____    ____                     _
 |  _ \|___ // ___|  / ___|_   _  __ _ _ __ __| |
 | |_) | |_ \\___ \ | |  _| | | |/ _` | '__/ _` |
 |  __/ ___) |___) || |_| | |_| | (_| | | | (_| |
 |_|   |____/|____/  \____|\__,_|\__,_|_|  \__,_|

 PHP2Shell 检测引擎 v{ver}   ·   防御性检测，不含利用代码
""".replace("\\", "\\")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="p2s",
        description="P2S-Guard — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 检测引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  p2s scan http://127.0.0.1:8801
  p2s scan http://a.com http://b.com --profile deep --md out/report.md --json out/result.json
  p2s scan https://example.com --ticket SEC-2026-1028 --i-have-authorization
  p2s scan http://10.0.0.5 --host 10.0.0.5 --ssh-user root --ssh-key ~/.ssh/id_rsa
  p2s hunt --log ./logs
        """,
    )
    ap.add_argument("-V", "--version", action="version", version=f"P2S-Guard {__version__}")

    sub = ap.add_subparsers(dest="cmd")

    # ---- scan ----
    s = sub.add_parser("scan", help="扫描目标")
    s.add_argument("targets", nargs="*", help="URL / 域名 / IP:端口（不含协议默认 http）")
    s.add_argument("--profile", default="standard",
                   choices=["passive", "standard", "deep", "forensic"],
                   help="检测画像：passive 仅被动 / standard 默认 / deep 加主机 / forensic 全量")
    s.add_argument("--local", action="store_true", help="同时核查本机 PHP（需本机安装 php）")
    s.add_argument("--host", help="SSH 主机（开启 D3 远程核查）")
    s.add_argument("--ssh-user", default="root")
    s.add_argument("--ssh-port", type=int, default=22)
    s.add_argument("--ssh-key", help="SSH 私钥路径")
    s.add_argument("--ssh-password", help="SSH 密码（不推荐，建议用密钥）")
    s.add_argument("--exposure", default="internet",
                   choices=["internet", "internet_waf", "internal", "ops_only", "unknown"])
    s.add_argument("--timeout", type=float, default=8.0)
    s.add_argument("--qps", type=float, default=5.0, help="单目标限速（请求/秒）")
    s.add_argument("--max-requests", type=int, default=60, help="单目标探测预算")
    s.add_argument("--ticket", default="", help="授权工单号/合同号")
    s.add_argument("--i-have-authorization", action="store_true", dest="authorized",
                   help="确认已获得目标所有者的书面授权")
    s.add_argument("--allow-intrusive", action="store_true", help="允许高危探测（D5 前置条件之一）")
    s.add_argument("--probe-oom", action="store_true", help="【危险】允许发送 OOM 探针（需与 --allow-intrusive 同时使用）")
    s.add_argument("--rules", help="外部规则包（JSON）")
    s.add_argument("--md", help="输出 Markdown 报告到指定路径")
    s.add_argument("--json", dest="json_path", help="输出 JSON 到指定路径")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--show-evidence", action="store_true", default=True)

    # ---- hunt ----
    h = sub.add_parser("hunt", help="失陷排查：扫描日志")
    h.add_argument("--log", required=True, help="日志文件或目录")
    h.add_argument("--md", help="输出 Markdown 报告")
    h.add_argument("--json", dest="json_path", help="输出 JSON")

    # ---- rules ----
    sub.add_parser("rules", help="显示当前规则库摘要")

    return ap


def _is_local(target: str) -> bool:
    parts = urlsplit(target if "://" in target else "http://" + target)
    return (parts.hostname or "") in LOCAL_HOSTS


def cmd_scan(args) -> int:
    enable_ansi()
    targets = list(args.targets)
    if not targets:
        print("错误：未指定目标。用 p2s scan http://127.0.0.1:8801", file=sys.stderr)
        return 2

    # 授权闸：非本机目标必须显式确认授权
    remote = [t for t in targets if not _is_local(t)]
    if remote and not (args.authorized and args.ticket.strip()):
        print("", file=sys.stderr)
        print("  授权检查未通过。", file=sys.stderr)
        print(f"  目标 {len(remote)} 个非本机地址，需要同时提供：", file=sys.stderr)
        print("    --i-have-authorization   （确认已获得书面授权）", file=sys.stderr)
        print("    --ticket <工单号/合同号>  （授权凭据，将写入报告）", file=sys.stderr)
        print("", file=sys.stderr)
        print("  本机回环地址（127.0.0.1/localhost）无需授权，可直接扫描。", file=sys.stderr)
        return 2

    if args.allow_intrusive and not args.probe_oom:
        print("提示：--allow-intrusive 已开启，但 D5 还需要 --probe-oom 才会执行 OOM 探针",
              file=sys.stderr)
    if args.probe_oom and not args.allow_intrusive:
        print("错误：--probe-oom 必须与 --allow-intrusive 同时使用（双重确认）", file=sys.stderr)
        return 2
    if args.probe_oom:
        print("", file=sys.stderr)
        print("  ⚠ 你已开启 OOM 探针。该动作会让目标 PHP worker 达到 memory_limit，", file=sys.stderr)
        print("    本质是一次 DoS 强度操作。请确认：已获授权、已通知运维、非共享主机、", file=sys.stderr)
        print("    已确认可回滚，且不要在业务高峰执行。", file=sys.stderr)
        print("", file=sys.stderr)

    try:
        ruleset = load_ruleset(args.rules)
    except Exception as e:  # noqa: BLE001
        print(f"规则包加载失败：{e}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(BANNER.format(ver=__version__))
        print(f"  规则库 {ruleset.get('version')}   画像 {args.profile}   "
              f"目标 {len(targets)}   限速 {args.qps}/s")
        print()

    ssh_conf = {}
    if args.host:
        ssh_conf = {
            "host": args.host, "user": args.ssh_user, "port": args.ssh_port,
            "key": os.path.expanduser(args.ssh_key) if args.ssh_key else None,
            "password": args.ssh_password,
        }

    eng = Engine(
        ruleset=ruleset, profile=args.profile, timeout=args.timeout, qps=args.qps,
        allow_intrusive=args.allow_intrusive, ticket=args.ticket,
        ssh_conf=ssh_conf, exposure=args.exposure, probe_oom=args.probe_oom,
        max_requests=args.max_requests, quiet=args.quiet,
    )

    report = eng.scan_many(targets)

    # 本机附加核查
    if args.local:
        from .detectors import d3_host
        from .models import DetectionContext
        from .verdict import judge
        print("  [附加] 本机 PHP 核查")
        ctx = DetectionContext(target="local://php", profile="deep")
        r = d3_host.run(ctx, mode="local")
        for ev in r.evidences:
            print(f"      {ev.key} = {ev.value}")
        for err in r.errors:
            print(f"      ! {err}")

    print(render_terminal(report, color=not args.no_color,
                          show_evidence=args.show_evidence))

    if args.md or args.json_path:
        _write_outputs(report, args.md, args.json_path, meta={"ticket": args.ticket})

    return _exit_code(report)


def _exit_code(report) -> int:
    """退出码约定（对齐 CI 用法）：
    0 全部已修复/不适用   1 存在确认受影响   3 存在无法判定   4 存在疑似
    """
    if any(f.verdict.value == "vulnerable" for f in report.findings):
        return 1
    if any(f.verdict.value == "likely_vulnerable" for f in report.findings):
        return 4
    if any(f.verdict.value == "unknown" for f in report.findings):
        return 3
    return 0


def _write_outputs(report, md_path: str | None, json_path: str | None,
                   hunt=None, meta=None) -> None:
    if md_path:
        os.makedirs(os.path.dirname(os.path.abspath(md_path)), exist_ok=True)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(report, hunt=hunt, meta=meta))
        print(f"  报告已写入 {md_path}")
    if json_path:
        os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(render_json(report, hunt=hunt))
        print(f"  JSON 已写入 {json_path}")


def cmd_hunt(args) -> int:
    enable_ansi()
    print(BANNER.format(ver=__version__))
    print(f"  失陷排查：{args.log}")
    print()
    res = d6_hunt.analyze([args.log])

    print(f"  文件 {len(res.files)} 个，日志行 {res.events}，成功解析 {res.parsed}")
    if res.earliest:
        print(f"  时间范围 {res.earliest:%Y-%m-%d %H:%M} ~ {res.latest:%Y-%m-%d %H:%M}")
    print(f"  综合判定 {res.verdict.upper()}")
    print()

    if res.findings:
        print(f"  {'时间':<20} {'规则':<10} {'说明'}")
        print("  " + "-" * 96)
        for h in res.findings[:60]:
            ts = h.ts.strftime("%Y-%m-%d %H:%M:%S") if h.ts else "-"
            print(f"  {ts:<20} {h.rule_id:<10} {h.detail[:60]}")
            print(f"  {'':<20} {'':<10}   {os.path.basename(h.log_file)}:{h.line_no}")
        print()

    for n in res.notes:
        print(f"  - {n}")
    for e in res.errors[:5]:
        print(f"  ! {e}")
    print()

    if args.md or args.json_path:
        from .models import ScanReport
        empty = ScanReport(ruleset_version="n/a", profile="forensic")
        empty.finished_at = time.time()
        _write_outputs(empty, args.md, args.json_path, hunt=res,
                       meta={"log": args.log})

    return 0 if res.verdict == "clean" else (1 if res.verdict == "suspicious" else 3)


def cmd_rules(_args) -> int:
    rs = load_ruleset()
    print(f"规则库：{rs['name']}")
    print(f"版本  ：{rs['version']}   发布时间：{rs['published_at']}")
    print(f"评分  ：CVSS v4 {rs['cvss_v4']}")
    print(f"在野利用起点：{rs['exploitation_seen_since']}")
    print()
    print("CVE：")
    for c in rs["cves"]:
        print(f"  - {c['id']}  {c['ghsa']}  {c['title']}")
    print()
    print("修复版本：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35")
    print("无修复  ：8.1 及更早（含 7.x / 5.x，可追溯至 5.4）")
    print()
    print("SAPI 权重：")
    for k, v in rs["sapi_matrix"].items():
        print(f"  {k:<16} {v['weight']:.2f}  {v['exploitable']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "hunt":
        return cmd_hunt(args)
    if args.cmd == "rules":
        return cmd_rules(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
