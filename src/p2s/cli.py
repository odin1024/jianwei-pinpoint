"""p2s 命令行入口。

    p2s discover --host 192.168.1.1 --report out/    # 设备发现（端口/类型/PHP 暴露面）
    p2s assets   --file hosts.txt --report out/       # 资产测绘 + 版本判定
    p2s probe    --file hosts.txt --report out/       # 资产测绘 + 主动探测
    p2s logs     --file access.log --report out/      # 被动日志检测
    p2s host     --report out/                        # 主机侧检测
    p2s ioc      --scan-file sample.txt               # IOC 匹配
    p2s rules    --format sigma                       # 导出规则
    p2s serve    --port 18080                          # 启动 Web 控制台
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

from .core import discovery, hostcheck, logscan
from .core import ioc as ioc_mod
from .core import probe as probe_mod
from .core import report as report_mod
from .core.oui import read_arp_table
from .core.rules import RULES


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _read_hosts(path: str | None, inline: list[str] | None) -> list[str]:
    hosts: list[str] = []
    if path:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    if inline:
        hosts.extend(h.strip() for h in inline if h.strip())
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _emit(result: report_mod.ScanResult, outdir: str | None, quiet: bool) -> None:
    result.finished_at = _now()
    if not quiet:
        counts = result.severity_counts
        print(f"\n扫描完成 [{result.scan_id}]  风险={result.risk.upper()}  目标={result.target_count}")
        if counts:
            print("  命中分布: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        for a in result.assets:
            if a.get("alive") is False:
                print(f"  [离线    ] {a.get('host')}  无有效协议响应（不计入台账）")
                continue
            if a.get("host"):
                print(f"  [{a.get('risk','-'):8}] {a.get('host')}  {a.get('device_label')}  "
                      f"产品={a.get('product') or '-'}  "
                      f"PHP={a.get('php_version') or ('无' if a.get('exposure') == 'not_php' else '?')}  "
                      f"暴露={a.get('exposure')} 置信={a.get('confidence')}")
            else:
                v = a.get("version_verdict", {})
                fpx = a.get("fingerprint", {})
                print(f"  [{a.get('risk','-'):8}] {a.get('url')}  PHP={v.get('version','?')} "
                      f"SAPI={fpx.get('sapi_label','?')}  版本={v.get('status','?')} 探测={a.get('probe_verdict','?')}")
        for f in result.findings[:20]:
            print(f"  ! [{f.get('severity')}] {f.get('rule_id')} {f.get('rule_name')} :: {str(f.get('evidence'))[:110]}")
        if len(result.findings) > 20:
            print(f"  ... 另有 {len(result.findings)-20} 条命中")
    if outdir:
        d = Path(outdir)
        d.mkdir(parents=True, exist_ok=True)
        base = d / result.scan_id
        report_mod.to_json(result, base.with_suffix(".json"))
        report_mod.to_markdown(result, base.with_suffix(".md"))
        report_mod.to_html(result, base.with_suffix(".html"))
        if not quiet:
            print(f"\n报告已生成:\n  {base}.json\n  {base}.md\n  {base}.html")


# --------------------------------------------------------------------------
def cmd_discover(args: argparse.Namespace) -> int:
    """设备发现：端口 -> 服务 -> 设备类型 -> PHP 暴露面。"""
    hosts = _read_hosts(args.file, args.host)
    if args.cidr:
        hosts.extend(_expand_cidr(args.cidr))
    hosts = [h for h in hosts if h]

    res = report_mod.ScanResult(
        scan_id=f"disc-{uuid.uuid4().hex[:10]}", kind="discover", started_at=_now()
    )
    res.target_count = len(hosts)
    for h in hosts:
        prof = discovery.discover(
            h,
            timeout=args.timeout,
            http_timeout=args.http_timeout,
            deep=not args.quick,
        )
        res.assets.append(prof.to_dict())
        for e in prof.errors:
            res.errors.append(f"{h}: {e}")

    if not args.quiet:
        print(f"\n发现完成 [{res.scan_id}]  目标={len(hosts)}")
        by_type: dict[str, int] = {}
        for a in res.assets:
            by_type[a.get("device_label", "?")] = by_type.get(a.get("device_label", "?"), 0) + 1
        print("  设备类型分布: " + ("  ".join(f"{k}×{v}" for k, v in sorted(by_type.items(), key=lambda x: -x[1])) or "-"))
        for a in res.assets:
            mark = {"critical": "[!]", "medium": "[~]", "low": "[ ]"}.get(a.get("risk", ""), "[?]")
            print(f"  {mark} {a.get('host'):<24} {a.get('device_label'):<22} "
                  f"PHP={a.get('php_version') or ('无' if a.get('exposure') == 'not_php' else '?')} "
                  f"暴露={a.get('exposure')} 置信={a.get('confidence')}")
            print(f"        端口: {a.get('open_ports')}")
            for ev in a.get("evidence", [])[:6]:
                print(f"        · {ev}")

    if args.report:
        d = Path(args.report)
        d.mkdir(parents=True, exist_ok=True)
        base = d / res.scan_id
        report_mod.to_json(res, base.with_suffix(".json"))
        report_mod.to_markdown(res, base.with_suffix(".md"))
        report_mod.to_html(res, base.with_suffix(".html"))
        if not args.quiet:
            print(f"\n报告已生成:\n  {base}.json\n  {base}.md\n  {base}.html")
    return 0


def _expand_cidr(cidr: str) -> list[str]:
    """把 CIDR 展开成主机列表（跳过网络号与广播地址）。"""
    import ipaddress

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses > 1024:
        return []
    return [str(h) for h in net.hosts()]


def cmd_assets(args: argparse.Namespace) -> int:
    hosts = _read_hosts(args.file, args.host or args.url)
    res = report_mod.ScanResult(scan_id=f"assets-{uuid.uuid4().hex[:10]}", kind="assets", started_at=_now())
    res.target_count = len(hosts)
    arp = read_arp_table()
    for h in hosts:
        host_only = h.split("://")[-1].split("/")[0].split(":")[0]
        # 与 Web 控制台共用同一引擎：同样的存活判定、同样的设备分类
        prof = discovery.discover(
            host_only, timeout=args.timeout, http_timeout=max(args.timeout * 3, 6.0),
            deep=not args.quick, arp=arp,
        )
        res.assets.append(prof.to_dict())
        for e in prof.errors:
            res.errors.append(f"{host_only}: {e}")
    _emit(res, args.report, args.quiet)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    hosts = _read_hosts(args.file, args.url)
    res = report_mod.ScanResult(scan_id=f"probe-{uuid.uuid4().hex[:10]}", kind="probe", started_at=_now())
    res.target_count = len(hosts)
    for h in hosts:
        url = h if h.startswith("http") else f"http://{h}"
        asm = probe_mod.assess(url, timeout=args.timeout, do_probe=not args.no_probe)
        res.assets.append(asm.to_dict())
    _emit(res, args.report, args.quiet)
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    res = report_mod.ScanResult(scan_id=f"logs-{uuid.uuid4().hex[:10]}", kind="logs", started_at=_now())
    lines = Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines()
    records = list(logscan.iter_records(lines))
    res.target_count = len(records)
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    from .core.rules import coverage_report
    res.coverage = coverage_report(fields)
    findings = logscan.scan_records(records)
    res.findings = [f.to_dict() for f in findings]
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    _emit(res, args.report, args.quiet)
    return 0


def cmd_host(args: argparse.Namespace) -> int:
    res = report_mod.ScanResult(scan_id=f"host-{uuid.uuid4().hex[:10]}", kind="host", started_at=_now())
    rep = hostcheck.run_host_check(deep=not args.shallow)
    res.target_count = 1
    res.host_reports = [rep.to_dict()]
    # 把主机侧的可疑痕迹也映射成 findings
    for a in rep.artifacts:
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.kind}",
            "severity": a.severity,
            "dimension": "host",
            "cves": ["CVE-2026-109618", "CVE-2026-109619"],
            "ts": rep.checked_at,
            "ip": rep.hostname,
            "uri": a.path,
            "evidence": a.detail,
        })
    _emit(res, args.report, args.quiet)
    return 0


def cmd_ioc(args: argparse.Namespace) -> int:
    lib = ioc_mod.IocLibrary()
    hits: list[dict] = []
    if args.scan_file:
        text = Path(args.scan_file).read_text(encoding="utf-8", errors="replace")
        for m in lib.match_text(text, context=args.scan_file):
            hits.append(m.to_dict())
    if args.hash:
        m = lib.match_hash(args.hash)
        if m:
            hits.append(m.to_dict())
    if args.summary or not (args.scan_file or args.hash):
        print(json.dumps(lib.summary(), ensure_ascii=False, indent=2))
    for h in hits:
        print(json.dumps(h, ensure_ascii=False))
    return 1 if hits else 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in RULES], ensure_ascii=False, indent=2))
    else:
        print(f"{'ID':<14}{'等级':<10}{'维度':<10}{'需要字段':<14}名称")
        for r in RULES:
            print(f"{r.id:<14}{r.severity:<10}{r.dimension:<10}{r.requires:<14}{r.name}")
    return 0


def _port_in_use(host: str, port: int) -> bool:
    """检测端口是否已被占用（纯本地 socket 绑定测试，不发任何流量）。"""
    import socket

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn

        from .console.app import app
    except ImportError as exc:
        print(f"缺少 Web 控制台依赖，请先安装: pip install -e \".[console]\"  ({exc})", file=sys.stderr)
        return 2
    port = args.port
    if _port_in_use(args.host, port):
        if args.no_fallback:
            print(f"端口 {port} 已被占用，请用 --port 指定其它端口", file=sys.stderr)
            return 3
        for candidate in range(port + 1, port + 50):
            if not _port_in_use(args.host, candidate):
                print(f"端口 {port} 已被占用，自动改用 {candidate}", file=sys.stderr)
                port = candidate
                break
        else:
            print(f"端口 {port}~{port + 49} 均被占用，请用 --port 指定", file=sys.stderr)
            return 3

    print(f"p2s 控制台已启动: http://{args.host}:{port}", file=sys.stderr)
    print("  首次访问需要输入口令（环境变量 P2S_CONSOLE_PASSWORD；未设置时启动日志里有随机口令）",
          file=sys.stderr)
    print("按 Ctrl+C 退出", file=sys.stderr)
    uvicorn.run(app, host=args.host, port=port, log_level="info")
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="p2s",
        description="php2shell (CVE-2026-109618 / CVE-2026-109619) 检测与暴露面评估工具",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_report(sp):
        sp.add_argument("--report", help="报告输出目录（会生成 json/md/html 三份）")
        sp.add_argument("--quiet", action="store_true", help="只输出报告路径")

    sp = sub.add_parser("discover", help="设备发现：端口 + 服务 + 设备类型 + PHP 暴露面")
    sp.add_argument("--host", action="append", help="单个主机 IP（可重复）")
    sp.add_argument("--file", help="主机列表文件")
    sp.add_argument("--cidr", help="网段，例如 192.168.1.0/24（最大 1024 台）")
    sp.add_argument("--timeout", type=float, default=1.2, help="TCP 探测超时")
    sp.add_argument("--http-timeout", type=float, default=8.0, help="HTTP 探测超时")
    sp.add_argument("--quick", action="store_true", help="跳过 HTTP 深度识别")
    add_report(sp)
    sp.set_defaults(func=cmd_discover)

    sp = sub.add_parser("assets", help="资产测绘：设备识别 + PHP 版本 + 修复状态")
    sp.add_argument("--file", help="主机/URL 列表文件")
    sp.add_argument("--host", action="append", help="单个主机 IP（可重复）")
    sp.add_argument("--url", action="append", help="单个 URL（可重复，兼容）")
    sp.add_argument("--quick", action="store_true", help="快速模式：只探测常见端口")
    sp.add_argument("--timeout", type=float, default=1.2, help="TCP 超时(秒)")
    add_report(sp)
    sp.set_defaults(func=cmd_assets)

    sp = sub.add_parser("probe", help="资产测绘 + 主动安全探测（无害）")
    sp.add_argument("--file", help="主机/URL 列表文件")
    sp.add_argument("--url", action="append", help="单个 URL（可重复）")
    sp.add_argument("--timeout", type=float, default=15.0)
    sp.add_argument("--no-probe", action="store_true", help="只做版本判定，不发探针")
    add_report(sp)
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("logs", help="被动日志检测（L1，零风险）")
    sp.add_argument("--file", required=True, help="日志文件路径")
    add_report(sp)
    sp.set_defaults(func=cmd_logs)

    sp = sub.add_parser("host", help="主机侧检测（L3）")
    sp.add_argument("--shallow", action="store_true", help="跳过文件内容与哈希检查")
    add_report(sp)
    sp.set_defaults(func=cmd_host)

    sp = sub.add_parser("ioc", help="IOC 库查询与匹配")
    sp.add_argument("--scan-file", help="要扫描 IOC 的文件")
    sp.add_argument("--hash", help="要匹配的 SHA-256")
    sp.add_argument("--summary", action="store_true", help="打印 IOC 库摘要")
    sp.set_defaults(func=cmd_ioc)

    sp = sub.add_parser("rules", help="查看/导出规则库")
    sp.add_argument("--format", choices=["table", "json"], default="table")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("serve", help="启动 Web 控制台")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=18080, help="默认 18080；被占用时自动顺延")
    sp.add_argument("--no-fallback", action="store_true", help="端口被占用时直接报错，不自动顺延")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("prune", help="清理历史扫描与上传文件（默认只预览，不删除）")
    sp.add_argument("--apply", action="store_true", help="真正删除；不加则只统计")
    sp.add_argument("--keep", type=int, default=3, help="同一输入保留份数（默认 3）")
    sp.add_argument("--days", type=int, default=7, help="只删早于 N 天的重复报告（默认 7）")
    sp.add_argument("--max", dest="max_total", type=int, default=300, help="扫描总数上限（默认 300）")
    sp.add_argument("--upload-days", type=int, default=7, help="上传文件保留天数（默认 7）")
    sp.set_defaults(func=cmd_prune)

    # 与 p2s-agent 等价：刚安装完还没重新生成 entry point 时也能跑
    sp = sub.add_parser("agent", help="主机侧 Agent（等同 p2s-agent）")
    sp.add_argument("agent_args", nargs=argparse.REMAINDER,
                    help="透传给 Agent 的参数，例如 --console http://x:18080 --token xxx")
    sp.set_defaults(func=cmd_agent)
    return p


def cmd_agent(args: argparse.Namespace) -> int:
    from .agent import agent as agent_mod

    return agent_mod.main(list(args.agent_args))


def cmd_prune(args: argparse.Namespace) -> int:
    """清理历史扫描与上传文件；默认只预览。"""
    from .core.retention import default_data_dir, prune_scans, prune_uploads

    data = default_data_dir()
    r = prune_scans(data / "scans", keep=args.keep, min_age_days=args.days,
                    apply=args.apply, max_total=args.max_total)
    u = prune_uploads(data / "uploads", max_age_days=args.upload_days, apply=args.apply)
    mode = "已删除" if args.apply else "可删除（预览，加 --apply 才真删）"
    print(f"扫描报告：重复清理 {r['removed']} 组，超上限裁剪 {r.get('capped', 0)} 份，"
          f"保留分组 {r['kept_groups']}（keep={args.keep}, days={args.days}, "
          f"max={args.max_total}）")
    print(f"上传文件：{u['removed']} / {u['scanned']} 个超过 {args.upload_days} 天")
    print(f"模式：{mode}")
    return 0


def _ensure_utf8_console() -> None:
    """Windows 控制台默认 GBK，中文输出会乱码；这里强制切到 UTF-8。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_console()
    argv = list(sys.argv[1:] if argv is None else argv)

    # `p2s agent --console ... --token ...` 直接转发给 Agent 自己的 argparse。
    # 不能让外层 argparse 解析：`--console` 会被当成未知选项直接报错。
    if argv and argv[0] == "agent":
        from .agent import agent as agent_mod

        return agent_mod.main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n已中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

