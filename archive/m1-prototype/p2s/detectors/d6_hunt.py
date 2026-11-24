"""D6 失陷排查

回答「补丁之前有没有被打进去」。
补丁只能关门，不能告诉你谁进来过 —— 这是本次事件里最容易被忽略的一环。

输入：Web 访问日志、PHP 错误日志、Apache 错误日志（支持 .gz）
输出：按时间排序的事件 + 规则命中 + 关联升级结论
"""

from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Iterable

START_HINT = datetime(2026, 10, 17, tzinfo=timezone.utc)

RE_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^\s"]*)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)
RE_PHP_ERR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+(?P<msg>PHP\s+\w+\s+error:.*|PHP\s+\w+:.*)$"
)
RE_APACHE_ERR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[[^\]]*\]\s+\[pid\s+\d+(?::tid\s+\d+)?\]\s+"
    r"(?:\[client\s+(?P<ip>[^\]:]+)[^\]]*\]\s+)?(?P<msg>.*)$"
)
RE_STARTUP_OOM = re.compile(
    r"Allowed memory size of (?P<limit>\d+) bytes exhausted.*?in Unknown on line 0"
)
RE_OOM_ANY = re.compile(r"Allowed memory size of (?P<limit>\d+) bytes exhausted")
RE_SEGFAULT = re.compile(r"AH00052: child pid .*?signal Segmentation fault|child exited on signal 11", re.I)
RE_SESSION_UPLOAD = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS", re.I)
RE_SHELL = re.compile(r"(/bin/(ba)?sh|/bin/dash|cmd\.exe|-c\s+curl|-c\s+wget)", re.I)

MAX_LINE = 8192


@dataclass(slots=True)
class Event:
    ts: datetime | None
    kind: str                 # access | php_error | apache_error
    ip: str = ""
    method: str = ""
    uri: str = ""
    status: int = 0
    size: int = 0
    message: str = ""
    src_file: str = ""
    line_no: int = 0
    raw: str = ""


@dataclass(slots=True)
class HuntFinding:
    rule_id: str
    rule_name: str
    confidence: str
    ts: datetime | None
    detail: str
    ip: str = ""
    method: str = ""
    uri: str = ""
    status: int = 0
    log_file: str = ""
    line_no: int = 0
    raw: str = ""
    correlated: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HuntResult:
    files: list[str] = field(default_factory=list)
    events: int = 0
    parsed: int = 0
    earliest: datetime | None = None
    latest: datetime | None = None
    findings: list[HuntFinding] = field(default_factory=list)
    verdict: str = "inconclusive"
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _parse_ts_access(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None


def _parse_ts_generic(ts: str) -> datetime | None:
    ts = ts.strip()
    for fmt in ("%d-%b-%Y %H:%M:%S %Z", "%d-%b-%Y %H:%M:%S",
                "%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def iter_files(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    out: list[str] = []
    for root, _dirs, files in os.walk(path):
        for f in files:
            if any(k in f.lower() for k in ("access", "error", "php", "nginx", "apache")) or f.endswith(".log") or f.endswith(".log.gz"):
                out.append(os.path.join(root, f))
    return sorted(out)


def parse_file(path: str, out: HuntResult, limit_lines: int = 5_000_000) -> list[Event]:
    events: list[Event] = []
    try:
        fh = _open_text(path)
    except Exception as e:  # noqa: BLE001
        out.errors.append(f"无法打开 {path}: {e}")
        return events

    with fh:
        for i, line in enumerate(fh, 1):
            if i > limit_lines:
                out.notes.append(f"{path} 超过 {limit_lines} 行，已截断")
                break
            line = line.rstrip("\n")[:MAX_LINE]
            if not line:
                continue
            out.events += 1

            m = RE_ACCESS.match(line)
            if m:
                size = m.group("size")
                events.append(Event(
                    ts=_parse_ts_access(m.group("ts")), kind="access",
                    ip=m.group("ip"), method=m.group("method"), uri=m.group("uri"),
                    status=int(m.group("status")),
                    size=int(size) if size.isdigit() else 0,
                    src_file=path, line_no=i, raw=line,
                ))
                out.parsed += 1
                continue

            m = RE_PHP_ERR.match(line)
            if m:
                events.append(Event(
                    ts=_parse_ts_generic(m.group("ts")), kind="php_error",
                    message=m.group("msg"), src_file=path, line_no=i, raw=line,
                ))
                out.parsed += 1
                continue

            m = RE_APACHE_ERR.match(line)
            if m:
                events.append(Event(
                    ts=_parse_ts_generic(m.group("ts")), kind="apache_error",
                    ip=(m.group("ip") or ""), message=m.group("msg"),
                    src_file=path, line_no=i, raw=line,
                ))
                out.parsed += 1
    return events


def analyze(paths: Iterable[str]) -> HuntResult:
    res = HuntResult()
    all_events: list[Event] = []

    for p in paths:
        for f in iter_files(p):
            res.files.append(f)
            all_events.extend(parse_file(f, res))

    if not all_events:
        res.notes.append("未解析到任何日志行；请确认路径与日志格式")
        return res

    stamps = [e.ts for e in all_events if e.ts]
    if stamps:
        res.earliest = min(stamps)
        res.latest = max(stamps)
        if res.earliest < START_HINT:
            res.notes.append(
                f"日志起点 {res.earliest:%Y-%m-%d} 早于在野利用起点 2026-10-17，覆盖充分"
            )
        else:
            res.notes.append(
                f"⚠ 日志起点 {res.earliest:%Y-%m-%d} 晚于在野利用起点 2026-10-17，"
                f"10-17 至该日期的活动无法覆盖"
            )

    # ---------- HUNT-001 启动期 OOM ----------
    oom_events = [e for e in all_events if e.kind == "php_error" and RE_STARTUP_OOM.search(e.message)]
    if oom_events:
        clusters = _cluster(oom_events, minutes=10)
        for c in clusters:
            if len(c) >= 3:
                res.findings.append(HuntFinding(
                    "HUNT-001", "启动期 OOM 聚集", "medium", c[0].ts,
                    f"{len(c)} 次启动期 OOM（Allowed memory size ... in Unknown on line 0）"
                    f"集中在 10 分钟内，符合 PHP2Shell 触发特征",
                    log_file=c[0].src_file, line_no=c[0].line_no, raw=c[0].raw[:300],
                ))

    # ---------- HUNT-002 OOM 与大 POST 关联 ----------
    big_posts = [e for e in all_events if e.kind == "access" and e.method == "POST" and e.size > 1_000_000]
    for oom in oom_events:
        for bp in big_posts:
            if oom.ts and bp.ts and abs((oom.ts - bp.ts).total_seconds()) <= 60:
                res.findings.append(HuntFinding(
                    "HUNT-002", "OOM 与大 POST 关联", "high", bp.ts,
                    f"启动期 OOM 前后 60s 内出现 {bp.size} 字节 POST，请求体大小与 OOM 触发条件吻合",
                    ip=bp.ip, method=bp.method, uri=bp.uri, status=bp.status,
                    log_file=bp.src_file, line_no=bp.line_no, raw=bp.raw[:300],
                    correlated=[f"HUNT-001@{oom.line_no}"],
                ))
                break

    # ---------- HUNT-003 worker 崩溃 ----------
    for e in all_events:
        if RE_SEGFAULT.search(e.message or ""):
            res.findings.append(HuntFinding(
                "HUNT-003", "Worker 崩溃（段错误）", "medium", e.ts,
                "Apache/FPM 子进程以 SIGSEGV 退出，可能是利用失败（地址猜测错误）的痕迹",
                log_file=e.src_file, line_no=e.line_no, raw=e.raw[:300],
            ))

    # ---------- HUNT-004 上传进度标记 ----------
    for e in all_events:
        if e.kind == "access" and RE_SESSION_UPLOAD.search(e.raw):
            res.findings.append(HuntFinding(
                "HUNT-004", "上传进度标记探测", "medium", e.ts,
                "请求中出现 PHP_SESSION_UPLOAD_PROGRESS，若非业务正常调用则高度可疑",
                ip=e.ip, method=e.method, uri=e.uri, status=e.status,
                log_file=e.src_file, line_no=e.line_no, raw=e.raw[:300],
            ))

    # ---------- HUNT-009 可疑 PHP 文件访问 ----------
    shell_like = [
        e for e in all_events
        if e.kind == "access" and re.search(r"\.(php|phtml|phar)$", e.uri.split("?")[0], re.I)
        and re.search(r"(cache|tmp|upload|uploads|images|assets)/[^/]*\.(php|phtml|phar)$", e.uri, re.I)
    ]
    for e in shell_like[:50]:
        res.findings.append(HuntFinding(
            "HUNT-009", "可疑路径下的 PHP 文件访问", "medium", e.ts,
            "Web 可写目录下出现 PHP 文件被访问，典型 webshell 落地特征",
            ip=e.ip, method=e.method, uri=e.uri, status=e.status,
            log_file=e.src_file, line_no=e.line_no, raw=e.raw[:300],
        ))

    # ---------- HUNT-010 进程派生 shell（错误日志中的线索）----------
    for e in all_events:
        if e.kind in ("php_error", "apache_error") and RE_SHELL.search(e.message or ""):
            res.findings.append(HuntFinding(
                "HUNT-010", "疑似 shell 派生痕迹", "high", e.ts,
                "错误/审计日志中出现 shell 或下载工具调用痕迹",
                log_file=e.src_file, line_no=e.line_no, raw=e.raw[:300],
            ))

    # ---------- HUNT-012 时间线关联升级 ----------
    cats = {f.rule_id for f in res.findings}
    if len(cats) >= 3:
        res.verdict = "suspicious"
        res.notes.append(f"命中 {len(cats)} 类规则（{','.join(sorted(cats))}），按「疑似失陷」处置")
    elif len(cats) >= 1:
        high = [f for f in res.findings if f.confidence == "high"]
        res.verdict = "suspicious" if high else "inconclusive"
        res.notes.append(f"命中 {len(res.findings)} 条规则，建议人工复核时间线")
    else:
        res.verdict = "clean"
        res.notes.append(
            "未命中任何规则。注意：成功利用可能既不崩溃也不报错，日志干净不等于没被打过"
        )

    # 去重：同一规则命中同一行只保留一条（避免同一次攻击被放大成多条）
    seen_lines = set()
    uniq: list[HuntFinding] = []
    for f in res.findings:
        sig = (f.rule_id, f.log_file, f.line_no)
        if sig in seen_lines:
            continue
        seen_lines.add(sig)
        uniq.append(f)
    res.findings = uniq

    res.findings.sort(key=lambda f: (f.ts or datetime.min.replace(tzinfo=timezone.utc)))
    return res


def _cluster(events: list[Event], minutes: int = 10) -> list[list[Event]]:
    buckets: list[list[Event]] = []
    window = timedelta(minutes=minutes)
    for e in sorted(events, key=lambda x: x.ts or datetime.min.replace(tzinfo=timezone.utc)):
        if buckets and e.ts and buckets[-1][-1].ts and (e.ts - buckets[-1][-1].ts) <= window:
            buckets[-1].append(e)
        else:
            buckets.append([e])
    return buckets
