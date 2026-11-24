"""日志解析与规则匹配引擎（L1 被动检测）。

支持三种常见格式的自动识别：
  - JSON 结构化日志（Nginx log_format json / Apache + mod_log_config json）
  - Common Log Format / Combined Log Format
  - 自定义 KV 格式（带 key=value 形式）

另提供行为关联（behavioral correlation）：单条规则命中是"证据"，多条按攻击链组合是"判定"。
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

from .redact import redact
from .rules import RULES, SEVERITY_ORDER, Rule

_CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<ident>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+(?P<proto>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_KV_RE = re.compile(r'(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)=(?:"(?P<q>[^"]*)"|(?P<v>[^\s]*))')

_TS_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


@dataclass
class LogRecord:
    """一条归一化后的日志记录。"""

    raw: str = ""
    ts: Optional[datetime] = None
    ip: Optional[str] = None
    method: Optional[str] = None
    uri: Optional[str] = None
    status: Optional[int] = None
    size: Optional[int] = None
    ua: Optional[str] = None
    referer: Optional[str] = None
    body: Optional[str] = None
    resp_body: Optional[str] = None
    req_headers: dict[str, str] = field(default_factory=dict)
    resp_headers: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def fields(self) -> set[str]:
        s = set()
        for name in ("body", "resp_body", "uri", "ua", "status"):
            if getattr(self, name):
                s.add(name)
        if self.req_headers:
            s.add("req_headers")
        if self.resp_headers:
            s.add("resp_headers")
        return s


@dataclass
class Finding:
    """一条命中记录。"""

    rule_id: str
    rule_name: str
    severity: str
    dimension: str
    cves: list[str]
    ts: Optional[str]
    ip: Optional[str]
    uri: Optional[str]
    evidence: str
    description: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = self.ts.isoformat() if isinstance(self.ts, datetime) else self.ts
        return d


def _parse_ts(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_line(line: str) -> Optional[LogRecord]:
    """自动识别并解析一行日志。无法识别时返回 None。"""
    line = line.strip()
    if not line:
        return None

    # 1) JSON
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            return _from_json(obj, line)

    # 2) CLF / Combined
    m = _CLF_RE.match(line)
    if m:
        d = m.groupdict()
        rec = LogRecord(raw=line, ts=_parse_ts(d.get("ts")), ip=d.get("ip"))
        rec.method = d.get("method")
        rec.uri = d.get("uri")
        rec.status = int(d["status"]) if d.get("status") else None
        size = d.get("size")
        rec.size = int(size) if size and size.isdigit() else None
        rec.ua = d.get("ua")
        rec.referer = d.get("referer")
        return rec

    # 3) KV
    if "=" in line:
        pairs = {m2.group("key"): (m2.group("q") if m2.group("q") is not None else m2.group("v"))
                 for m2 in _KV_RE.finditer(line)}
        if pairs:
            return _from_kv(pairs, line)

    return None


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _from_json(obj: dict, raw: str) -> LogRecord:
    rec = LogRecord(raw=raw)
    ts = _first(obj, "time", "timestamp", "@timestamp", "time_local", "ts")
    rec.ts = _parse_ts(ts) if isinstance(ts, str) else None
    if rec.ts is None and isinstance(ts, (int, float)):
        try:
            rec.ts = datetime.fromtimestamp(ts)
        except (OverflowError, OSError, ValueError):
            rec.ts = None
    ip = _first(obj, "remote_addr", "client_ip", "ip", "src_ip", "clientip")
    rec.ip = str(ip) if ip is not None else None
    method = _first(obj, "request_method", "method", "verb")
    rec.method = str(method).upper() if method else None
    uri = _first(obj, "request_uri", "uri", "url", "path", "request")
    rec.uri = str(uri) if uri is not None else None
    status = _first(obj, "status", "response_code", "status_code", "http_status")
    try:
        rec.status = int(status) if status is not None else None
    except (TypeError, ValueError):
        rec.status = None
    size = _first(obj, "body_bytes_sent", "bytes", "size", "response_size")
    try:
        rec.size = int(size) if size is not None else None
    except (TypeError, ValueError):
        rec.size = None
    ua = _first(obj, "http_user_agent", "user_agent", "ua")
    rec.ua = str(ua) if ua is not None else None
    referer = _first(obj, "http_referer", "referer")
    rec.referer = str(referer) if referer is not None else None
    body = _first(obj, "request_body", "body", "req_body", "request_body_bytes")
    if body is not None:
        rec.body = body if isinstance(body, str) else str(body)
    rb = _first(obj, "response_body", "resp_body", "upstream_response_body")
    if rb is not None:
        rec.resp_body = rb if isinstance(rb, str) else str(rb)
    hdrs = _first(obj, "request_headers", "req_headers", "headers_in")
    if isinstance(hdrs, dict):
        rec.req_headers = {str(k).lower(): str(v) for k, v in hdrs.items()}
    rhdrs = _first(obj, "response_headers", "resp_headers", "headers_out")
    if isinstance(rhdrs, dict):
        rec.resp_headers = {str(k).lower(): str(v) for k, v in rhdrs.items()}
    rec.extra = {k: v for k, v in obj.items() if k not in
                 {"time", "timestamp", "remote_addr", "client_ip", "ip", "request_method", "method",
                  "request_uri", "uri", "url", "status", "response_code", "status_code",
                  "body_bytes_sent", "bytes", "size", "http_user_agent", "user_agent", "ua",
                  "http_referer", "referer", "request_body", "body", "req_body",
                  "response_body", "resp_body", "request_headers", "req_headers", "headers_in",
                  "response_headers", "resp_headers", "headers_out"}}
    return rec


_KV_ALIASES = {
    "ip": ("ip", "client_ip", "remote_addr", "src"),
    "method": ("method", "request_method", "verb"),
    "uri": ("uri", "url", "path", "request_uri"),
    "status": ("status", "response_code", "status_code"),
    "size": ("bytes", "size", "body_bytes_sent"),
    "ua": ("user_agent", "http_user_agent", "ua"),
    "body": ("request_body", "body", "req_body"),
    "resp_body": ("response_body", "resp_body"),
    "ts": ("time", "timestamp", "ts"),
}


def _from_kv(pairs: dict, raw: str) -> LogRecord:
    rec = LogRecord(raw=raw)

    def pick(field: str) -> Any:
        for alias in _KV_ALIASES.get(field, (field,)):
            if alias in pairs:
                return pairs[alias]
        return None

    rec.ip = pick("ip")
    rec.method = (pick("method") or "").upper() or None
    rec.uri = pick("uri")
    st = pick("status")
    try:
        rec.status = int(st) if st is not None else None
    except (TypeError, ValueError):
        rec.status = None
    sz = pick("size")
    try:
        rec.size = int(sz) if sz is not None and str(sz).isdigit() else None
    except (TypeError, ValueError):
        rec.size = None
    rec.ua = pick("ua")
    rec.body = pick("body")
    rec.resp_body = pick("resp_body")
    ts = pick("ts")
    rec.ts = _parse_ts(ts) if isinstance(ts, str) else None
    rec.extra = pairs
    return rec


def iter_records(lines: Iterable[str]) -> Iterator[LogRecord]:
    for line in lines:
        rec = parse_line(line)
        if rec is not None:
            yield rec


# --------------------------------------------------------------------------
# 规则匹配
# --------------------------------------------------------------------------

_FILENAME_RE = re.compile(r"""filename\s*=\s*"(?P<v1>[^"]*)"|filename\*\s*=\s*"(?P<v3>[^"]*)"|filename\*\s*=\s*[^\s]*''\s*(?P<v2>[^"\r\n]*)""")
_SERIALIZED_RE = re.compile(r"\|(?:O|C|a|r):\d+:")
_PHP_CODE_RE = re.compile(r"<\?(?:php|=)")
_SESSION_PATH_RE = re.compile(r"(?:/|^)(?:sess_|sess_)|sess_[A-Za-z0-9]{8,}")
_OOM_RE = re.compile(r"Allowed memory size.{1,80}exhausted", re.IGNORECASE | re.DOTALL)
_SESSION_DESTROY_RE = re.compile(r"Session object destruction failed", re.IGNORECASE)
_UPLOAD_PROGRESS_RE = re.compile(r"PHP_SESSION_UPLOAD_PROGRESS")
_PHPSESSID_FIELD_RE = re.compile(r'name=["\']?PHPSESSID["\']?', re.IGNORECASE)


def _filenames(body: str) -> list[str]:
    """提取 multipart 中的所有 filename，同时支持 filename="..." 与 filename*=UTF-8''... 。"""
    out: list[str] = []
    for m in _FILENAME_RE.finditer(body):
        for g in ("v1", "v3", "v2"):
            val = m.group(g)
            if val is not None:
                out.append(val)
                break
    return out


def _match(rule: Rule, rec: LogRecord, ctx: dict) -> Optional[str]:
    m = rule.matcher
    if m == "upload_progress":
        if rec.body and _UPLOAD_PROGRESS_RE.search(rec.body):
            return "请求体命中 PHP_SESSION_UPLOAD_PROGRESS"
        return None
    if m == "phpsessid_in_body":
        if rec.body and _PHPSESSID_FIELD_RE.search(rec.body):
            return "请求体含 PHPSESSID 表单字段"
        return None
    if m == "php_in_filename":
        if not rec.body:
            return None
        for fn in _filenames(rec.body):
            if _PHP_CODE_RE.search(fn):
                return f"filename 含 PHP 代码: {redact(fn, max_len=120)!r}"
        return None
    if m == "serialized_in_filename":
        if not rec.body:
            return None
        for fn in _filenames(rec.body):
            if _SERIALIZED_RE.search(fn):
                return f"filename 含序列化对象: {redact(fn, max_len=120)!r}"
        return None
    if m == "oversized_filename":
        if not rec.body:
            return None
        for fn in _filenames(rec.body):
            if len(fn) > 10240:
                return f"filename 长度 {len(fn)} 字节（阈值 10240）"
        return None
    if m == "chunked_multipart":
        if not rec.req_headers:
            return None
        te = rec.req_headers.get("transfer-encoding", "")
        ct = rec.req_headers.get("content-type", "")
        if "chunked" in te.lower() and "multipart" in ct.lower():
            return "Transfer-Encoding: chunked + multipart/form-data"
        return None
    if m == "session_path_in_uri":
        if rec.uri and _SESSION_PATH_RE.search(rec.uri):
            return f"URI 含会话文件路径: {rec.uri[:160]}"
        return None
    if m == "oom_in_response":
        if rec.resp_body and _OOM_RE.search(rec.resp_body):
            return "响应体含 PHP 内存耗尽错误"
        return None
    if m == "session_destruction_failed":
        if rec.resp_body and _SESSION_DESTROY_RE.search(rec.resp_body):
            return "响应体含 Session object destruction failed"
        return None
    if m == "anomalous_sessionid_length":
        sid = rec.resp_headers.get("set-cookie", "")
        m2 = re.search(r"PHPSESSID=([^;]+)", sid)
        if m2 and len(m2.group(1)) > 256:
            return f"PHPSESSID 长度 {len(m2.group(1))} 字节（阈值 256）"
        return None
    if m == "probe_burst":
        return ctx.get("probe_burst_evidence")
    if m == "scanner_user_agent":
        if rec.ua and any(k in rec.ua.lower() for k in ("php2shell", "p2srun")):
            return f"扫描器 User-Agent: {rec.ua[:120]}"
        return None
    if m == "vulnerable_version_banner":
        from .versions import classify

        for hdr in (rec.resp_headers.get("x-powered-by", ""), rec.resp_headers.get("server", "")):
            if hdr and "php/" in hdr.lower():
                v = classify(hdr)
                if v.needs_action:
                    return f"横幅暴露 {v.version} -> {v.status}"
        return None
    return None


def scan_records(records: list[LogRecord]) -> list[Finding]:
    """对记录集合执行规则匹配 + 行为关联。"""
    findings: list[Finding] = []
    present: set[str] = set()
    for r in records:
        present |= r.fields()

    # --- 行为关联：高频 upload_progress 探测 ---
    burst = _detect_probe_bursts(records)
    burst_by_ip = {b["ip"]: b for b in burst}

    for rec in records:
        ctx: dict = {}
        b = burst_by_ip.get(rec.ip or "")
        if b:
            ctx["probe_burst_evidence"] = (
                f"同源 {b['count']} 次 upload_progress 探测，"
                f"时间窗 {b['window']}s（阈值 {b['threshold']}/{b['window']}s）"
            )
        for rule in RULES:
            if rule.requires not in ("any",) and rule.requires not in present:
                continue
            evidence = _match(rule, rec, ctx)
            if not evidence:
                continue
            if rule.matcher == "probe_burst" and rec.ip not in burst_by_ip:
                continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    dimension=rule.dimension,
                    cves=list(rule.cves),
                    ts=rec.ts.isoformat() if rec.ts else None,
                    ip=rec.ip,
                    uri=rec.uri,
                    evidence=evidence,
                    description=rule.description,
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id))
    return findings


def _detect_probe_bursts(
    records: list[LogRecord], threshold: int = 3, window_seconds: int = 60
) -> list[dict]:
    """检测同一来源在时间窗内的高频 upload_progress 探测。"""
    per_ip: dict[str, list[datetime]] = defaultdict(list)
    for rec in records:
        if not rec.ts:
            continue
        body_hit = bool(rec.body and _UPLOAD_PROGRESS_RE.search(rec.body))
        ua_hit = bool(rec.ua and any(k in rec.ua.lower() for k in ("php2shell", "p2srun")))
        if body_hit or ua_hit:
            per_ip[rec.ip or "?"].append(rec.ts)

    out: list[dict] = []
    for ip, times in per_ip.items():
        times.sort()
        best = 0
        best_span = 0.0
        for i, t0 in enumerate(times):
            j = i
            while j < len(times) and (times[j] - t0).total_seconds() <= window_seconds:
                j += 1
            if j - i > best:
                best = j - i
                best_span = (times[j - 1] - t0).total_seconds()
        if best >= threshold:
            out.append({"ip": ip, "count": best, "window": window_seconds, "span": best_span,
                        "threshold": threshold})
    return out
