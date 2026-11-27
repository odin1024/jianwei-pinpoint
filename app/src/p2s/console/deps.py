"""控制台共享底座：路径、存储、鉴权、任务队列、CSV 工具。

从 app.py 拆出（第一阶段）。只放**被多处复用**的东西，不放路由、不放中间件；
app.py 通过 `from .deps import *` 使用，后续拆路由时各模块同样从这里取依赖。
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException
from fastapi.responses import Response

from ..core import discovery
from ..core import report as report_mod
from ..core.jobs import JobManager

DATA_DIR = Path(os.environ.get("P2S_DATA_DIR", "./p2s-data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_FILE = DATA_DIR / "assets.json"
ASSETS_DB = DATA_DIR / "assets.db"
SCANS_DIR = DATA_DIR / "scans"
UPLOAD_DIR = DATA_DIR / "uploads"
_lock = threading.Lock()
JOBS = JobManager(DATA_DIR, max_workers=1)

#: 资产存储实例（延迟创建，见 _asset_store()）
_ASSET_STORE = None

# --------------------------------------------------------------------------
# 认证
#
# 设计取舍：这是内网单机工具，不引入用户体系与数据库，只做「单账号 + 会话 Cookie」。
# 没有口令就不许用：未显式设置口令时随机生成并打印到启动日志，
# 宁可让部署者去翻日志，也不留一个裸奔的扫描控制台。
#
# 这里绝不能有硬编码兜底口令。控制台掌握扫描发起、加固下发与报告读取，
# 一旦以 --host 0.0.0.0 部署，任何默认口令都等于把生产处置权限公开。
# --------------------------------------------------------------------------
SESSION_COOKIE = "p2s_session"
SESSION_TTL = 12 * 3600          # 12 小时
_UNAUTH_OK = {"/login", "/api/login", "/api/health", "/favicon.ico",
              # Agent 用 X-P2S-Token 鉴权，不走会话 Cookie；端点内部自己校验令牌
              "/api/agent/report"}

#: 控制台账号名（口令一律走下面的随机生成 / 环境变量，不设默认值）
ADMIN_USER = os.environ.get("P2S_ADMIN_USER", "admin")

#: 登录口令：显式配置优先，否则每次启动随机生成
CONSOLE_PASSWORD = os.environ.get("P2S_CONSOLE_PASSWORD", "")
_generated_pw = not CONSOLE_PASSWORD
if _generated_pw:
    CONSOLE_PASSWORD = secrets.token_urlsafe(12)

#: P2S_ADMIN_PASSWORD 可单独覆盖登录口令；未设时与 CONSOLE_PASSWORD 一致
_ADMIN_PW_ENV = os.environ.get("P2S_ADMIN_PASSWORD", "")
ADMIN_PASSWORD = _ADMIN_PW_ENV or CONSOLE_PASSWORD

if _generated_pw:
    print(
        f"[p2s] 未设置 P2S_CONSOLE_PASSWORD，本次启动登录凭据：\n"
        f"[p2s]   用户名：{ADMIN_USER}\n"
        f"[p2s]   口令  ：{CONSOLE_PASSWORD}\n"
        f"[p2s] 生产部署请显式设置 P2S_CONSOLE_PASSWORD，否则每次重启口令都会变。",
        file=sys.stderr,
    )

#: Agent 上报令牌；缺省复用控制台口令，便于单机部署
AGENT_TOKEN = os.environ.get("P2S_AGENT_TOKEN", CONSOLE_PASSWORD)

_sessions: dict[str, float] = {}
_sessions_lock = threading.Lock()

#: 日志路径白名单根目录（可用 P2S_LOG_ROOTS 以 os.pathsep 追加）
#: 目标：允许「日志分析」这个功能本身需要的目录，同时挡住 /etc/shadow、
#: C:\Windows\win.ini 这类任意文件读取。
_LOG_ROOTS = [UPLOAD_DIR, (Path.cwd() / "logs"), (Path.cwd() / "examples"),
              (Path.cwd().parent / "samples")]
for _sys_log in ("/var/log", "/var/log/nginx", "/var/log/apache2", "/var/log/httpd",
                 "/usr/local/var/log"):
    if Path(_sys_log).is_dir():
        _LOG_ROOTS.append(Path(_sys_log))
for _extra in filter(None, os.environ.get("P2S_LOG_ROOTS", "").split(os.pathsep)):
    _LOG_ROOTS.append(Path(_extra).expanduser())

#: 文件名形状也约束一次：即便在允许目录里，也不去读 .ini / .pem / .key 之类
#: 指纹知识库：确认过的「指纹 → 产品」跨批次复用
KB_FILE = DATA_DIR / "fingerprints.json"

_LOG_SUFFIXES = {".log", ".gz", ".txt", ".json", ".csv", ".out", ".sample"}

MAX_LOG_BYTES = 256 * 1024 * 1024
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


def _issue_session() -> str:
    sid = secrets.token_urlsafe(32)
    with _sessions_lock:
        now = time.time()
        for k, exp in list(_sessions.items()):
            if exp < now:
                _sessions.pop(k, None)
        _sessions[sid] = now + SESSION_TTL
    return sid


def _session_valid(sid: str | None) -> bool:
    if not sid:
        return False
    with _sessions_lock:
        exp = _sessions.get(sid)
        if not exp:
            return False
        if exp < time.time():
            _sessions.pop(sid, None)
            return False
    return True


def _password_ok(given: str) -> bool:
    """兼容旧调用：只比对口令。"""
    return hmac.compare_digest(given or "", ADMIN_PASSWORD)


def _credentials_ok(user: str, password: str) -> bool:
    """校验用户名与口令。

    两个比较都用 compare_digest 且**不短路**：先算两个布尔再与，
    避免"用户名错"与"口令错"的响应时间差被用来枚举账号。
    """
    user_ok = hmac.compare_digest((user or "").strip(), ADMIN_USER)
    pw_ok = hmac.compare_digest(password or "", ADMIN_PASSWORD)
    return user_ok and pw_ok



def _atomic_write(path: Path, text: str) -> None:
    """先写临时文件再 os.replace —— 进程被杀也不会留下半截 JSON。

    临时文件名必须唯一：调度线程和 API 线程会并发写同一个文件，
    共用固定 .tmp 名会互相覆盖，os.replace 有机会把半截内容搬上正，
    读方就会解析失败（曾经表现为「计划列表被清空」）。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        # Windows 上目标文件正被别的线程/进程打开时 os.replace 会抛 PermissionError，
        # 读方（调度线程 load_schedules）恰好开着时就会撞上，重试几次即可。
        for attempt in range(25):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 24:
                    raise
                time.sleep(0.02)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


_SECRET_FILE = DATA_DIR / ".signing-key"
_secret_cache: Optional[bytes] = None


def signing_secret() -> bytes:
    """加固令牌的 HMAC 密钥：每套部署独立随机生成并持久化。

    绝不能用源码常量做密钥 —— 令牌内容是「主机名|动作哈希|过期时间」，
    全部可预测，一旦密钥公开任何人都能离线伪造合法令牌，
    「一次性令牌 + 白名单」这层授权就完全失效。
    """
    global _secret_cache
    if _secret_cache is not None:
        return _secret_cache
    env = os.environ.get("P2S_SIGNING_KEY", "")
    if env:
        _secret_cache = env.encode()
        return _secret_cache
    try:
        if _SECRET_FILE.exists():
            val = _SECRET_FILE.read_text(encoding="utf-8").strip()
            if val:
                _secret_cache = val.encode()
                return _secret_cache
    except OSError:
        pass
    val = secrets.token_urlsafe(48)
    try:
        _atomic_write(_SECRET_FILE, val)
        if os.name != "nt":
            os.chmod(_SECRET_FILE, 0o600)
    except OSError:
        # 落盘失败就只在本次进程内有效，仍然强于固定密钥
        pass
    _secret_cache = val.encode()
    return _secret_cache


def validate_webhook_url(url: str) -> None:
    """校验 Webhook 目标，挡住 SSRF 中真正会越权的那部分。

    本产品本身就是内网扫描器，登录用户当然能访问 RFC1918 地址，
    因此不禁止私网 Webhook（内网 IM 机器人是正常用法）。
    必须挡的是两类「扫描功能给不了的能力」：
      - 链路本地 169.254.0.0/16：云厂商元数据服务，可窃取实例 IAM 凭证
      - 回环地址：可打到控制台自身或本机 Docker/DB 等未鉴权服务
    域名会被解析后再判断，避免用 DNS 指向元数据地址绕过。
    """
    import socket
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="通知地址格式不合法") from exc
    if parts.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="通知地址必须以 http:// 或 https:// 开头")
    host = parts.hostname or ""
    if not host:
        raise HTTPException(status_code=400, detail="通知地址缺少主机名")

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"通知地址无法解析：{host}") from exc

    allow_loop = os.environ.get("P2S_ALLOW_LOOPBACK_WEBHOOK", "").lower() in ("1", "true", "yes")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_link_local:
            raise HTTPException(
                status_code=400,
                detail="通知地址不能指向链路本地网段（云元数据服务 169.254.0.0/16）",
            )
        if ip.is_loopback and not allow_loop:
            raise HTTPException(
                status_code=400,
                detail="通知地址不能指向回环地址；确需本机回调请设 P2S_ALLOW_LOOPBACK_WEBHOOK=1",
            )


def _asset_store():
    """返回进程级唯一的资产存储实例（首次调用时创建）。"""
    global _ASSET_STORE
    if _ASSET_STORE is None:
        from .asset_store import AssetStore

        _ASSET_STORE = AssetStore(ASSETS_DB, ASSETS_FILE, redact=_redact_asset_text)
        # 首次启动：若检测到旧的 assets.json 且数据库为空，自动导入。
        # 原文件保留不删 —— 数据迁移必须可回退。
        try:
            _ASSET_STORE._migrate_from_json()
        except Exception:          # noqa: BLE001 —— 迁移失败不该阻断启动
            pass
    return _ASSET_STORE


def _load_assets() -> list[dict]:
    """读出全部资产。

    走 SQLite 存储（见 ``console/asset_store.py``）。首次启动时若检测到旧的
    ``assets.json`` 会自动导入 —— 原文件保留不删，出问题可人工回退。
    SQLite 不可用时自动回退 JSON 读取，平台不因存储故障整体不可用。
    """
    return _asset_store().load()


#: 资产里属于「自由文本」的字段：可能承载攻击载荷或敏感回显，落盘前脱敏。
#: 不能对整个资产对象无差别脱敏 —— redact 会把 40+ 位十六进制当 blob 抹掉，
#: 而 favicon / asset_fingerprints 正是 SHA256，整体脱敏会直接毁掉指纹。
_ASSET_TEXT_KEYS = frozenset({
    "note", "evidence", "errors", "remediation", "banner", "title",
    "cmdline", "command", "message", "detail", "raw", "snippet", "sample",
    "reason", "description", "path", "value",
})


def _redact_asset_text(obj):
    """只对自由文本字段脱敏，结构化标识与哈希保持原样。"""
    from ..core.redact import redact

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _ASSET_TEXT_KEYS:
                if isinstance(v, str):
                    out[k] = redact(v)
                    continue
                if isinstance(v, list):
                    out[k] = [redact(x) if isinstance(x, str) else _redact_asset_text(x)
                              for x in v]
                    continue
            out[k] = _redact_asset_text(v)
        return out
    if isinstance(obj, list):
        return [_redact_asset_text(x) for x in obj]
    return obj


def _save_assets(assets: list[dict]) -> None:
    """写入全部资产。落盘前统一脱敏。"""
    _asset_store().save(assets)


def _upsert_asset(asset: dict) -> None:
    """写入/覆盖单条资产 —— 增量写。

    比 `_save_assets` 快得多：代价与台账规模无关。
    单条增删改的接口应当优先用这个。
    """
    _asset_store().upsert(asset)


def _delete_asset(host: str) -> bool:
    """删除单条资产。返回是否确实删掉了。"""
    return _asset_store().delete(host)


def _get_asset(host: str) -> dict | None:
    """按 host 取单条资产 —— O(1)，不扫全表。"""
    return _asset_store().get(host)


def _count_assets() -> int:
    """资产条数 —— 比 load() 再 len() 便宜得多。"""
    return _asset_store().count()


def _resolve_log_path(raw: str) -> Path:
    """把用户给的日志路径收敛到白名单目录内，并做大小上限校验。

    控制台可能被部署在内网任何位置，日志路径参数不能直接当任意文件读取用。
    """
    if not raw:
        raise HTTPException(status_code=400, detail="缺少日志路径")
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    try:
        p = p.resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(status_code=400, detail=f"日志文件不存在: {raw}") from None
    if not p.is_file():
        raise HTTPException(status_code=400, detail=f"不是普通文件: {raw}")
    roots = []
    for r in _LOG_ROOTS:
        try:
            roots.append(r.resolve())
        except OSError:
            continue
    if not any(p == r or r in p.parents for r in roots):
        raise HTTPException(
            status_code=403,
            detail=(
                "日志路径不在允许的目录内。允许的根目录："
                + "、".join(str(r) for r in roots)
                + "；也可用环境变量 P2S_LOG_ROOTS 追加。"
            ),
        )
    if p.suffix.lower() not in _LOG_SUFFIXES and "log" not in p.name.lower():
        raise HTTPException(
            status_code=403,
            detail=f"该文件不像日志（后缀 {p.suffix or '无'}）。允许的后缀："
                   + "、".join(sorted(_LOG_SUFFIXES)),
        )
    size = p.stat().st_size
    if size > MAX_LOG_BYTES:
        raise HTTPException(status_code=413, detail=f"日志过大（{size} 字节），上限 {MAX_LOG_BYTES} 字节")
    return p


def _csv_cell(value: Any) -> str:
    """CSV 单元格：防公式注入 + 标准引号转义。"""
    s = "" if value is None else str(value)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    if any(ch in s for ch in (",", '"', "\n", "\r")):
        s = '"' + s.replace('"', '""') + '"'
    return s


def _csv_response(rows: list[list[Any]], filename: str) -> Response:
    body = "\ufeff" + "\r\n".join(",".join(_csv_cell(c) for c in row) for row in rows) + "\r\n"
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _new_scan(kind: str) -> report_mod.ScanResult:
    return report_mod.ScanResult(
        scan_id=f"{kind}-{uuid.uuid4().hex[:10]}",
        kind=kind,
        started_at=datetime.now().isoformat(timespec="seconds"),
    )


def _persist(res: report_mod.ScanResult) -> None:
    # 先落 finished_at 再写文件，否则交付给客户的报告里结束时间恒为空
    res.finished_at = res.finished_at or datetime.now().isoformat(timespec="seconds")
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    base = SCANS_DIR / res.scan_id
    report_mod.to_json(res, base.with_suffix(".json"))
    report_mod.to_markdown(res, base.with_suffix(".md"))
    report_mod.to_html(res, base.with_suffix(".html"))


def _asset_from_profile(prof: discovery.DeviceProfile, group: str, owner: str, note: str) -> dict:
    favicon = next((s.favicon_sha256 for s in prof.services if s.favicon_sha256), None)
    favicon_mmh3 = next((s.favicon_mmh3 for s in prof.services if s.favicon_mmh3 is not None), None)
    return {
        "id": uuid.uuid4().hex[:12],
        "host": prof.host,
        "group": group,
        "owner": owner,
        "note": note,
        "alive": prof.alive,
        "device_type": prof.device_type,
        "device_label": prof.device_label,
        "product": prof.product,
        "vendor": prof.vendor,
        "vendor_source": prof.vendor_source,
        "product_source": prof.product_source,
        "favicon": favicon,
        "favicon_mmh3": favicon_mmh3,
        "brand_hints": sorted({b for s in prof.services for b in (getattr(s, "brand_hints", None) or [])}),
        "asset_fingerprints": [h for s in prof.services for h in (getattr(s, "asset_hashes", None) or [])],
        "os_hint": prof.os_hint,
        "tech_stack": prof.tech_stack,
        "mac": prof.mac,
        "mac_vendor": prof.mac_vendor,
        "open_ports": prof.open_ports,
        "meaningful_ports": prof.meaningful_ports,
        "noise_ports": prof.noise_ports,
        "candidates": prof.candidates,
        "services": [s.to_dict() for s in prof.services],
        "php_present": prof.php_present,
        "php_version": prof.php_version,
        "php_instances": getattr(prof, "php_instances", []) or [],
        "sapi": prof.sapi,
        "exposure": prof.exposure,
        "risk": prof.risk,
        "confidence": prof.confidence,
        "evidence": prof.evidence,
        "remediation": prof.remediation,
        "errors": prof.errors,
        "last_checked": prof.scanned_at,
    }


_CHANGE_FIELDS = ("exposure", "php_version", "risk", "sapi", "alive")


def _diff_asset(old: dict | None, new: dict) -> dict | None:
    """对比同一台主机的两次画像，返回变化描述；无变化返回 None。"""
    if old is None:
        return {"kind": "new", "fields": {}}
    diffs = {
        k: [old.get(k), new.get(k)]
        for k in _CHANGE_FIELDS
        if (old.get(k) or None) != (new.get(k) or None)
    }
    return {"kind": "changed", "fields": diffs} if diffs else None


#: 产品级证据（能确定型号/厂商）；其余属于服务级或推断


_SCAN_SUMMARY_KEYS = ("scan_id", "kind", "risk", "started_at", "finished_at",
                      "target_count", "severity_counts", "changes")


def _scan_target_label(d: dict) -> str:
    """把扫描目标压缩成一句人话 —— 报告列表里最需要的信息。"""
    saved = str(d.get("target_label") or "").strip()
    if saved:
        return saved
    params = d.get("params") or {}
    if d.get("kind") == "logs":
        path = params.get("path") or ""
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        return name or path or "日志分析"
    cidr = params.get("cidr") or ""
    if cidr:
        return cidr
    hosts = params.get("hosts") or []
    if len(hosts) == 1:
        return str(hosts[0])
    if hosts:
        return f"{hosts[0]} 等 {len(hosts)} 台"
    return str(d.get("kind") or "-")


def _scan_dedupe_key(d: dict) -> str:
    """内容指纹：同源同结果的重复扫描应折叠成一条。

    刻意不含时间与 scan_id —— 否则同一份日志反复分析会堆出 N 条一样的记录。
    """
    sev = d.get("severity_counts") or {}
    return "|".join([
        str(d.get("kind")),
        _scan_target_label(d),
        ",".join(f"{k}:{sev.get(k, 0)}" for k in sorted(sev)),
        str(len(d.get("findings") or [])),
        str(d.get("target_count") or 0),
    ])


def _scan_summary(d: dict) -> dict:
    out = {k: d.get(k) for k in _SCAN_SUMMARY_KEYS if k in d}
    out["finding_count"] = len(d.get("findings") or [])
    out["error_count"] = len(d.get("errors") or [])
    out["target_label"] = _scan_target_label(d)
    out["dedupe_key"] = _scan_dedupe_key(d)
    return out


#: 扫描目录指纹 → 解析结果缓存。71 份报告每次请求都重新 JSON 解析太浪费。
_SCAN_CACHE: dict[str, Any] = {"sig": None, "full": []}


def _scan_signature() -> tuple[int, float]:
    if not SCANS_DIR.exists():
        return (0, 0.0)
    files = list(SCANS_DIR.glob("*.json"))
    newest = max((p.stat().st_mtime for p in files), default=0.0)
    return (len(files), round(newest, 3))


def _load_scans(limit: int | None = None, *, full: bool = True) -> list[dict]:
    """按修改时间倒序读取历史扫描（最新的在前），带目录指纹缓存。

    以前按文件名排序，但扫描 ID 是 `kind-随机串`，与时间无关，
    「最近扫描」实际上并不是最近的。
    """
    if not SCANS_DIR.exists():
        return []
    sig = _scan_signature()
    if _SCAN_CACHE["sig"] != sig:
        files = sorted(SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        loaded: list[dict] = []
        for p in files[:1000]:
            try:
                loaded.append(json.loads(p.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                continue
        _SCAN_CACHE["sig"] = sig
        _SCAN_CACHE["full"] = loaded
    scans = _SCAN_CACHE["full"]
    scans = scans[:limit] if limit else scans
    return scans if full else [_scan_summary(s) for s in scans]


def _expand_cidr(cidr: str, limit: int = 1024) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses > limit:
        raise HTTPException(status_code=400, detail=f"网段过大（{net.num_addresses} 台），上限 {limit} 台")
    return [str(h) for h in net.hosts()]


# 显式导出：`from .deps import *` 不会带下划线开头的名字，必须列全
__all__ = [
    "KB_FILE",
    "ADMIN_PASSWORD",
    "ADMIN_USER",
    "AGENT_TOKEN",
    "ASSETS_FILE",
    "ASSETS_DB",
    "CONSOLE_PASSWORD",
    "DATA_DIR",
    "JOBS",
    "MAX_LOG_BYTES",
    "MAX_UPLOAD_BYTES",
    "SCANS_DIR",
    "SESSION_COOKIE",
    "SESSION_TTL",
    "UPLOAD_DIR",
    "_ADMIN_PW_ENV",
    "_CHANGE_FIELDS",
    "_LOG_ROOTS",
    "_LOG_SUFFIXES",
    "_SCAN_CACHE",
    "_SCAN_SUMMARY_KEYS",
    "_UNAUTH_OK",
    "_asset_from_profile",
    "_atomic_write",
    "signing_secret",
    "validate_webhook_url",
    "_credentials_ok",
    "_csv_cell",
    "_csv_response",
    "_diff_asset",
    "_expand_cidr",
    "_issue_session",
    "_load_assets",
    "_load_scans",
    "_lock",
    "_new_scan",
    "_password_ok",
    "_persist",
    "_resolve_log_path",
    "_save_assets",
    "_upsert_asset",
    "_delete_asset",
    "_get_asset",
    "_count_assets",
    "_scan_signature",
    "_scan_summary",
    "_session_valid",
    "_sessions",
    "_sessions_lock",
]
