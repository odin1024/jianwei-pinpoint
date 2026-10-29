"""HTTP 指纹与 SAPI 识别。

SAPI（Server API）决定同一 PHP 版本的实际风险与可用的检测手段：
  - mod_php   : 风险最高，未认证请求可在应用代码运行前触发利用
  - PHP-FPM   : 启动失败会退出子进程，部分链路被阻断
  - php-cgi   : 受影响
  - FrankenPHP: 与 mod_php 行为同构，源码分析表明很可能易受影响
  - LiteSpeed : 建模类似 FPM
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional

import httpx

#: SAPI 签名特征：按判定优先级排列（越靠前越具体）
SAPI_SIGNATURES: list[tuple[str, tuple[str, ...], str]] = [
    ("openresty", ("openresty",), "OpenResty / Nginx + PHP-FPM"),
    ("frankenphp", ("frankenphp", "caddy"), "FrankenPHP"),
    ("litespeed", ("litespeed", "openlitespeed"), "LiteSpeed / OpenLiteSpeed"),
    ("iis-cgi", ("microsoft-iis", "iis"), "Microsoft IIS + php-cgi"),
    ("apache-fpm", ("apache/", "apache "), "Apache + mod_proxy_fcgi (PHP-FPM)"),
    ("nginx", ("nginx",), "Nginx + PHP-FPM"),
    ("apache", ("apache",), "Apache + mod_php"),
    ("iis", ("microsoft-iis",), "Microsoft IIS"),
]

#: 响应体 / 错误页中的 SAPI 指纹
_BODY_SIGNATURES: list[tuple[str, str]] = [
    (r"Primary script unknown", "fpm"),
    (r"No input file specified\.", "cgi"),
    (r"Apache/\d[\d.]*\s+Server at", "apache"),
    (r"Failed loading .*\.so", "apache"),
    (r"phpinfo\(\)", "any"),
]

_PHP_IN_BODY_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)")


@dataclass
class Fingerprint:
    """一次 HTTP 指纹采集的结果。"""

    url: str
    ok: bool = False
    status_code: Optional[int] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    php_version: Optional[str] = None
    sapi: Optional[str] = None
    sapi_label: Optional[str] = None
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _detect_sapi(server: str | None, powered_by: str | None, body: str) -> tuple[Optional[str], Optional[str], list[str]]:
    signals: list[str] = []
    blob = f"{server or ''} {powered_by or ''}".lower()
    for key, needles, label in SAPI_SIGNATURES:
        if any(n in blob for n in needles):
            signals.append(f"header:{key}")
            sapi, sapi_label = key, label
            break
    else:
        sapi, sapi_label = None, None

    for pattern, hint in _BODY_SIGNATURES:
        if re.search(pattern, body, re.IGNORECASE):
            signals.append(f"body:{hint}")
            if sapi is None:
                sapi = hint
                sapi_label = {
                    "fpm": "PHP-FPM",
                    "cgi": "php-cgi",
                    "apache": "Apache + mod_php",
                }.get(hint, "未知")

    # mod_php 判定增强：Apache Server 头 + PHP X-Powered-By 同时出现
    if server and "apache" in server.lower() and powered_by and "php/" in powered_by.lower():
        if sapi in (None, "apache", "apache-fpm"):
            signals.append("combo:apache+php")
            sapi = "apache"
            sapi_label = "Apache + mod_php"

    return sapi, sapi_label, signals


def extract_php_version(server: str | None, powered_by: str | None, body: str = "") -> Optional[str]:
    """从响应头与响应体中提取 PHP 版本号。"""
    for candidate in (powered_by, server):
        if candidate:
            m = re.search(r"PHP/(\d+\.\d+\.\d+)", candidate)
            if m:
                return m.group(1)
    if body:
        m = _PHP_IN_BODY_RE.search(body)
        if m:
            return m.group(1)
    return None


def fingerprint(url: str, *, timeout: float = 10.0, verify_tls: bool = True, method: str = "GET") -> Fingerprint:
    """采集单个 URL 的版本与 SAPI 指纹。只读操作，不发送任何利用载荷。"""
    fp = Fingerprint(url=url)
    try:
        with httpx.Client(follow_redirects=False, timeout=timeout, verify=verify_tls) as client:
            resp = client.request(method, url, headers={"User-Agent": "p2s-fingerprint/0.1"})
        fp.ok = True
        fp.status_code = resp.status_code
        fp.server = resp.headers.get("Server")
        fp.x_powered_by = resp.headers.get("X-Powered-By")
        body = ""
        if resp.headers.get("content-type", "").lower().startswith("text/"):
            body = resp.text[:20000]
        fp.php_version = extract_php_version(fp.server, fp.x_powered_by, body)
        sapi, label, signals = _detect_sapi(fp.server, fp.x_powered_by, body)
        fp.sapi, fp.sapi_label, fp.signals = sapi, label, signals
        fp.confidence = 0.9 if fp.php_version else 0.3
        if fp.php_version and fp.sapi:
            fp.confidence = 0.95
        elif fp.php_version:
            fp.confidence = 0.8
    except Exception as exc:  # noqa: BLE001 - 采集类工具需要吞掉一切网络异常
        fp.error = f"{type(exc).__name__}: {exc}"
    return fp


#: 常见探测路径（只读）
DEFAULT_PATHS: tuple[str, ...] = ("/index.php", "/", "/phpinfo.php", "/info.php")


def fingerprint_paths(
    base_url: str, paths: tuple[str, ...] = DEFAULT_PATHS, *, timeout: float = 10.0
) -> list[Fingerprint]:
    """对一组路径做指纹采集，返回去重后的结果。"""
    out: list[Fingerprint] = []
    seen: set[str] = set()
    for p in paths:
        url = base_url.rstrip("/") + p
        fp = fingerprint(url, timeout=timeout)
        key = f"{fp.php_version}|{fp.sapi}"
        if key in seen and fp.ok:
            continue
        seen.add(key)
        out.append(fp)
    return out
