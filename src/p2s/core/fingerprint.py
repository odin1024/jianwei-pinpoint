"""HTTP 指纹 —— 兼容层。

真正的探测实现在 `core/discovery.py`，与设备发现共用同一套
HTTP 探测、路径/UA 回退阶梯与 SAPI 判定逻辑。

历史上这里有一份独立实现，导致 **CLI 与 Web 控制台用两套引擎**：
CLI 看不到设备类型、不做存活判定，Web 能看到。结果不一致。
现在统一到 discovery，本模块只保留旧接口供 URL 探测与外部调用使用。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import urlparse

from .discovery import _detect_sapi as detect_sapi
from .discovery import probe_http


@dataclass
class Fingerprint:
    """一次 HTTP 指纹采集的结果（兼容旧接口）。"""

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


_SAPI_LABEL = {
    "apache": "Apache + mod_php",
    "fpm": "PHP-FPM",
    "iis": "Microsoft IIS + php-cgi",
    "litespeed": "LiteSpeed",
    "unknown": "未知 SAPI",
}


def fingerprint(url: str, *, timeout: float = 10.0, verify_tls: bool = True,
                method: str = "GET") -> Fingerprint:
    """采集单个 URL 的版本与 SAPI 指纹（只读）。"""
    fp = Fingerprint(url=url)
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    https = parsed.scheme == "https"
    if not host:
        fp.error = "无法解析主机名"
        return fp

    svc = probe_http(host, port, https=https, timeout=timeout, quick=True)
    if svc is None:
        fp.error = "探测失败"
        return fp
    if svc.http_status is None:
        fp.error = svc.banner or "无 HTTP 响应"
        return fp

    fp.ok = True
    fp.status_code = svc.http_status
    fp.server = svc.server
    fp.x_powered_by = svc.x_powered_by
    fp.php_version = svc.php_hint if (svc.php_hint or "").lower().startswith("php/") else None
    if fp.php_version and "/" in fp.php_version:
        fp.php_version = fp.php_version.split("/", 1)[1]
    sapi = detect_sapi(svc.server, svc.x_powered_by, port)
    fp.sapi = sapi
    fp.sapi_label = _SAPI_LABEL.get(sapi or "unknown")
    fp.confidence = 0.9 if fp.php_version else 0.5
    fp.signals = [f"status:{fp.status_code}"]
    if svc.server:
        fp.signals.append(f"server:{svc.server}")
    if svc.http_title:
        fp.signals.append(f"title:{svc.http_title[:60]}")
    return fp


def fingerprint_paths(base_url: str, paths=("/index.php", "/", "/info.php", "/phpinfo.php"),
                       *, timeout: float = 10.0) -> list[Fingerprint]:
    """对一组路径做指纹采集，返回去重后的结果。"""
    out: list[Fingerprint] = []
    seen: set[str] = set()
    for path in paths:
        fp = fingerprint(base_url.rstrip("/") + path, timeout=timeout)
        key = f"{fp.php_version}|{fp.sapi}"
        if key in seen and fp.ok:
            continue
        seen.add(key)
        out.append(fp)
    return out
