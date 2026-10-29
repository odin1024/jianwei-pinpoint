"""资产发现引擎 —— 端口 → 服务 → 存活 → 设备类型 → PHP 暴露面。

技术栈说明：
  L0 存活与端口发现   并发 TCP connect 探测（非 SYN 扫描，不需要 root/原始套接字，
                     任何平台都能跑；代价是比 SYN 扫描慢，且会留下完整连接日志）
  L1 服务协议识别     HTTP/HTTPS 指纹 + TLS 证书取证 + SSH/FTP/SMTP banner + favicon 哈希
                     自签名证书自动降级；UA 与路径双回退阶梯
  L2 存活判定         **必须拿到有意义的协议响应**才算在线。
                     出口 NAT / tarpit 会让任意 IP 的某些端口"可连但无数据"，
                     只看 TCP 握手会把几百台不存在的设备写进台账。
  L3 设备类型分类     页面标题 / Server 头 / TLS 证书 / 登录路径 / Cookie 为主，
                     端口画像兜底；辅以 MAC OUI 厂商
  L4 PHP 暴露面       有无 PHP → SAPI → 版本 → 对比修复基线
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

import httpx

from .identification import Classification, assess_liveness, classify
from .oui import vendor_for_ip
from .versions import Status, Verdict
from .versions import classify as classify_version

# --------------------------------------------------------------------------
# 端口表
# --------------------------------------------------------------------------
DEVICE_PORTS = (
    2000, 2001, 2082, 2083, 2086, 2087, 2095, 2096, 4243, 5000, 7070, 7443,
    8009, 8181, 8282, 8383, 8484, 8880, 8899, 9000, 9090, 9443, 10000, 10001,
    10443, 10250, 11211, 15672,
)

TOP_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 161, 389, 443, 445, 465, 514,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3128, 3306, 3389, 4848,
    5432, 5672, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8088, 8443,
    8888, 9200, 9300, 27017, 28017, 50000,
)

FULL_PORT_SET = tuple(sorted(set(TOP_PORTS) | set(DEVICE_PORTS)))

FAST_PORT_SET = (
    21, 22, 23, 25, 80, 110, 143, 161, 445, 3306, 3389, 5432, 6379, 8080,
    8443, 8888, 9090, 2000, 8000, 10000, 8081, 8088, 9000, 3000, 4243, 443,
)

WEB_HTTP_PORTS = (80, 81, 88, 800, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 3000, 5000, 7001, 7070, 7443, 8181, 8880, 10000)
WEB_HTTPS_PORTS = (443, 8443, 9443, 10443, 2083, 2087, 2001, 2096)
AMBIGUOUS_WEB_PORTS = (2000, 2082, 2086, 4243, 10001)
WEB_PORTS = tuple(sorted(set(WEB_HTTP_PORTS) | set(WEB_HTTPS_PORTS) | set(AMBIGUOUS_WEB_PORTS)))

#: 路径回退阶梯 —— 覆盖实测到的华为交换机 /simple/view/login.html、iBMC /login.html
PATH_LADDER = ("/", "/login.html", "/simple/view/login.html", "/webui/", "/index.asp", "/admin/")

#: User-Agent 阶梯
UA_LADDER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0",
    "curl/8.5.0",
)

_OK_STATUS = (200, 301, 302, 303, 307, 308, 401, 403)


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------
@dataclass
class Service:
    """一个开放端口上的服务。"""

    port: int
    proto: str = "unknown"
    banner: Optional[str] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    location: Optional[str] = None
    cookie: Optional[str] = None
    www_auth: Optional[str] = None
    matched_path: Optional[str] = None
    body_sample: Optional[str] = None
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_san: list[str] = field(default_factory=list)
    tls_expired: bool = False
    favicon_sha256: Optional[str] = None
    php_hint: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeviceProfile:
    """一台设备的完整画像。"""

    host: str
    alive: bool = False
    scanned_at: str = ""
    open_ports: list[int] = field(default_factory=list)
    meaningful_ports: list[int] = field(default_factory=list)
    noise_ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    device_type: str = "unknown"
    device_label: str = "未识别设备"
    vendor: Optional[str] = None
    product: Optional[str] = None
    os_hint: Optional[str] = None
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None
    tech_stack: list[str] = field(default_factory=list)
    php_present: bool = False
    php_version: Optional[str] = None
    sapi: Optional[str] = None
    verdict: Optional[Verdict] = None
    confidence: float = 0.0
    exposure: str = "unknown"
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if self.exposure == "exposed":
            return "critical"
        if self.exposure == "unknown" and self.php_present:
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.to_dict() if self.verdict else None
        d["risk"] = self.risk
        return d


# --------------------------------------------------------------------------
# L0 端口发现
# --------------------------------------------------------------------------
def tcp_probe(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(host: str, ports: Iterable[int] = FULL_PORT_SET, *, timeout: float = 1.2,
               workers: int = 96) -> list[int]:
    ports = list(ports)
    found: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_probe, host, p, timeout): p for p in ports}
        for f in as_completed(futs):
            try:
                if f.result():
                    found.append(futs[f])
            except Exception:
                pass
    return sorted(found)


# --------------------------------------------------------------------------
# L1 服务识别
# --------------------------------------------------------------------------
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PHP_VER_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)")


def _extract_title(body: str) -> Optional[str]:
    m = _TITLE_RE.search(body)
    if not m:
        return None
    t = re.sub(r"\s+", " ", m.group(1)).strip()
    return t[:160] if t else None


def _tls_info(host: str, port: int, timeout: float = 8.0):
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
    except Exception:
        return None, None, [], False
    try:
        from cryptography import x509

        c = x509.load_der_x509_certificate(der)
        san: list[str] = []
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san = [str(g.value) for g in ext]
        except Exception:
            pass
        expired = False
        try:
            expired = c.not_valid_after_utc < datetime.now(c.not_valid_after_utc.tzinfo)
        except Exception:
            pass
        return c.subject.rfc4514_string(), c.issuer.rfc4514_string(), san, expired
    except Exception:
        return None, None, [], False


def probe_http(host: str, port: int, *, https: bool = False, timeout: float = 8.0,
               quick: bool = False, favicon: bool = False) -> Optional[Service]:
    """HTTP/HTTPS 指纹采集。"""
    svc = Service(port=port, proto="https" if https else "http")
    scheme = "https" if https else "http"
    base = f"{scheme}://{host}:{port}"
    paths = ("/",) if quick else PATH_LADDER
    deadline = time.monotonic() + max(timeout * 2.0, 10.0)
    best: Optional[httpx.Response] = None
    best_path = "/"
    best_title = False

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        for ua in UA_LADDER:
            for path in paths:
                if time.monotonic() > deadline:
                    break
                try:
                    resp = client.get(f"{base}{path}", headers={"User-Agent": ua, "Accept": "*/*"})
                except Exception as exc:  # noqa: BLE001
                    svc.banner = f"{type(exc).__name__}: {str(exc)[:100]}"
                    if best is None:
                        return svc
                    continue
                ctype = resp.headers.get("Content-Type", "")
                body_text = resp.text[:20000] if ("text" in ctype or not ctype) else ""
                has_title = bool(_TITLE_RE.search(body_text))
                if best is None or (resp.status_code in _OK_STATUS and best.status_code not in _OK_STATUS):
                    best, best_path = resp, path
                if has_title:
                    best_title = True
                # 200 但页面没有标题（空白框架页/跳转页）时继续往下试，
                # 真正的产品标题通常在 /login.html 这类子路径上
                if resp.status_code in _OK_STATUS and has_title:
                    best, best_path = resp, path
                    break
            # 只有拿到标题才算识别成功；否则继续换 UA 再试
            if best is not None and best.status_code in _OK_STATUS and best_title:
                break
            if quick:
                break
            if best is not None and best.status_code not in (404, 400, 403, 405, 501):
                break

    if best is None:
        return svc

    svc.http_status = best.status_code
    svc.server = best.headers.get("Server")
    svc.x_powered_by = best.headers.get("X-Powered-By")
    svc.location = best.headers.get("Location")
    svc.cookie = best.headers.get("Set-Cookie")
    svc.www_auth = best.headers.get("WWW-Authenticate")
    svc.matched_path = best_path
    ctype = best.headers.get("Content-Type", "")
    body = best.text[:60000] if ("text" in ctype or not ctype) else ""
    svc.http_title = _extract_title(body)
    if body:
        low = body.lower()
        svc.body_sample = " ".join(
            low.split()
        )[:600] if any(k in low for k in ("php", "powered by", "login", "dashboard", "username")) else None

    # PHP 线索
    if svc.x_powered_by and "php" in svc.x_powered_by.lower():
        svc.php_hint = svc.x_powered_by
    elif "phpsessid" in (svc.cookie or "").lower():
        svc.php_hint = "PHPSESSID cookie"
    elif _PHP_VER_RE.search(svc.server or ""):
        svc.php_hint = svc.server
    elif "powered by php" in body.lower():
        svc.php_hint = "Powered by PHP"

    # favicon 哈希（深度模式）。
    # 注意：上面的 client 已经随 with 块关闭，这里必须另开一个连接，
    # 否则每次都会抛 "client has been closed" 被静默吞掉 —— favicon 永远拿不到。
    if favicon:
        try:
            with httpx.Client(verify=False, timeout=min(timeout, 5.0), follow_redirects=False) as fc:
                fr = fc.get(f"{base}/favicon.ico", headers={"User-Agent": UA_LADDER[0]})
            if fr.status_code == 200 and fr.content:
                svc.favicon_sha256 = hashlib.sha256(fr.content).hexdigest()
        except Exception:
            pass
    return svc


def probe_ssh(host: str, port: int = 22, timeout: float = 6.0) -> Optional[Service]:
    svc = Service(port=port, proto="ssh")
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256)
        svc.banner = banner.decode("utf-8", errors="replace").strip()
        return svc
    except Exception as exc:  # noqa: BLE001
        svc.banner = f"{type(exc).__name__}"
        return svc


def probe_banner(host: str, port: int, timeout: float = 5.0) -> Optional[Service]:
    svc = Service(port=port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(512)
            except (socket.timeout, TimeoutError):
                data = b""
            svc.banner = data.decode("utf-8", errors="replace").strip()[:200]
            low = (svc.banner or "").lower()
            if low.startswith("ssh-"):
                svc.proto = "ssh"
            elif low.startswith("220"):
                svc.proto = "smtp"
            elif low.startswith("+ok"):
                svc.proto = "ftp"
            elif low.startswith("* ok"):
                svc.proto = "imap"
            else:
                svc.proto = "tcp"
        return svc
    except Exception as exc:  # noqa: BLE001
        svc.banner = f"{type(exc).__name__}"
        svc.proto = "tcp"
        return svc


# --------------------------------------------------------------------------
# L2/L3/L4 主流程
# --------------------------------------------------------------------------
def _detect_sapi(server: Optional[str], powered_by: Optional[str], port: int) -> Optional[str]:
    blob = f"{server or ''} {powered_by or ''}".lower()
    if "litespeed" in blob or "openlitespeed" in blob:
        return "litespeed"
    if "openresty" in blob or "nginx" in blob:
        return "fpm"
    if "apache" in blob:
        return "apache"
    if "microsoft-iis" in blob or "iis" in blob:
        return "iis"
    if port in (80, 443, 8080, 8000, 8443):
        return "fpm"
    return None


def discover(
    host: str,
    *,
    ports: Iterable[int] | None = None,
    timeout: float = 1.2,
    http_timeout: float = 8.0,
    deep: bool = True,
    arp: Optional[dict[str, str]] = None,
) -> DeviceProfile:
    """对一台设备做完整画像。"""
    prof = DeviceProfile(host=host, scanned_at=datetime.now().isoformat(timespec="seconds"))
    if ":" in host and not host.replace(":", "").isdigit():
        prof.errors.append("主机名含端口，请拆分后重试")
        return prof

    port_list = list(ports) if ports is not None else (
        list(FULL_PORT_SET) if deep else list(FAST_PORT_SET))
    open_ports = scan_ports(host, port_list, timeout=(timeout if deep else min(timeout, 0.8)))
    prof.open_ports = open_ports

    if not open_ports:
        prof.errors.append("端口探测无响应：主机离线，或被防火墙完全拦截")
        prof.evidence.append("端口探测无响应：主机离线或被完全拦截")
        prof.device_type = "offline"
        prof.device_label = "离线 / 无响应"
        prof.exposure = "not_applicable"
        prof.confidence = 0.0
        return prof

    # ---- 服务识别（各端口并行）----
    services: list[Service] = []

    def _probe_port(p: int) -> Optional[Service]:
        fast = not deep
        if p == 22:
            return probe_ssh(host, p, timeout=http_timeout)
        if p in WEB_HTTPS_PORTS:
            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast,
                             favicon=deep)
            if svc is None:
                return None
            if fast:
                return svc
            subject, issuer, san, expired = _tls_info(host, p, timeout=http_timeout)
            svc.tls_subject, svc.tls_issuer, svc.tls_san, svc.tls_expired = subject, issuer, san, expired
            if subject:
                svc.proto = "https"
            return svc
        if p in AMBIGUOUS_WEB_PORTS:
            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast, favicon=deep)
            if svc is None:
                return None
            if fast:
                return svc
            if svc.http_status in (400, 404, 405, 501) and not svc.tls_subject:
                alt = probe_http(host, p, https=False, timeout=http_timeout, quick=fast)
                if alt is not None and alt.http_status in _OK_STATUS:
                    svc = alt
            if svc.http_status in _OK_STATUS and svc.proto == "https":
                subject, issuer, san, expired = _tls_info(host, p, timeout=http_timeout)
                svc.tls_subject, svc.tls_issuer, svc.tls_san, svc.tls_expired = subject, issuer, san, expired
            return svc
        if p in WEB_HTTP_PORTS:
            return probe_http(host, p, https=False, timeout=http_timeout, quick=fast, favicon=deep)
        # banner 类服务都会在连接后主动发欢迎语；1.5s 没数据基本是 tarpit
        # 已知非 Web 的协议端口（邮件/文件传输）直接抓 banner，
        # 先试 HTTP 的话在 tarpit 端口上会白等一个 HTTP 超时
        if p in (21, 25, 110, 143, 465, 587, 993):
            # banner 类服务都会在连接后主动发欢迎语（<100ms）；
            # tarpit 端口永远不回数据，快速模式 0.5s 就够
            return probe_banner(host, p, timeout=(0.5 if fast else min(http_timeout, 1.5)))
        # 未知端口：先按 HTTP 试一下（Web 服务常挂在非标准端口），
        # 拿不到 HTTP 响应再退回 banner 探测
        svc = probe_http(host, p, https=False, timeout=min(http_timeout, 3.0), quick=True)
        if svc is not None and svc.http_status is not None:
            return svc
        return probe_banner(host, p, timeout=(0.5 if fast else min(http_timeout, 1.5)))

    with ThreadPoolExecutor(max_workers=min(12, max(1, len(open_ports)))) as ex:
        futs = {ex.submit(_probe_port, p): p for p in open_ports}
        for f in as_completed(futs):
            try:
                svc = f.result()
            except Exception:
                svc = None
            if svc is not None:
                services.append(svc)
    services.sort(key=lambda s: s.port)
    prof.services = services

    # ---- 存活判定 ----
    live = assess_liveness(services, open_ports)
    prof.alive = live.alive
    prof.meaningful_ports = live.meaningful_services
    prof.noise_ports = live.noise_ports
    prof.evidence.append(f"存活判定：{live.reason}")
    if not live.alive:
        prof.errors.append(live.reason)
        prof.device_type = "offline"
        prof.device_label = "离线 / 端口无有效响应"
        prof.exposure = "not_applicable"
        prof.confidence = 0.0
        return prof

    # ---- MAC / OUI ----
    try:
        mac, vendor = vendor_for_ip(host, arp)
        prof.mac = mac
        prof.mac_vendor = vendor
    except Exception:
        pass

    # ---- 设备分类 ----
    cls: Classification = classify(services, open_ports, mac=prof.mac, mac_vendor=prof.mac_vendor)
    prof.device_type = cls.device_type
    prof.device_label = cls.device_label
    prof.vendor = cls.vendor or None
    prof.product = cls.product or None
    prof.tech_stack = cls.tech_stack
    prof.confidence = cls.confidence
    prof.candidates = cls.candidates
    prof.evidence.extend(cls.evidence)

    # ---- PHP 暴露面 ----
    php_services = [s for s in services if s.php_hint]
    if php_services:
        prof.php_present = True
        ver = None
        sapi = None
        for s in php_services:
            if not ver:
                m = _PHP_VER_RE.search(s.x_powered_by or "")
                if m:
                    ver = m.group(1)
            if not ver:
                m = _PHP_VER_RE.search(s.server or "")
                if m:
                    ver = m.group(1)
            if not sapi:
                sapi = _detect_sapi(s.server, s.x_powered_by, s.port)
        prof.php_version = ver
        prof.sapi = sapi
        prof.verdict = classify_version(ver) if ver else None
        if prof.verdict and prof.verdict.status == Status.VULNERABLE:
            prof.exposure = "exposed"
            prof.evidence.append(
                f"检测到 PHP {ver}（{sapi or 'SAPI 未知'}），低于修复基线 {prof.verdict.fixed_release}")
            prof.remediation = [
                f"立即升级到 PHP {prof.verdict.fixed_release}（或更高），升级后重启全部 PHP worker",
                "无法升级时：memory_limit=-1（php_admin_value 级别）+ post_max_size 收紧至 8M/32M",
                "设置 session.upload_progress.enabled=0（写在 php.ini / FPM pool），并重启 worker",
                "PHP 8.5 另需设置 fatal_error_backtraces=0 并重启 worker",
            ]
        elif prof.verdict and prof.verdict.status == Status.PATCHED:
            prof.exposure = "patched"
            prof.evidence.append(f"检测到 PHP {ver}，已达修复基线 {prof.verdict.fixed_release}")
            prof.remediation = [
                "保持版本领先",
                "按 PHP 2026-10-23 公告，保持 session.upload_progress.enabled=0 直到下次常规修复版",
            ]
        else:
            prof.exposure = "unknown"
            prof.evidence.append(f"存在 PHP 迹象但未能确定版本（{php_services[0].php_hint}）")
            prof.remediation = ["人工确认 PHP 版本与 SAPI"]
    else:
        prof.exposure = "not_php"
        prof.evidence.append(
            "未检测到 PHP 痕迹（X-Powered-By / PHPSESSID / 版本串均无），该设备与 php2shell 无关")
        prof.remediation = ["该资产不在 php2shell 影响范围内，无需处置；保留在台账中作为基线"]

    return prof
