"""资产发现与设备分类引擎。

检测原理（四层，逐层收敛）：

  L0 存活与端口发现   TCP 连接探测 -> 哪些端口开着
  L1 服务协议识别     HTTP/HTTPS 指纹 + TLS 证书取证 + SSH/SMTP banner
  L2 设备类型分类     端口画像 + 证书 CN/O/OU + Server 头 + 页面标题 + SSH banner 综合打分
  L3 PHP 暴露面判定   是否跑 PHP -> SAPI -> 版本 -> 是否低于修复基线 -> 结论

为什么要做 L0~L2：
  php2shell 只影响跑 PHP 的服务。一个客户的资产清单里大量是防火墙、堡垒机、
  路由器、Linux 主机、邮件网关、摄像头——它们根本不跑 PHP。
  旧版工具只找 PHP 横幅，对这类设备一律输出空白，用户无法区分
  "这台确实没 PHP" 和 "这台工具没识别出来"。这两件事必须说清楚。

设计要点：
  - 内网设备普遍使用自签名证书 -> 自动降级为不校验并提取证书信息
  - 部分安全设备要求特定 Host 头 -> 多路径 + Host 变体回退
  - 结论永远带证据，不给黑盒判定
"""
from __future__ import annotations

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

from .versions import Status, Verdict, classify

# --------------------------------------------------------------------------
# 端口画像
# --------------------------------------------------------------------------

#: 网络设备 / 安全设备常见的非标准管理端口
DEVICE_PORTS: tuple[int, ...] = (
    2000, 2001, 2082, 2083, 2086, 2087, 2095, 2096, 4243, 5000, 7070, 7443,
    8009, 8181, 8282, 8383, 8484, 8880, 8899, 9000, 9090, 9443, 10000, 10001,
    10443, 10250, 11211, 15672,
)

#: 通用服务端口
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 161, 389, 443, 445, 465, 514,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 3000, 3128, 3306, 3389, 4848,
    5432, 5672, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8088, 8443,
    8888, 9200, 9300, 27017, 28017, 50000,
)

#: 快速模式端口表：只保留最常见的服务端口
FAST_PORT_SET: tuple[int, ...] = (
    22, 80, 443, 445, 3389, 3306, 5432, 6379, 8080, 8443, 8888, 9090,
    2000, 8000, 10000, 8081, 8088, 9000, 3000, 4243,
)

#: 完整端口表 = 通用 + 设备专属（去重排序）
FULL_PORT_SET: tuple[int, ...] = tuple(sorted(set(TOP_PORTS) | set(DEVICE_PORTS)))

#: 明文 HTTP 端口
WEB_HTTP_PORTS: tuple[int, ...] = (
    80, 81, 88, 800, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 3000, 5000,
    7001, 7070, 7443, 8181, 8880, 10000,
)

#: TLS 端口
WEB_HTTPS_PORTS: tuple[int, ...] = (
    443, 8443, 9443, 10443, 2083, 2087, 2001, 2096,
)

#: 协议不明确的安全设备端口（先试 HTTPS，再回落 HTTP）
AMBIGUOUS_WEB_PORTS: tuple[int, ...] = (2000, 2082, 2086, 4243, 10001)

#: 全部可能承载 Web 的端口
WEB_PORTS: tuple[int, ...] = tuple(sorted(set(WEB_HTTP_PORTS) | set(WEB_HTTPS_PORTS) | set(AMBIGUOUS_WEB_PORTS)))

# --------------------------------------------------------------------------
# 指纹库
# --------------------------------------------------------------------------

#: 页面标题 -> (设备类型, 厂商)
TITLE_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("堡垒机", "bastion", "generic"),
    ("jumpserver", "bastion", "JumpServer"),
    ("assetserver", "bastion", "JumpServer"),
    ("防火墙", "firewall", "generic"),
    ("安全网关", "firewall", "generic"),
    ("上网行为管理", "firewall", "generic"),
    ("下一代防火墙", "firewall", "generic"),
    ("router", "network_device", "generic"),
    ("路由", "network_device", "generic"),
    ("交换机", "network_device", "generic"),
    ("监控", "monitoring", "generic"),
    ("zabbix", "monitoring", "Zabbix"),
    ("grafana", "monitoring", "Grafana"),
    ("prometheus", "monitoring", "Prometheus"),
    ("jenkins", "devops", "Jenkins"),
    ("gitlab", "devops", "GitLab"),
    ("mail", "mail", "generic"),
    ("webmail", "mail", "generic"),
    ("wordpress", "cms", "WordPress"),
    ("drupal", "cms", "Drupal"),
    ("joomla", "cms", "Joomla"),
    ("magento", "cms", "Magento"),
    ("typo3", "cms", "TYPO3"),
    ("nextcloud", "file_service", "Nextcloud"),
    ("owncloud", "file_service", "ownCloud"),
    ("confluence", "devops", "Confluence"),
    ("openstack", "cloud", "OpenStack"),
    ("kubernetes", "cloud", "Kubernetes"),
    ("docker", "container", "Docker"),
    ("portainer", "container", "Portainer"),
    ("phpmyadmin", "db_tool", "phpMyAdmin"),
)

#: Server 头 -> (设备类型, 厂商)
SERVER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("jump_server", "bastion", "JumpServer"),
    ("fortinet", "firewall", "Fortinet"),
    ("fortiweb", "firewall", "Fortinet"),
    ("netscaler", "network_device", "Citrix"),
    ("big-ip", "network_device", "F5"),
    ("cisco", "network_device", "Cisco"),
    ("sangfor", "firewall", "Sangfor"),
    ("h3c", "network_device", "H3C"),
    ("ruijie", "network_device", "Ruijie"),
    ("huawei", "network_device", "Huawei"),
    ("juniper", "network_device", "Juniper"),
    ("mikrotik", "network_device", "MikroTik"),
    ("nginx", "web_server", "nginx"),
    ("apache", "web_server", "Apache httpd"),
    ("openresty", "web_server", "OpenResty"),
    ("litespeed", "web_server", "LiteSpeed"),
    ("microsoft-iis", "web_server", "Microsoft IIS"),
    ("tomcat", "app_server", "Apache Tomcat"),
    ("jetty", "app_server", "Jetty"),
    ("weblogic", "app_server", "WebLogic"),
    ("websphere", "app_server", "WebSphere"),
    ("lighttpd", "web_server", "lighttpd"),
    ("caddy", "web_server", "Caddy"),
)

#: 证书 O/OU/CN -> (设备类型, 厂商)
CERT_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("jump", "bastion", "JumpServer"),
    ("yanfa", "bastion", "JumpServer"),
    ("fortinet", "firewall", "Fortinet"),
    ("firewall", "firewall", "generic"),
    ("utm", "firewall", "generic"),
    ("sangfor", "firewall", "Sangfor"),
    ("h3c", "network_device", "H3C"),
    ("huawei", "network_device", "Huawei"),
    ("cisco", "network_device", "Cisco"),
    ("juniper", "network_device", "Juniper"),
    ("mikrotik", "network_device", "MikroTik"),
    ("ruijie", "network_device", "Ruijie"),
    ("nginx", "web_server", "nginx"),
    ("apache", "web_server", "Apache httpd"),
)

#: SSH banner -> (设备类型, 厂商/OS)
SSH_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("ubuntu", "linux_host", "Ubuntu"),
    ("debian", "linux_host", "Debian"),
    ("centos", "linux_host", "CentOS"),
    ("red hat", "linux_host", "RHEL"),
    ("rhel", "linux_host", "RHEL"),
    ("rocky", "linux_host", "Rocky Linux"),
    ("alma", "linux_host", "AlmaLinux"),
    ("opensuse", "linux_host", "openSUSE"),
    ("fedora", "linux_host", "Fedora"),
    ("raspbian", "iot_device", "Raspbian"),
    ("busybox", "network_device", "BusyBox"),
    ("dropbear", "network_device", "Dropbear"),
    ("openssh", "linux_host", "generic"),
    ("win32", "windows_host", "Windows"),
    ("microsoft", "windows_host", "Windows"),
)

#: 设备类型中文标签
DEVICE_LABELS: dict[str, str] = {
    "firewall": "防火墙 / 安全网关",
    "bastion": "堡垒机 / 运维审计",
    "network_device": "网络设备（路由/交换）",
    "mail_gateway": "邮件网关 / 邮件服务器",
    "linux_host": "Linux 主机",
    "windows_host": "Windows 主机",
    "web_server": "Web 服务器（无 PHP）",
    "php_app": "PHP 应用站点",
    "app_server": "Java / 应用服务器",
    "cms": "CMS 网站",
    "db_tool": "数据库管理工具",
    "monitoring": "监控 / 运维平台",
    "devops": "DevOps 平台",
    "file_service": "文件共享服务",
    "cloud": "云 / 容器编排平台",
    "container": "容器管理平台",
    "iot_device": "IoT / 嵌入式设备",
    "appliance": "网络设备 / 嵌入式 appliance",
    "unknown": "未识别设备",
}

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
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_san: list[str] = field(default_factory=list)
    tls_expired: bool = False
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
    services: list[Service] = field(default_factory=list)
    device_type: str = "unknown"
    device_label: str = "未识别设备"
    vendor: Optional[str] = None
    os_hint: Optional[str] = None
    php_present: bool = False
    php_version: Optional[str] = None
    sapi: Optional[str] = None
    verdict: Optional[Verdict] = None
    confidence: float = 0.0
    exposure: str = "unknown"          # exposed | not_php | patched | unknown
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

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


def scan_ports(
    host: str, ports: Iterable[int] = FULL_PORT_SET, *, timeout: float = 1.2, workers: int = 96
) -> list[int]:
    """并发 TCP 端口探测，返回开放端口。"""
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


def _tls_info(host: str, port: int, timeout: float = 8.0) -> tuple[Optional[str], Optional[str], list[str], bool]:
    """提取 TLS 证书信息：主题、签发者、SAN、是否过期。"""
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
        subject = c.subject.rfc4514_string()
        issuer = c.issuer.rfc4514_string()
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
        return subject, issuer, san, expired
    except Exception:
        return None, None, [], False


#: User-Agent 阶梯。部分安全设备会对含 scanner/bot 关键字的 UA 直接返回 4xx。
UA_LADDER: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0",
    "curl/8.5.0",
)

#: 路径回退。设备根路径可能返回 4xx，真实入口往往在子路径。
PATH_LADDER: tuple[str, ...] = ("/", "/index.html", "/login")

#: 视为"服务可用"的状态码
_OK_STATUS = (200, 301, 302, 303, 307, 308, 401, 403)


def probe_http(
    host: str,
    port: int,
    *,
    https: bool = False,
    timeout: float = 8.0,
    paths: tuple[str, ...] = PATH_LADDER,
    quick: bool = False,
) -> Optional[Service]:
    """HTTP/HTTPS 指纹采集。

    - 自动降级为不校验证书（内网设备大量自签名）
    - User-Agent 与路径各走一个回退阶梯，绕开设备的反扫描策略
    """
    svc = Service(port=port, proto="https" if https else "http")
    scheme = "https" if https else "http"
    best: Optional[httpx.Response] = None
    best_path = "/"

    if quick:
        paths = ("/",)
    deadline = time.monotonic() + max(timeout * 2.5, 12.0)
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        for ua in UA_LADDER:
            for path in paths:
                if time.monotonic() > deadline:
                    break
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    resp = client.get(url, headers={"User-Agent": ua, "Accept": "*/*"})
                except Exception as exc:  # noqa: BLE001
                    svc.banner = f"{type(exc).__name__}: {str(exc)[:120]}"
                    if best is None:
                        return svc
                    continue
                if best is None or (resp.status_code in _OK_STATUS and best.status_code not in _OK_STATUS):
                    best, best_path = resp, path
                if resp.status_code in _OK_STATUS:
                    break
            # 拿到可用响应就收工；只有全部路径都失败才换 UA 重试
            if best is not None and best.status_code in _OK_STATUS:
                break
            if quick:
                break   # 快速模式不升级 UA
            if best is not None and best.status_code not in (404, 400, 403, 405, 501):
                break

    if best is None:
        return svc

    svc.http_status = best.status_code
    svc.server = best.headers.get("Server")
    svc.x_powered_by = best.headers.get("X-Powered-By")
    svc.location = best.headers.get("Location")
    ctype = best.headers.get("Content-Type", "")
    body = best.text[:120000] if ("text" in ctype or not ctype) else ""
    svc.http_title = _extract_title(body)
    svc.banner = f"path={best_path}"

    # PHP 线索：X-Powered-By / Set-Cookie PHPSESSID / Server 版本串 / 正文 .php 链接
    if svc.x_powered_by and "php" in svc.x_powered_by.lower():
        svc.php_hint = svc.x_powered_by
    elif "phpsessid" in best.headers.get("Set-Cookie", "").lower():
        svc.php_hint = "PHPSESSID cookie"
    elif _PHP_VER_RE.search(svc.server or ""):
        svc.php_hint = svc.server
    elif re.search(r"\.php[\"']?\s", body, re.IGNORECASE) and "powered by php" in body.lower():
        svc.php_hint = "page links to .php + Powered by PHP footer"
    return svc


def probe_ssh(host: str, port: int = 22, timeout: float = 6.0) -> Optional[Service]:
    """抓 SSH banner（不发起认证）。"""
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
    """通用 banner 抓取（FTP/SMTP/POP3/IMAP 等）。"""
    svc = Service(port=port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # FTP/SMTP/POP3/IMAP 都会在连接后主动发欢迎语。
            # 不要先发 EHLO —— POP3/IMAP 收到非预期数据会直接丢弃，
            # 导致这里白等到超时（每台带邮件服务的设备多花 4~5 秒）。
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
# L2 设备分类
# --------------------------------------------------------------------------

def _match_signatures(blob: str, table: tuple[tuple[str, str, str], ...]) -> Optional[tuple[str, str, str]]:
    low = (blob or "").lower()
    for needle, dtype, vendor in table:
        if needle in low:
            return (needle, dtype, vendor)
    return None


def classify_device(services: list[Service], open_ports: list[int]) -> dict:
    """综合端口画像 + 证书 + Server 头 + 标题 + SSH banner，给出设备类型判定。"""
    evidence: list[str] = []
    scores: dict[str, float] = {}
    vendor: Optional[str] = None
    os_hint: Optional[str] = None

    def bump(dtype: str, weight: float) -> None:
        scores[dtype] = scores.get(dtype, 0.0) + weight

    # --- 1) SSH banner ---
    for svc in services:
        if svc.proto == "ssh" and svc.banner:
            m = _match_signatures(svc.banner, SSH_SIGNATURES)
            if m:
                _, dtype, v = m
                bump(dtype, 3.0)
                os_hint = os_hint or v
                vendor = vendor or (None if v == "generic" else v)
                evidence.append(f"SSH banner: {svc.banner[:90]} -> {DEVICE_LABELS.get(dtype, dtype)}")
            else:
                evidence.append(f"SSH banner: {svc.banner[:90]}")

    # --- 2) TLS 证书 ---
    for svc in services:
        blob = " ".join(filter(None, [svc.tls_subject or "", svc.tls_issuer or "", " ".join(svc.tls_san)]))
        if blob:
            m = _match_signatures(blob, CERT_SIGNATURES)
            if m:
                _, dtype, v = m
                bump(dtype, 3.5)
                vendor = vendor or (None if v == "generic" else v)
                evidence.append(f"TLS 证书: {svc.tls_subject[:110]}")
            elif svc.tls_subject:
                evidence.append(f"TLS 证书: {svc.tls_subject[:110]}")

    # --- 3) HTTP Server 头 ---
    for svc in services:
        if svc.server:
            m = _match_signatures(svc.server, SERVER_SIGNATURES)
            if m:
                _, dtype, v = m
                bump(dtype, 2.0)
                vendor = vendor or (None if v == "generic" else v)
                evidence.append(f"Server 头: {svc.server[:80]}")

    # --- 4) 页面标题 ---
    for svc in services:
        if svc.http_title:
            m = _match_signatures(svc.http_title, TITLE_SIGNATURES)
            if m:
                _, dtype, v = m
                bump(dtype, 2.5)
                vendor = vendor or (None if v == "generic" else v)
                evidence.append(f"页面标题: {svc.http_title[:80]}")
            else:
                evidence.append(f"页面标题: {svc.http_title[:80]}")

    # --- 5) 端口画像 ---
    pset = set(open_ports)
    if {25, 110, 143} & pset and len({25, 110, 143} & pset) >= 2:
        bump("mail_gateway", 2.0)
        evidence.append("端口画像: 25/110/143 -> 邮件服务")
    if 3389 in pset:
        bump("windows_host", 1.5)
    if 22 in pset and 80 in pset:
        bump("linux_host", 1.0)
    if {2000, 10000, 10443, 2082, 2083, 2086, 2087, 4243} & pset:
        bump("appliance", 1.5)
        evidence.append("端口画像: 命中安全设备常见管理端口")
    if {2375, 2376, 4243, 10250, 10255, 6443} & pset:
        bump("container", 2.0)
        evidence.append("端口画像: 命中容器编排端口")
    if {161, 162} & pset:
        bump("network_device", 1.0)
    if {23} & pset:
        bump("network_device", 1.0)

    # --- 6) PHP 存在性直接判定类型 ---
    php_services = [s for s in services if s.php_hint]
    if php_services:
        bump("php_app", 4.0)

    if not scores:
        return {
            "device_type": "unknown" if not open_ports else "appliance",
            "device_label": DEVICE_LABELS["unknown"] if not open_ports else DEVICE_LABELS["appliance"],
            "vendor": vendor,
            "os_hint": os_hint,
            "confidence": 0.25,
            "evidence": evidence or ["无任何可识别特征"],
            "scores": scores,
        }

    best = max(scores.items(), key=lambda kv: kv[1])
    dtype, score = best
    total = sum(scores.values())
    confidence = min(0.98, 0.35 + score / max(total, 1.0) * 0.5 + min(score, 6) / 6 * 0.2)

    # 次优类型如果分数接近，作为候选附上
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    if len(ranked) > 1 and ranked[1][1] >= score * 0.6:
        evidence.append(f"候选类型: {DEVICE_LABELS.get(dtype, dtype)} / {DEVICE_LABELS.get(ranked[1][0], ranked[1][0])}")

    return {
        "device_type": dtype,
        "device_label": DEVICE_LABELS.get(dtype, dtype),
        "vendor": vendor,
        "os_hint": os_hint,
        "confidence": round(confidence, 2),
        "evidence": evidence,
        "scores": scores,
    }


# --------------------------------------------------------------------------
# L3 主流程
# --------------------------------------------------------------------------

def _detect_sapi(server: Optional[str], powered_by: Optional[str], port: int, https: bool) -> Optional[str]:
    blob = f"{server or ''} {powered_by or ''}".lower()
    if "jump_server" in blob:
        return "unknown"
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
    timeout: float = 1.5,
    http_timeout: float = 8.0,
    deep: bool = True,
) -> DeviceProfile:
    """对一台设备做完整画像：端口 -> 服务 -> 类型 -> PHP 暴露面。"""
    prof = DeviceProfile(host=host, scanned_at=datetime.now().isoformat(timespec="seconds"))
    if ":" in host and not host.replace(":", "").isdigit():
        prof.errors.append("主机名含端口，请拆分后重试")
        return prof

    if ports is not None:
        port_list = list(ports)
    elif not deep:
        port_list = list(FAST_PORT_SET)
    else:
        port_list = list(FULL_PORT_SET)
    open_ports = scan_ports(host, port_list, timeout=(timeout if deep else min(timeout, 0.8)))
    prof.open_ports = open_ports
    if not open_ports:
        prof.errors.append("端口探测无响应，主机可能离线或被防火墙拦截")
        return prof
    prof.alive = True

    # 服务识别（各端口并行，避免一台多端口设备串行等待）
    services: list[Service] = []

    def _probe_port(p: int) -> Optional[Service]:
        """探测单个端口的服务，返回 Service（失败返回 None）。"""
        fast = not deep
        if p == 22:
            return probe_ssh(host, p, timeout=http_timeout)

        if p in WEB_HTTPS_PORTS:
            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast)
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
            # 安全设备常把管理界面挂在非标准端口，且默认走 TLS
            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast)
            if svc is None:
                return None
            if fast:
                return svc
            if svc.http_status in (400, 404, 405, 501) and not svc.tls_subject:
                alt = probe_http(host, p, https=False, timeout=http_timeout)
                if alt is not None and alt.http_status in _OK_STATUS:
                    svc = alt
            if svc.http_status in _OK_STATUS and svc.proto == "https":
                subject, issuer, san, expired = _tls_info(host, p, timeout=http_timeout)
                svc.tls_subject, svc.tls_issuer, svc.tls_san, svc.tls_expired = subject, issuer, san, expired
            return svc

        if p in WEB_HTTP_PORTS:
            return probe_http(host, p, https=False, timeout=http_timeout, quick=fast)

        # banner 类服务都会在连接后立刻发欢迎语；1.5s 没数据基本是 tarpit/静默端口
        return probe_banner(host, p, timeout=min(http_timeout, 1.5))

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
    prof.services = [s for s in services if s is not None]
    # 设备分类
    cls = classify_device(prof.services, prof.open_ports)
    prof.device_type = cls["device_type"]
    prof.device_label = cls["device_label"]
    prof.vendor = cls.get("vendor")
    prof.os_hint = cls.get("os_hint")
    prof.confidence = cls.get("confidence", 0.0)
    prof.evidence.extend(cls.get("evidence", []))

    # PHP 暴露面
    php_services = [s for s in prof.services if s.php_hint]
    if php_services:
        prof.php_present = True
        ver = None
        sapi = None
        for s in php_services:
            if not ver:
                m = _PHP_VER_RE.search(s.x_powered_by or "")
                if m:
                    ver = m.group(1)
            if not ver and s.server:
                m = _PHP_VER_RE.search(s.server)
                if m:
                    ver = m.group(1)
            if not sapi:
                sapi = _detect_sapi(s.server, s.x_powered_by, s.port, s.proto == "https")
        prof.php_version = ver
        prof.sapi = sapi
        prof.verdict = classify(ver) if ver else None
        if prof.verdict and prof.verdict.status == Status.VULNERABLE:
            prof.exposure = "exposed"
            prof.evidence.append(
                f"检测到 PHP {ver}（{sapi or 'SAPI 未知'}），低于修复基线 {prof.verdict.fixed_release}"
            )
            prof.remediation = [
                f"立即升级到 PHP {prof.verdict.fixed_release} 并重启全部 worker",
                "无法升级时：memory_limit=-1 + post_max_size 收紧 + session.upload_progress.enabled=0",
                "PHP 8.5 另需 fatal_error_backtraces=0",
            ]
        elif prof.verdict and prof.verdict.status == Status.PATCHED:
            prof.exposure = "patched"
            prof.evidence.append(f"检测到 PHP {ver}，已达修复基线 {prof.verdict.fixed_release}")
            prof.remediation = ["保持版本领先；按 PHP 2026-10-23 公告保持 session.upload_progress.enabled=0"]
        else:
            prof.exposure = "unknown"
            prof.evidence.append(f"存在 PHP 迹象但未能确定版本（{php_services[0].php_hint}）")
            prof.remediation = ["人工确认 PHP 版本与 SAPI"]
    else:
        prof.exposure = "not_php"
        prof.evidence.append(
            "未检测到 PHP 痕迹（X-Powered-By / PHPSESSID / 版本串均无），该设备与 php2shell 无关"
        )
        prof.remediation = ["该资产不在 php2shell 影响范围内，无需处置；保留在台账中作为基线"]

    return prof