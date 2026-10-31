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
from urllib.parse import urljoin

import httpx

from .identification import Classification, assess_liveness, classify
from .oui import vendor_for_ip
from .signatures import BRAND_KEYWORDS
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

#: 常见"自定义 Web 端口"补充表。
#: 默认表只有 110 个端口，内网里 PHP/面板跑在 8xxx、9xxx 上非常常见，
#: 固定表会直接导致"这台明明有 PHP 却扫不到"。这里按东海旭日式的高频区间采样：
#:   · 8000–8100 每 10 个取 1（覆盖大量自建站/面板）
#:   · 8100–9100 每 25 个取 1（覆盖中间件管理口）
#:   · 9000–9100 段另含常见面板口
#: 更彻底的全端口扫描属于可选项，不放进默认路径（254 台会从 12 分钟涨到数小时）。
EXTRA_WEB_PORTS = (
    tuple(range(8000, 8101, 10)) + tuple(range(8100, 9101, 25)) +
    # 8081/8082/8088 是极常见的第二 Web 端口（Tomcat、备用站点、反代），必须覆盖
    (8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8888, 8899, 9000, 9001, 9090, 9091, 9200, 9201, 9443,
     9800, 9900, 10000, 10080, 10443, 10800, 11000, 12000, 18080, 20000)
)

FULL_PORT_SET = tuple(sorted(set(TOP_PORTS) | set(DEVICE_PORTS) | set(EXTRA_WEB_PORTS)))

FAST_PORT_SET = (
    21, 22, 23, 25, 80, 110, 143, 161, 445, 3306, 3389, 5432, 6379, 8080,
    8443, 8888, 9090, 2000, 8000, 10000, 8081, 8088, 9000, 3000, 4243, 443,
)

WEB_HTTP_PORTS = (80, 81, 88, 800, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 3000, 5000, 7001, 7070, 7443, 8181, 8880, 10000)
WEB_HTTPS_PORTS = (443, 8443, 9443, 10443, 2083, 2087, 2001, 2096)
AMBIGUOUS_WEB_PORTS = (2000, 2082, 2086, 4243, 10001)
WEB_PORTS = tuple(sorted(set(WEB_HTTP_PORTS) | set(WEB_HTTPS_PORTS) | set(AMBIGUOUS_WEB_PORTS)))

#: 路径回退阶梯 —— 覆盖实测到的华为交换机 /simple/view/login.html、iBMC /login.html
PATH_LADDER = ("/", "/login", "/login.html", "/simple/view/login.html", "/webui/",
               "/index.asp", "/admin/")

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
    tls_self_signed: bool = False
    alpn: Optional[str] = None
    favicon_sha256: Optional[str] = None
    #: Shodan / Fofa 口径的 favicon 指纹（mmh3(base64(favicon))），可拿去外部库比对
    favicon_mmh3: Optional[int] = None
    #: 页面元数据（meta generator / application-name / og:site_name / h1）
    page_meta: Optional[str] = None
    #: 从正文/静态资源/404 页扫出来的品牌词（厂商名）
    brand_hints: list[str] = field(default_factory=list)
    #: 从 JS/CSS 里提取的产品线词（JS 渲染设备的主要线索）
    js_hints: str = ""
    #: 静态资源（js/css）与 404 页的 sha256，用于跨主机同款聚类
    asset_hashes: list[str] = field(default_factory=list)
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
    #: 结论依据：title / cert / path / server / banner / favicon / port
    vendor_source: str = ""
    product_source: str = ""
    os_hint: Optional[str] = None
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None
    tech_stack: list[str] = field(default_factory=list)
    php_present: bool = False
    php_version: Optional[str] = None
    #: 全部检出的 PHP 实例 [{port, version, sapi}]
    php_instances: list[dict] = field(default_factory=list)
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
_H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL)
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r'([A-Za-z:_-]+)\s*=\s*["\']([^"\']*)["\']')
_PHP_VER_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)")

#: 这些标题不含任何产品信息，不能当作身份标签
_GENERIC_TITLES = {
    "", "登录", "登陆", "用户登录", "login", "sign in", "signin", "log in",
    "首页", "主页", "home", "index", "default", "document", "untitled",
    "error", "404", "403", "welcome", "系统登录",
}
#: 能当"产品名"用的元数据键（按优先级）
_META_KEYS = ("application-name", "og:site_name", "apple-mobile-web-app-title", "generator")


def _clean(s: str, limit: int = 160) -> Optional[str]:
    t = re.sub(r"\s+", " ", (s or "")).strip()
    return t[:limit] if t else None


def _extract_meta(body: str) -> Optional[str]:
    """从 <meta> 里取产品/应用名。

    SPA 设备（捷普 226/235 这类）的 <title> 常是空的，由 JS 运行时填充；
    但 meta application-name / og:site_name / generator 往往在源码里就写死了。
    """
    found: dict[str, str] = {}
    for tag in _META_TAG_RE.findall(body or ""):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        key = (attrs.get("name") or attrs.get("property") or "").strip().lower()
        val = _clean(attrs.get("content") or "", 120)
        if key in _META_KEYS and val and key not in found:
            found[key] = val
    for k in _META_KEYS:
        if k in found:
            return found[k]
    return None


def _extract_labels(body: str) -> tuple[Optional[str], Optional[str]]:
    """返回 (身份标签, 元数据标签)。

    优先级：有信息量的 <title> > meta 应用名/generator > <h1>。
    「登录 / Login / 首页」这类通用标题不当作产品名 —— 它们只会污染签名匹配。
    """
    title = None
    m = _TITLE_RE.search(body or "")
    if m:
        title = _clean(m.group(1))
    meta = _extract_meta(body or "")

    usable_title = title if (title and title.lower() not in _GENERIC_TITLES) else None
    if usable_title:
        return usable_title, meta
    if meta:
        return meta, meta
    if title:
        return title, None      # 只剩通用标题时保留，便于人工判断
    m = _H1_RE.search(body or "")
    if m:
        h1 = _clean(re.sub(r"<[^>]+>", " ", m.group(1)), 80)
        if h1 and h1.lower() not in _GENERIC_TITLES:
            return h1, None
    return None, None


def _extract_title(body: str) -> Optional[str]:
    """兼容旧调用：只要标签。"""
    return _extract_labels(body)[0]


# --------------------------------------------------------------------------
# favicon 指纹
# --------------------------------------------------------------------------
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32（纯 Python 实现，与 mmh3.hash 结果一致）。

    用它是为了跟 Shodan / Fofa / Censys 的 `http.favicon.hash` 对齐：
    同一个 favicon 在外部库里能直接搜到同款设备/产品。
    """
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h = seed & 0xFFFFFFFF
    rounded = length & ~0x3
    for i in range(0, rounded, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    k = 0
    tail = data[rounded:]
    if len(tail) == 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_fingerprints(data: bytes) -> tuple[str, int]:
    """返回 (sha256, shodan 风格 mmh3)。"""
    import base64

    sha = hashlib.sha256(data).hexdigest()
    b64 = base64.encodebytes(data)      # 注意：Shodan 用的是带换行的标准 base64
    return sha, _mmh3_32(b64)


# --------------------------------------------------------------------------
# 品牌词与静态资源
#
# 背景：很多设备（尤其国产安全设备）的 `<title>` 是空的（JS 渲染或本来就没写），
# 但品牌名几乎一定出现在**页面正文、静态 JS/CSS、404 错误页**里。
# 这三处扫一遍，比硬猜型号可靠得多，也不需要浏览器。
# --------------------------------------------------------------------------
_ASSET_REF_RE = re.compile(
    r"""<(?:script|link)\b[^>]*(?:src|href)\s*=\s*["']?([^"'\s>]+\.(?:js|css)(?:\?[^"'\s>]*)?)""",
    re.IGNORECASE,
)

#: 优先抓这几类资源：i18n 文案与主包最容易暴露产品线
_ASSET_PRIORITY = ("language", "i18n", "locale", "main", "app", "index", "bundle")


def _brand_hints(text: str) -> set[str]:
    """在任意文本里找品牌词，返回命中的厂商名集合。

    纯 ASCII 别名按**整词**匹配：`h3c` 不能命中十六进制串，`edr` 不能命中
    hundred 这类单词；中文别名按子串匹配。
    """
    if not text:
        return set()
    low = text[:400000].lower()
    hits: set[str] = set()
    for vendor, aliases in BRAND_KEYWORDS.items():
        for alias in aliases:
            if alias.isascii():
                if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", low):
                    hits.add(vendor)
                    break
            elif alias in low:
                hits.add(vendor)
                break
    return hits


def _asset_refs(html: str, base: str, limit: int = 5) -> list[str]:
    """从页面里取 js/css 的绝对地址（限同源、去重、限量）。"""
    out: list[str] = []
    seen: set[str] = set()
    matches = list(_ASSET_REF_RE.finditer(html or ""))

    def _score(mm) -> int:
        name = mm.group(1).lower()
        for i, key in enumerate(_ASSET_PRIORITY):
            if key in name:
                return i
        return len(_ASSET_PRIORITY)

    for m in sorted(matches, key=_score):
        raw = m.group(1).strip()
        if not raw or raw.startswith("data:"):
            continue
        url = urljoin(base + "/", raw)
        if not url.startswith(base):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= limit:
            break
    return out


def _probe_brand_sources(base: str, html: str, timeout: float) -> tuple[set[str], list[str], list[str]]:
    """抓静态资源 + 404 页，从中提取品牌词与内容哈希。

    只在"标题没给出产品信息"时调用，正常设备不会多付这几个请求。
    """
    hints: set[str] = set()
    _lines: set[str] = set()
    hashes: list[str] = []
    try:
        with httpx.Client(verify=False, timeout=min(timeout, 6.0), follow_redirects=True) as c:
            for url in _asset_refs(html, base):
                try:
                    r = c.get(url, headers={"User-Agent": UA_LADDER[0]})
                except Exception:
                    continue
                if r.status_code != 200 or not r.content:
                    continue
                hashes.append(hashlib.sha256(r.content).hexdigest())
                ctype = (r.headers.get("Content-Type") or "").lower()
                # application/javascript 不含 "text"，但它正是最关键的资源类型
                if not ctype or any(k in ctype for k in ("text", "javascript", "json", "xml")):
                    text = r.text[:1_500_000]
                    hints |= _brand_hints(text[:400000])
                    try:
                        from .jsfingerprint import extract_product_lines
                        _lines.update(extract_product_lines(text))
                    except Exception:
                        pass
                if len(hints) >= 2:
                    break
            if not hints:
                # 404 页也常带品牌与产品名
                bad = f"{base}/p2s-not-exist-{int(time.time() * 1000) % 100000}"
                try:
                    r = c.get(bad, headers={"User-Agent": UA_LADDER[0]})
                    if r.status_code < 500 and r.content:
                        hashes.append(hashlib.sha256(r.content).hexdigest())
                        hints |= _brand_hints(r.text[:200000])
                except Exception:
                    pass
    except Exception:
        pass
    return hints, hashes, sorted(_lines)


def _tls_info(host: str, port: int, timeout: float = 8.0) -> dict:
    """TLS 取证：证书主体/签发者/SAN/是否自签/是否过期/协商到的 ALPN 协议。"""
    out = {"subject": None, "issuer": None, "san": [], "expired": False,
           "self_signed": False, "alpn": None}
    der = None
    try:
        ctx = ssl._create_unverified_context()
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])   # 看对端支持 HTTP/2 与否
        except NotImplementedError:
            pass
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                try:
                    out["alpn"] = s.selected_alpn_protocol()
                except Exception:
                    pass
    except Exception:
        return out
    try:
        from cryptography import x509

        c = x509.load_der_x509_certificate(der)
        out["subject"] = c.subject.rfc4514_string()
        out["issuer"] = c.issuer.rfc4514_string()
        # 自签名：主体与签发者完全一致（内网设备极常见）
        out["self_signed"] = out["subject"] == out["issuer"]
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            out["san"] = [str(g.value) for g in ext]
        except Exception:
            pass
        try:
            out["expired"] = c.not_valid_after_utc < datetime.now(c.not_valid_after_utc.tzinfo)
        except Exception:
            pass
    except Exception:
        pass
    return out



_JS_REDIRECT_RE = re.compile(
    r"""(?:location\.href|location\.replace\s*\()\s*=?\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _js_redirect(body: str) -> Optional[str]:
    """提取页面里的 JS 跳转目标。

    嵌入式设备（打印机/摄像头/NAS）常用 `<script>location.href='./home/index.html'</script>`
    做首页跳转 —— 它不是 HTTP 3xx，只跟 Location 头会永远拿不到真实页面。
    """
    m = _JS_REDIRECT_RE.search(body or "")
    if not m:
        return None
    target = m.group(1).strip()
    if not target or target.startswith(("javascript:", "mailto:", "#")):
        return None
    return target


def _apply_tls(svc: Service, info: dict) -> None:
    svc.tls_subject = info.get("subject")
    svc.tls_issuer = info.get("issuer")
    svc.tls_san = info.get("san") or []
    svc.tls_expired = bool(info.get("expired"))
    svc.tls_self_signed = bool(info.get("self_signed"))
    svc.alpn = info.get("alpn")



def _url_host(host: str) -> str:
    """URL 里的主机部分：IPv6 字面量必须加方括号（http://[::1]:8080/）。"""
    h = (host or "").strip()
    if ":" in h and not h.startswith("["):
        return f"[{h}]"
    return h


def probe_http(host: str, port: int, *, https: bool = False, timeout: float = 8.0,
               quick: bool = False, favicon: bool = False) -> Optional[Service]:
    """HTTP/HTTPS 指纹采集。"""
    svc = Service(port=port, proto="https" if https else "http")
    scheme = "https" if https else "http"
    base = f"{scheme}://{_url_host(host)}:{port}"
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

    # 首页没有信息量时，跟随一次跳转（大量设备 / -> /login 才有真正的登录页标题）
    if not _extract_labels(body)[0] and best.status_code in (301, 302, 303, 307, 308):
        loc = best.headers.get("Location") or ""
        if loc:
            try:
                with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as rc:
                    rr = rc.get(httpx.URL(base).join(loc), headers={"User-Agent": UA_LADDER[0]})
                rct = rr.headers.get("Content-Type", "")
                if ("text" in rct or not rct) and rr.status_code < 400:
                    body = rr.text[:60000]
                    svc.location = loc
                    svc.http_status = rr.status_code
                    svc.server = svc.server or rr.headers.get("Server")
                    svc.cookie = svc.cookie or rr.headers.get("Set-Cookie")
                    best_path = f"{best_path}→{httpx.URL(loc).path}" if loc.startswith("/") else best_path
                    svc.matched_path = best_path
            except Exception:
                pass

    # JS 跳转跟随：嵌入式设备的首页常常只有一句 location.href
    if not _extract_labels(body)[0]:
        js_target = _js_redirect(body)
        if js_target:
            try:
                with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as jc:
                    jr = jc.get(httpx.URL(base + "/").join(js_target),
                                headers={"User-Agent": UA_LADDER[0]})
                jct = jr.headers.get("Content-Type", "")
                if jr.status_code < 400 and ("text" in jct or not jct):
                    body = jr.text[:60000]
                    svc.matched_path = f"{best_path}→(js){js_target}"
            except Exception:
                pass

    svc.http_title, svc.page_meta = _extract_labels(body)
    svc.brand_hints = sorted(_brand_hints(body))

    # 正文里没有品牌词、标题也没给出产品名时，再花 2~3 个请求去静态资源 / 404 页找。
    # 这是"标题为空"设备（捷普 226/235 这类）唯一不需要浏览器的补救手段。
    # 深度模式总是抓静态资源：品牌已经认出来时，仍需要产品线（JS 渲染设备的唯一线索）
    if not quick:
        _js_brand, hashes, js_lines = _probe_brand_sources(base, body, timeout)
        # 关键：JS 里的品牌词不可信（i18n 常含"厂商下拉列表"，实测出现别家品牌）。
        # 因此只用**页面 HTML 已确认的单一品牌** + JS 产品线做组合，例如「捷普防火墙」。
        # 先原样保存产品线词；与品牌的组合放到 classify 之后（那时才确定厂商）
        svc.js_hints = " ".join(js_lines)
        # JS 里的品牌词一律不采信（i18n 常含"厂商下拉列表"，实测出现过别家品牌），
        # 只保留页面 HTML 自身的品牌证据；JS 仅用于产品线组合（见上方 js_hints）。
        if _js_brand and not svc.brand_hints:
            pass    # 明确不使用 JS 品牌
        svc.asset_hashes = hashes
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
                svc.favicon_sha256, svc.favicon_mmh3 = favicon_fingerprints(fr.content)
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
            svc.proto = _guess_proto(svc.banner, port)
        return svc
    except Exception as exc:  # noqa: BLE001
        svc.banner = f"{type(exc).__name__}"
        svc.proto = "tcp"
        return svc


def _guess_proto(banner: str, port: int) -> str:
    """从 banner 猜协议。

    FTP 与 SMTP 都以 `220` 开头（且可能是多行 220-...），只看前三位会把
    FileZilla 误判成邮件服务器 —— 这里结合端口与关键字再判一次。
    """
    low = (banner or "").lower()
    if low.startswith("ssh-"):
        return "ssh"
    if low.startswith("+ok"):
        return "ftp"
    if low.startswith("* ok"):
        return "imap"
    if low.startswith("220"):
        if any(k in low for k in ("ftp", "filezilla", "vsftpd", "proftpd", "serv-u", "pure-ftpd")):
            return "ftp"
        if any(k in low for k in ("smtp", "esmtp", "postfix", "exim", "sendmail", "mail")):
            return "smtp"
        return "ftp" if port == 21 else "smtp"
    return "tcp"


# --------------------------------------------------------------------------
# L2/L3/L4 主流程
# --------------------------------------------------------------------------

#: PHP 判定状态的严重度排序（越小越严重）
_STATUS_RANK = {
    "vulnerable": 0, "eol_unpatchable": 1, "eol_backport_available": 2,
    "unknown": 3, "dev_branch": 4, "patched": 5,
}


def pick_worst_php(instances: list[dict]) -> dict:
    """从多个 PHP 实例里挑出最该关注的那个：先看判定严重度，再看版本高低。

    一台主机可能同时跑多个 PHP（不同站点/容器/pool），只报"第一个检出的"
    会把更老的漏洞版本掩盖掉（实测过：8.2.34 被 8.4.26 盖住）。
    """
    def _key(i: dict) -> tuple:
        v = classify_version(i.get("version")) if i.get("version") else None
        rank = _STATUS_RANK.get(v.status if v else "unknown", 3)
        try:
            nums = tuple(int(x) for x in (i.get("version") or "999").split(".")[:3])
        except ValueError:
            nums = (999,)
        return (rank, nums)

    return min(instances, key=_key)


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
            _apply_tls(svc, _tls_info(host, p, timeout=http_timeout))
            if svc.tls_subject:
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
                _apply_tls(svc, _tls_info(host, p, timeout=http_timeout))
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
    cls: Classification = classify(
        services,
        open_ports,
        meaningful_ports=prof.meaningful_ports,
        mac=prof.mac,
        mac_vendor=prof.mac_vendor,
    )
    prof.device_type = cls.device_type
    prof.device_label = cls.device_label
    prof.vendor = cls.vendor or None
    prof.product = cls.product or None
    prof.vendor_source = cls.vendor_source
    prof.product_source = cls.product_source
    prof.tech_stack = cls.tech_stack
    prof.confidence = cls.confidence
    prof.candidates = cls.candidates
    prof.evidence.extend(cls.evidence)

    # ---- PHP 暴露面 ----
    php_services = [s for s in services if s.php_hint]
    if php_services:
        prof.php_present = True
        # 逐个服务收集版本，而不是"取第一个"——多版本主机上会掩盖更差的那个
        instances: list[dict] = []
        for s in php_services:
            v = None
            m = _PHP_VER_RE.search(s.x_powered_by or "") or _PHP_VER_RE.search(s.server or "")
            if m:
                v = m.group(1)
            instances.append({"port": s.port, "version": v,
                              "sapi": _detect_sapi(s.server, s.x_powered_by, s.port)})
        prof.php_instances = [i for i in instances if i["version"]] or instances

        # 取"最差"：先按判定严重度（vulnerable > EOL > unknown > patched），再按版本低
        worst = pick_worst_php(prof.php_instances)
        ver = worst.get("version")
        sapi = worst.get("sapi") or _detect_sapi("", "", worst.get("port"))
        prof.php_version = ver
        prof.sapi = sapi
        if len(prof.php_instances) > 1:
            detail = "、".join(
                f":{i['port']}={i['version'] or '版本未知'}" for i in
                sorted(prof.php_instances, key=lambda x: x["port"])
            )
            prof.evidence.append(f"共检出 {len(prof.php_instances)} 个 PHP 实例（{detail}），按最差版本判定")
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
