"""存活判定与设备分类引擎。

存活判定（本工具的第一道关卡）：
  在很多企业网络里，出口防火墙做**全锥 NAT** 或对某些端口做 **tarpit**，
  结果是**任意 IP 的 25/110/143 都能连上但一个字节都不回**。
  实测本机所在网段 254 个 IP 全部在这三个端口"连通"。
  如果只看 TCP 握手，每台主机都会被误判为存活 —— 台账里就会多出几百条
  "未识别设备"。

  正确判据：**必须产生有意义的协议响应**。
    - HTTP：拿到任意状态码（含 401/403/404 —— 有响应就说明服务真的在）
    - SSH/FTP/SMTP：拿到非空 banner
    - TLS：握手成功并能完成 HTTP 交换
    - 纯 TCP 连上但超时无数据 = 噪声（tarpit / NAT），**不算存活**

分类引擎：
  以**标签类证据**为主（页面标题、Server 头、TLS 证书、登录路径、Cookie），
  端口画像只作兜底。因为端口只能说明"有个 Web 服务"，
  标签才能说明"这是台什么设备"。
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .signatures import PORT_SIGNATURES, SIGNATURES, TYPE_LABELS, Field, Sig, T


@dataclass
class Classification:
    """设备分类结果。"""

    device_type: str = T.UNKNOWN
    device_label: str = TYPE_LABELS[T.UNKNOWN]
    vendor: str = ""
    product: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Liveness:
    """存活判定结果。"""

    alive: bool = False
    meaningful_services: list[int] = field(default_factory=list)
    noise_ports: list[int] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


#: 常见"全锥 NAT / tarpit"噪声端口组合
NOISE_PORT_SETS: tuple[frozenset[int], ...] = (
    frozenset({25, 110, 143}),
    frozenset({25, 110, 143, 465, 587}),
    frozenset({21, 25, 110, 143}),
)


def is_meaningful_service(svc: Any) -> bool:
    """该服务是否产生了有意义的协议响应。"""
    proto = getattr(svc, "proto", "") or ""
    if proto in ("http", "https"):
        return getattr(svc, "http_status", None) is not None
    if proto in ("ssh", "ftp", "smtp", "imap"):
        banner = (getattr(svc, "banner", "") or "").strip()
        return bool(banner) and not banner.startswith(("TimeoutError", "ConnectionRefused"))
    # 其它协议：连上且有 banner 才算
    banner = (getattr(svc, "banner", "") or "").strip()
    return bool(banner) and not banner.startswith(("TimeoutError", "ConnectionRefused", "OSError"))


def assess_liveness(services: list[Any], open_ports: list[int]) -> Liveness:
    """判定主机是否真的在线。"""
    meaningful = [s.port for s in services if is_meaningful_service(s)]
    noise = [s.port for s in services if not is_meaningful_service(s) and s.port in open_ports]
    # 已开但未探测服务的端口也算噪声
    probed = {s.port for s in services}
    noise += [p for p in open_ports if p not in probed]

    if meaningful:
        return Liveness(
            alive=True,
            meaningful_services=sorted(meaningful),
            noise_ports=sorted(set(noise)),
            reason=f"{len(meaningful)} 个端口返回了有效协议响应",
        )
    if open_ports:
        return Liveness(
            alive=False,
            meaningful_services=[],
            noise_ports=sorted(set(noise)),
            reason=(
                f"{len(open_ports)} 个端口可连接但无任何协议响应"
                f"（{'/'.join(str(p) for p in sorted(set(noise))[:6])}）—— "
                "疑似出口 NAT / tarpit 拦截，非真实存活主机"
            ),
        )
    return Liveness(alive=False, meaningful_services=[], noise_ports=[],
                    reason="端口探测无响应，主机离线或被防火墙完全拦截")


def detect_noise_ports(all_open_port_sets: list[list[int]]) -> set[int]:
    """跨主机统计，识别出"所有主机都在"的噪声端口（NAT / tarpit 特征）。

    如果超过 30% 的可达主机都开着同一组端口且无响应，这组端口就是网络级噪声，
    不应该作为存活证据。
    """
    if len(all_open_port_sets) < 5:
        return set()
    counter: dict[int, int] = {}
    for ports in all_open_port_sets:
        for p in set(ports):
            counter[p] = counter.get(p, 0) + 1
    total = len(all_open_port_sets)
    return {p for p, c in counter.items() if c / total > 0.3}


def _cert_cn(subject: str) -> str:
    m = re.search(r"CN=([^,/]+)", subject or "")
    return m.group(1).strip() if m else ""


def classify(
    services: list[Any],
    open_ports: list[int],
    *,
    mac: Optional[str] = None,
    mac_vendor: Optional[str] = None,
) -> Classification:
    """综合多源证据给出设备分类。"""
    res = Classification()
    observations: list[tuple[str, str, Any]] = []

    for svc in services:
        if getattr(svc, "server", None):
            observations.append((Field.SERVER, svc.server, svc))
        if getattr(svc, "http_title", None):
            observations.append((Field.TITLE, svc.http_title, svc))
        if getattr(svc, "tls_subject", None):
            observations.append((Field.CERT, svc.tls_subject, svc))
            cn = _cert_cn(svc.tls_subject)
            if cn:
                observations.append((Field.CERT_CN, cn, svc))
        if getattr(svc, "banner", None) and getattr(svc, "proto", "") in (
            "ssh", "ftp", "smtp", "imap", "tcp"
        ):
            observations.append((Field.BANNER, svc.banner, svc))
        if getattr(svc, "cookie", None):
            observations.append((Field.COOKIE, svc.cookie, svc))
        if getattr(svc, "www_auth", None):
            observations.append((Field.WWW_AUTH, svc.www_auth, svc))
        if getattr(svc, "matched_path", None):
            observations.append((Field.PATH, svc.matched_path, svc))
        if getattr(svc, "body_sample", None):
            observations.append((Field.BODY, svc.body_sample, svc))

    # ---- 签名匹配 ----
    scores: dict[tuple[str, str, str], float] = {}
    details: dict[tuple[str, str, str], list[tuple[Sig, Any]]] = {}
    counted: set[tuple[str, str, str, str]] = set()
    for fld, value, svc in observations:
        for sig in SIGNATURES:
            if sig.field != fld:
                continue
            if sig.needle not in str(value).lower():
                continue
            key = (sig.dtype, sig.vendor, sig.product)
            # 同一条签名只计一次 —— 否则同一设备开 5 个 Web 端口就会把
            # Server 头的分数翻 5 倍，压过更具体的页面标题证据
            ckey = (key[0], key[1], key[2], sig.needle)
            if ckey in counted:
                details.setdefault(key, []).append((sig, svc))
                continue
            counted.add(ckey)
            # 页面标题是最"人写的"产品标签，权重高于 Server 头和证书
            w = sig.weight * (1.8 if sig.field == Field.TITLE else 1.0)
            # 同一产品取最高权重而不是累加 —— 否则 "ssh-2.0-openssh"(3.0) 与
            # "openssh"(2.5) 叠加成 5.5，会盖过更具体的 "ubuntu"(3.5)
            if w > scores.get(key, 0.0):
                scores[key] = w
            details.setdefault(key, []).append((sig, svc))

    # 互证加分：同一产品被**不同字段**（标题/证书/Server 头）同时命中，说明结论更可靠
    for key, hits in details.items():
        fields_seen = {sig.field for sig, _ in hits}
        if len(fields_seen) > 1:
            scores[key] = scores.get(key, 0.0) + 0.8 * (len(fields_seen) - 1)

    # ---- 技术栈（与设备类型正交）----
    stack: set[str] = set()
    for fld, value, _ in observations:
        low = str(value).lower()
        if fld == Field.COOKIE:
            if "phpsessid" in low or "think_lang" in low:
                stack.add("PHP")
            if "jsessionid" in low:
                stack.add("Java")
            if "asp.net_sessionid" in low:
                stack.add(".NET")
        if fld == Field.BODY and "powered by php" in low:
            stack.add("PHP")
        if fld == Field.SERVER:
            if "php/" in low:
                stack.add("PHP")
            elif "tomcat" in low or "jetty" in low or "weblogic" in low:
                stack.add("Java")
            elif "microsoft-iis" in low or "asp.net" in low:
                stack.add(".NET")
    res.tech_stack = sorted(stack)

    # ---- 选出最优 ----
    if scores:
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        (dtype, vendor, product), top = ranked[0]
        res.device_type = dtype
        res.device_label = TYPE_LABELS.get(dtype, dtype)
        res.vendor = vendor
        res.product = product
        # 标题类签名（如"防火墙系统"）通常不带厂商，
        # 若有更高分的候选带了厂商（品牌名提示），则继承该厂商
        if not res.vendor:
            for (_dt, vd, _pr), sc in ranked:
                if vd and sc > 0:
                    res.vendor = vd
                    break
        total = sum(scores.values())
        # 置信度：最高分占比 + 绝对强度
        strength = min(1.0, top / 8.0)
        dominance = top / total if total else 0
        res.confidence = round(min(0.98, 0.35 + dominance * 0.35 + strength * 0.30), 2)
        for (sig, svc) in details.get((dtype, vendor, product), []):
            src = {
                Field.SERVER: "Server 头",
                Field.TITLE: "页面标题",
                Field.CERT: "TLS 证书",
                Field.CERT_CN: "证书 CN",
                Field.BANNER: "服务 banner",
                Field.COOKIE: "Set-Cookie",
                Field.WWW_AUTH: "认证域",
                Field.PATH: "登录路径",
                Field.BODY: "响应正文",
            }.get(sig.field, sig.field)
            val = {
                Field.SERVER: getattr(svc, "server", ""),
                Field.TITLE: getattr(svc, "http_title", ""),
                Field.CERT: getattr(svc, "tls_subject", ""),
                Field.CERT_CN: _cert_cn(getattr(svc, "tls_subject", "") or ""),
                Field.BANNER: getattr(svc, "banner", ""),
                Field.COOKIE: getattr(svc, "cookie", ""),
                Field.WWW_AUTH: getattr(svc, "www_auth", ""),
                Field.PATH: getattr(svc, "matched_path", ""),
                Field.BODY: getattr(svc, "body_sample", ""),
            }.get(sig.field, "")
            res.evidence.append(f"{src}：{str(val)[:120]} → {product or TYPE_LABELS.get(dtype, dtype)}")
        # 次优候选
        for (dt, vd, pr), sc in ranked[1:4]:
            if sc >= top * 0.40:
                res.candidates.append({
                    "label": pr or TYPE_LABELS.get(dt, dt),
                    "type": dt, "vendor": vd, "score": round(sc, 1),
                })
    else:
        # ---- 端口画像兜底 ----
        pset = set(open_ports)
        best = None
        for pattern, dtype, vendor in PORT_SIGNATURES:
            want = {int(x) for x in pattern.split(",")}
            if want <= pset:
                if best is None:
                    best = (dtype, vendor)
        if best:
            res.device_type, res.vendor = best
            res.device_label = TYPE_LABELS.get(best[0], best[0])
            res.product = TYPE_LABELS.get(best[0], best[0])
            res.confidence = 0.3
            res.evidence.append(f"端口画像：{sorted(pset)} → 推断为 {res.device_label}")
        else:
            res.device_type = T.UNKNOWN
            res.device_label = TYPE_LABELS[T.UNKNOWN]
            res.confidence = 0.1
            res.evidence.append(
                "未匹配到任何产品级特征（标题/Server 头/证书/登录路径），仅凭端口无法判断设备类型"
            )

    # ---- MAC / OUI 补充厂商 ----
    if mac:
        res.evidence.append(f"MAC 地址：{mac}")
        if mac_vendor and not res.vendor:
            res.vendor = mac_vendor
            res.confidence = min(0.95, res.confidence + 0.15)

    return res