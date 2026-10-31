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
    """设备分类结果。

    `vendor` 只能来自**产品级证据**（标题里的品牌名、厂商证书）；`mac_vendor`
    是网卡 OUI 查出来的硬件厂商，两者语义不同，绝不互相覆盖。
    """

    device_type: str = T.UNKNOWN
    device_label: str = TYPE_LABELS[T.UNKNOWN]
    vendor: str = ""
    product: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    #: 结论来自哪一级证据：title / cert / path / server / banner / port
    vendor_source: str = ""
    product_source: str = ""

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


def apply_noise_ports(profiles: list[Any]) -> set[int]:
    """把跨主机统计出的噪声端口从每台设备的端口清单里剔除。

    只在**批量扫描**时有意义：单台主机看不出"某个端口在整片网段都开着"。

    判据（两者必须同时满足，且按"无响应端口"统计）：
      1) 该端口在 >30% 的可达主机上都"开着但没有有意义的协议响应"；
      2) 该端口在本机也没有有意义的协议响应。

    关键在于只统计**无响应**的端口。早期版本直接统计"开着的端口"，结果在
    一个同构的企业网段里，22/80/443 因为"很多设备都开"被判成噪声，
    把真正的 Web 端口也剔掉了。
    """
    alive = [p for p in profiles if getattr(p, "alive", False)]
    if not alive:
        return set()

    meaningless_sets: list[list[int]] = []
    for p in alive:
        meaningful = set(getattr(p, "meaningful_ports", []) or [])
        meaningless_sets.append([port for port in p.open_ports if port not in meaningful])

    noise = detect_noise_ports(meaningless_sets)
    if not noise:
        return noise

    for p in alive:
        meaningful = set(getattr(p, "meaningful_ports", []) or [])
        removed = [port for port in p.open_ports if port in noise and port not in meaningful]
        if not removed:
            continue
        p.open_ports = [port for port in p.open_ports if port not in removed]
        p.noise_ports = sorted(set(p.noise_ports) | set(removed))
        p.evidence.append(
            "跨主机统计：端口 "
            + "/".join(str(x) for x in removed)
            + " 在超过 30% 的可达主机上都存在且无有效响应，判定为网络级噪声（NAT/tarpit），已从端口清单剔除"
        )
    return noise


#: 证据分级（决定「谁能推出厂商」）
#: T1 产品级：页面标题、TLS 证书、证书 CN、登录路径、认证域 —— 设备自己写明的身份
#: T2 服务级：Server 头、协议 banner、Cookie、响应正文 —— 只说明"跑着什么软件"
#: T3 推断级：端口画像、MAC OUI —— 只能作兜底，且必须显式标注
TIER1_FIELDS = frozenset({Field.TITLE, Field.META, Field.BRAND, Field.CERT, Field.CERT_CN,
                          Field.PATH, Field.WWW_AUTH})
TIER2_FIELDS = frozenset({Field.SERVER, Field.BANNER, Field.COOKIE, Field.BODY})

#: T2 证据的折算系数：服务级证据永远不能压过同权重的产品级证据
TIER2_FACTOR = 0.7

_FIELD_SOURCE = {
    Field.TITLE: "title",
    Field.META: "meta",
    Field.JS: "js",
    Field.BRAND: "brand",
    Field.CERT: "cert",
    Field.CERT_CN: "cert",
    Field.PATH: "path",
    Field.WWW_AUTH: "www_auth",
    Field.SERVER: "server",
    Field.BANNER: "banner",
    Field.COOKIE: "cookie",
    Field.BODY: "body",
}


def _cert_cn(subject: str) -> str:
    m = re.search(r"CN=([^,/]+)", subject or "")
    return m.group(1).strip() if m else ""


def classify(
    services: list[Any],
    open_ports: list[int],
    *,
    meaningful_ports: Optional[list[int]] = None,
    mac: Optional[str] = None,
    mac_vendor: Optional[str] = None,
) -> Classification:
    """综合多源证据给出设备分类。

    meaningful_ports：真正返回过有效协议响应的端口。端口画像兜底只用它 ——
    否则一个 NAT/tarpit 网段里"连得上但零响应"的 25/110/143 会把设备推断成邮件网关。
    """
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
        if getattr(svc, "js_hints", ""):
            observations.append((Field.JS, svc.js_hints, svc))
        if getattr(svc, "page_meta", None):
            observations.append((Field.META, svc.page_meta, svc))
        if getattr(svc, "body_sample", None):
            observations.append((Field.BODY, svc.body_sample, svc))
        # 品牌词（正文/静态资源/404 页扫出来的厂商名）：产品级证据
        for brand in (getattr(svc, "brand_hints", None) or []):
            observations.append((Field.BRAND, brand, svc))

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
            # 标题是最"人写的"产品标签；服务级证据（Server/banner/Cookie）打折，
            # 避免「Server: jump」这类泛化标识压过「捷普WEB应用防火墙」这样的产品标题。
            if sig.field == Field.TITLE:
                factor = 1.8
            elif sig.field in TIER2_FIELDS:
                factor = TIER2_FACTOR
            else:
                factor = 1.0
            w = sig.weight * factor
            # 同一产品取最高权重而不是累加 —— 否则 "ssh-2.0-openssh"(3.0) 与
            # "openssh"(2.5) 叠加成 5.5，会盖过更具体的 "ubuntu"(3.5)
            if w > scores.get(key, 0.0):
                scores[key] = w
            details.setdefault(key, []).append((sig, svc))

    # 互证加分：同一产品被**不同字段**同时命中，说明结论更可靠。
    # 只有产品级字段之间才给满分互证；凑上服务级字段只算半份。
    for key, hits in details.items():
        fields_seen = {sig.field for sig, _ in hits}
        if len(fields_seen) > 1:
            tier1_seen = fields_seen & TIER1_FIELDS
            bonus = 0.8 * (len(tier1_seen) - 1) if len(tier1_seen) > 1 else 0.0
            if tier1_seen and (fields_seen - TIER1_FIELDS):
                bonus += 0.4
            scores[key] = scores.get(key, 0.0) + bonus

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

        top_hits = details.get((dtype, vendor, product), [])
        top_fields = {sig.field for sig, _ in top_hits}
        # 最高分结论来自哪级证据：决定置信度上限与展示口径
        from_tier1 = bool(top_fields & TIER1_FIELDS)
        res.product_source = _FIELD_SOURCE.get(
            next((s.field for s, _ in top_hits if s.field in TIER1_FIELDS),
                 top_hits[0][0].field if top_hits else Field.TITLE), "")

        # 厂商只认产品级证据：
        #   1) 最高分结论自带厂商 → 用它；
        #   2) 否则在**同类型**的 T1 命中里找厂商锚点（例如标题『捷普…』）；
        #   3) 都没有就留空 —— 宁可写"未知"，也不拿 MAC OUI 冒充厂商。
        if not res.vendor:
            for (_dt, vd, _pr), _sc in ranked:
                if vd and _dt == dtype:
                    sig_hits = details.get((_dt, vd, _pr), [])
                    if any(sig.field in TIER1_FIELDS for sig, _ in sig_hits):
                        res.vendor = vd
                        break
        if res.vendor:
            res.vendor_source = next(
                (
                    _FIELD_SOURCE.get(sig.field, "")
                    for (sig, _) in top_hits
                    if sig.vendor == res.vendor and sig.field in TIER1_FIELDS
                ),
                "",
            ) or "candidate"

        total = sum(scores.values())
        strength = min(1.0, top / 8.0)
        dominance = top / total if total else 0
        conf = 0.35 + dominance * 0.35 + strength * 0.30
        if not from_tier1:
            conf = min(conf, 0.72)   # 只靠 Server 头/banner 得出的结论，不许显得很确定
        res.confidence = round(min(0.98, conf), 2)
        for (sig, svc) in details.get((dtype, vendor, product), []):
            src = {
                Field.SERVER: "Server 头",
                Field.TITLE: "页面标题",
                Field.META: "页面元数据",
                Field.JS: "静态资源文案",
                Field.BRAND: "品牌词",
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
                Field.META: getattr(svc, "page_meta", ""),
                Field.JS: getattr(svc, "js_hints", ""),
                Field.BRAND: "、".join(getattr(svc, "brand_hints", []) or []),
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
        # 只用「真的有过有效响应」的端口：NAT/tarpit 网段里 25/110/143 连得上但零响应，
        # 拿它们推"邮件网关"会一路把不存在的设备写进台账。
        responsive = [p for p in (meaningful_ports or [])]
        # 少数端口的语义足够强，即使没有应用层响应也能定性：
        # 9100/515/631 打印、554 RTSP、623 IPMI、2049/3260 存储。
        # 它们不属于会被 NAT/tarpit 批量占用的端口，因此单独放行。
        semantic = set(open_ports or []) & {9100, 515, 631, 554, 623, 2049, 3260}
        pset = set(responsive) | semantic
        best = None
        if pset:
            for pattern, dtype, vendor in PORT_SIGNATURES:
                want = {int(x) for x in pattern.split(",")}
                if want <= pset:
                    if best is None:
                        best = (dtype, vendor)
        if best:
            res.device_type, port_vendor = best
            res.device_label = TYPE_LABELS.get(best[0], best[0])
            # 只能在没有任何产品标签时兜底，所以产品名必须标明是推断
            res.product = f"{res.device_label}（端口推断）"
            res.vendor = port_vendor or ""
            res.vendor_source = "port" if port_vendor else ""
            res.product_source = "port"
            res.confidence = 0.3
            res.evidence.append(
                f"端口画像：{sorted(pset)} → 推断为 {res.device_label}"
                f"（无标题/证书/Server 头等产品级证据，结论仅供参考）"
            )
        else:
            res.device_type = T.UNKNOWN
            res.device_label = TYPE_LABELS[T.UNKNOWN]
            res.confidence = 0.1
            if pset:
                res.evidence.append(
                    f"未匹配到任何产品级特征（标题/证书/Server 头/登录路径）；"
                    f"有效端口 {sorted(pset)} 也不足以判定类型"
                )
            else:
                res.evidence.append(
                    "未匹配到任何产品级特征，且没有端口产生有效协议响应 —— "
                    "设备类型无法判定（不回退到端口猜测，避免把 NAT/tarpit 噪声当成设备特征）"
                )

    # ---- MAC / OUI：只作"网卡厂商"，绝不冒充设备厂商 ----
    if mac:
        res.evidence.append(f"MAC 地址：{mac}")
        if mac_vendor:
            res.evidence.append(
                f"网卡厂商（OUI）：{mac_vendor}"
                "（只说明网卡/整机代工厂，不代表设备品牌；设备品牌以上面的产品级证据为准）"
            )
    # JS 渲染设备：厂商已定时，用静态资源里的产品线词补全产品名（服务级证据）
    _js = " ".join((getattr(s, "js_hints", "") or "") for s in (services or [])).strip()
    if _js and res.vendor and res.product_source in ("port", "server", "banner", ""):
        # 取**出现次数最多**的产品线词，而不是列表顺序（i18n 里 VPN 出现极多，易误选）
        _cand = [w for w in ("安全感知平台", "信息审计", "准入控制", "运维审计",
                             "管控平台", "管理平台", "防火墙", "SSL VPN", "SSLVPN", "VPN")
                 if w.lower() in _js.lower()]
        _word = max(_cand, key=lambda w: _js.lower().count(w.lower())) if _cand else ""
        if _word:
            res.product = f"{res.vendor}{_word}（静态资源）"
            res.product_source = "js"
            res.confidence = min(res.confidence, 0.72)
            res.evidence.append(f"静态资源文案：出现「{_word}」→ 推断产品线（服务级证据，非产品级确认）")
    return res
