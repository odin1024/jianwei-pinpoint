"""静态资源产品词提取（借鉴 Fofa/Shodan 的 body/JS 特征思路）。

用于 JS 渲染的设备（如捷普 226/235）：首页只有一段脚本，标题为空，
但 i18n/业务 JS 里会反复出现**产品线名称**。

纪律（避免误判）：
  · 只认**白名单里的产品线词**，不凭空造产品名；
  · 同一词必须在单个资源里出现 ≥3 次（排除偶发提及）；
  · 结论按服务级证据处理（T2），置信度封顶，不当成产品级确认。
"""
from __future__ import annotations

import re

#: 产品线词白名单：只收厂商真实使用的产品线名称
PRODUCT_LINE_WORDS: tuple[str, ...] = (
    "防火墙", "信息审计", "网络安全审计", "准入控制", "安全感知平台", "管控平台",
    "管理平台", "运维审计", "堡垒机", "SSL VPN", "SSLVPN", "VPN", "网闸",
    "入侵防御", "入侵检测", "漏洞扫描", "数据库审计", "日志审计", "态势感知",
    "上网行为管理", "负载均衡", "web应用防火墙", "WEB应用防火墙",
)

#: 出现这些词说明是"通用框架文案"，不能当产品线
_NOISE = ("操作系统", "业务系统", "重启网关", "下一跳网关", "修改系统", "今日系统")


def extract_product_lines(text: str, min_hits: int = 3, limit: int = 2) -> list[str]:
    """从 JS/CSS 文本里挑出反复出现的产品线词。"""
    if not text:
        return []
    low = text[:2_000_000]
    scored: list[tuple[int, str]] = []
    for word in PRODUCT_LINE_WORDS:
        if any(n in word for n in _NOISE):
            continue
        n = low.count(word)
        if n >= min_hits:
            scored.append((n, word))
    scored.sort(reverse=True)
    out: list[str] = []
    for _n, word in scored:
        if any(word in kept or kept in word for kept in out):
            continue          # 去掉被更长词包含的短词（如 VPN ⊂ SSL VPN）
        out.append(word)
        if len(out) >= limit:
            break
    return out


def build_hint(words: list[str]) -> str:
    """把产品线词拼成一段可被签名匹配的文本。"""
    return " ".join(words)


_TEXT_LIKE = re.compile(r"text/(?:javascript|css|html|plain)", re.IGNORECASE)


def is_text_asset(content_type: str) -> bool:
    return bool(_TEXT_LIKE.search(content_type or ""))
