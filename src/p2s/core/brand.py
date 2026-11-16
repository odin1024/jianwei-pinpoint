"""品牌标识。

命名：见微 · Pinpoint
  「见微」—— 见微知著。工具的价值恰在此：在一堆资产里，
             看见那一个极小的信号（一枚 PHPSESSID Cookie），
             从而知道整体的风险。这正是产品与"扫端口工具"的分野。
  Pinpoint —— 精确定位。从 254 台候选里定位到 1 台需要修的机器。

图形：四角取景框 + 中心实心点
  - 取景框 = 资产范围 / 精确探测
  - 中心点 = 那一个真正需要处置的目标
  - 纯几何、单色、扁平，在 16px 到 512px 都成立
"""

APP_NAME_CN = "见微"
APP_NAME_EN = "Pinpoint"
APP_TAGLINE = "PHP 暴露面评估"
APP_TITLE = "见微 Pinpoint · PHP 暴露面评估"
CLI_NAME = "pinpoint"
CLI_ALIAS = "p2s"

#: 品牌色（同时用于界面令牌与图标）
BRAND = {
    "primary": "#1d4ed8",
    "primary_hover": "#1a44bd",
    "primary_soft": "#eef3fe",
    "primary_border": "#c4d6f8",
    "secondary": "#0f9b8e",
    "secondary_soft": "#e8f7f5",
    "secondary_border": "#b9e4de",
    "ink": "#101828",
}

#: 侧边栏品牌区与 favicon 共用的图形（currentColor 描边 + 中心实心点）
MARK_GLYPH = (
    '<path d="M4 11.5V6.5A2.5 2.5 0 0 1 6.5 4h5" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>'
    '<path d="M28 11.5V6.5A2.5 2.5 0 0 0 25.5 4h-5" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>'
    '<path d="M4 20.5v5A2.5 2.5 0 0 0 6.5 28h5" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>'
    '<path d="M28 20.5v5A2.5 2.5 0 0 1 25.5 28h-5" fill="none" stroke="currentColor" '
    'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/>'
    '<circle cx="16" cy="16" r="3.6" fill="currentColor"/>'
)


def icon_svg(color: str = BRAND["primary"], size: int = 32, radius: int = 7) -> str:
    """生成带底色的应用图标 SVG 字符串（用于 favicon）。"""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="{size}" height="{size}">'
        f'<rect width="32" height="32" rx="{radius}" fill="{color}"/>'
        f'<g transform="translate(0,0)" color="#ffffff" stroke-width="2.1">{MARK_GLYPH}</g>'
        f"</svg>"
    )


def favicon_data_uri(color: str = BRAND["primary"]) -> str:
    """返回可直接放进 <link rel="icon"> 的 data URI。"""
    import base64

    svg = icon_svg(color)
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


#: 扫描类型 → 中文
SCAN_KIND_LABELS = {
    "discover": "设备发现",
    "logs": "日志分析",
    "host": "本地取证",
    "url": "URL 探测",
    "agent": "Agent 上报",
}


def scan_kind_label(kind: str) -> str:
    return SCAN_KIND_LABELS.get(kind, kind or "-")