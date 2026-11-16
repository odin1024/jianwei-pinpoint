"""统一的 httpx 客户端工厂。

为什么需要这一层：
    httpx 在构造 Client 时会把 NO_PROXY 的每个条目转成 URL 挂载模式。
    形如 `[::1]` 的带方括号 IPv6 字面量会被转成非法模式 `all://*[::1]`，
    构造阶段直接抛 InvalidURL —— 且发生在任何请求之前，调用方的
    try/except 往往包不住，最终表现为「端口开放但无协议响应」这类静默误判。

    企业内网的 NO_PROXY 普遍带 IPv6 条目，因此这不是边缘场景。

做法：
    关闭 httpx 的隐式环境读取（trust_env=False），改由本模块显式解析代理变量，
    逐条校验挂载模式合法性，非法条目跳过而不是让整个客户端构造失败。
    代理行为对用户保持兼容，但不再受畸形条目影响。
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

import httpx

__all__ = ["make_client", "proxy_mounts", "tls_verify"]


def _env(*names: str) -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v.strip()
    return ""


def _normalize_no_proxy_entry(entry: str) -> Optional[str]:
    """把 NO_PROXY 条目规整成 httpx 能解析的主机形态。

    IPv6 必须保留方括号（`all://[::1]` 合法，`all://::1` 非法），
    且不能再加 `*` 通配前缀 —— httpx 自身正是栽在 `all://*[::1]` 上。
    """
    e = entry.strip()
    if not e:
        return None
    if e == "*":
        return "*"

    bare = e[1:-1] if e.startswith("[") and e.endswith("]") else e
    try:
        ipaddress.IPv6Address(bare)
    except ValueError:
        pass
    else:
        return f"[{bare}]"

    # 主机名前导点表示子域通配（.corp.local），转成 httpx 的 * 前缀写法
    if e.startswith("."):
        e = "*" + e
    return e or None


def proxy_mounts() -> dict[str, Any]:
    """从环境变量构造代理挂载表，跳过一切非法模式。"""
    mounts: dict[str, Any] = {}

    all_proxy = _env("ALL_PROXY", "all_proxy")
    http_proxy = _env("HTTP_PROXY", "http_proxy")
    https_proxy = _env("HTTPS_PROXY", "https_proxy")

    if all_proxy:
        mounts["all://"] = all_proxy
    if http_proxy:
        mounts["http://"] = http_proxy
    if https_proxy:
        mounts["https://"] = https_proxy

    no_proxy = _env("NO_PROXY", "no_proxy")
    if no_proxy:
        for raw in no_proxy.split(","):
            host = _normalize_no_proxy_entry(raw)
            if host is None:
                continue
            key = "all://" if host == "*" else f"all://{host}"
            mounts[key] = None

    # 逐条校验：任何解析不了的模式都丢弃，绝不拖垮客户端构造
    safe: dict[str, Any] = {}
    for key, val in mounts.items():
        try:
            httpx.URL(key)
        except Exception:
            continue
        safe[key] = val
    return safe


def tls_verify(default: bool = False) -> bool:
    """TLS 校验开关。

    默认关闭：本产品大量探测内网自签证书设备，开启校验会让绝大多数目标
    直接握手失败、拿不到任何指纹。需要严格校验时设 P2S_VERIFY_TLS=1。
    """
    v = _env("P2S_VERIFY_TLS").lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def make_client(**kwargs: Any) -> httpx.Client:
    """构造 httpx.Client，代理与 TLS 行为统一在此收敛。

    调用方显式传入的 trust_env / mounts / verify 优先，不被覆盖。
    """
    kwargs.setdefault("trust_env", False)
    if "mounts" not in kwargs:
        m = proxy_mounts()
        if m:
            kwargs["mounts"] = m
    kwargs.setdefault("verify", tls_verify())
    return httpx.Client(**kwargs)
