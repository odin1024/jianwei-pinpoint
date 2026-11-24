"""定位外部工具（Chrome / Node），避免硬编码本机路径。

优先级：环境变量 → PATH → 常见安装位置 → 明确报错。
环境变量：
    P2S_CHROME   Chrome / Chromium 可执行文件路径
    P2S_NODE     Node 可执行文件路径

为什么需要它：此前脚本里写死了 `C:\\Users\\admin\\...` 与
`C:\\Program Files\\Google\\Chrome\\...`，换一台机器（或 CI）就跑不起来。
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

_CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]

_NODE_CANDIDATES = [
    r"C:\Program Files\nodejs\node.exe",
    "/usr/bin/node",
    "/usr/local/bin/node",
]


def _resolve(env_var: str, names: list[str], candidates: list[str], label: str) -> str:
    explicit = os.environ.get(env_var)
    if explicit:
        if Path(explicit).exists():
            return explicit
        raise SystemExit(f"{env_var} 指向的文件不存在：{explicit}")
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    for c in candidates:
        if Path(c).exists():
            return c
    raise SystemExit(
        f"找不到 {label}。请安装后用环境变量指定，例如：\n"
        f'    $env:{env_var} = "<{label} 可执行文件路径>"'
    )


def chrome() -> str:
    """Chrome / Chromium 路径。"""
    return _resolve("P2S_CHROME", ["google-chrome", "chromium", "chrome"],
                    _CHROME_CANDIDATES, "Chrome / Chromium")


def node() -> str:
    """Node.js 路径。"""
    return _resolve("P2S_NODE", ["node"], _NODE_CANDIDATES, "Node.js")


def user_data_dir(tag: str) -> str:
    """给 CDP 用的临时 profile 目录（可移植，不写死用户目录）。"""
    return str(Path(tempfile.gettempdir()) / f"p2s-cdp-{tag}")
