"""从环境变量读取控制台凭据，供验收脚本共用。

控制台自 1.0.5 起不再有内置默认口令，所有脚本必须显式拿到凭据：
  P2S_ADMIN_USER      登录用户名，缺省 admin
  P2S_ADMIN_PASSWORD  登录口令
  P2S_CONSOLE_PASSWORD 控制台口令（未设 P2S_ADMIN_PASSWORD 时回退用）
"""
from __future__ import annotations

import json
import os

USER = os.environ.get("P2S_ADMIN_USER", "admin")
PASSWORD = (
    os.environ.get("P2S_ADMIN_PASSWORD")
    or os.environ.get("P2S_CONSOLE_PASSWORD")
    or ""
)


def credentials() -> dict[str, str]:
    if not PASSWORD:
        raise SystemExit(
            "未设置 P2S_ADMIN_PASSWORD / P2S_CONSOLE_PASSWORD，无法登录控制台"
        )
    return {"username": USER, "password": PASSWORD}


def credentials_json() -> str:
    """可直接嵌进 JS 的 JSON 字面量。"""
    return json.dumps(credentials(), ensure_ascii=False)
