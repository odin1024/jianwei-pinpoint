"""p2s 控制台前端（单文件，零外部依赖，内网离线可用）。

界面取向：**企业级工具**，不是营销页。
  - 无 emoji，统一使用单色线性 SVG 图标
  - 单一强调色 + 语义状态色（其余一律中性）
  - 扁平化：1px 描边分层，不用渐变、不用装饰性阴影
  - 紧凑的行距与信息密度，等宽数字
  - 所有交互走真实后端 API，无任何模拟数据
"""
from __future__ import annotations

import pathlib

from .. import __version__
from .ui_css import STYLESHEET
from .ui_pages import PAGES

_TDIR = pathlib.Path(__file__).with_name("templates")


def _load_template(name: str) -> str:
    """从 templates/ 读模板：模板是 HTML 文件，不再是 Python 字符串。"""
    p = _TDIR / name
    if not p.exists():                      # 兜底：打包漏了资源时给出明确错误
        raise RuntimeError(f"模板缺失：{p}")
    return p.read_text(encoding="utf-8")


DASHBOARD_HTML = _load_template("dashboard.html")
LOGIN_HTML = _load_template("login.html")


# 占位符替换（每个请求都很便宜：字符串 replace，缓存由 lru 之外的调用方负责）
DASHBOARD_HTML = DASHBOARD_HTML.replace("/*__P2S_CSS__*/", STYLESHEET)
DASHBOARD_HTML = DASHBOARD_HTML.replace("/*__P2S_PAGES__*/", PAGES)
LOGIN_HTML = LOGIN_HTML.replace("__P2S_VERSION__", __version__)
