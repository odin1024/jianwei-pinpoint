import pathlib

"""控制台样式表（从 ui.py 拆出，便于单独维护与复用）。

只放 CSS，不含业务逻辑；ui.py 在模块末尾把它注入 DASHBOARD_HTML 的占位符。
"""


_TDIR = pathlib.Path(__file__).with_name("templates")
STYLESHEET = (_TDIR / "app.css").read_text(encoding="utf-8")
