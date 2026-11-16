"""页面片段：关于（模板已抽到 js/about.js）。"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "about.js").read_text(encoding="utf-8")
