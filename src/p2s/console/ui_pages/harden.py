"""页面片段：配置加固（模板已抽到 js/harden.js）。"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "harden.js").read_text(encoding="utf-8")
