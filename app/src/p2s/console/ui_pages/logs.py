"""页面：日志分析"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "logs.js").read_text(encoding="utf-8")
