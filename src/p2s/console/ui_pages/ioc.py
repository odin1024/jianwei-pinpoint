"""页面：IOC 库"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "ioc.js").read_text(encoding="utf-8")
