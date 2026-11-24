"""页面：任务中心"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "tasks.js").read_text(encoding="utf-8")
