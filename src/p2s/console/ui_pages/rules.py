"""页面：规则中心"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "rules.js").read_text(encoding="utf-8")
