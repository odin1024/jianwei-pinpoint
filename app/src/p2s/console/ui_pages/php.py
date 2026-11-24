"""页面：PHP 暴露面"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "php.js").read_text(encoding="utf-8")
