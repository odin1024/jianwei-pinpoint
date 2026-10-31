"""页面：Agent 管理（只读已有资产数据，无新增后端字段）。"""
import pathlib

PART = (pathlib.Path(__file__).with_name("js") / "agents.js").read_text(encoding="utf-8")
