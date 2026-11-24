"""控制台页面级前端代码（每个模块是一段 JS，最终拼进同一个 <script>）。

拆分的意义：改某个页面只动一个文件；因为拼接后仍在同一作用域内，
函数之间可以继续互相调用，不需要任何模块化改造。
"""

from . import about, agents, drawer, harden, ioc, logs, ops, overview, php, remediation, reports, rules, tasks

PARTS: list[str] = [
    overview.PART, tasks.PART, drawer.PART, php.PART,
    logs.PART, rules.PART, ioc.PART, reports.PART,
    agents.PART, remediation.PART, harden.PART, about.PART, ops.PART,
]

PAGES = "\n".join(PARTS)
