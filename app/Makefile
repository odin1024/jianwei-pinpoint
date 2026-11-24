.PHONY: help venv install dev test lint typecheck run console guard verify verify-ui lock

help:
	@echo "── 环境 ──"
	@echo "venv       创建 .venv 虚拟环境"
	@echo "install    安装本项目 (editable) + 全部可选依赖"
	@echo "lock       重新导出依赖锁文件 requirements.lock.txt"
	@echo "── 门禁（与 CI 一致）──"
	@echo "verify     本地跑完 CI 的**无浏览器**门禁（测试/风格/载荷/脚本语法）"
	@echo "verify-ui  本地跑完浏览器门禁（需先 make console，且需 Chrome）"
	@echo "test       仅单元测试"
	@echo "lint       仅 ruff"
	@echo "typecheck  mypy（需先 pip install mypy）"
	@echo "guard      载荷字面量守护"
	@echo "── 运行 ──"
	@echo "console    启动本地 Web 控制台 http://127.0.0.1:18080"
	@echo "run        快速自检示例资产"

$(PY) ?= python
VENV  := .venv
BIN   := $(VENV)/Scripts
POSBIN:= $(VENV)/bin

venv:
	$(PY) -m venv $(VENV)
	@echo "完成。Windows 下执行: $(VENV)\\Scripts\\activate"

install dev:
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[all]"

lock:
	$(PY) -m pip freeze | sort > requirements.lock.txt
	@echo "已更新 requirements.lock.txt（注意：需手工剔除 cloudtest 闭包，见文件头说明）"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests scripts

typecheck:
	$(PY) -m mypy src || echo "mypy 未安装：pip install mypy"

guard:
	$(PY) scripts/check_payload_literals.py .

# ── 与 CI 的 test / contract / agent-scripts 三个 job 等价 ──────────────
# 不需要浏览器，任何机器都能跑；密码用测试固定值，不受 shell 环境影响
verify:
	@echo "=== 1/6 代码风格 ==="
	$(PY) -m ruff check src tests scripts
	@echo "=== 2/6 单元测试 ==="
	$(PY) -m pytest -q
	@echo "=== 3/6 载荷守护 ==="
	$(PY) scripts/check_payload_literals.py .
	@echo "=== 4/6 采集脚本语法（Linux/Windows 双平台）==="
	$(PY) -m pytest tests/test_agent_script.py -q
	@echo "=== 5/6 版本与规则库一致性 ==="
	$(PY) -m pytest tests/test_version.py tests/test_rulebook.py -q
	@echo "=== 6/6 文档数字与代码一致 ==="
	$(PY) -m pytest tests/test_doc_freshness.py tests/test_benchmark.py -q
	@echo "全部通过。"

# ── 与 CI 的 ui-gates job 等价（需先 make console）────────────────────
verify-ui:
	@echo "=== JS 语法 ==="
	$(PY) scripts/check_page_js.py
	@echo "=== HTML 配平 ==="
	$(PY) scripts/check_page_html.py
	@echo "=== 前后端接口一致性 ==="
	$(PY) scripts/check_api_consistency.py
	@echo "=== 布局与弹窗 ==="
	$(PY) scripts/check_page_layout.py
	@echo "=== 全站 16 页审计 ==="
	$(PY) scripts/audit_pages.py
	@echo "=== 控制台验收 ==="
	$(PY) scripts/verify_console.py

console:
	$(PY) -m p2s.console

run:
	$(PY) -m p2s.cli assets --file examples/hosts.txt --report reports/
