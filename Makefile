.PHONY: help venv install dev test lint typecheck run console guard

help:
	@echo "venv       创建 .venv 虚拟环境"
	@echo "install    安装本项目 (editable) + 全部可选依赖"
	@echo "test       运行测试"
	@echo "lint       ruff 静态检查"
	@echo "typecheck  mypy 类型检查（需先 pip install mypy）"
	@echo "guard      载荷字面量守护检查"
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

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests scripts

# mypy 不在任何 extra 里，单独列出并在没装时给出提示，
# 避免 `make lint` 因为一个未声明依赖直接失败。
typecheck:
	$(PY) -m mypy src || echo "mypy 未安装：pip install mypy"

guard:
	$(PY) scripts/check_payload_literals.py .

console:
	$(PY) -m p2s.console

run:
	$(PY) -m p2s.cli assets --file examples/hosts.txt --report reports/
