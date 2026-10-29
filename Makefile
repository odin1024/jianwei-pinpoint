.PHONY: help venv install dev test lint run console fmt

help:
	@echo "venv     创建 .venv 虚拟环境"
	@echo "install  安装本项目 (editable) + 全部可选依赖"
	@echo "dev      开发模式安装"
	@echo "test     运行测试"
	@echo "lint     ruff + mypy 检查"
	@echo "console  启动本地 Web 控制台 http://127.0.0.1:8080"
	@echo "run      快速自检示例资产"

$(PY) ?= python
VENV  := .venv
BIN   := $(VENV)/Scripts
POSBIN:= $(VENV)/bin

venv:
	$(PY) -m venv $(VENV)
	@echo "完成。Windows 下执行: $(VENV)\\Scripts\\activate"

install:
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[all]"

dev:
	$(PY) -m pip install -U pip
	$(PY) -m pip install -e ".[all]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check src tests
	$(PY) -m mypy src

console:
	$(PY) -m p2s.console.app

run:
	$(PY) -m p2s.cli assets --file examples/hosts.txt --report reports/assets.json
