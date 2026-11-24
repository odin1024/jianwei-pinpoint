"""让 `python -m p2s.console` 能直接起控制台（`make console` 依赖它）。"""
from __future__ import annotations

import sys


def main() -> int:
    try:
        import uvicorn

        from .app import app
    except ImportError as exc:  # pragma: no cover - 缺依赖时给可执行的提示
        print(f'缺少控制台依赖，请安装：pip install -e ".[console]"（{exc}）', file=sys.stderr)
        return 2
    uvicorn.run(app, host="127.0.0.1", port=18080, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
