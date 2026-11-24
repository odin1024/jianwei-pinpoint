"""把控制台页面里的内联 JS 抽出来做语法检查（node --check）。

价值：模板字符串被改坏时，Python 侧 ruff/pytest 全绿，前端却是白屏。
这个检查能在启动浏览器之前就抓到语法错误。
"""
from __future__ import annotations

import http.cookiejar
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _console_auth import credentials  # noqa: E402

BASE = "http://127.0.0.1:18080"
NODE = r"C:\Users\<用户名>\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe"


def fetch_html() -> str:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(
        BASE + "/api/login",
        data=json.dumps(credentials()).encode(),
        headers={"Content-Type": "application/json"}, method="POST"))
    return op.open(BASE + "/", timeout=20).read().decode("utf-8", "replace")


def main() -> int:
    html = fetch_html()
    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
    if not scripts:
        print("[FAIL] 页面里没有 <script>")
        return 1
    body = max(scripts, key=len)
    tmp = pathlib.Path(tempfile.gettempdir()) / "p2s_page.js"
    tmp.write_text(body, encoding="utf-8")
    node = NODE if pathlib.Path(NODE).exists() else "node"
    r = subprocess.run([node, "--check", str(tmp)], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode == 0:
        print(f"[OK] 内联 JS 语法正确（{len(body)} 字符）")
        return 0
    print("[FAIL] 内联 JS 语法错误：")
    print(r.stderr.strip()[:1200])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
