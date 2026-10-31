"""检查服务端返回页面的 HTML 标签配平（能抓"少一个 </div>"这类事故）。

为什么需要：改前端模板时，少一个闭合标签会让整页塌掉（实测过一次整页被压成 150px 竖条），
而 ruff / pytest / node --check 都看不见。这个脚本补上这一层。
"""
from __future__ import annotations

import http.cookiejar
import json
import sys
import urllib.request
from html.parser import HTMLParser

BASE = "http://127.0.0.1:18080"

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


class Balance(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, int]] = []
        self.errors: list[str] = []
        self.seen = 0

    def handle_starttag(self, tag, attrs):
        self.seen += 1
        if tag in VOID:
            return
        self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"多余的 </{tag}>（第 {self.getpos()[0]} 行）")
            return
        # 容忍浏览器式的隐式闭合：回溯到最近的同名标签
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                unclosed = self.stack[i + 1:]
                for t, ln in unclosed:
                    self.errors.append(f"<{t}> 未闭合（起始于第 {ln} 行）")
                del self.stack[i:]
                return
        self.errors.append(f"</{tag}> 没有对应的开始标签（第 {self.getpos()[0]} 行）")


def fetch(path: str = "/") -> str:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(
        BASE + "/api/login",
        data=json.dumps({"username": "admin", "password": "admin@123"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST"))
    return op.open(BASE + path, timeout=20).read().decode("utf-8", "replace")


def main() -> int:
    html = fetch("/")
    b = Balance()
    b.feed(html)
    unclosed = [f"<{t}> 到文件结束仍未闭合（起始于第 {ln} 行）" for t, ln in b.stack]
    problems = b.errors + unclosed
    if not problems:
        print(f"[OK] HTML 标签配平（{b.seen} 个起始标签）")
        return 0
    print(f"[FAIL] 发现 {len(problems)} 处标签问题：")
    for p in problems[:15]:
        print("   -", p)
    return 1


if __name__ == "__main__":
    sys.exit(main())
