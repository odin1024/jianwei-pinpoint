"""用 CDP 真实打开控制台，点击铃铛 / ✕ / 点外部，验证弹层能开能关。"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websocket  # websocket-client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _console_auth import credentials_json  # noqa: E402

PORT = 9333
BASE = "http://127.0.0.1:18080"
EDGE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def launch() -> subprocess.Popen:
    return subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}", "--user-data-dir=" + r"C:\Users\<用户名>\AppData\Local\Temp\cdp-prof2",
         "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def ws_url() -> str:
    for _ in range(40):
        try:
            data = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2))
            pages = [t for t in data if t.get("type") == "page"]
            if pages:
                return pages[0]["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("找不到调试目标")


class CDP:
    def __init__(self, url: str) -> None:
        self.ws = websocket.create_connection(url, timeout=30, suppress_origin=True)
        self.i = 0
        self.send("Page.enable")
        self.send("Runtime.enable")

    def send(self, method: str, **params):
        self.i += 1
        self.ws.send(json.dumps({"id": self.i, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.i:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    def eval(self, expr: str):
        r = self.send("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")


def main() -> int:
    proc = launch()
    try:
        c = CDP(ws_url())
        c.send("Page.navigate", url=BASE + "/login")
        time.sleep(3)
        # 登录
        c.eval("""
        (async()=>{
          await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({__CRED__})});
          location.href='/';
        })()""".replace("{__CRED__}", credentials_json()))
        time.sleep(4)
        checks = {}
        checks["页面就绪"] = c.eval("!!document.querySelector('#btn-alert')")
        checks["初始隐藏"] = c.eval("document.querySelector('#alert-pop').classList.contains('hide')")
        # 点铃铛 → 应打开
        c.eval("document.querySelector('#btn-alert').click()")
        time.sleep(0.5)
        checks["点铃铛后打开"] = c.eval("!document.querySelector('#alert-pop').classList.contains('hide')")
        # 点 ✕ → 应关闭
        c.eval("document.querySelector('#alert-close').click()")
        time.sleep(0.5)
        checks["点✕后关闭"] = c.eval("document.querySelector('#alert-pop').classList.contains('hide')")
        # 再打开 → 点遮罩关闭
        c.eval("document.querySelector('#btn-alert').click()")
        time.sleep(0.3)
        c.eval("document.querySelector('#alert-bg').click()")
        time.sleep(0.3)
        checks["点遮罩后关闭"] = c.eval("document.querySelector('#alert-pop').classList.contains('hide')")
        # 再打开 → ESC 关闭
        c.eval("document.querySelector('#btn-alert').click()")
        time.sleep(0.3)
        c.eval("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))")
        time.sleep(0.3)
        checks["ESC 关闭"] = c.eval("document.querySelector('#alert-pop').classList.contains('hide')")
        # 再打开 → 点页面空白处关闭
        c.eval("document.querySelector('#btn-alert').click()")
        time.sleep(0.3)
        c.eval("document.querySelector('#content').click()")
        time.sleep(0.3)
        checks["点页面外部关闭"] = c.eval("document.querySelector('#alert-pop').classList.contains('hide')")

        for k, v in checks.items():
            print(f"  [{'PASS' if v else 'FAIL'}] {k}")
        bad = [k for k, v in checks.items() if not v]
        print("失败:", bad or "无")
        return 0 if not bad else 1
    finally:
        proc.terminate()


if __name__ == "__main__":
    for _s in (sys.stdout, sys.stderr):
        _s.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
