"""弹层家族回归：告警弹层 / 抽屉 / 确认框 的打开与关闭。"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request

import websocket

PORT = 9336
BASE = "http://127.0.0.1:18080"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def launch():
    return subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}",
         "--user-data-dir=" + r"C:\Users\<用户名>\AppData\Local\Temp\cdp-prof4", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=30, suppress_origin=True)
        self.i = 0
        self.send("Page.enable")
        self.send("Runtime.enable")

    def send(self, method, **params):
        self.i += 1
        self.ws.send(json.dumps({"id": self.i, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.i:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    def eval(self, expr):
        r = self.send("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")


def main() -> int:
    proc = launch()
    ok = []
    bad = []

    def check(name, val):
        (ok if val else bad).append(name)
        print(f"  [{'PASS' if val else 'FAIL'}] {name}")

    try:
        c = CDP(ws_url())
        c.send("Page.navigate", url=BASE + "/login")
        time.sleep(3)
        c.eval("""(async()=>{await fetch('/api/login',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({username:'admin',password:'admin@123'})});location.href='/'})()""")
        time.sleep(4)

        # ---------- 抽屉 ----------
        c.eval("void (openAsset && openAsset('192.168.1.200'));'ok'")
        time.sleep(2)
        check("抽屉打开", c.eval("document.querySelector('#drawer').classList.contains('on')"))
        c.eval("document.querySelector('#drawer-bg').click()")
        time.sleep(0.6)
        check("点遮罩关闭抽屉", not c.eval("document.querySelector('#drawer').classList.contains('on')"))

        c.eval("void openAsset('192.168.1.200');'ok'")
        time.sleep(2)
        c.eval("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))")
        time.sleep(0.6)
        check("ESC 关闭抽屉", not c.eval("document.querySelector('#drawer').classList.contains('on')"))

        # ---------- 确认框 ----------
        c.eval("window.__cf=askConfirm({title:'测试',body:'x'});'ok'")
        time.sleep(0.6)
        check("确认框出现", c.eval("!!document.querySelector('.modal')"))
        c.eval("document.querySelector('.modal [data-r=\"0\"]').click()")
        time.sleep(0.5)
        check("点取消后消失", c.eval("!document.querySelector('.modal')"))

        c.eval("window.__cf2=askConfirm({title:'测试2',body:'y'});'ok'")
        time.sleep(0.5)
        c.eval("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))")
        time.sleep(0.5)
        check("ESC 关闭确认框", c.eval("!document.querySelector('.modal')"))

        # ---------- 页面切换后弹层残留 ----------
        c.eval("document.querySelector('#btn-alert').click()")
        time.sleep(0.3)
        c.eval("void go('assets');'ok'")
        time.sleep(1.5)
        check("切页后告警弹层自动收起", c.eval("document.querySelector('#alert-pop').classList.contains('hide')"))

        print("\n通过", len(ok), "失败", len(bad), bad or "")
        return 0 if not bad else 1
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
