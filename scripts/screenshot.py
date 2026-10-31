"""截图工具：用 Chrome CDP 打开控制台并截取指定页面。"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
import urllib.request

import websocket

PORT = 9340
BASE = "http://127.0.0.1:18080"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def launch() -> subprocess.Popen:
    return subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--window-size=1600,1000",
         "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}",
         "--user-data-dir=" + r"C:\Users\<用户名>\AppData\Local\Temp\cdp-shot", "about:blank"],
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

    def eval(self, expr):
        r = self.send("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")

    def shot(self, path: str, full: bool = False) -> None:
        r = self.send("Page.captureScreenshot", format="png", captureBeyondViewport=full)
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "overview.png"
    tab = sys.argv[2] if len(sys.argv) > 2 else "overview"
    theme = sys.argv[3] if len(sys.argv) > 3 else "light"
    proc = launch()
    try:
        c = CDP(ws_url())
        c.send("Page.navigate", url=BASE + "/login")
        time.sleep(2.5)
        c.eval("""(async()=>{await fetch('/api/login',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({username:'admin',password:'admin@123'})});location.href='/'})()""")
        time.sleep(3.5)
        if theme == "dark":
            c.eval("document.documentElement.dataset.theme='dark';'ok'")
        c.eval(f"void go('{tab}');'ok'")
        time.sleep(2.5)
        c.shot(out)
        print(f"saved {out}")
        return 0
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
