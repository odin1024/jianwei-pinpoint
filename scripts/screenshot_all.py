"""批量截图：遍历所有页面，按 tab 名保存 PNG。"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websocket

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _console_auth import credentials_json  # noqa: E402

PORT = 9342
BASE = "http://127.0.0.1:18080"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
TABS = ["overview", "discover", "tasks", "assets", "php", "logs",
        "host", "agents", "remediation", "schedule", "audit", "rules", "ioc", "reports"]


def launch():
    return subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--window-size=1600,1000",
         "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}",
         "--user-data-dir=" + r"C:\Users\<用户名>\AppData\Local\Temp\cdp-all", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ws_url():
    for _ in range(40):
        try:
            data = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2))
            pages = [t for t in data if t.get("type") == "page"]
            if pages:
                return pages[0]["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("no target")


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=40, suppress_origin=True)
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

    def shot(self, path):
        r = self.send("Page.captureScreenshot", format="png")
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "shots"
    theme = sys.argv[2] if len(sys.argv) > 2 else "light"
    d = pathlib.Path(outdir)
    d.mkdir(parents=True, exist_ok=True)

    proc = launch()
    try:
        c = CDP(ws_url())
        c.send("Page.navigate", url=BASE + "/login")
        time.sleep(2.5)
        c.eval("""(async()=>{await fetch('/api/login',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({__CRED__})});location.href='/'})()""".replace("{__CRED__}", credentials_json()))
        time.sleep(3.5)
        if theme == "dark":
            c.eval("document.documentElement.dataset.theme='dark';'ok'")
        for tab in TABS:
            c.eval(f"void go('{tab}');'ok'")
            time.sleep(2.2)
            c.shot(str(d / f"{theme}-{tab}.png"))
            print("saved", tab)
        return 0
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
