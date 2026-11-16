"""全站页面审计：14 个页面 × 浅色/深色 × 对比度/横向溢出。

背景：布局门禁此前只覆盖总览与资产两页，其余 12 页从没被量过。
本脚本用同一套 CDP 量测跑遍全部页面，把"看不见的问题"变成数字。
"""
from __future__ import annotations

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

PORT = 9360
BASE = "http://127.0.0.1:18080"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

PAGES = [
    ("overview", "态势总览"),
    ("devices", "设备发现"),
    ("tasks", "任务中心"),
    ("assets", "资产台账"),
    ("php", "PHP 暴露面"),
    ("logs", "日志分析"),
    ("agents", "Agent 管理"),
    ("hostcheck", "主机侧检测"),
    ("rules", "规则中心"),
    ("ioc", "IOC 中心"),
    ("remediation", "整改跟踪"),
    ("schedule", "计划任务"),
    ("audit", "审计日志"),
    ("reports", "报告中心"),
]

PROBE = r"""
(() => {
  const de = document.documentElement;
  const parse = c => (String(c).match(/[\d.]+/g) || [0,0,0]).slice(0,3).map(Number);
  const lum = c => { const [r,g,b] = parse(c).map(x => {
      x /= 255; return x <= .03928 ? x/12.92 : Math.pow((x+.055)/1.055, 2.4); });
      return .2126*r + .7152*g + .0722*b; };
  const ratio = (a,b) => { const l1=lum(a), l2=lum(b);
      return (Math.max(l1,l2)+.05)/(Math.min(l1,l2)+.05); };
  const bg = getComputedStyle(document.body).backgroundColor;

  const samples = [];
  const sels = ['.muted', 'td', '.card-h h3', '.hint', '.sub', 'th'];
  for (const sel of sels) {
    const el = document.querySelector(sel);
    if (!el) continue;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) continue;
    const card = el.closest('.card, table, .tbl-wrap');
    const cardBg = card ? getComputedStyle(card).backgroundColor : bg;
    const eff = (cardBg === 'rgba(0, 0, 0, 0)' || cardBg === 'transparent') ? bg : cardBg;
    samples.push({sel, color: cs.color, bg: eff,
                  ratio: +ratio(cs.color, eff).toFixed(2)});
  }
  const worst = samples.length ? Math.min(...samples.map(s=>s.ratio)) : 99;
  const worstSel = (samples.find(s=>s.ratio===worst)||{}).sel || '';
  return JSON.stringify({
    theme: de.dataset.theme,
    bg,
    overflow: de.scrollWidth - de.clientWidth,
    worstContrast: worst,
    worstSel,
    tables: document.querySelectorAll('table').length,
    cards: document.querySelectorAll('.card').length,
  });
})()
"""


def launch():
    profile = pathlib.Path.home() / "AppData/Local/Temp/cdp-audit"
    return subprocess.Popen(
        [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--window-size=1600,1000",
         "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ws_url() -> str:
    for _ in range(40):
        try:
            for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list")):
                if t.get("type") == "page":
                    return t["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("Chrome 未就绪")


class C:
    def __init__(self, url: str) -> None:
        self.ws = websocket.create_connection(url, timeout=40)
        self.i = 0

    def call(self, m: str, **p):
        self.i += 1
        self.ws.send(json.dumps({"id": self.i, "method": m, "params": p}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.i:
                return msg.get("result", {})

    def ev(self, expr: str, aw: bool = False):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=aw)
        return r.get("result", {}).get("value")


def main() -> int:
    proc = launch()
    rows: list[dict] = []
    fails: list[str] = []
    try:
        c = C(ws_url())
        c.call("Page.enable")
        c.call("Runtime.enable")
        c.call("Page.navigate", url=BASE)
        time.sleep(3)
        c.ev(f"""fetch('{BASE}/api/login',{{method:'POST',
             headers:{{'Content-Type':'application/json'}},
             body:JSON.stringify({credentials_json()})}}).then(r=>r.status)""", True)
        c.call("Page.navigate", url=BASE)
        time.sleep(3)

        for _key, label in PAGES:
            ok = c.ev(f"""(()=>{{const a=[...document.querySelectorAll('.nav a, aside a')]
                       .find(x=>x.textContent.trim().startsWith({json.dumps(label)}));
                       if(a){{a.click(); return true}} return false}})()""")
            if not ok:
                fails.append(f"{label}：侧栏找不到入口")
                continue
            time.sleep(1.6)

            light = json.loads(c.ev(PROBE))
            c.ev("document.documentElement.dataset.theme='dark'")
            time.sleep(0.9)
            dark = json.loads(c.ev(PROBE))
            c.ev("document.documentElement.dataset.theme='light'")
            time.sleep(0.3)

            rows.append({"page": label, "light": light, "dark": dark})

            if light["overflow"] > 8:
                fails.append(f"{label}（浅色）横向溢出 {light['overflow']}px")
            if dark["overflow"] > 8:
                fails.append(f"{label}（深色）横向溢出 {dark['overflow']}px")
            if light["worstContrast"] < 4.5:
                fails.append(f"{label}（浅色）{light['worstSel']} 对比度 {light['worstContrast']} < 4.5")
            if dark["worstContrast"] < 4.5:
                fails.append(f"{label}（深色）{dark['worstSel']} 对比度 {dark['worstContrast']} < 4.5")
    finally:
        proc.terminate()

    print(f"{'页面':<12}{'浅色对比':>10}{'深色对比':>10}{'溢出(浅/深)':>14}  最差元素")
    for r in rows:
        print(f"{r['page']:<12}{r['light']['worstContrast']:>10}"
              f"{r['dark']['worstContrast']:>10}"
              f"{str(r['light']['overflow'])+'/'+str(r['dark']['overflow']):>14}"
              f"  {r['light']['worstSel']}")

    if fails:
        print(f"\n[FAIL] {len(fails)} 处问题：")
        for f in fails:
            print("   -", f)
        return 1
    print(f"\n[OK] {len(rows)} 个页面 · 浅色/深色对比度均 >= 4.5 · 无横向溢出")
    return 0


if __name__ == "__main__":
    sys.exit(main())
