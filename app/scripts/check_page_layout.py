"""页面布局门禁：用 CDP 量真实 DOM，断言关键区块没有"样式静默失效"。

起因：CSS 少一个 `}` 导致 44% 规则失效——表格行高 107px、操作列竖排、顶栏按钮掉出视口，
而 ruff / node --check / HTML 配平 全部通过。只有量计算样式才能发现。
"""
from __future__ import annotations

import http.cookiejar
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import websocket

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _console_auth import credentials_json  # noqa: E402
from _toolpath import chrome as _chrome  # noqa: E402
from _toolpath import user_data_dir as _udd

PORT = 9346
BASE = "http://127.0.0.1:18080"
CHROME = None  # 运行时由 _chrome() 定位（环境变量 P2S_CHROME 可覆盖）

ASSETS_PROBE = r"""
(() => {
  const q = s => document.querySelector(s);
  const cs = e => e ? getComputedStyle(e) : null;
  const out = {};
  const ta = q('.top-actions');
  out.topActionsDisplay = ta ? cs(ta).display : 'MISSING';
  out.topActionsTop = ta ? Math.round(ta.getBoundingClientRect().top) : -999;
  const row = q('#a-table tbody tr');
  out.rowHeight = row ? row.offsetHeight : -1;
  const act = q('#a-table .act-row');
  out.actDisplay = act ? cs(act).display : 'MISSING';
  out.thVisible = [...document.querySelectorAll('#a-table thead th')]
      .filter(t => t.offsetParent !== null).length;
  out.cssRules = (() => { let n=0; for (const s of document.styleSheets){
      try{ n += s.cssRules.length }catch(e){} } return n; })();
  return JSON.stringify(out);
})()
"""

OVERVIEW_PROBE = r"""
(() => {
  const q = s => document.querySelector(s);
  const cs = e => e ? getComputedStyle(e) : null;
  const kpi = q('.kpi');
  const v = q('.kpi .v');
  const body = getComputedStyle(document.body);
  const parse = c => (c.match(/\d+/g) || [0,0,0]).slice(0,3).map(Number);
  const lum = c => { const [r,g,b] = parse(c).map(x => {
      x /= 255; return x <= .03928 ? x/12.92 : Math.pow((x+.055)/1.055, 2.4); });
      return .2126*r + .7152*g + .0722*b; };
  const ratio = (a,b) => { const l1=lum(a), l2=lum(b);
      return ((Math.max(l1,l2)+.05)/(Math.min(l1,l2)+.05)).toFixed(2); };
  const bg = body.backgroundColor;
  const out = {
    kpiDisplay: kpi ? cs(kpi).display : 'MISSING',
    bodyBg: bg,
    kpiValueColor: v ? cs(v).color : 'MISSING',
    contrast: v ? ratio(cs(v).color, bg) : '0',
    mutedContrast: (() => {
      const m = q('.muted');
      return m ? ratio(cs(m).color, bg) : '0';
    })(),
    theme: document.documentElement.dataset.theme || 'light',
  };
  return JSON.stringify(out);
})()
"""


NARROW_PROBE = r"""
(() => {
  const de = document.documentElement;
  const out = {
    scrollW: de.scrollWidth, clientW: de.clientWidth,
    overflow: de.scrollWidth - de.clientWidth,
    tableOverflow: 0, worst: ''
  };
  for (const t of document.querySelectorAll('table')) {
    const w = t.parentElement ? t.parentElement.scrollWidth - t.parentElement.clientWidth : 0;
    if (w > out.tableOverflow) { out.tableOverflow = w; }
  }
  let worstEl = null, worstW = 0;
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.right > de.clientWidth + 2 && r.width < de.clientWidth * 2) {
      if (r.right - de.clientWidth > worstW) { worstW = r.right - de.clientWidth; worstEl = el; }
    }
  }
  out.worst = worstEl ? (worstEl.tagName + '.' + (worstEl.className||'').toString().split(' ')[0]
                        + ' +' + Math.round(worstW) + 'px') : '';
  return JSON.stringify(out);
})()
"""


FORM_ROW_PROBE = r"""
(() => {
  const rows = [...document.querySelectorAll('.row')]
      .filter(r => r.querySelector('.check') || r.querySelector('.btn'));
  const bad = [];
  for (const row of rows) {
    const kids = [...row.children].filter(el => el.offsetParent !== null);
    if (kids.length < 2) continue;
    const bottoms = kids.map(el => Math.round(el.getBoundingClientRect().bottom));
    const spread = Math.max(...bottoms) - Math.min(...bottoms);
    if (spread > 2) {
      bad.push({
        text: (row.textContent || '').trim().slice(0, 24),
        spread: spread,
        bottoms: bottoms
      });
    }
  }
  return JSON.stringify({rows: rows.length, misaligned: bad});
})()
"""


DIALOG_PROBE = r"""
(() => {
  const m = document.querySelector('.modal');
  const bg = document.querySelector('.modal-bg');
  if (!m) return JSON.stringify({found:false});
  const cs = getComputedStyle(m);
  const r = m.getBoundingClientRect();
  return JSON.stringify({
    found: true,
    cls: m.className,
    display: cs.display,
    width: Math.round(r.width),
    height: Math.round(r.height),
    visible: r.width > 100 && r.height > 40 && cs.display !== 'none',
    bgOn: bg ? getComputedStyle(bg).display : '-',
    inputs: m.querySelectorAll('input,select,textarea').length
  });
})()
"""


def launch() -> subprocess.Popen:
    profile = pathlib.Path(_udd("layout"))
    return subprocess.Popen(
        [_chrome(), "--headless=new", "--disable-gpu", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--window-size=1600,1000",
         "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}",
         "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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
        self.ws = websocket.create_connection(url, timeout=30)
        self.i = 0

    def call(self, m: str, **p):
        self.i += 1
        self.ws.send(json.dumps({"id": self.i, "method": m, "params": p}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.i:
                return msg.get("result", {})

    def ev(self, expr: str, await_promise: bool = False):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True,
                      awaitPromise=await_promise)
        return r.get("result", {}).get("value")



# ---------------------------------------------------------------------------
# 门禁自备数据：测量资产页前先确保表格里有行，测完清理
# ---------------------------------------------------------------------------
SEED_HOSTS = ["127.0.0.71", "127.0.0.72", "127.0.0.73"]
SEED_GROUP = "ui-gate"


#: 共享 Cookie：所有请求必须复用同一会话，否则每次都是未登录（401）
_JAR = http.cookiejar.CookieJar()
_OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_JAR))


def _http(method: str, path: str, body: dict | None = None) -> tuple[int, str]:
    """极简 HTTP 调用（复用已装的 urllib，带 Cookie，不引第三方依赖）。"""
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json",
    })
    try:
        with _OPENER.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _login() -> None:
    _http("POST", "/api/login", json.loads(credentials_json()))


def _existing_hosts() -> set[str]:
    code, body = _http("GET", "/api/assets")
    if code != 200:
        print(f"  [WARN] 读取资产失败 HTTP {code}（登录态可能无效）")
        return set()
    return {a.get("host") for a in json.loads(body).get("assets", [])}


def _seed_assets() -> list[str]:
    """确保资产页至少有 3 行，返回本次新建的 host 列表（供清理）。"""
    _login()
    before = _existing_hosts()
    created: list[str] = []
    for host in SEED_HOSTS:
        if host in before:
            continue
        code, _ = _http("POST", "/api/assets",
                        {"host": host, "group": SEED_GROUP, "note": "布局门禁临时数据"})
        if code in (200, 201):
            created.append(host)
    print(f"门禁自备数据：新建 {len(created)} 台（原有 {len(before)} 台）")
    return created


def _cleanup_assets(created: list[str]) -> None:
    for host in created:
        _http("DELETE", f"/api/assets?host={urllib.parse.quote(host)}")
    if created:
        print(f"已清理门禁临时资产 {len(created)} 台")

def main() -> int:
    created = _seed_assets()
    proc = launch()
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

        # ---- 总览页：KPI 与对比度（浅色）----
        ov = json.loads(c.ev(OVERVIEW_PROBE))
        print("总览(浅):", json.dumps(ov, ensure_ascii=False))
        if ov["kpiDisplay"] == "MISSING":
            fails.append("总览页 KPI 卡片缺失")
        if float(ov["contrast"]) < 4.5:
            fails.append(f"KPI 数值对比度 {ov['contrast']} < 4.5")

        # ---- 深色模式：正文与次要文字都要可读 ----
        c.ev("document.documentElement.dataset.theme='dark'")
        time.sleep(1)
        dk = json.loads(c.ev(OVERVIEW_PROBE))
        print("总览(深):", json.dumps(dk, ensure_ascii=False))
        if float(dk["contrast"]) < 4.5:
            fails.append(f"深色模式 KPI 对比度 {dk['contrast']} < 4.5")
        if float(dk["mutedContrast"]) < 3.0:
            fails.append(f"深色模式次要文字对比度 {dk['mutedContrast']} < 3.0")
        c.ev("document.documentElement.dataset.theme='light'")

        # ---- 资产页：表格与顶栏 ----
        c.ev("""(()=>{const a=[...document.querySelectorAll('.nav a, aside a')]
                .find(x=>x.textContent.includes('资产台账')); if(a)a.click(); return !!a})()""")
        time.sleep(3)
        data = json.loads(c.ev(ASSETS_PROBE))
        print("资产页:", json.dumps(data, ensure_ascii=False))
        if data["topActionsDisplay"] != "flex":
            fails.append(f"顶栏操作区 display={data['topActionsDisplay']}（应 flex）")
        if data["topActionsTop"] < 0:
            fails.append(f"顶栏操作区 top={data['topActionsTop']}（应 >=0）")
        if not (0 < data["rowHeight"] <= 70):
            fails.append(f"表格行高={data['rowHeight']}px（应 <=70）")
        if data["actDisplay"] != "flex":
            fails.append(f"操作列 display={data['actDisplay']}（应 flex）")
        if data["thVisible"] > 11:
            fails.append(f"可见列={data['thVisible']}（应 <=11）")
        if data["cssRules"] < 300:
            fails.append(f"生效 CSS 规则={data['cssRules']}（应 >=300）")
        # ---- 表单行：同一 row 内控件的底边必须对齐 ----
        c.ev("""(()=>{const a=[...document.querySelectorAll('.nav a, aside a')]
                .find(x=>x.textContent.includes('设备发现')); if(a)a.click(); return !!a})()""")
        time.sleep(2.5)
        fr = json.loads(c.ev(FORM_ROW_PROBE))
        print("表单行:", json.dumps(fr, ensure_ascii=False))
        if fr["misaligned"]:
            for bad in fr["misaligned"][:3]:
                fails.append(f"表单行底边错位 {bad['spread']}px：{bad['text']}")

        # ---- 弹窗：点开「新增计划」必须真的看得见 ----
        c.ev("void go('schedule')")
        time.sleep(2.0)
        c.ev("(()=>{const b=document.querySelector('#sc-add'); if(b)b.click(); return !!b})()")
        time.sleep(1.2)
        dlg = json.loads(c.ev(DIALOG_PROBE))
        print("弹窗:", json.dumps(dlg, ensure_ascii=False))
        if not dlg.get("found"):
            fails.append("排程弹窗：点击后没有生成 .modal 节点")
        else:
            if not dlg["visible"]:
                fails.append(f"排程弹窗不可见（display={dlg['display']}, "
                             f"{dlg['width']}x{dlg['height']}）—— 遮罩出现但内容没显示")
            if dlg["width"] < 600:
                fails.append(f"排程弹窗宽度只有 {dlg['width']}px，wide 样式未生效")
            if dlg["inputs"] < 5:
                fails.append(f"排程弹窗只有 {dlg['inputs']} 个输入控件，内容可能没渲染")
        c.ev("(()=>{const b=document.querySelector('#sd-cancel'); if(b)b.click(); return true})()")
        time.sleep(0.5)

        # ---- 窄屏：1200px 下不应出现横向溢出 ----
        c.call("Emulation.setDeviceMetricsOverride", width=1200, height=900,
               deviceScaleFactor=1, mobile=False)
        time.sleep(2)
        nar = json.loads(c.ev(NARROW_PROBE))
        print("资产页(1200px):", json.dumps(nar, ensure_ascii=False))
        if nar["overflow"] > 8:
            fails.append(f"1200px 下页面横向溢出 {nar['overflow']}px（{nar['worst']}）")

        c.ev("""(()=>{const a=[...document.querySelectorAll('.nav a, aside a')]
                .find(x=>x.textContent.includes('报告中心')); if(a)a.click(); return !!a})()""")
        time.sleep(2.5)
        nar2 = json.loads(c.ev(NARROW_PROBE))
        print("报告中心(1200px):", json.dumps(nar2, ensure_ascii=False))
        if nar2["overflow"] > 8:
            fails.append(f"报告中心 1200px 横向溢出 {nar2['overflow']}px（{nar2['worst']}）")
    finally:
        proc.terminate()
        _cleanup_assets(created)

    if fails:
        print("\n[FAIL] 布局检查未通过：")
        for f in fails:
            print("   -", f)
        return 1
    print("\n[OK] 布局 + 对比度检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
