"""p2s Web 控制台（FastAPI）。

形态定位：给客户交付时的主要交互界面。
  - 资产台账：集中管理目标、分组、责任人、修复状态
  - 扫描编排：网页发起资产测绘 / 主动探测 / 日志检测 / 主机侧检测
  - 报告中心：一键生成 JSON / Markdown / HTML 报告，可直接发给客户
  - 规则与 IOC：内置规则库与 IOC 库，支持导出

开发期： p2s serve --port 8080
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from ..core import hostcheck, logscan
from ..core import probe as probe_mod
from ..core import report as report_mod
from ..core.ioc import IocLibrary
from ..core.rules import RULES, coverage_report
from ..core.versions import classify

app = FastAPI(
    title="p2s — php2shell 检测控制台",
    description="CVE-2026-109618 / CVE-2026-109619 检测与暴露面评估",
    version="0.1.0",
)

DATA_DIR = Path(os.environ.get("P2S_DATA_DIR", "./p2s-data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_FILE = DATA_DIR / "assets.json"
SCANS_DIR = DATA_DIR / "scans"

_lock = threading.Lock()


# --------------------------------------------------------------------------
# 存储
# --------------------------------------------------------------------------
def _load_assets() -> list[dict]:
    if not ASSETS_FILE.exists():
        return []
    try:
        return json.loads(ASSETS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_assets(assets: list[dict]) -> None:
    ASSETS_FILE.write_text(json.dumps(assets, ensure_ascii=False, indent=2), encoding="utf-8")


def _new_scan(kind: str) -> report_mod.ScanResult:
    return report_mod.ScanResult(
        scan_id=f"{kind}-{uuid.uuid4().hex[:10]}", kind=kind, started_at=datetime.now().isoformat(timespec="seconds")
    )


def _persist(res: report_mod.ScanResult) -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    base = SCANS_DIR / res.scan_id
    report_mod.to_json(res, base.with_suffix(".json"))
    report_mod.to_markdown(res, base.with_suffix(".md"))
    report_mod.to_html(res, base.with_suffix(".html"))
    res.finished_at = datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# API 模型
# --------------------------------------------------------------------------
class AssetIn(BaseModel):
    url: str
    group: str = "default"
    owner: str = ""
    note: str = ""


class UrlScanIn(BaseModel):
    url: str
    do_probe: bool = True
    timeout: float = 15.0


class LogScanIn(BaseModel):
    path: str
    group: str = "default"


class AgentReportIn(BaseModel):
    hostname: str = ""
    data: dict[str, Any] = {}


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now().isoformat(timespec="seconds")}


@app.get("/api/rules")
def api_rules() -> dict:
    return {
        "count": len(RULES),
        "rules": [r.to_dict() for r in RULES],
    }


@app.get("/api/ioc")
def api_ioc() -> dict:
    lib = IocLibrary()
    return {
        "summary": lib.summary(),
        "ips": list(lib.ips),
        "domains": list(lib.domains),
        "urls": list(lib.urls),
        "hashes": lib.hashes,
    }


@app.get("/api/assets")
def api_assets() -> dict:
    return {"assets": _load_assets()}


@app.post("/api/assets")
def api_add_asset(body: AssetIn) -> dict:
    url = body.url if body.url.startswith("http") else f"http://{body.url}"
    fp = probe_mod.fingerprint(url, timeout=10)
    vv = classify(fp.php_version)
    with _lock:
        assets = _load_assets()
        assets = [a for a in assets if a.get("url") != url]
        assets.append({
            "url": url,
            "group": body.group,
            "owner": body.owner,
            "note": body.note,
            "php_version": fp.php_version,
            "sapi": fp.sapi,
            "sapi_label": fp.sapi_label,
            "status": vv.status,
            "needs_action": vv.needs_action,
            "reason": vv.reason,
            "last_checked": datetime.now().isoformat(timespec="seconds"),
        })
        _save_assets(assets)
    return {"ok": True, "total": len(assets)}


@app.delete("/api/assets")
def api_del_asset(url: str) -> dict:
    with _lock:
        assets = _load_assets()
        before = len(assets)
        assets = [a for a in assets if a.get("url") != url]
        _save_assets(assets)
    return {"ok": True, "removed": before - len(assets)}


@app.post("/api/scan/url")
def api_scan_url(body: UrlScanIn) -> dict:
    url = body.url if body.url.startswith("http") else f"http://{body.url}"
    res = _new_scan("url")
    res.target_count = 1
    asm = probe_mod.assess(url, timeout=body.timeout, do_probe=body.do_probe)
    res.assets.append(asm.to_dict())
    _persist(res)
    return res.to_dict()


@app.post("/api/scan/logs")
def api_scan_logs(body: LogScanIn) -> dict:
    p = Path(body.path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"日志文件不存在: {body.path}")
    res = _new_scan("logs")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    records = list(logscan.iter_records(lines))
    res.target_count = len(records)
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    res.coverage = coverage_report(fields)
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    res.findings = [f.to_dict() for f in logscan.scan_records(records)]
    _persist(res)
    return res.to_dict()


@app.post("/api/scan/host")
def api_scan_host() -> dict:
    res = _new_scan("host")
    rep = hostcheck.run_host_check(deep=True)
    res.target_count = 1
    res.host_reports = [rep.to_dict()]
    for a in rep.artifacts:
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.kind}",
            "severity": a.severity,
            "dimension": "host",
            "cves": list(("CVE-2026-109618", "CVE-2026-109619")),
            "ts": rep.checked_at,
            "ip": rep.hostname,
            "uri": a.path,
            "evidence": a.detail,
        })
    _persist(res)
    return res.to_dict()


@app.get("/api/scans")
def api_scans() -> dict:
    out = []
    if SCANS_DIR.exists():
        for p in sorted(SCANS_DIR.glob("*.json")):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
    return {"scans": out}


@app.get("/api/scans/{scan_id}/report", response_class=PlainTextResponse)
def api_report(scan_id: str, fmt: str = "md") -> str:
    p = SCANS_DIR / f"{scan_id}.{fmt}"
    if not p.exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    if fmt == "html":
        return HTMLResponse(p.read_text(encoding="utf-8"))  # type: ignore[return-value]
    return p.read_text(encoding="utf-8")


@app.post("/api/agent/report")
def api_agent_report(body: AgentReportIn) -> dict:
    """接收 Agent 上报的主机侧检测结果。"""
    res = _new_scan("agent")
    res.target_count = 1
    data = body.data or {}
    data.setdefault("hostname", body.hostname)
    res.host_reports = [data]
    for a in data.get("artifacts", []):
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.get('kind')}",
            "severity": a.get("severity", "medium"),
            "dimension": "host",
            "cves": list(("CVE-2026-109618", "CVE-2026-109619")),
            "ts": data.get("checked_at"),
            "ip": data.get("hostname"),
            "uri": a.get("path"),
            "evidence": a.get("detail"),
        })
    _persist(res)
    return {"ok": True, "scan_id": res.scan_id}


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
_DASH = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>p2s 控制台</title>
<style>
:root{--bg:#0d0f14;--panel:#151922;--line:#222836;--fg:#e8eaed;--dim:#8b93a1;--acc:#4c8dff}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--fg)}
header{padding:18px 28px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;background:var(--panel)}
header h1{font-size:17px;margin:0;font-weight:600}
header .tag{font-size:11px;color:#0d0f14;background:#ff9f43;padding:2px 8px;border-radius:20px;font-weight:600}
header .sp{flex:1}
nav{display:flex;gap:4px;padding:0 20px;border-bottom:1px solid var(--line);background:var(--panel)}
nav button{background:none;border:none;color:var(--dim);padding:12px 16px;cursor:pointer;font-size:13px;border-bottom:2px solid transparent}
nav button.on{color:var(--fg);border-bottom-color:var(--acc)}
main{padding:24px 28px;max-width:1400px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{color:var(--dim);font-size:12px}.card .v{font-size:24px;font-weight:600;margin-top:4px}
.panel{background:var(--panel);border:1px solid varline;border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
h2{font-size:15px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:500;font-size:12px}
input,select,textarea{background:#0f1218;border:1px solid var(--line);color:var(--fg);padding:8px 10px;border-radius:6px;font-size:13px;font-family:inherit}
button.act{background:var(--acc);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
button.ghost{background:none;border:1px solid var(--line);color:var(--fg);padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px}
.risk-critical{color:#ff6b6b;font-weight:700}.risk-high{color:#ffa94d;font-weight:700}.risk-medium{color:#ffd43b}.risk-low{color:#69db7c}.risk-unknown{color:var(--dim)}
.sev-critical{color:#ff6b6b}.sev-high{color:#ffa94d}.sev-medium{color:#ffd43b}.sev-low{color:#8b93a1}.sev-info{color:#8b93a1}
pre{background:#0f1218;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;max-height:520px;font-size:12px;line-height:1.55}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.tagline{color:var(--dim);font-size:12px}
.alert{background:#1f1420;border:1px solid #4a2540;border-radius:8px;padding:12px 14px;font-size:13px;color:#e8c8e0;margin-bottom:18px}
</style></head><body>
<header><h1>p2s 控制台</h1><span class="tag">php2shell</span>
<span class="sp"></span><span class="tagline" id="clock"></span></header>
<nav>
 <button class="on" data-tab="dash">总览</button>
 <button data-tab="assets">资产台账</button>
 <button data-tab="scan">扫描</button>
 <button data-tab="host">主机侧</button>
 <button data-tab="rules">规则 / IOC</button>
</nav>
<main>
<div class="alert"><b>修复基线：</b>PHP <b>8.5.12 / 8.4.27 / 8.3.36 / 8.2.35</b>（CVE-2026-109618 / CVE-2026-109619，已被 CISA 列入 KEV）。
唯一完整修复是升级并重启全部 PHP worker。</div>

<section id="dash">
 <div class="cards">
  <div class="card"><div class="k">资产总数</div><div class="v" id="c-asset">-</div></div>
  <div class="card"><div class="k">需处置</div><div class="v risk-critical" id="c-risk">-</div></div>
  <div class="card"><div class="k">严重命中</div><div class="v sev-critical" id="c-crit">-</div></div>
  <div class="card"><div class="k">高危命中</div><div class="v sev-high" id="v-high">-</div></div>
  <div class="card"><div class="k">规则数</div><div class="v" id="c-rules">-</div></div>
 </div>
 <div class="panel"><h2>最近扫描</h2><table id="t-scans"><thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始时间</th></tr></thead><tbody></tbody></table></div>
</section>

<section id="assets" style="display:none">
 <div class="panel">
  <h2>添加资产</h2>
  <div class="row">
   <input id="a-url" placeholder="https://example.com 或 10.0.0.5" style="min-width:300px">
   <input id="a-group" placeholder="分组" value="default">
   <input id="a-owner" placeholder="负责人">
   <button class="act" onclick="addAsset()">添加并识别</button>
  </div>
  <div class="tagline">添加时会立即做一次版本指纹采集（只读）。</div>
 </div>
 <div class="panel"><h2>资产列表</h2><table id="t-assets"><thead><tr><th>URL</th><th>PHP</th><th>SAPI</th><th>状态</th><th>分组</th><th>负责人</th><th>操作</th></tr></thead><tbody></tbody></table></div>
</section>

<section id="scan" style="display:none">
 <div class="panel"><h2>主动扫描（安全探针）</h2>
  <div class="row"><input id="s-url" placeholder="https://example.com" style="min-width:320px">
  <label class="tagline"><input type="checkbox" id="s-probe" checked> 发送无害探针</label>
  <button class="act" onclick="scanUrl()">开始</button></div>
  <div class="tagline">探针只发送最小无害请求以触发可观测差异，不含任何利用载荷。</div>
 </div>
 <div class="panel"><h2>被动日志检测</h2>
  <div class="row"><input id="s-log" placeholder="日志文件绝对路径" style="min-width:320px">
  <button class="act" onclick="scanLogs()">分析</button></div>
  <div class="tagline">零风险。规则覆盖情况会在结果中标注。</div>
 </div>
 <div class="panel"><h2>结果</h2><pre id="scan-out">（尚未执行）</pre></div>
</section>

<section id="host" style="display:none">
 <div class="panel"><h2>本机主机侧检测</h2>
  <div class="row"><button class="act" onclick="hostCheck()">执行主机侧检测</button>
  <span class="tagline">检查 PHP 安装点、生效配置、可疑文件、已知样本哈希、进程与连接</span></div>
 </div>
 <div class="panel"><pre id="host-out">（尚未执行）</pre></div>
</section>

<section id="rules" style="display:none">
 <div class="panel"><h2>检测规则</h2><table id="t-rules"><thead><tr><th>ID</th><th>名称</th><th>等级</th><th>维度</th><th>需要字段</th><th>CVE</th></tr></thead><tbody></tbody></table></div>
 <div class="panel"><h2>IOC 库</h2><pre id="ioc-out">（加载中）</pre></div>
</section>
</main>
<script>
const $=(s)=>document.querySelector(s);
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');
  document.querySelectorAll('section').forEach(s=>s.style.display='none');
  $('#'+b.dataset.tab).style.display='block';
  if(b.dataset.tab==='dash')loadDash();
  if(b.dataset.tab==='assets')loadAssets();
  if(b.dataset.tab==='rules')loadRules();
});
async function api(u,o){const r=await fetch(u,o);if(!r.ok)throw new Error(r.status+' '+(await r.text()));return r.json()}
function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function loadDash(){
  const a=await api('/api/assets');const assets=a.assets||[];
  const s=await api('/api/scans');const scans=s.scans||[];
  $('#c-asset').textContent=assets.length;
  $('#c-risk').textContent=assets.filter(x=>x.needs_action).length;
  let crit=0,high=0;scans.forEach(x=>{crit+=x.severity_counts?.critical||0;high+=x.severity_counts?.high||0});
  $('#c-crit').textContent=crit;$('#v-high').textContent=high;
  const r=await api('/api/rules');$('#c-rules').textContent=r.count;
  $('#t-scans tbody').innerHTML=scans.map(x=>`<tr>
   <td><a href="#" onclick="showReport('${x.scan_id}')">${esc(x.scan_id)}</a></td>
   <td>${esc(x.kind)}</td><td class="risk-${esc(x.risk)}">${esc(x.risk).toUpperCase()}</td>
   <td>${x.target_count}</td><td class="sev-critical">${x.severity_counts?.critical||0}</td>
   <td class="sev-high">${x.severity_counts?.high||0}</td><td>${esc(x.started_at)}</td></tr>`).join('')
   ||'<tr><td colspan=7 class=tagline>暂无扫描记录</td></tr>';
}
async function showReport(id){const t=await (await fetch(`/api/scans/${id}/report?fmt=md`)).text();$('#scan-out').textContent=t;
  document.querySelector('nav button[data-tab=scan]').click();}
async function loadAssets(){
  const a=await api('/api/assets');
  $('#t-assets tbody').innerHTML=(a.assets||[]).map(x=>`<tr>
   <td>${esc(x.url)}</td><td>${esc(x.php_version||'-')}</td><td>${esc(x.sapi_label||'-')}</td>
   <td class="${x.needs_action?'risk-critical':'risk-low'}">${esc(x.status||'-')}</td>
   <td>${esc(x.group||'')}</td><td>${esc(x.owner||'')}</td>
   <td><button class="ghost" onclick="delAsset('${esc(x.url)}')">删除</button></td></tr>`).join('')
   ||'<tr><td colspan=7 class=tagline>暂无资产</td></tr>';
}
async function addAsset(){
  const u=$('#a-url').value.trim();if(!u)return;
  await api('/api/assets',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url:u,group:$('#a-group').value,owner:$('#a-owner').value})});
  $('#a-url').value='';loadAssets();}
async function delAsset(url){await api('/api/assets?url='+encodeURIComponent(url),{method:'DELETE'});loadAssets();}
async function scanUrl(){
  const u=$('#s-url').value.trim();if(!u)return;
  $('#scan-out').textContent='扫描中...';
  const r=await api('/api/scan/url',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url:u,do_probe:$('#s-probe').checked})});
  $('#scan-out').textContent=JSON.stringify(r,null,2);}
async function scanLogs(){
  const p=$('#s-log').value.trim();if(!p)return;
  $('#scan-out').textContent='分析中...';
  try{const r=await api('/api/scan/logs',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({path:p})});$('#scan-out').textContent=JSON.stringify(r,null,2);}
  catch(e){$('#scan-out').textContent='错误: '+e.message}}
async function hostCheck(){
  $('#host-out').textContent='检测中...';
  const r=await api('/api/scan/host',{method:'POST'});
  $('#host-out').textContent=JSON.stringify(r,null,2);}
async function loadRules(){
  const r=await api('/api/rules');
  $('#t-rules tbody').innerHTML=r.rules.map(x=>`<tr><td>${esc(x.id)}</td><td>${esc(x.name)}</td>
   <td class="sev-${esc(x.severity)}">${esc(x.severity)}</td><td>${esc(x.dimension)}</td>
   <td><code>${esc(x.requires)}</code></td><td>${esc((x.cves||[]).join(', '))}</td></tr>`).join('');
  const i=await api('/api/ioc');$('#ioc-out').textContent=JSON.stringify(i,null,2);}
setInterval(()=>{$('#clock').textContent=new Date().toLocaleString('zh-CN')},1000);
loadDash();
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return _DASH
