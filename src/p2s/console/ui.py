"""p2s 控制台前端（单文件，零外部依赖，内网离线可用）。

界面取向：**企业级工具**，不是营销页。
  - 无 emoji，统一使用单色线性 SVG 图标
  - 单一强调色 + 语义状态色（其余一律中性）
  - 扁平化：1px 描边分层，不用渐变、不用装饰性阴影
  - 紧凑的行距与信息密度，等宽数字
  - 所有交互走真实后端 API，无任何模拟数据
"""
from __future__ import annotations

DASHBOARD_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>p2s · php2shell 暴露面评估</title>
<style>
:root{
  --bg:#f2f3f5; --surface:#fff; --surface-2:#f7f8fa; --surface-3:#edeff2;
  --border:#dfe3e8; --border-2:#c9cfd6; --border-3:#aeb6c0;
  --text:#14181f; --text-2:#545c68; --text-3:#8a929e;
  --accent:#1f5fd0; --accent-hover:#1a52b5; --accent-soft:#eef3fc; --accent-border:#c3d5f3;
  --danger:#b42318; --danger-soft:#fdf1f0; --danger-border:#f3c9c4;
  --warn:#b54708; --warn-soft:#fdf6ec; --warn-border:#f0d5b0;
  --ok:#067647; --ok-soft:#edf8f1; --ok-border:#b9e0c8;
  --neutral:#5a6472; --neutral-soft:#f1f3f5; --neutral-border:#dde1e6;
  --r:4px; --r-lg:6px;
  --sidebar:208px; --topbar:56px;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:"Inter","Segoe UI",-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
}
[data-theme="dark"]{
  --bg:#14171c; --surface:#1a1e25; --surface-2:#20252d; --surface-3:#272d36;
  --border:#2a313b; --border-2:#39424f; --border-3:#4c5766;
  --text:#e3e7ec; --text-2:#a3abb8; --text-3:#727c8a;
  --accent:#5f96e8; --accent-hover:#7aa9ee; --accent-soft:#18243a; --accent-border:#2b3f60;
  --danger:#e8776c; --danger-soft:#2a1a19; --danger-border:#4a2c29;
  --warn:#d99a4e; --warn-soft:#2a2117; --warn-border:#4d3b23;
  --ok:#4cc38a; --ok-soft:#15281f; --ok-border:#244936;
  --neutral:#8b95a3; --neutral-soft:#232830; --neutral-border:#333b46;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:var(--sans);font-size:13.5px;line-height:1.5;color:var(--text);background:var(--bg);-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
button,input,select,textarea{font-family:inherit;font-size:inherit}
.num{font-variant-numeric:tabular-nums}
.mono{font-family:var(--mono);font-size:12px}
svg.i{width:16px;height:16px;stroke:currentColor;stroke-width:1.6;fill:none;
  stroke-linecap:round;stroke-linejoin:round;flex:0 0 16px}
svg.i.s12{width:12px;height:12px;flex:0 0 12px;stroke-width:1.8}
svg.i.s18{width:18px;height:18px;flex:0 0 18px}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:6px;border:3px solid transparent;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:var(--border-3);background-clip:content-box}

/* ---- 布局 ---- */
.app{display:flex;min-height:100vh}
.sidebar{width:var(--sidebar);flex:0 0 var(--sidebar);position:fixed;inset:0 auto 0 0;z-index:40;
  background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column}
.brand{height:var(--topbar);padding:0 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:9px}
.brand-mark{width:26px;height:26px;border-radius:var(--r);background:var(--accent);color:#fff;
  display:grid;place-items:center;font-size:10.5px;font-weight:700;letter-spacing:.3px;flex:0 0 26px}
.brand-txt b{display:block;font-size:13px;font-weight:650;line-height:1.25}
.brand-txt span{display:block;font-size:10px;color:var(--text-3);letter-spacing:.4px}
.nav{padding:10px 8px;flex:1;overflow-y:auto}
.nav-group{padding:12px 8px 5px;font-size:10px;font-weight:600;color:var(--text-3);letter-spacing:.5px}
.nav a{display:flex;align-items:center;gap:8px;padding:6.5px 8px;border-radius:var(--r);
  color:var(--text-2);font-size:13px;font-weight:450;margin-bottom:1px;transition:background .12s,color .12s}
.nav a:hover{background:var(--surface-3);color:var(--text)}
.nav a.on{background:var(--accent-soft);color:var(--accent);font-weight:550}
.nav a .cnt{margin-left:auto;font-size:10.5px;font-weight:600;padding:0 5px;border-radius:8px;
  background:var(--surface-3);color:var(--text-2);min-width:18px;text-align:center}
.nav a.on .cnt{background:var(--accent);color:#fff}
.nav a .cnt.run{background:var(--warn-soft);color:var(--warn);border:1px solid var(--warn-border)}
.side-foot{padding:10px;border-top:1px solid var(--border)}
.note-box{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r);
  padding:8px 10px;font-size:11px;color:var(--text-2);line-height:1.55}
.note-box b{display:block;color:var(--text);font-size:11.5px;margin-bottom:2px}

.main{flex:1;margin-left:var(--sidebar);min-width:0;display:flex;flex-direction:column}
.topbar{height:var(--topbar);position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:12px;
  padding:0 20px;background:var(--surface);border-bottom:1px solid var(--border)}
.topbar h1{font-size:15px;font-weight:620;letter-spacing:-.1px}
.topbar .sub{font-size:11.5px;color:var(--text-3);margin-top:1px}
.topbar .sp{flex:1}
.content{padding:20px;max-width:1500px;width:100%}

/* ---- 通用 ---- */
.page-head{display:flex;align-items:flex-start;gap:14px;margin-bottom:16px}
.page-head h2{font-size:17px;font-weight:640;letter-spacing:-.2px}
.page-head p{font-size:12.5px;color:var(--text-2);margin-top:2px}
.page-head .sp{flex:1}
.btn{display:inline-flex;align-items:center;gap:6px;padding:6px 11px;border-radius:var(--r);cursor:pointer;
  border:1px solid var(--border-2);background:var(--surface);color:var(--text);font-size:12.5px;font-weight:520;
  transition:.12s;white-space:nowrap}
.btn:hover{background:var(--surface-3);border-color:var(--border-3)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn.ghost{border-color:transparent;background:transparent;color:var(--text-2)}
.btn.ghost:hover{background:var(--surface-3);color:var(--text)}
.btn.sm{padding:3.5px 8px;font-size:11.5px}
.btn.danger{color:var(--danger);border-color:var(--danger-border)}
.btn.danger:hover{background:var(--danger-soft)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.icon-btn{width:30px;height:30px;border-radius:var(--r);border:1px solid var(--border);background:var(--surface);
  color:var(--text-2);cursor:pointer;display:grid;place-items:center;transition:.12s}
.icon-btn:hover{background:var(--surface-3);color:var(--text);border-color:var(--border-2)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);overflow:hidden}
.card-h{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:9px}
.card-h h3{font-size:12.5px;font-weight:620}
.card-h .sp{flex:1}
.card-b{padding:13px 14px}
.grid{display:grid;gap:12px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:14px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:12px 13px}
.kpi .k{font-size:11px;color:var(--text-3);font-weight:520;display:flex;align-items:center;gap:5px}
.kpi .v{font-size:24px;font-weight:650;letter-spacing:-.5px;margin-top:3px;line-height:1.15}
.kpi .v.danger{color:var(--danger)} .kpi .v.ok{color:var(--ok)} .kpi .v.warn{color:var(--warn)}
.kpi .d{font-size:11px;color:var(--text-3);margin-top:2px}
.tag{display:inline-flex;align-items:center;gap:4px;padding:1px 6px;border-radius:3px;font-size:11px;
  font-weight:560;border:1px solid transparent;white-space:nowrap;line-height:1.7}
.tag.crit{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-border)}
.tag.high{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-border)}
.tag.ok{background:var(--ok-soft);color:var(--ok);border-color:var(--ok-border)}
.tag.info{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-border)}
.tag.mute{background:var(--surface-3);color:var(--text-2);border-color:var(--border)}
.tag.solid{background:var(--accent);color:#fff;border-color:var(--accent)}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;padding:7px 12px;font-size:10.5px;font-weight:620;color:var(--text-3);
  text-transform:uppercase;letter-spacing:.4px;background:var(--surface-2);
  border-bottom:1px solid var(--border);white-space:nowrap;position:sticky;top:0;z-index:1}
td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:hover{background:var(--surface-2)}
tbody tr:last-child td{border-bottom:none}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:var(--text)}
.muted{color:var(--text-3)}
.h{font-weight:600}
.empty{text-align:center;padding:36px 16px;color:var(--text-3);font-size:12.5px}
.empty .i{width:26px;height:26px;margin:0 auto 8px;opacity:.4}
.empty b{display:block;color:var(--text-2);font-size:13px;font-weight:560;margin-bottom:3px}
.empty p{max-width:420px;margin:0 auto;line-height:1.6}
code{font-family:var(--mono);font-size:11px;background:var(--surface-3);padding:1px 4px;border-radius:3px;border:1px solid var(--border)}
pre{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r);padding:11px;overflow:auto;
  max-height:520px;font-size:11.5px;line-height:1.6;font-family:var(--mono);color:var(--text-2)}
.field{margin-bottom:10px}
.field label{display:block;font-size:11.5px;font-weight:560;color:var(--text-2);margin-bottom:4px}
input,select,textarea{width:100%;padding:6px 9px;border:1px solid var(--border-2);border-radius:var(--r);
  background:var(--surface);color:var(--text);font-size:12.5px;transition:.12s}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-soft)}
textarea{resize:vertical;min-height:76px;font-family:var(--mono);font-size:11.5px;line-height:1.6}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.row>*{flex:1;min-width:0}
.row>.f150{flex:0 0 130px}
.row>.f190{flex:0 0 170px}
.check{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-2);cursor:pointer}
.check input{width:auto;margin:0}
.seg{display:inline-flex;border:1px solid var(--border-2);border-radius:var(--r);overflow:hidden;background:var(--surface)}
.seg button{border:none;background:none;padding:5px 11px;font-size:12px;color:var(--text-2);cursor:pointer;
  border-right:1px solid var(--border);transition:.12s}
.seg button:last-child{border-right:none}
.seg button.on{background:var(--accent-soft);color:var(--accent);font-weight:600}
.hint{font-size:11.5px;color:var(--text-3);line-height:1.6}
.hint b{color:var(--text-2)}
.kv{display:grid;grid-template-columns:96px 1fr;gap:6px 10px;font-size:12px}
.kv dt{color:var(--text-3)} .kv dd{font-weight:480;word-break:break-word}
.evi{background:var(--surface-2);border:1px solid var(--border);border-left:2px solid var(--accent-border);
  border-radius:0 var(--r) var(--r) 0;padding:6px 10px;font-size:11.5px;color:var(--text-2);margin-bottom:5px;
  font-family:var(--mono);line-height:1.55;word-break:break-all}
.fixbox{background:var(--ok-soft);border:1px solid var(--ok-border);border-radius:var(--r);padding:10px 12px;font-size:12px}
.fixbox.warn{background:var(--warn-soft);border-color:var(--warn-border)}
.fixbox ul{margin:5px 0 0 15px;padding:0} .fixbox li{margin-bottom:2px}/* ---- 设备卡片 ---- */
.dev-grid{grid-template-columns:repeat(auto-fill,minmax(310px,1fr))}
.dev{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:12px 13px;
  cursor:pointer;transition:.14s}
.dev:hover{border-color:var(--border-3);background:var(--surface-2)}
.dev-top{display:flex;align-items:flex-start;gap:9px}
.dev-ico{width:28px;height:28px;border-radius:var(--r);background:var(--surface-3);color:var(--text-2);
  display:grid;place-items:center;flex:0 0 28px}
.dev h4{font-size:13px;font-weight:600;line-height:1.35}
.dev .ip{font-family:var(--mono);font-size:11px;color:var(--text-3);margin-top:1px}
.dev-meta{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.dev-foot{margin-top:9px;padding-top:8px;border-top:1px solid var(--border);display:flex;
  align-items:center;gap:6px;font-size:11px;color:var(--text-3)}
.ports{display:flex;flex-wrap:wrap;gap:3px}
.port{font-family:var(--mono);font-size:10.5px;font-weight:600;padding:0 4px;border-radius:3px;
  background:var(--surface-3);color:var(--text-2);border:1px solid var(--border);line-height:1.6}
.port.web{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-border)}
.port.php{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-border)}

/* ---- 图表 ---- */
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:1100px){.chart-row{grid-template-columns:1fr}}
.legend{display:flex;flex-direction:column;gap:5px;font-size:12px}
.legend div{display:flex;align-items:center;gap:7px}
.legend .sw{width:8px;height:8px;border-radius:2px;flex:0 0 8px}
.legend .vv{margin-left:auto;font-weight:620;font-variant-numeric:tabular-nums}
.bar-line{display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:5px}
.bar-line .nm{width:124px;flex:0 0 124px;color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-line .track{flex:1;height:6px;border-radius:3px;background:var(--surface-3);overflow:hidden}
.bar-line .fill{display:block;height:100%;background:var(--accent);border-radius:3px}
.bar-line .n{width:28px;text-align:right;font-variant-numeric:tabular-nums;font-weight:620}

/* ---- 任务中心 ---- */
.job{border:1px solid var(--border);border-radius:var(--r-lg);background:var(--surface);margin-bottom:9px;overflow:hidden}
.job-h{padding:9px 12px;display:flex;align-items:center;gap:9px;background:var(--surface-2);
  border-bottom:1px solid var(--border)}
.job-h .t{font-weight:580;font-size:12.5px}
.job-h .sp{flex:1}
.job-b{padding:10px 12px}
.pbar{height:4px;background:var(--surface-3);border-radius:3px;overflow:hidden;margin:7px 0 5px}
.pbar i{display:block;height:100%;background:var(--accent);border-radius:3px;transition:width .4s}
.pbar.run i{background:var(--accent)}
.pbar.ok i{background:var(--ok)} .pbar.err i{background:var(--danger)} .pbar.warn i{background:var(--warn)}
.job-msg{font-size:11.5px;color:var(--text-2);display:flex;align-items:center;gap:7px}
.spin{width:11px;height:11px;border:1.5px solid var(--accent-border);border-top-color:var(--accent);
  border-radius:50%;animation:spin .7s linear infinite;flex:0 0 11px}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---- 抽屉 ---- */
.drawer-bg{position:fixed;inset:0;background:rgba(16,20,26,.42);z-index:60;opacity:0;pointer-events:none;transition:.2s}
.drawer-bg.on{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(540px,94vw);z-index:61;background:var(--surface);
  transform:translateX(101%);transition:.24s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;
  border-left:1px solid var(--border)}
.drawer.on{transform:none}
.drawer-h{padding:13px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.drawer-h h3{font-size:14px;font-weight:620}
.drawer-b{padding:14px 16px;overflow-y:auto;flex:1}
.drawer-f{padding:11px 16px;border-top:1px solid var(--border);display:flex;gap:7px;align-items:center;background:var(--surface-2)}
.drawer-f .sp{flex:1}
.sect{margin-bottom:16px}
.sect-t{font-size:10.5px;font-weight:620;color:var(--text-3);text-transform:uppercase;letter-spacing:.5px;
  margin-bottom:7px;display:flex;align-items:center;gap:7px}
.sect-t::after{content:"";flex:1;height:1px;background:var(--border)}

/* ---- Toast ---- */
.toast-wrap{position:fixed;right:18px;bottom:18px;z-index:90;display:flex;flex-direction:column;gap:7px}
.toast{background:var(--surface);border:1px solid var(--border-2);border-left:2px solid var(--accent);
  border-radius:var(--r);padding:8px 12px;box-shadow:0 4px 14px rgba(16,20,26,.1);font-size:12.5px;min-width:220px;
  animation:tin .2s ease}
.toast.ok{border-left-color:var(--ok)} .toast.err{border-left-color:var(--danger)} .toast.warn{border-left-color:var(--warn)}
@keyframes tin{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
.hide{display:none!important}
.editable{border:1px solid transparent;border-radius:3px;padding:1px 4px;cursor:text;display:inline-block;min-width:40px}
.editable:hover{background:var(--surface-3);border-color:var(--border)}
.editable:focus{background:var(--surface);border-color:var(--accent);outline:none;box-shadow:0 0 0 2px var(--accent-soft)}
.dz{border:1px dashed var(--border-2);border-radius:var(--r);padding:16px;text-align:center;color:var(--text-3);
  font-size:12.5px;cursor:pointer;transition:.12s}
.dz:hover,.dz.over{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}
</style>
</head>
<body>
<svg style="display:none" xmlns="http://www.w3.org/2000/svg">
  <symbol id="i-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></symbol>
  <symbol id="i-radar" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18 6"/></symbol>
  <symbol id="i-list" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></symbol>
  <symbol id="i-alert" viewBox="0 0 24 24"><path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v5M12 17.5h.01"/></symbol>
  <symbol id="i-scan" viewBox="0 0 24 24"><path d="M3 8V5.5A2.5 2.5 0 0 1 5.5 3H8M16 3h2.5A2.5 2.5 0 0 1 21 5.5V8M21 16v2.5a2.5 2.5 0 0 1-2.5 2.5H16M8 21H5.5A2.5 2.5 0 0 1 3 18.5V16M7 12h10"/></symbol>
  <symbol id="i-server" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/></symbol>
  <symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></symbol>
  <symbol id="i-filter" viewBox="0 0 24 24"><path d="M3 5h18l-7 8v6l-4 2v-8L3 5Z"/></symbol>
  <symbol id="i-target" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r=".8"/></symbol>
  <symbol id="i-file" viewBox="0 0 24 24"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5"/></symbol>
  <symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 11a8 8 0 1 0-2.3 6.3M20 5v6h-6"/></symbol>
  <symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/></symbol>
  <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
  <symbol id="i-x" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><path d="m4 12 5 5L20 6"/></symbol>
  <symbol id="i-download" viewBox="0 0 24 24"><path d="M12 3v12M7 11l5 5 5-5M4 20h16"/></symbol>
  <symbol id="i-play" viewBox="0 0 24 24"><path d="M6 4l14 8-14 8V4Z"/></symbol>
  <symbol id="i-stop" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1.5"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17v3Z"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
  <symbol id="i-upload" viewBox="0 0 24 24"><path d="M12 16V4M7 9l5-5 5 5M4 20h16"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
  <symbol id="i-box" viewBox="0 0 24 24"><path d="M21 8 12 3 3 8v8l9 5 9-5V8Z"/><path d="m3 8 9 5 9-5M12 13v8"/></symbol>
  <symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 5 3.4 8.4 8 9.5 4.6-1.1 8-4.5 8-9.5V6l-8-3Z"/></symbol>
  <symbol id="i-boxx" viewBox="0 0 24 24"><path d="M3 7.5 12 3l9 4.5v9L12 21l-9-4.5v-9Z"/><path d="m3 7.5 9 4.5 9-4.5M12 12v9"/></symbol>
  <symbol id="i-layers" viewBox="0 0 24 24"><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5M3 17l9 5 9-5" transform="translate(0,-1)"/></symbol>
  <symbol id="i-db" viewBox="0 0 24 24"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></symbol>
  <symbol id="i-mail" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></symbol>
  <symbol id="i-net" viewBox="0 0 24 24"><rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="9" y="15" width="6" height="6" rx="1"/><path d="M6 9v3h12V9M12 12v3"/></symbol>
  <symbol id="i-terminal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></symbol>
  <symbol id="i-code" viewBox="0 0 24 24"><path d="m9 8-5 4 5 4M15 8l5 4-5 4"/></symbol>
  <symbol id="i-cloud" viewBox="0 0 24 24"><path d="M7 18a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 18 9.5 4.3 4.3 0 0 1 17.5 18H7Z"/></symbol>
  <symbol id="i-app" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/></symbol>
</svg>

<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">P2S</div>
      <div class="brand-txt"><b>php2shell</b><span>暴露面评估</span></div>
    </div>
    <nav class="nav">
      <div class="nav-group">总览</div>
      <a href="#overview" data-tab="overview" class="on"><svg class="i"><use href="#i-grid"/></svg>态势总览</a>
      <a href="#discover" data-tab="discover"><svg class="i"><use href="#i-radar"/></svg>设备发现</a>
      <a href="#tasks" data-tab="tasks"><svg class="i"><use href="#i-clock"/></svg>任务中心<span class="cnt run hide" id="nav-run"></span></a>
      <a href="#assets" data-tab="assets"><svg class="i"><use href="#i-list"/></svg>资产台账<span class="cnt hide" id="nav-assets"></span></a>
      <div class="nav-group">暴露面</div>
      <a href="#php" data-tab="php"><svg class="i"><use href="#i-alert"/></svg>PHP 暴露面<span class="cnt hide" id="nav-php"></span></a>
      <a href="#logs" data-tab="logs"><svg class="i"><use href="#i-scan"/></svg>日志分析</a>
      <a href="#host" data-tab="host"><svg class="i"><use href="#i-server"/></svg>主机侧检测</a>
      <div class="nav-group">能力</div>
      <a href="#rules" data-tab="rules"><svg class="i"><use href="#i-filter"/></svg>规则中心</a>
      <a href="#ioc" data-tab="ioc"><svg class="i"><use href="#i-target"/></svg>IOC 中心</a>
      <a href="#reports" data-tab="reports"><svg class="i"><use href="#i-file"/></svg>报告中心</a>
    </nav>
    <div class="side-foot">
      <div class="note-box">
        <b>CISA KEV 已收录</b>
        CVE-2026-109618 / 109619 存在在野利用，强制修复截止 2026-10-29。
      </div>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <div>
        <h1 id="pg-title">态势总览</h1>
        <div class="sub" id="pg-sub"></div>
      </div>
      <div class="sp"></div>
      <div class="row" style="flex:0 0 auto">
        <button class="icon-btn" id="btn-theme" title="切换深浅色"><svg class="i"><use href="#i-moon"/></svg></button>
        <button class="btn" id="btn-refresh"><svg class="i s12"><use href="#i-refresh"/></svg>刷新</button>
      </div>
    </header>
    <main class="content" id="content"></main>
  </div>
</div>

<div class="drawer-bg" id="drawer-bg"></div>
<aside class="drawer" id="drawer">
  <div class="drawer-h"><h3 id="drawer-title">详情</h3><div class="sp"></div>
    <button class="icon-btn" id="drawer-close"><svg class="i"><use href="#i-x"/></svg></button></div>
  <div class="drawer-b" id="drawer-body"></div>
  <div class="drawer-f" id="drawer-foot"></div>
</aside>
<div class="toast-wrap" id="toasts"></div>
<script>/* ==================== 基础 ==================== */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ico=(n,cls='')=>`<svg class="i ${cls}"><use href="#i-${n}"/></svg>`;
const api=async(u,o={})=>{
  const opt={headers:{'Content-Type':'application/json'},...o};
  if(o.body && !(o.body instanceof FormData)) opt.body=JSON.stringify(o.body);
  const r=await fetch(u,opt);
  if(!r.ok){let m=r.statusText;try{m=(await r.json()).detail||m}catch(e){}throw new Error(m)}
  return r.json()};
function toast(msg,kind='info'){const t=document.createElement('div');t.className='toast '+kind;t.textContent=msg;
  $('#toasts').appendChild(t);setTimeout(()=>{t.style.opacity=0;t.style.transition='.3s';setTimeout(()=>t.remove(),320)},3600)}

const RISK={critical:['crit','严重'],high:['high','高危'],medium:['high','中危'],low:['ok','低危']};
const EXP={exposed:['crit','暴露·需修复'],patched:['ok','已修复'],not_php:['mute','无 PHP'],unknown:['warn','待确认']};
const JOBS={queued:['mute','排队中'],running:['info','执行中'],done:['ok','已完成'],
            failed:['crit','失败'],cancelled:['mute','已取消']};
const tag=(cls,txt)=>`<span class="tag ${cls}">${esc(txt)}</span>`;
const DEV_ICON={firewall:'shield',bastion:'terminal',network_device:'net',mail_gateway:'mail',
  linux_host:'terminal',windows_host:'app',web_server:'globe',php_app:'code',app_server:'layers',
  cms:'file',db_tool:'db',monitoring:'grid',devops:'layers',file_service:'box',cloud:'cloud',
  container:'boxx',iot_device:'target',appliance:'box',unknown:'box'};
const SAPI_RISK={apache:'mod_php（风险最高）',fpm:'PHP-FPM',iis:'php-cgi',litespeed:'LiteSpeed',unknown:'未知 SAPI'};
const JOB_STYLE={queued:'',running:'run',done:'ok',failed:'err',cancelled:'warn'};

/* ==================== 主题 ==================== */
const savedTheme=localStorage.getItem('p2s-theme')||'light';
document.documentElement.dataset.theme=savedTheme;
function syncThemeBtn(){const d=document.documentElement.dataset.theme==='dark';
  $('#btn-theme').innerHTML=ico(d?'sun':'moon');
  $('#btn-theme').title=d?'切换到浅色':'切换到深色'}
$('#btn-theme').onclick=()=>{const n=document.documentElement.dataset.theme==='light'?'dark':'light';
  document.documentElement.dataset.theme=n;localStorage.setItem('p2s-theme',n);syncThemeBtn()};
syncThemeBtn();

/* ==================== 全局状态 & 路由 ==================== */
const PAGES={
  overview:{t:'态势总览',s:'php2shell 暴露面全局视图',fn:loadOverview},
  discover:{t:'设备发现',s:'网段 / 批量主机 → 设备类型 → PHP 暴露面',fn:loadDiscover},
  tasks:{t:'任务中心',s:'后台任务：进度、取消、历史',fn:loadTasks},
  assets:{t:'资产台账',s:'设备画像持久化 · 分组 · 责任人',fn:loadAssets},
  php:{t:'PHP 暴露面',s:'只关注真正跑 PHP 的资产',fn:loadPhp},
  logs:{t:'日志分析',s:'被动检测 · 零风险',fn:loadLogs},
  host:{t:'主机侧检测',s:'本机配置 / 痕迹 / 进程 / 连接',fn:loadHost},
  rules:{t:'规则中心',s:'检测规则 · 一键导出',fn:loadRules},
  ioc:{t:'IOC 中心',s:'在野利用指标库',fn:loadIoc},
  reports:{t:'报告中心',s:'历史扫描与交付报告',fn:loadReports},
};
const S={assets:[],jobs:[],timer:null};
async function go(tab){
  const p=PAGES[tab]; if(!p) return;
  $('#pg-title').textContent=p.t; $('#pg-sub').textContent=p.s;
  $$('.nav a').forEach(a=>a.classList.toggle('on',a.dataset.tab===tab));
  const c=$('#content'); c.innerHTML='<div class="empty">'+ico('clock')+'<b>加载中…</b></div>';
  try{await p.fn(c)}catch(e){c.innerHTML='<div class="empty">'+ico('alert')+'<b>加载失败</b><p>'+esc(e.message)+'</p></div>'}
}
$$('.nav a').forEach(a=>a.onclick=e=>{e.preventDefault();location.hash=a.dataset.tab});
$('#btn-refresh').onclick=()=>go(location.hash.slice(1)||'overview');
window.addEventListener('hashchange',()=>go(location.hash.slice(1)||'overview'));

/* 任务轮询：任何页面都能看到运行中的任务 */
async function pollJobs(){
  try{
    const r=await api('/api/jobs');
    S.jobs=r.jobs||[];
    const running=S.jobs.filter(j=>j.state==='running'||j.state==='queued').length;
    const b=$('#nav-run');
    b.classList.toggle('hide',!running); b.textContent=running;
    b.classList.toggle('run',running>0);
    const na=$('#nav-assets'); na.classList.toggle('hide',!S.assets.length); na.textContent=S.assets.length;
    if(location.hash.slice(1)==='tasks' && $('#jobs-body')) renderJobs();
    if(location.hash.slice(1)==='discover' && $('#d-jobs')){
      const before = S.jobs.map(j=>j.id+':'+j.state).join(',');
      renderDiscoverJobs();
      if(before !== S._lastJobSig){ S._lastJobSig = before; refreshDiscoverResults(); }
    }
  }catch(e){}
  S.timer=setTimeout(pollJobs,1500);
}

/* ==================== 态势总览 ==================== */
async function loadOverview(c){
  const o=await api('/api/overview');
  S.assets=(await api('/api/assets')).assets;
  const exp=[['exposed',o.exposed],['patched',o.patched],['not_php',o.not_php],['unknown',o.unknown]];
  const COL={'exposed':'var(--danger)','patched':'var(--ok)','not_php':'var(--border-3)','unknown':'var(--warn)'};
  const total=Math.max(1,exp.reduce((s,x)=>s+x[1],0));
  let acc=0;
  const arcs=exp.map(([k,v])=>{
    const a0=acc/total*2*Math.PI,a1=(acc+v)/total*2*Math.PI;acc+=v;
    if(!v) return '';
    const large=(a1-a0)>Math.PI?1:0;
    const x0=80+56*Math.sin(a0),y0=80-56*Math.cos(a0),x1=80+56*Math.sin(a1),y1=80-56*Math.cos(a1);
    const lx=80+38*Math.sin((a0+a1)/2),ly=80-38*Math.cos((a0+a1)/2);
    return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A 56 56 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}"
      fill="none" stroke="${COL[k]}" stroke-width="18"/>
      ${v>=1?`<text x="${lx.toFixed(1)}" y="${(ly+5).toFixed(1)}" text-anchor="middle" font-size="14" font-weight="620" fill="var(--text)">${v}</text>`:''}`;
  }).join('');
  const types=Object.entries(o.by_type).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxT=Math.max(1,...types.map(t=>t[1]));
  const runJobs=S.jobs.filter(j=>j.active).length;

  c.innerHTML=`
  <div class="grid kpis">
    <div class="kpi"><div class="k">${ico('box','s12')}资产总数</div><div class="v num">${o.total_assets}</div><div class="d">存活 ${o.alive} · 分组 ${o.groups.length}</div></div>
    <div class="kpi"><div class="k">${ico('code','s12')}存在 PHP</div><div class="v num">${o.php_present}</div><div class="d">未修复 <b>${o.exposed}</b></div></div>
    <div class="kpi"><div class="k">${ico('alert','s12')}暴露待修复</div><div class="v num ${o.exposed?'danger':''}">${o.exposed}</div><div class="d">版本低于修复基线</div></div>
    <div class="kpi"><div class="k">${ico('check','s12')}PHP 已修复</div><div class="v num ok">${o.patched}</div><div class="d">已达基线版本</div></div>
    <div class="kpi"><div class="k">${ico('shield','s12')}不含 PHP</div><div class="v num">${o.not_php}</div><div class="d">与本漏洞无关</div></div>
    <div class="kpi"><div class="k">${ico('clock','s12')}运行中任务</div><div class="v num">${runJobs}</div><div class="d">历史 ${o.scan_count} 次扫描</div></div>
  </div>

  <div class="chart-row">
    <div class="card">
      <div class="card-h"><h3>PHP 暴露面构成</h3><div class="sp"></div><span class="muted" style="font-size:11.5px">共 ${o.total_assets} 台</span></div>
      <div class="card-b" style="display:flex;gap:22px;align-items:center;flex-wrap:wrap">
        <svg viewBox="0 0 160 160" width="160" height="160" style="flex:0 0 160px">
          <circle cx="80" cy="80" r="56" fill="none" stroke="var(--surface-3)" stroke-width="18"/>
          ${arcs}
          <text x="80" y="76" text-anchor="middle" font-size="10.5" fill="var(--text-3)">暴露</text>
          <text x="80" y="96" text-anchor="middle" font-size="20" font-weight="650" fill="var(--text)">${o.exposed}</text>
        </svg>
        <div class="legend" style="flex:1;min-width:140px">
          ${exp.map(([k,v])=>`<div><span class="sw" style="background:${COL[k]}"></span>${esc(EXP[k][1])}<span class="vv num">${v}</span></div>`).join('')}
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-h"><h3>设备类型分布</h3><div class="sp"></div>
        <button class="btn sm ghost" onclick="location.hash='discover'">设备发现 ${ico('x','s12')}</button></div>
      <div class="card-b">
        ${types.length?types.map(([k,v])=>`<div class="bar-line">
            <span class="nm" title="${esc(k)}">${esc(k)}</span>
            <span class="track"><i class="fill" style="width:${(v/maxT*100).toFixed(1)}%"></i></span>
            <span class="n num">${v}</span></div>`).join('')
          :'<div class="empty">'+ico('radar')+'<b>还没有资产</b><p>去「设备发现」跑一次网段扫描</p></div>'}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-h"><h3>最近扫描</h3><div class="sp"></div>
      <button class="btn sm ghost" onclick="location.hash='reports'">全部报告 ${ico('x','s12')}</button></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始时间</th><th></th></tr></thead>
      <tbody>${(o.recent_scans||[]).map(s=>`<tr>
        <td class="mono">${esc(s.scan_id)}</td><td>${esc(s.kind)}</td>
        <td>${tag((RISK[s.risk]||['mute','未知'])[0],(RISK[s.risk]||['mute','未知'])[1])}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td>
        <td class="num">${s.severity_counts?.high||0}</td>
        <td class="muted num" style="font-size:11.5px">${esc(s.started_at)}</td>
        <td style="text-align:right"><button class="btn sm" onclick="viewReport('${esc(s.scan_id)}')">查看</button></td>
      </tr>`).join('')||'<tr><td colspan="8"><div class="empty">'+ico('clock')+'<b>暂无扫描记录</b></div></td></tr>'}</tbody>
    </table></div>
  </div>`;
}/* ==================== 设备发现 ==================== */
async function loadDiscover(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>设备发现</h2><p>逐台完成 端口 → 服务 → 设备类型 → PHP 暴露面 四层收敛。扫描在后台执行，可随时切页或取消。</p></div></div>
  <div class="card" style="margin-bottom:14px">
    <div class="card-h"><h3>扫描目标</h3><div class="sp"></div>
      <div class="seg" id="d-mode">
        <button class="on" data-m="quick">快速</button><button data-m="deep">深度</button></div></div>
    <div class="card-b">
      <div class="row">
        <div class="f190"><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">网段 CIDR</label>
          <input id="d-cidr" placeholder="192.168.1.0/24"></div>
        <div><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">主机列表（每行一个）</label>
          <input id="d-hosts" placeholder="192.168.1.229, 192.168.1.188"></div>
        <div class="f150"><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">分组</label>
          <input id="d-group" value="default"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <label class="check" style="flex:0 0 auto"><input type="checkbox" id="d-save" checked>保存到台账</label>
        <div class="f150"><input id="d-timeout" type="number" value="1.2" step="0.1" title="TCP 超时(秒)"></div>
        <div class="f150"><input id="d-htimeout" type="number" value="8" step="1" title="HTTP 超时(秒)"></div>
        <button class="btn primary" id="d-run" style="flex:0 0 auto">${ico('play','s12')}开始扫描</button>
      </div>
      <div class="hint" style="margin-top:8px" id="d-est"></div>
      <div id="d-jobs" style="margin-top:12px"></div>
    </div>
  </div>
  <div class="grid dev-grid" id="d-results"></div>`;

  let mode='quick';
  $$('#d-mode button').forEach(b=>b.onclick=()=>{$$('#d-mode button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');mode=b.dataset.m;updateEst()});
  const countTargets=()=>{
    const hosts=$('#d-hosts').value.split(/[\s,;]+/).filter(Boolean);
    const cidr=$('#d-cidr').value.trim();
    let n=hosts.length;
    if(cidr){const m=cidr.match(/^(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
      if(m){const size=2**(32-parseInt(m[4]));n+=Math.max(0,size-2)}}
    return n;
  };
  const updateEst=()=>{
    const n=countTargets();
    const per=mode==='quick'?1.6:2.5;
    $('#d-est').innerHTML=n?`预计 <b>${n}</b> 台目标 · 快速模式约 <b>${Math.max(1,Math.round(n*per/60))}</b> 分钟（快速仅探测 20 个常见端口与 SSH banner；深度探测 110+ 端口、HTTP 指纹与 TLS 证书）`:'填写网段或主机列表后开始';
  };
  updateEst();
  ['#d-hosts','#d-cidr'].forEach(s=>$(s).addEventListener('input',updateEst));

  $('#d-run').onclick=async()=>{
    const hosts=$('#d-hosts').value.split(/[\s,;]+/).map(x=>x.trim()).filter(Boolean);
    const cidr=$('#d-cidr').value.trim();
    if(!hosts.length&&!cidr){toast('请填写网段或主机列表','warn');return}
    const btn=$('#d-run'); btn.disabled=true;
    try{
      const job=await api('/api/jobs',{method:'POST',body:{kind:'discover',hosts,cidr,
        group:$('#d-group').value||'default',quick:mode==='quick',
        timeout:parseFloat($('#d-timeout').value)||1.2,
        http_timeout:parseFloat($('#d-htimeout').value)||8,
        save:$('#d-save').checked}});
      toast('任务已提交：'+job.id,'ok');
      S.jobs.unshift(job); renderDiscoverJobs();
      $('#d-cidr').value='';
    }catch(e){toast('提交失败: '+e.message,'err')}
    finally{btn.disabled=false}
  };
  await refreshDiscoverResults();
  renderDiscoverJobs();
}

async function refreshDiscoverResults(){
  S.assets=(await api('/api/assets')).assets;
  const box=$('#d-results'); if(!box) return;
  const running=S.jobs.filter(j=>j.kind==='discover'&&(j.state==='running'||j.state==='queued')).length;
  const latest=S.jobs.find(j=>j.kind==='discover'&&j.state==='done'&&j.result&&j.result.assets);
  const label=running?`扫描进行中（${running} 个任务）`:
    (latest?`最近一次扫描结果 · ${latest.id}`:'台账中的设备');
  box.innerHTML=`<div style="grid-column:1/-1;display:flex;align-items:center;gap:9px;margin-bottom:2px">
      <span style="font-size:12.5px;font-weight:600">${esc(label)}</span>
      <span class="muted" style="font-size:11.5px">共 ${S.assets.length} 台</span></div>`+
    (latest?`<div style="grid-column:1/-1" class="hint">下方为本次扫描识别到的设备；台账完整列表见「资产台账」。</div>`:'');
  renderDevices(box,S.assets);
}

function renderDiscoverJobs(){
  const box=$('#d-jobs'); if(!box) return;
  const list=S.jobs.filter(j=>j.kind==='discover').slice(0,4);
  if(!list.length){box.innerHTML='';return}
  box.innerHTML=list.map(j=>jobRow(j)).join('');
}
function jobRow(j){
  const st=JOBS[j.state]||['mute',j.state];
  const pct=Math.round((j.progress||0)*100);
  const active=j.state==='running'||j.state==='queued';
  return `<div class="job">
    <div class="job-h">
      ${active?'<span class="spin"></span>':ico(j.state==='done'?'check':j.state==='failed'?'x':'stop','s12')}
      <span class="t">${esc(j.title)}</span>
      <span class="muted mono" style="font-size:11px">${esc(j.id)}</span>
      <div class="sp"></div>
      ${tag(st[0],st[1])}
      ${active?`<button class="btn sm" onclick="cancelJob('${esc(j.id)}')">${ico('stop','s12')}取消</button>`:''}
    </div>
    <div class="job-b">
      <div class="pbar ${JOB_STYLE[j.state]||''}"><i style="width:${pct}%"></i></div>
      <div class="job-msg">
        ${active?`<span class="num">${j.done||0}/${j.total||0}</span>`:`<span class="num">${pct}%</span>`}
        <span>${esc(j.message||j.error||'')}</span>
      </div>
    </div></div>`;
}

async function cancelJob(id){
  try{await api(`/api/jobs/${id}/cancel`,{method:'POST'});toast('已请求取消','warn')}
  catch(e){toast('取消失败: '+e.message,'err')}
}

function renderDevices(box,assets){
  if(!assets||!assets.length){box.innerHTML='<div class="empty" style="grid-column:1/-1">'+ico('radar')+
    '<b>暂无设备</b><p>输入网段或主机列表后点击「开始扫描」</p></div>';return}
  box.innerHTML=assets.map(a=>{
    const exp=EXP[a.exposure]||['mute',a.exposure||'未知'];
    const phpPorts=(a.services||[]).filter(s=>s.php_hint).map(s=>s.port);
    return `<div class="dev" onclick="openAsset('${esc(a.host)}')">
      <div class="dev-top">
        <div class="dev-ico">${ico(DEV_ICON[a.device_type]||'box')}</div>
        <div style="min-width:0;flex:1">
          <h4>${esc(a.device_label||'未识别设备')}</h4>
          <div class="ip">${esc(a.host)}</div>
        </div>
        ${tag(exp[0],exp[1])}
      </div>
      <div class="dev-meta">
        ${a.vendor?tag('info',a.vendor):''}
        ${a.os_hint?tag('mute',a.os_hint):''}
        ${a.php_version?tag('crit','PHP '+esc(a.php_version)):a.php_present?tag('warn','PHP 版本未知'):''}
        ${a.sapi?tag('mute',SAPI_RISK[a.sapi]||a.sapi):''}
      </div>
      <div class="ports" style="margin-top:8px">
        ${(a.open_ports||[]).slice(0,20).map(p=>`<span class="port ${phpPorts.includes(p)?'php':(/^(80|443|8080|8443|2000|8888|10000)$/.test(p)?'web':'')}">${p}</span>`).join('')}
        ${(a.open_ports||[]).length>20?`<span class="port">+${a.open_ports.length-20}</span>`:''}
      </div>
      <div class="dev-foot">
        <span>置信度 ${((a.confidence||0)*100).toFixed(0)}%</span><span>·</span>
        <span>${(a.evidence||[]).length} 条证据</span><span style="margin-left:auto">详情</span>
      </div>
    </div>`;
  }).join('');
}

/* ==================== 任务中心 ==================== */
async function loadTasks(c){
  const r=await api('/api/jobs'); S.jobs=r.jobs||[];
  c.innerHTML=`
  <div class="page-head"><div><h2>任务中心</h2><p>后台任务状态持久化到 p2s-data/jobs.json，控制台重启后历史仍在</p></div>
    <div class="sp"></div><button class="btn" id="t-refresh">${ico('refresh','s12')}刷新</button></div>
  <div id="jobs-body"></div>`;
  $('#t-refresh').onclick=()=>loadTasks($('#content'));
  renderJobs();
}
function renderJobs(){
  const box=$('#jobs-body'); if(!box) return;
  if(!S.jobs.length){box.innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('clock')+
    '<b>还没有任务</b><p>去「设备发现」提交第一个扫描任务</p></div></div></div>';return}
  const active=S.jobs.filter(j=>j.state==='running'||j.state==='queued');
  const hist=S.jobs.filter(j=>!(j.state==='running'||j.state==='queued'));
  box.innerHTML=
    (active.length?`<div class="sect-t">运行中（${active.length}）</div>`+active.map(j=>jobRow(j)).join(''):'')+
    (hist.length?`<div class="sect-t" style="margin-top:16px">历史（${hist.length}）</div>`+hist.map(j=>`
      <div class="job">
        <div class="job-h">
          ${ico(j.state==='done'?'check':j.state==='failed'?'x':'stop','s12')}
          <span class="t">${esc(j.title)}</span>
          <span class="muted mono" style="font-size:11px">${esc(j.id)}</span>
          <div class="sp"></div>
          ${tag((JOBS[j.state]||['mute',j.state])[0],(JOBS[j.state]||['mute',j.state])[1])}
          <button class="btn sm" onclick="deleteJob('${esc(j.id)}')">${ico('trash','s12')}删除</button>
        </div>
        <div class="job-b">
          <div class="pbar ${JOB_STYLE[j.state]||''}"><i style="width:${Math.round((j.progress||0)*100)}%"></i></div>
          <div class="job-msg">
            <span class="num">${j.done||0}/${j.total||0}</span>
            <span>${esc(j.message||j.error||'')}</span>
            ${j.finished_at?`<span class="muted" style="margin-left:auto">${esc(j.finished_at)}</span>`:''}
          </div>
          ${j.error?`<div class="evi" style="margin-top:6px;border-left-color:var(--danger-border)">${esc(j.error)}</div>`:''}
        </div>
      </div>`).join(''):'');
}
async function deleteJob(id){
  try{await api('/api/jobs/'+id,{method:'DELETE'});toast('已删除','ok');
    S.jobs=S.jobs.filter(j=>j.id!==id);renderJobs()}
  catch(e){toast('删除失败: '+e.message,'err')}
}/* ==================== 资产台账 ==================== */
async function loadAssets(c){
  const a=(await api('/api/assets')).assets; S.assets=a;
  c.innerHTML=`
  <div class="page-head"><div><h2>资产台账</h2><p>共 ${a.length} 台设备</p></div><div class="sp"></div>
    <button class="btn" id="a-import">${ico('upload','s12')}批量导入</button>
    <button class="btn" id="a-export">${ico('download','s12')}导出 CSV</button>
    <button class="btn primary" onclick="location.hash='discover'">${ico('plus','s12')}发现设备</button></div>
  <div id="import-box" class="card hide" style="margin-bottom:12px">
    <div class="card-h"><h3>批量导入主机</h3><div class="sp"></div>
      <button class="icon-btn" id="import-close"><svg class="i"><use href="#i-x"/></svg></button></div>
    <div class="card-b">
      <div class="field"><label>主机列表（每行一个，支持逗号分隔）</label>
        <textarea id="imp-text" placeholder="192.168.1.229&#10;192.168.1.188&#10;10.0.0.0/28"></textarea></div>
      <div class="row">
        <div class="f190"><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">分组</label>
          <input id="imp-group" value="default"></div>
        <button class="btn primary" id="imp-run" style="flex:0 0 auto">${ico('play','s12')}导入并扫描</button>
      </div>
      <div class="hint" style="margin-top:7px">导入会为每个目标发起一次发现任务（快速模式）。网段会展开为具体主机，最多 1024 台。</div>
    </div>
  </div>
  <div class="card">
    <div class="card-h">
      <div class="seg" id="a-filter">
        <button class="on" data-f="all">全部</button><button data-f="exposed">暴露</button>
        <button data-f="patched">已修复</button><button data-f="not_php">无 PHP</button><button data-f="unknown">待确认</button></div>
      <div class="sp"></div>
      <input id="a-search" placeholder="搜索 IP / 厂商 / 设备类型" style="max-width:230px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>设备类型</th><th>厂商</th><th>PHP</th><th>SAPI</th><th>暴露面</th><th>风险</th>
        <th>分组</th><th>负责人</th><th></th></tr></thead>
      <tbody id="a-body"></tbody>
    </table></div>
  </div>`;

  $('#a-import').onclick=()=>$('#import-box').classList.toggle('hide');
  $('#import-close').onclick=()=>$('#import-box').classList.add('hide');
  $('#imp-run').onclick=async()=>{
    const text=$('#imp-text').value.trim();
    if(!text){toast('请填写主机列表','warn');return}
    const hosts=[],cidrs=[];
    text.split(/[\s,;]+/).filter(Boolean).forEach(x=>{
      if(x.includes('/')) cidrList_push(cidrs,x); else hosts.push(x);
    });
    const group=$('#imp-group').value||'default';
    const btn=$('#imp-run'); btn.disabled=true;
    try{
      if(hosts.length){
        const j=await api('/api/jobs',{method:'POST',body:{kind:'discover',hosts,group,quick:true,save:true}});
        toast('已提交导入任务 '+j.id,'ok');
      }
      for(const c of cidrList_unique(cidrs)){
        const j=await api('/api/jobs',{method:'POST',body:{kind:'discover',cidr:c,group,quick:true,save:true}});
        toast('已提交网段任务 '+j.id,'ok');
      }
      $('#imp-text').value=''; $('#import-box').classList.add('hide');
    }catch(e){toast('导入失败: '+e.message,'err')}
    finally{btn.disabled=false}
  };
  function cidrList_push(arr,v){arr.push(v)}
  function cidrList_unique(arr){return [...new Set(arr)]}

  const draw=()=>{
    const f=$('#a-filter .on').dataset.f, q=$('#a-search').value.trim().toLowerCase();
    const rows=a.filter(x=>{
      if(f==='exposed'&&x.exposure!=='exposed')return false;
      if(f==='patched'&&x.exposure!=='patched')return false;
      if(f==='not_php'&&x.exposure!=='not_php')return false;
      if(f==='unknown'&&x.exposure!=='unknown')return false;
      if(q&&!((x.host||'')+(x.device_label||'')+(x.vendor||'')+(x.php_version||'')).toLowerCase().includes(q))return false;
      return true;
    });
    $('#a-body').innerHTML=rows.map(x=>`<tr>
      <td class="mono h">${esc(x.host)}</td>
      <td>${ico(DEV_ICON[x.device_type]||'box','s12')} ${esc(x.device_label||'-')}</td>
      <td>${x.vendor?esc(x.vendor):'<span class="muted">-</span>'}</td>
      <td class="num">${x.php_version?'<b>'+esc(x.php_version)+'</b>':(x.php_present?tag('warn','未知'):'<span class="muted">无</span>')}</td>
      <td style="font-size:11.5px">${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'<span class="muted">-</span>'}</td>
      <td>${tag((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
      <td>${tag((RISK[x.risk]||['mute','?'])[0],(RISK[x.risk]||['mute','?'])[1])}</td>
      <td><span class="editable" contenteditable="true" data-k="group" data-h="${esc(x.host)}">${esc(x.group||'')}</span></td>
      <td><span class="editable" contenteditable="true" data-k="owner" data-h="${esc(x.host)}">${esc(x.owner||'')}</span></td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn sm" onclick="event.stopPropagation();openAsset('${esc(x.host)}')">详情</button>
        <button class="btn sm ghost" onclick="event.stopPropagation();rescan('${esc(x.host)}')">复扫</button></td></tr>`).join('')
      ||'<tr><td colspan="10"><div class="empty">'+ico('list')+'<b>没有匹配的资产</b></div></td></tr>';
    $$('#a-body .editable').forEach(el=>{
      el.onblur=async()=>{
        const host=el.dataset.h,k=el.dataset.k,v=el.textContent.trim();
        const orig=a.find(y=>y.host===host); if(!orig||orig[k]===v) return;
        try{await api('/api/assets',{method:'PATCH',body:{host,[k]:v}});orig[k]=v;toast('已保存','ok')}
        catch(err){el.textContent=orig[k]||'';toast('保存失败: '+err.message,'err')}
      };
    });
  };
  $$('#a-filter button').forEach(b=>b.onclick=()=>{$$('#a-filter button').forEach(x=>x.classList.remove('on'));
    b.classList.add('on');draw()});
  $('#a-search').oninput=draw; draw();
  $('#a-export').onclick=()=>{window.location='/api/assets/export'};
}

/* ==================== 抽屉：资产详情 ==================== */
async function openAsset(host){
  let x=S.assets.find(y=>y.host===host);
  if(!x){S.assets=(await api('/api/assets')).assets;x=S.assets.find(y=>y.host===host)}
  if(!x){toast('未找到资产','err');return}
  $('#drawer-title').textContent=x.host;
  const exp=EXP[x.exposure]||['mute','未知'];
  const svc=(x.services||[]).filter(s=>s.http_status||s.banner||s.tls_subject);
  $('#drawer-body').innerHTML=`
    <div class="sect">
      <div class="sect-t">设备画像</div>
      <div class="row" style="margin-bottom:9px">
        ${tag(exp[0],exp[1])} ${tag((RISK[x.risk]||['mute','?'])[0],(RISK[x.risk]||['mute','?'])[1])}
        ${x.vendor?tag('info',x.vendor):''} ${x.os_hint?tag('mute',x.os_hint):''}</div>
      <dl class="kv">
        <dt>设备类型</dt><dd>${ico(DEV_ICON[x.device_type]||'box','s12')} ${esc(x.device_label||'-')}</dd>
        <dt>置信度</dt><dd class="num">${((x.confidence||0)*100).toFixed(0)}%</dd>
        <dt>PHP</dt><dd>${x.php_version?'<b>PHP '+esc(x.php_version)+'</b>':(x.php_present?'存在但版本未知':'未检测到')}</dd>
        <dt>SAPI</dt><dd>${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</dd>
        <dt>开放端口</dt><dd><div class="ports">${(x.open_ports||[]).map(p=>`<span class="port">${p}</span>`).join('')||'-'}</div></dd>
        <dt>分组 / 负责人</dt><dd>${esc(x.group||'-')} / ${esc(x.owner||'-')}</dd>
        <dt>最后检测</dt><dd class="num muted">${esc(x.last_checked||'-')}</dd></dl>
    </div>
    ${(x.remediation||[]).length?`<div class="sect"><div class="sect-t">处置建议</div>
      <div class="fixbox ${x.exposure==='exposed'?'warn':''}">
        <b>${x.exposure==='exposed'?'需立即处置':'说明'}</b>
        <ul>${(x.remediation||[]).map(r=>`<li>${esc(r)}</li>`).join('')}</ul></div></div>`:''}
    ${svc.length?`<div class="sect"><div class="sect-t">服务明细</div>
      <div class="tbl-wrap"><table><thead><tr><th>端口</th><th>协议</th><th>状态</th><th>Server</th><th>标题 / 证书</th></tr></thead>
      <tbody>${svc.map(s=>`<tr><td class="num">${s.port}</td><td style="font-size:11.5px">${esc(s.proto||'-')}</td>
        <td class="num">${s.http_status||'-'}</td><td style="font-size:11.5px">${esc(s.server||'-')}</td>
        <td style="font-size:11.5px">${esc(s.http_title||s.tls_subject||s.banner||'-')}</td></tr>`).join('')}</tbody></table></div></div>`:''}
    <div class="sect"><div class="sect-t">判定证据（${(x.evidence||[]).length}）</div>
      ${(x.evidence||[]).map(e=>`<div class="evi">${esc(e)}</div>`).join('')||'<div class="muted" style="font-size:12px">无</div>'}</div>
    ${(x.errors||[]).length?`<div class="sect"><div class="sect-t">错误</div>
      ${(x.errors||[]).map(e=>`<div class="evi" style="border-left-color:var(--danger-border)">${esc(e)}</div>`).join('')}</div>`:''}`;
  $('#drawer-foot').innerHTML=`
    <button class="btn" onclick="rescan('${esc(x.host)}')">${ico('refresh','s12')}重新检测</button>
    <button class="btn danger" onclick="delAsset('${esc(x.host)}')">${ico('trash','s12')}移出台账</button>
    <div class="sp"></div><button class="btn primary" onclick="closeDrawer()">关闭</button>`;
  $('#drawer').classList.add('on');$('#drawer-bg').classList.add('on');
}
function closeDrawer(){$('#drawer').classList.remove('on');$('#drawer-bg').classList.remove('on')}
$('#drawer-close').onclick=closeDrawer;$('#drawer-bg').onclick=closeDrawer;
async function rescan(host){
  try{
    const j=await api('/api/jobs',{method:'POST',body:{kind:'discover',hosts:[host],group:'default',quick:false,save:true}});
    toast('复扫任务已提交 '+j.id,'ok');closeDrawer();
  }catch(e){toast('复扫失败: '+e.message,'err')}
}
async function delAsset(host){
  if(!confirm('将 '+host+' 移出台账？')) return;
  try{await api('/api/assets?host='+encodeURIComponent(host),{method:'DELETE'});
    toast('已移除','ok');closeDrawer();S.assets=S.assets.filter(a=>a.host!==host);go(location.hash.slice(1)||'overview')}
  catch(e){toast('删除失败: '+e.message,'err')}
}

/* ==================== PHP 暴露面 ==================== */
async function loadPhp(c){
  const r=await api('/api/php-exposure');
  c.innerHTML=`
  <div class="page-head"><div><h2>PHP 暴露面</h2><p>只列出真正跑 PHP 的资产 —— 其它设备与本漏洞无关，不必处置</p></div>
    <div class="sp"></div>
    <button class="btn" onclick="window.location='/api/php-exposure/export'">${ico('download','s12')}导出 CSV</button></div>
  <div class="grid kpis">
    <div class="kpi"><div class="k">${ico('alert','s12')}暴露</div><div class="v num danger">${r.rows.filter(x=>x.exposure==='exposed').length}</div><div class="d">版本低于基线</div></div>
    <div class="kpi"><div class="k">${ico('check','s12')}已修复</div><div class="v num ok">${r.rows.filter(x=>x.exposure==='patched').length}</div><div class="d">已达基线</div></div>
    <div class="kpi"><div class="k">${ico('alert','s12')}待确认</div><div class="v num warn">${r.rows.filter(x=>x.exposure==='unknown').length}</div><div class="d">有 PHP 迹象无版本</div></div>
    <div class="kpi"><div class="k">${ico('code','s12')}PHP 资产</div><div class="v num">${r.rows.length}</div><div class="d">总��</div></div>
  </div>
  <div class="card">
    <div class="card-h"><h3>受影响资产明细</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">修复基线 ${Object.values(r.fixed_releases).join(' / ')}</span></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>设备</th><th>PHP 版本</th><th>SAPI</th><th>修复基线</th><th>状态</th><th>判定说明</th><th>负责人</th></tr></thead>
      <tbody>${r.rows.map(x=>`<tr>
        <td class="mono h">${esc(x.host)}</td>
        <td>${esc(x.device_label||'-')}</td>
        <td class="num"><b>${esc(x.php_version||'?')}</b></td>
        <td style="font-size:11.5px">${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</td>
        <td class="num muted">${esc(x.fixed_release||'-')}</td>
        <td>${tag((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
        <td class="muted" style="font-size:11.5px">${esc(x.reason||'')}</td>
        <td>${esc(x.owner||'-')}</td></tr>`).join('')
        ||'<tr><td colspan="8"><div class="empty">'+ico('code')+'<b>没有跑 PHP 的资产</b><p>所有已发现设备均与 php2shell 无关</p></div></td></tr>'}
      </tbody></table></div>
  </div>`;
}

/* ==================== 日志分析 ==================== */
async function loadLogs(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>日志分析</h2><p>被动检测，零风险 · 支持 CLF / JSON / KV 三种格式自动识别</p></div></div>
  <div class="card" style="margin-bottom:12px">
    <div class="card-h"><h3>日志来源</h3></div>
    <div class="card-b">
      <div class="row" style="margin-bottom:10px">
        <input id="l-path" placeholder="服务器上的日志绝对路径，例如 /var/log/nginx/access.log">
        <button class="btn" id="l-run" style="flex:0 0 auto">${ico('play','s12')}分析</button>
      </div>
      <div class="dz" id="l-drop">${ico('upload')} 点击选择或拖入日志文件（上传到服务端后分析）</div>
      <input type="file" id="l-file" class="hide" accept=".log,.txt,.json,.csv,*">
      <div class="hint" style="margin-top:8px">
        标准访问日志<b>不记录请求体</b>，因此 <code>PHP_SESSION_UPLOAD_PROGRESS</code> 类规则需要开启请求体落盘
        （WAF 日志 / <code>$request_body</code>）才能覆盖。报告会明确标出覆盖缺口。</div>
    </div>
  </div>
  <div id="l-out"></div>`;

  $('#l-run').onclick=async()=>{
    const p=$('#l-path').value.trim();
    if(!p){toast('请填写日志路径','warn');return}
    $('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('clock')+'<b>分析中…</b></div></div></div>';
    try{const r=await api('/api/jobs',{method:'POST',body:{kind:'logs',path:p}});
      toast('任务已提交 '+r.id,'ok');watchJob(r.id,'logs')}
    catch(e){$('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<p>'+esc(e.message)+'</p></div></div></div>'}
  };
  const dz=$('#l-drop'),fi=$('#l-file');
  dz.onclick=()=>fi.click();
  dz.ondragover=e=>{e.preventDefault();dz.classList.add('over')};
  dz.ondragleave=()=>dz.classList.remove('over');
  dz.ondrop=e=>{e.preventDefault();dz.classList.remove('over');if(e.dataTransfer.files[0])uploadFile(e.dataTransfer.files[0])};
  fi.onchange=()=>{if(fi.files[0])uploadFile(fi.files[0])};
  async function uploadFile(file){
    $('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('clock')+'<b>上传并分析中…</b></div></div></div>';
    const fd=new FormData(); fd.append('file',file);
    try{const r=await api('/api/scan/logs/upload',{method:'POST',body:fd});
      renderLog(r)}
    catch(e){$('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<p>'+esc(e.message)+'</p></div></div></div>'}
  }
  if(S.lastLog) renderLog(S.lastLog);
}
async function watchJob(id,kind){
  const t=setInterval(async()=>{
    try{
      const j=await api('/api/jobs/'+id);
      if(j.state==='done'){clearInterval(t);
        if(kind==='logs'){S.lastLog=j.result;renderLog(j.result)}}
      else if(j.state==='failed'){clearInterval(t);
        $('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<b>分析失败</b><p>'+esc(j.error||'')+'</p></div></div></div>'}
    }catch(e){clearInterval(t)}
  },1200);
}
function renderLog(r){
  const cov=r.coverage||{};
  $('#l-out').innerHTML=`
  <div class="grid kpis">
    <div class="kpi"><div class="k">总体风险</div><div class="v ${r.risk==='critical'?'danger':''}" style="font-size:18px">${esc((r.risk||'').toUpperCase())}</div><div class="d">${r.findings.length} 条命中</div></div>
    <div class="kpi"><div class="k">严重</div><div class="v num danger">${r.severity_counts?.critical||0}</div></div>
    <div class="kpi"><div class="k">高危</div><div class="v num warn">${r.severity_counts?.high||0}</div></div>
    <div class="kpi"><div class="k">解析记录</div><div class="v num">${cov.parsed_records||0}</div><div class="d">共 ${cov.total_lines||0} 行</div></div>
    <div class="kpi"><div class="k">规则覆盖缺口</div><div class="v num ${(cov.uncovered||[]).length?'warn':'ok'}">${(cov.uncovered||[]).length}</div><div class="d">条规则无法命中</div></div>
  </div>
  <div class="card">
    <div class="card-h"><h3>命中明细</h3><div class="sp"></div>
      <button class="btn sm" onclick="viewReport('${esc(r.scan_id)}')">${ico('file','s12')}查看报告</button></div>
    <div class="tbl-wrap"><table><thead><tr><th>规则</th><th>名称</th><th>等级</th><th>维度</th><th>时间</th><th>来源 IP</th><th>URI</th><th>证据</th></tr></thead>
      <tbody>${(r.findings||[]).map(f=>`<tr>
        <td class="mono">${esc(f.rule_id)}</td><td style="font-size:12px">${esc(f.rule_name)}</td>
        <td>${tag((RISK[f.severity]||['mute',f.severity])[0],(RISK[f.severity]||['mute',f.severity])[1])}</td>
        <td class="muted" style="font-size:11.5px">${esc(f.dimension)}</td>
        <td class="muted num" style="font-size:11.5px">${esc((f.ts||'').replace('T',' ').slice(0,19))}</td>
        <td class="mono">${esc(f.ip||'-')}</td>
        <td style="font-size:11.5px">${esc((f.uri||'-').slice(0,44))}</td>
        <td class="muted" style="font-size:11.5px">${esc(f.evidence||'')}</td></tr>`).join('')
        ||'<tr><td colspan="8"><div class="empty">'+ico('check')+'<b>未发现异常</b></div></td></tr>'}</tbody></table></div>
  </div>
  ${(cov.uncovered||[]).length?`<div class="card" style="margin-top:12px">
    <div class="card-h"><h3>覆盖缺口</h3><div class="sp"></div>${tag('warn','需开启请求体/响应体落盘')}</div>
    <div class="card-b"><div class="row">${cov.uncovered.map(r=>tag('mute',r)).join('')}</div>
    <div class="hint" style="margin-top:8px">这些规则依赖请求体或响应体字段，普通访问日志不含这些内容，因此无法命中。建议在 WAF 或反代层开启请求体记录。</div></div></div>`:''}`;
}/* ==================== 主机侧检测 ==================== */
async function loadHost(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>主机侧检测</h2><p>读取本机 PHP 安装点、生效配置、可疑文件、进程与连接 —— 全部只读</p></div>
    <div class="sp"></div>
    <button class="btn" id="h-export">${ico('download','s12')}导出台账 CSV</button>
    <button class="btn primary" id="h-run">${ico('play','s12')}执行检测</button></div>
  <div id="h-out"><div class="card"><div class="card-b"><div class="empty">'+ico('server')+'<b>尚未执行</b><p>点击「执行检测」开始检测当前这台机器</p></div></div></div></div>`;
  $('#h-run').onclick=async()=>{
    $('#h-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('clock')+'<b>检测中…</b></div></div></div>';
    try{const j=await api('/api/jobs',{method:'POST',body:{kind:'host'}});
      toast('任务已提交 '+j.id,'ok');watchHost(j.id)}
    catch(e){$('#h-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<p>'+esc(e.message)+'</p></div></div></div>'}
  };
  $('#h-export').onclick=()=>{window.location='/api/host/export'};
}
async function watchHost(id){
  const t=setInterval(async()=>{
    try{const j=await api('/api/jobs/'+id);
      if(j.state==='done'){clearInterval(t);renderHost(j.result)}
      else if(j.state==='failed'){clearInterval(t);
        $('#h-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<b>检测失败</b><p>'+esc(j.error||'')+'</p></div></div></div>'}
    }catch(e){clearInterval(t)}
  },1200);
}
function renderHost(r){
  const h=(r.host_reports||[])[0]||{};
  $('#h-out').innerHTML=`
  <div class="grid kpis">
    <div class="kpi"><div class="k">主机风险</div><div class="v ${h.risk==='critical'?'danger':(h.risk==='high'?'warn':'ok')}" style="font-size:18px">${esc((h.risk||'').toUpperCase())}</div><div class="d">${esc(h.hostname||'')}</div></div>
    <div class="kpi"><div class="k">PHP 安装点</div><div class="v num">${(h.installs||[]).length}</div></div>
    <div class="kpi"><div class="k">可疑痕迹</div><div class="v num ${(h.artifacts||[]).length?'danger':'ok'}">${(h.artifacts||[]).length}</div></div>
    <div class="kpi"><div class="k">配置项</div><div class="v num">${(h.settings||[]).length}</div><div class="d">生效值核查</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
    <div class="card"><div class="card-h"><h3>PHP 安装点</h3></div>
      <div class="tbl-wrap"><table><thead><tr><th>版本</th><th>SAPI</th><th>路径</th><th>状态</th></tr></thead>
        <tbody>${(h.installs||[]).map(i=>`<tr><td class="num"><b>${esc(i.version||'?')}</b></td>
          <td style="font-size:11.5px">${esc(i.sapi||'-')}</td><td class="mono muted" style="font-size:11px">${esc(i.path)}</td>
          <td>${i.needs_action?tag('crit','需升级'):tag('ok','已修复')}</td></tr>`).join('')
          ||'<tr><td colspan="4" class="muted" style="padding:14px;font-size:12px">本机未发现 PHP</td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-h"><h3>关键配置生效值</h3></div>
      <div class="tbl-wrap"><table><thead><tr><th>配置项</th><th>实际值</th><th>期望</th><th></th></tr></thead>
        <tbody>${(h.settings||[]).map(s=>`<tr><td class="mono" style="font-size:11.5px">${esc(s.name)}</td>
          <td class="num">${esc(s.actual||'-')}</td><td class="num muted">${esc(s.expected)}</td>
          <td>${s.ok?tag('ok','OK'):tag('warn','需调整')}</td></tr>`).join('')
          ||'<tr><td colspan="4" class="muted" style="padding:14px;font-size:12px">无</td></tr>'}</tbody></table></div></div>
  </div>
  <div class="card" style="margin-top:12px"><div class="card-h"><h3>可疑痕迹</h3><div class="sp"></div>
    ${tag((h.artifacts||[]).length?'crit':'ok',(h.artifacts||[]).length+' 项')}</div>
    <div class="card-b">${(h.artifacts||[]).length?(h.artifacts||[]).map(a=>`
      <div class="evi" style="border-left-color:var(--danger-border)">${tag((RISK[a.severity]||['mute',a.severity])[0],a.kind)} ${esc(a.path)}<br>
        <span class="muted">${esc(a.detail||'')}</span></div>`).join('')
      :'<div class="empty" style="padding:22px">'+ico('check')+'<b>未发现可疑痕迹</b></div>'}</div></div>`;
}

/* ==================== 规则中心 ==================== */
async function loadRules(c){
  const r=await api('/api/rules');
  c.innerHTML=`
  <div class="page-head"><div><h2>规则中心</h2><p>${r.count} 条数据驱动检测规则 · 一键导出到 SIEM / WAF / IDS</p></div>
    <div class="sp"></div>
    <button class="btn" onclick="exportRules('sigma')">${ico('download','s12')}Sigma</button>
    <button class="btn" onclick="exportRules('modsecurity')">${ico('download','s12')}ModSecurity</button>
    <button class="btn" onclick="exportRules('suricata')">${ico('download','s12')}Suricata</button></div>
  <div class="card">
    <div class="card-h"><h3>规则列表</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">维度：request / response / host / behavior / recon</span></div>
    <div class="tbl-wrap"><table><thead><tr><th>ID</th><th>名称</th><th>等级</th><th>维度</th><th>需要字段</th><th>涉及 CVE</th><th>说明</th></tr></thead>
      <tbody>${r.rules.map(x=>`<tr>
        <td class="mono">${esc(x.id)}</td>
        <td class="h" style="font-size:12.5px">${esc(x.name)}</td>
        <td>${tag((RISK[x.severity]||['mute',x.severity])[0],x.severity)}</td>
        <td class="muted" style="font-size:11.5px">${esc(x.dimension)}</td>
        <td><code>${esc(x.requires)}</code></td>
        <td style="font-size:11px">${(x.cves||[]).map(c=>tag('mute',c)).join(' ')}</td>
        <td class="muted" style="font-size:11.5px">${esc(x.description)}</td></tr>`).join('')}</tbody></table></div>
  </div>`;
}
async function exportRules(fmt){
  try{
    const resp=await fetch('/api/rules/export/'+fmt);
    if(!resp.ok) throw new Error('HTTP '+resp.status);
    const t=await resp.text();
    const b=new Blob([t],{type:'text/plain'}),u=URL.createObjectURL(b);
    const a=document.createElement('a');a.href=u;a.download='p2s-php2shell.'+fmt;a.click();
    toast('已导出 '+fmt+' 规则','ok');
  }catch(e){toast('导出失败: '+e.message,'err')}
}

/* ==================== IOC 中心 ==================== */
async function loadIoc(c){
  const r=await api('/api/ioc');
  c.innerHTML=`
  <div class="page-head"><div><h2>IOC 中心</h2><p>来源：TU Delft INTELLAB 蜜罐观测 / NCSC-NL / CISA KEV · 更新于 ${esc(r.summary.updated)}</p></div></div>
  <div class="grid kpis">
    <div class="kpi"><div class="k">攻击者 IP</div><div class="v num danger">${r.summary.ips}</div></div>
    <div class="kpi"><div class="k">域名</div><div class="v num">${r.summary.domains}</div></div>
    <div class="kpi"><div class="k">URL</div><div class="v num">${r.summary.urls}</div></div>
    <div class="kpi"><div class="k">样本哈希</div><div class="v num">${r.summary.hashes}</div></div>
    <div class="kpi"><div class="k">UA 特征</div><div class="v num">${r.summary.user_agents}</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
    <div class="card"><div class="card-h"><h3>基础设施</h3></div><div class="card-b">
      <div class="sect-t">IP</div>${r.ips.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">域名</div>${r.domains.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">User-Agent 特征</div>${r.user_agents.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
    </div></div>
    <div class="card"><div class="card-h"><h3>Dropper URL 与样本</h3></div><div class="card-b">
      ${r.urls.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">恶意样本</div>
      ${Object.entries(r.hashes).map(([h,d])=>`<div class="evi"><b>${esc(d)}</b><br><span class="muted">${esc(h)}</span></div>`).join('')}
    </div></div>
  </div>`;
}

/* ==================== 报告中心 ==================== */
async function loadReports(c){
  const r=await api('/api/scans');
  c.innerHTML=`
  <div class="page-head"><div><h2>报告中心</h2><p>共 ${r.scans.length} 份扫描报告</p></div></div>
  <div class="card"><div class="card-h"><h3>历史扫描</h3></div>
    <div class="tbl-wrap"><table><thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始</th><th>操作</th></tr></thead>
      <tbody>${r.scans.map(s=>`<tr>
        <td class="mono">${esc(s.scan_id)}</td><td>${esc(s.kind)}</td>
        <td>${tag((RISK[s.risk]||['mute','?'])[0],(RISK[s.risk]||['mute','?'])[1])}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td><td class="num">${s.severity_counts?.high||0}</td>
        <td class="muted num" style="font-size:11.5px">${esc(s.started_at)}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="btn sm" onclick="viewReport('${esc(s.scan_id)}')">查看</button>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=md" target="_blank">MD</a>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=html" target="_blank">HTML</a>
          <button class="btn sm ghost" onclick="delReport('${esc(s.scan_id)}')" title="删除">${ico('trash','s12')}</button>
        </td></tr>`).join('')||'<tr><td colspan="8"><div class="empty">'+ico('file')+'<b>暂无报告</b></div></td></tr>'}</tbody></table></div></div>`;
}
async function viewReport(id){
  try{
    const resp=await fetch('/api/scans/'+id+'/report?fmt=md');
    if(!resp.ok) throw new Error('HTTP '+resp.status);
    const t=await resp.text();
    $('#drawer-title').textContent='报告 · '+id;
    $('#drawer-body').innerHTML='<pre>'+esc(t)+'</pre>';
    $('#drawer-foot').innerHTML=`
      <a class="btn" href="/api/scans/${id}/report?fmt=md" target="_blank">${ico('download','s12')}Markdown</a>
      <a class="btn" href="/api/scans/${id}/report?fmt=html" target="_blank">${ico('download','s12')}HTML</a>
      <div class="sp"></div><button class="btn primary" onclick="closeDrawer()">关闭</button>`;
    $('#drawer').classList.add('on');$('#drawer-bg').classList.add('on');
  }catch(e){toast('读取报告失败: '+e.message,'err')}
}
async function delReport(id){
  if(!confirm('删除报告 '+id+'？')) return;
  try{await api('/api/scans/'+id,{method:'DELETE'});toast('已删除','ok');loadReports($('#content'))}
  catch(e){toast('删除失败: '+e.message,'err')}
}

/* ==================== 启动 ==================== */
pollJobs();
go(location.hash.slice(1)||'overview');
</script>
</body>
</html>
"""