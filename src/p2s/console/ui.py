"""p2s 控制台前端（单文件，无外部依赖，离线可用）。

设计目标：
  - 浅色为主（默认）+ 深色切换，解决"太暗"的问题
  - 层次感：背景 / 表面 / 浮层三级 + 三档阴影 + 1px 描边
  - 信息密度高但不拥挤：等宽数字、状态胶囊、粘性表头
  - 图表用内联 SVG，不引入任何 CDN，保证内网离线可用
"""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>p2s 控制台 · php2shell 暴露面评估</title>
<style>
/* ============ 设计令牌 ============ */
:root{
  --bg:#eef2f7; --bg-grad:radial-gradient(1200px 600px at 12% -8%,#e5edfb 0%,transparent 60%),
                    radial-gradient(900px 500px at 92% 0%,#eaf0fe 0%,transparent 55%);
  --surface:#ffffff; --surface-2:#f8fafc; --surface-3:#f1f5f9;
  --border:#e4e9f1; --border-2:#cfd8e6; --border-3:#b9c5d6;
  --text:#0d1526; --text-2:#4a5568; --text-3:#8896aa;
  --accent:#2563eb; --accent-2:#6d5ef8; --accent-soft:#eff5ff; --accent-line:#c9dcfd;
  --ok:#0f9d58; --ok-soft:#e8f8f0; --ok-line:#b7e6cd;
  --warn:#d97706; --warn-soft:#fff6e6; --warn-line:#f6dfae;
  --danger:#dc2626; --danger-soft:#fdeeee; --danger-line:#f6c4c4;
  --purple:#7c3aed; --purple-soft:#f4efff; --purple-line:#dcc9fb;
  --sh-1:0 1px 2px rgba(13,21,38,.05),0 1px 3px rgba(13,21,38,.05);
  --sh-2:0 2px 6px rgba(13,21,38,.05),0 10px 28px rgba(13,21,38,.07);
  --sh-3:0 18px 48px rgba(13,21,38,.16);
  --r-s:8px; --r-m:12px; --r-l:16px;
  --sidebar:232px; --topbar:60px; --fs:14px;
}
[data-theme="dark"]{
  --bg:#0c1017; --bg-grad:radial-gradient(1200px 600px at 12% -8%,#152036 0%,transparent 60%),
                    radial-gradient(900px 500px at 92% 0%,#1a1836 0%,transparent 55%);
  --surface:#141a24; --surface-2:#1a212d; --surface-3:#212a38;
  --border:#242e3d; --border-2:#334052; --border-3:#3d4a5e;
  --text:#e8edf5; --text-2:#a5b1c4; --text-3:#75839a;
  --accent:#5b9cff; --accent-2:#8b7cff; --accent-soft:#16243d; --accent-line:#25406b;
  --ok:#35d08a; --ok-soft:#0f2a20; --ok-line:#1d5340;
  --warn:#f5b545; --warn-soft:#2e2313; --warn-line:#5c4620;
  --danger:#ff6b6b; --danger-soft:#2e1719; --danger-line:#5f2b2f;
  --purple:#a78bfa; --purple-soft:#221a38; --purple-line:#40306a;
  --sh-1:0 1px 2px rgba(0,0,0,.4);
  --sh-2:0 2px 6px rgba(0,0,0,.35),0 10px 28px rgba(0,0,0,.4);
  --sh-3:0 18px 48px rgba(0,0,0,.6);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:"Inter","Segoe UI",-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
  font-size:var(--fs); color:var(--text); background:var(--bg); background-image:var(--bg-grad);
  background-attachment:fixed; -webkit-font-smoothing:antialiased; line-height:1.55;
}
.num{font-variant-numeric:tabular-nums;font-feature-settings:"tnum"}
a{color:var(--accent);text-decoration:none}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:var(--border-2);border-radius:8px;border:3px solid transparent;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:var(--border-3);background-clip:content-box}

/* ============ 布局 ============ */
.app{display:flex;min-height:100vh}
.sidebar{
  width:var(--sidebar);flex:0 0 var(--sidebar);position:fixed;inset:0 auto 0 0;z-index:40;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;box-shadow:var(--sh-1);
}
.brand{padding:18px 20px 14px;border-bottom:1px solid var(--border);display:flex;gap:11px;align-items:center}
.brand-mark{
  width:34px;height:34px;border-radius:10px;flex:0 0 34px;
  background:linear-gradient(140deg,var(--accent),var(--accent-2));
  display:grid;place-items:center;color:#fff;font-weight:800;font-size:13px;
  box-shadow:0 4px 12px rgba(37,99,235,.32);
}
.brand-txt b{display:block;font-size:14.5px;letter-spacing:-.2px}
.brand-txt span{font-size:10px;color:var(--text-3);letter-spacing:.6px;text-transform:uppercase;font-weight:600}
.nav{padding:12px 10px;flex:1;overflow-y:auto}
.nav-label{font-size:10px;font-weight:700;letter-spacing:.8px;color:var(--text-3);padding:12px 10px 6px;text-transform:uppercase}
.nav a{
  display:flex;align-items:center;gap:10px;padding:8.5px 11px;border-radius:var(--r-s);
  color:var(--text-2);font-size:13.5px;font-weight:500;margin-bottom:2px;transition:.16s;position:relative;
}
.nav a:hover{background:var(--surface-3);color:var(--text)}
.nav a.on{background:var(--accent-soft);color:var(--accent);font-weight:600}
.nav a.on::before{content:"";position:absolute;left:-10px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.nav a .ico{width:17px;text-align:center;font-size:14px;opacity:.9}
.nav a .badge{margin-left:auto;font-size:10.5px;font-weight:700;padding:1px 6px;border-radius:20px;background:var(--danger);color:#fff}
.side-foot{padding:12px;border-top:1px solid var(--border)}
.kev-card{background:linear-gradient(150deg,var(--danger-soft),transparent);border:1px solid var(--danger-line);
  border-radius:var(--r-m);padding:11px 12px}
.kev-card b{font-size:12px;color:var(--danger);display:block;margin-bottom:3px}
.kev-card p{font-size:11.5px;color:var(--text-2);line-height:1.5}

.main{flex:1;margin-left:var(--sidebar);min-width:0;display:flex;flex-direction:column}
.topbar{
  height:var(--topbar);position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:14px;
  padding:0 26px;background:color-mix(in srgb,var(--surface) 86%,transparent);
  backdrop-filter:saturate(180%) blur(12px);border-bottom:1px solid var(--border);
}
.topbar h1{font-size:16.5px;font-weight:650;letter-spacing:-.3px}
.topbar .sub{font-size:12px;color:var(--text-3);margin-top:1px}
.topbar .sp{flex:1}
.icon-btn{
  width:34px;height:34px;border-radius:9px;border:1px solid var(--border);background:var(--surface);
  color:var(--text-2);cursor:pointer;display:grid;place-items:center;font-size:14px;transition:.15s;
}
.icon-btn:hover{background:var(--surface-3);color:var(--text);border-color:var(--border-2);transform:translateY(-1px)}
.icon-btn.on{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}
.content{padding:24px 26px 56px;max-width:1560px;width:100%}/* ============ 通用组件 ============ */
.page-head{display:flex;align-items:flex-start;gap:16px;margin-bottom:20px}
.page-head h2{font-size:20px;font-weight:680;letter-spacing:-.4px}
.page-head p{font-size:13px;color:var(--text-2);margin-top:3px}
.page-head .sp{flex:1}
.btn{
  display:inline-flex;align-items:center;gap:7px;padding:8px 14px;border-radius:9px;cursor:pointer;
  border:1px solid var(--border-2);background:var(--surface);color:var(--text);font-size:13px;font-weight:560;
  transition:.15s;font-family:inherit;text-decoration:none;
}
.btn:hover{background:var(--surface-3);transform:translateY(-1px);box-shadow:var(--sh-1)}
.btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));border-color:transparent;color:#fff;
  box-shadow:0 4px 14px rgba(37,99,235,.3)}
.btn.primary:hover{box-shadow:0 8px 22px rgba(37,99,235,.38)}
.btn.ghost{border-color:transparent;background:transparent;color:var(--text-2)}
.btn.ghost:hover{background:var(--surface-3)}
.btn.sm{padding:5px 10px;font-size:12px;border-radius:7px}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-l);
  box-shadow:var(--sh-1);overflow:hidden;
}
.card-h{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.card-h h3{font-size:14px;font-weight:650;letter-spacing:-.2px}
.card-h .sp{flex:1}
.card-b{padding:16px 18px}
.grid{display:grid;gap:16px}

.kpis{grid-template-columns:repeat(auto-fit,minmax(178px,1fr));margin-bottom:18px}
.kpi{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-l);padding:16px 18px;
  position:relative;overflow:hidden;box-shadow:var(--sh-1);transition:.18s;
}
.kpi::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;
  background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.kpi.ok::before{background:linear-gradient(90deg,var(--ok),#34d399)}
.kpi.warn::before{background:linear-gradient(90deg,var(--warn),#fbbf24)}
.kpi.danger::before{background:linear-gradient(90deg,var(--danger),#f87171)}
.kpi.purple::before{background:linear-gradient(90deg,var(--purple),#a78bfa)}
.kpi:hover{transform:translateY(-2px);box-shadow:var(--sh-2)}
.kpi .k{font-size:11.5px;color:var(--text-3);font-weight:600;letter-spacing:.2px;display:flex;align-items:center;gap:6px}
.kpi .v{font-size:30px;font-weight:700;letter-spacing:-1px;margin-top:6px;line-height:1.1}
.kpi .d{font-size:11.5px;color:var(--text-3);margin-top:4px}

.pill{
  display:inline-flex;align-items:center;gap:5px;padding:2.5px 9px;border-radius:20px;
  font-size:11.5px;font-weight:620;white-space:nowrap;border:1px solid transparent;line-height:1.6;
}
.pill.crit{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-line)}
.pill.high{background:var(--warn-soft);color:var(--warn);border-color:var(--warn-line)}
.pill.ok{background:var(--ok-soft);color:var(--ok);border-color:var(--ok-line)}
.pill.info{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}
.pill.pur{background:var(--purple-soft);color:var(--purple);border-color:var(--purple-line)}
.pill.mute{background:var(--surface-3);color:var(--text-2);border-color:var(--border)}
.dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex:0 0 6px}

.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{
  text-align:left;padding:10px 14px;font-size:11px;font-weight:700;color:var(--text-3);
  text-transform:uppercase;letter-spacing:.5px;background:var(--surface-2);
  border-bottom:1px solid var(--border);position:sticky;top:0;white-space:nowrap;z-index:1;
}
td{padding:11px 14px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr{transition:.12s}
tbody tr:hover{background:var(--surface-2)}
tbody tr:last-child td{border-bottom:none}
.t-host{font-weight:640;font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:12.5px}
.t-mute{color:var(--text-3)}
.t-sm{font-size:12px}
.row-actions{display:flex;gap:5px;justify-content:flex-end}

.dev-grid{grid-template-columns:repeat(auto-fill,minmax(330px,1fr))}
.dev{
  background:var(--surface);border:1px solid var(--border);border-radius:var(--r-l);padding:16px;
  box-shadow:var(--sh-1);transition:.18s;cursor:pointer;position:relative;overflow:hidden;
}
.dev:hover{transform:translateY(-3px);box-shadow:var(--sh-2);border-color:var(--border-2)}
.dev::after{content:"";position:absolute;right:-18px;top:-18px;width:86px;height:86px;border-radius:50%;
  background:var(--accent-soft);opacity:.55}
.dev-top{display:flex;align-items:flex-start;gap:10px;position:relative;z-index:1}
.dev-ico{
  width:38px;height:38px;border-radius:11px;flex:0 0 38px;display:grid;place-items:center;font-size:17px;
  background:var(--accent-soft);border:1px solid var(--accent-line);
}
.dev h4{font-size:13.5px;font-weight:660;letter-spacing:-.2px}
.dev .ip{font-size:11.5px;color:var(--text-3);font-family:ui-monospace,Menlo,Consolas,monospace}
.dev-meta{display:flex;flex-wrap:wrap;gap:5px;margin-top:11px;position:relative;z-index:1}
.dev-foot{margin-top:12px;padding-top:11px;border-top:1px dashed var(--border);display:flex;
  align-items:center;gap:8px;font-size:11.5px;color:var(--text-3);position:relative;z-index:1}

.ports{display:flex;flex-wrap:wrap;gap:4px}
.port{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;font-weight:640;
  padding:1px 6px;border-radius:5px;background:var(--surface-3);color:var(--text-2);border:1px solid var(--border)}
.port.web{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-line)}
.port.php{background:var(--danger-soft);color:var(--danger);border-color:var(--danger-line)}

.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:1180px){.chart-row{grid-template-columns:1fr}}
.legend{display:flex;flex-direction:column;gap:7px;font-size:12px}
.legend div{display:flex;align-items:center;gap:8px}
.legend .sw{width:9px;height:9px;border-radius:3px;flex:0 0 9px}
.legend .vv{margin-left:auto;font-weight:650;font-variant-numeric:tabular-nums}
.bar-line{display:flex;align-items:center;gap:9px;font-size:12px;margin-bottom:7px}
.bar-line .nm{width:132px;flex:0 0 132px;color:var(--text-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-line .track{flex:1;height:7px;border-radius:5px;background:var(--surface-3);overflow:hidden}
.bar-line .fill{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,var(--accent),var(--accent-2))}
.bar-line .n{width:30px;text-align:right;font-variant-numeric:tabular-nums;font-weight:650}

.drawer-bg{position:fixed;inset:0;background:rgba(9,14,26,.45);backdrop-filter:blur(2px);z-index:60;
  opacity:0;pointer-events:none;transition:.22s}
.drawer-bg.on{opacity:1;pointer-events:auto}
.drawer{
  position:fixed;top:0;right:0;bottom:0;width:min(560px,94vw);z-index:61;background:var(--surface);
  box-shadow:var(--sh-3);transform:translateX(102%);transition:.26s cubic-bezier(.4,0,.2,1);
  display:flex;flex-direction:column;border-left:1px solid var(--border);
}
.drawer.on{transform:none}
.drawer-h{padding:18px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.drawer-h h3{font-size:15.5px;font-weight:660}
.drawer-b{padding:18px 20px;overflow-y:auto;flex:1}
.drawer-f{padding:13px 20px;border-top:1px solid var(--border);display:flex;gap:9px;background:var(--surface-2);align-items:center}
.drawer-f .sp{flex:1}

.sect{margin-bottom:20px}
.sect-t{font-size:11px;font-weight:700;color:var(--text-3);text-transform:uppercase;letter-spacing:.7px;
  margin-bottom:9px;display:flex;align-items:center;gap:7px}
.sect-t::after{content:"";flex:1;height:1px;background:var(--border)}
.kv{display:grid;grid-template-columns:104px 1fr;gap:7px 12px;font-size:12.5px;margin:0}
.kv dt{color:var(--text-3)}
.kv dd{font-weight:540;word-break:break-word;margin:0}
.evi{background:var(--surface-2);border:1px solid var(--border);border-left:2px solid var(--accent);
  border-radius:0 var(--r-s) var(--r-s) 0;padding:9px 12px;font-size:12px;color:var(--text-2);margin-bottom:6px;
  font-family:ui-monospace,Menlo,Consolas,monospace;line-height:1.6;word-break:break-all}
.fixbox{background:var(--ok-soft);border:1px solid var(--ok-line);border-radius:var(--r-m);padding:12px 14px;font-size:12.5px}
.fixbox.warn{background:var(--warn-soft);border-color:var(--warn-line)}
.fixbox ul{margin:6px 0 0 16px;padding:0}
.fixbox li{margin-bottom:3px}

.field{margin-bottom:13px}
.field label{display:block;font-size:11.5px;font-weight:640;color:var(--text-2);margin-bottom:5px}
input,select,textarea{
  width:100%;padding:8px 11px;border:1px solid var(--border-2);border-radius:9px;background:var(--surface);
  color:var(--text);font-size:13px;font-family:inherit;transition:.15s;
}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 16%,transparent)}
textarea{resize:vertical;min-height:84px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.row{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
.row>*{flex:1;min-width:0}
.row>.narrow{flex:0 0 148px}

.seg{display:inline-flex;background:var(--surface-3);border:1px solid var(--border);border-radius:9px;padding:2.5px;gap:2px}
.seg button{border:none;background:none;padding:5px 12px;border-radius:7px;font-size:12.5px;color:var(--text-2);
  cursor:pointer;font-family:inherit;font-weight:540;transition:.14s}
.seg button.on{background:var(--surface);color:var(--text);font-weight:640;box-shadow:var(--sh-1)}

.toast-wrap{position:fixed;right:22px;bottom:22px;z-index:90;display:flex;flex-direction:column;gap:9px}
.toast{
  background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:var(--r-m);padding:11px 15px;box-shadow:var(--sh-2);font-size:13px;min-width:250px;
  animation:slideIn .24s cubic-bezier(.4,0,.2,1);
}
.toast.ok{border-left-color:var(--ok)} .toast.err{border-left-color:var(--danger)} .toast.warn{border-left-color:var(--warn)}
@keyframes slideIn{from{opacity:0;transform:translateX(22px)}to{opacity:1;transform:none}}
.progress{height:4px;background:var(--surface-3);border-radius:4px;overflow:hidden;margin:10px 0}
.progress i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent-2));
  width:0;transition:width .3s;border-radius:4px}
.empty{text-align:center;padding:44px 20px;color:var(--text-3)}
.empty .ico{font-size:38px;opacity:.35;margin-bottom:10px}
.empty b{display:block;color:var(--text-2);font-size:14px;margin-bottom:5px;font-weight:600}
.empty p{font-size:12.5px;max-width:460px;margin:0 auto;line-height:1.7}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;background:var(--surface-3);
  padding:1.5px 5px;border-radius:5px;border:1px solid var(--border)}
pre{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-m);padding:14px;
  overflow:auto;max-height:560px;font-size:11.5px;line-height:1.65;
  font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--text-2)}
.sec{animation:fade .22s ease}
@keyframes fade{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.hide{display:none!important}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">P2S</div>
      <div class="brand-txt"><b>php2shell</b><span>Exposure Console</span></div>
    </div>
    <nav class="nav">
      <div class="nav-label">总览</div>
      <a href="#overview" data-tab="overview" class="on"><span class="ico">◈</span>态势总览</a>
      <a href="#discover" data-tab="discover"><span class="ico">⌖</span>设备发现</a>
      <a href="#assets" data-tab="assets"><span class="ico">▤</span>资产台账<span class="badge hide" id="nav-badge-assets"></span></a>
      <div class="nav-label">暴露面</div>
      <a href="#php" data-tab="php"><span class="ico">⚠</span>PHP 暴露面<span class="badge hide" id="nav-badge-php"></span></a>
      <a href="#logs" data-tab="logs"><span class="ico">⌗</span>日志分析</a>
      <a href="#host" data-tab="host"><span class="ico">⛨</span>主机侧检测</a>
      <div class="nav-label">能力</div>
      <a href="#rules" data-tab="rules"><span class="ico">≡</span>规则中心</a>
      <a href="#ioc" data-tab="ioc"><span class="ico">◎</span>IOC 中心</a>
      <a href="#reports" data-tab="reports"><span class="ico">◲</span>报告中心</a>
    </nav>
    <div class="side-foot">
      <div class="kev-card">
        <b>⚠ CISA KEV 已收录</b>
        <p>CVE-2026-109618 / 109619 已被列为在野利用，强制修复截止 <b>2026-10-29</b>。</p>
      </div>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <div>
        <h1 id="pg-title">态势总览</h1>
        <div class="sub" id="pg-sub">php2shell 暴露面全局视图</div>
      </div>
      <div class="sp"></div>
      <div class="row" style="flex:0 0 auto">
        <button class="btn sm" id="btn-refresh" title="刷新当前页">↻ 刷新</button>
        <button class="icon-btn" id="btn-theme" title="切换深浅色">◐</button>
      </div>
    </header>

    <main class="content" id="content"></main>
  </div>
</div>

<div class="drawer-bg" id="drawer-bg"></div>
<aside class="drawer" id="drawer">
  <div class="drawer-h"><h3 id="drawer-title">详情</h3><div class="sp"></div>
    <button class="icon-btn" id="drawer-close">✕</button></div>
  <div class="drawer-b" id="drawer-body"></div>
  <div class="drawer-f" id="drawer-foot"></div>
</aside>

<div class="toast-wrap" id="toasts"></div>

<script>/* ==================== 基础 ==================== */
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=async(u,o={})=>{const r=await fetch(u,{headers:{'Content-Type':'application/json'},...o});
  if(!r.ok){let m=r.statusText;try{m=(await r.json()).detail||m}catch(e){}throw new Error(m)}
  return r.json()};
function toast(msg,kind='info'){const t=document.createElement('div');t.className='toast '+kind;t.innerHTML=esc(msg);
  $('#toasts').appendChild(t);setTimeout(()=>{t.style.opacity=0;t.style.transition='.3s';setTimeout(()=>t.remove(),320)},3400)}
const RISK={critical:['crit','严重'],high:['high','高危'],medium:['high','中危'],low:['ok','低危']};
const EXP={exposed:['crit','暴露·需修复'],patched:['ok','已修复'],not_php:['mute','无PHP·无关'],unknown:['warn','待确认']};
const pill=(cls,txt)=>`<span class="pill ${cls}">${esc(txt)}</span>`;
const DEVI={
  firewall:'🛡️',bastion:'🔐',network_device:'🔀',mail_gateway:'📮',linux_host:'🐧',windows_host:'🪟',
  web_server:'🌐',php_app:'🐘',app_server:'☕',cms:'📝',db_tool:'🗄️',monitoring:'📈',devops:'⚙️',
  file_service:'📁',cloud:'☁️',container:'🐳',iot_device:'📷',appliance:'🔲',unknown:'❔'};
const SAPI_RISK={apache:'⚠ mod_php 风险最高',fpm:'PHP-FPM',iis:'php-cgi',litespeed:'LiteSpeed',unknown:'未知 SAPI'};

/* ==================== 主题 ==================== */
const savedTheme=localStorage.getItem('p2s-theme')||'light';
document.documentElement.dataset.theme=savedTheme;
$('#btn-theme').onclick=()=>{const n=document.documentElement.dataset.theme==='light'?'dark':'light';
  document.documentElement.dataset.theme=n;localStorage.setItem('p2s-theme',n);$('#btn-theme').classList.toggle('on',n==='dark')};
$('#btn-theme').classList.toggle('on',savedTheme==='dark');

/* ==================== 路由 ==================== */
const PAGES={
  overview:{t:'态势总览',s:'php2shell 暴露面全局视图',fn:loadOverview},
  discover:{t:'设备发现',s:'网段 / 批量主机 → 设备类型 → PHP 暴露面',fn:loadDiscover},
  assets:{t:'资产台账',s:'设备画像持久化 · 分组 · 责任人',fn:loadAssets},
  php:{t:'PHP 暴露面',s:'只关注真正跑 PHP 的资产',fn:loadPhp},
  logs:{t:'日志分析',s:'被动检测 · 零风险',fn:loadLogs},
  host:{t:'主机侧检测',s:'本机配置 / 痕迹 / 进程 / 连接',fn:loadHost},
  rules:{t:'规则中心',s:'13 条检测规则 · 一键导出',fn:loadRules},
  ioc:{t:'IOC 中心',s:'在野利用指标库',fn:loadIoc},
  reports:{t:'报告中心',s:'历史扫描与交付报告',fn:loadReports},
};
let STATE={assets:[],overview:null,rules:[],ioc:null,lastLog:null};
async function go(tab){
  const p=PAGES[tab]; if(!p) return;
  $('#pg-title').textContent=p.t; $('#pg-sub').textContent=p.s;
  $$('.nav a').forEach(a=>a.classList.toggle('on',a.dataset.tab===tab));
  const c=$('#content'); c.innerHTML='<div class="empty"><div class="ico">◌</div><b>加载中…</b></div>';
  try{ await p.fn(c); }catch(e){ c.innerHTML=`<div class="empty"><div class="ico">⚠</div><b>加载失败</b><p>${esc(e.message)}</p></div>`; }
}
$$('.nav a').forEach(a=>a.onclick=e=>{e.preventDefault();location.hash=a.dataset.tab});
$('#btn-refresh').onclick=()=>go(location.hash.slice(1)||'overview');
window.addEventListener('hashchange',()=>go(location.hash.slice(1)||'overview'));

/* ==================== 总览 ==================== */
async function loadOverview(c){
  const o=await api('/api/overview'); STATE.overview=o;
  STATE.assets=(await api('/api/assets')).assets;
  const nbA=$('#nav-badge-assets'), nbP=$('#nav-badge-php');
  nbA.classList.toggle('hide',!o.total_assets); nbA.textContent=o.total_assets;
  nbP.classList.toggle('hide',!o.exposed); nbP.textContent=o.exposed;

  const exp=[['exposed',o.exposed],['patched',o.patched],['not_php',o.not_php],['unknown',o.unknown]];
  const COL={'exposed':'var(--danger)','patched':'var(--ok)','not_php':'var(--text-3)','unknown':'var(--warn)'};
  const total=Math.max(1,exp.reduce((s,x)=>s+x[1],0));
  let acc=0; const arcs=exp.map(([k,v])=>{
    const a0=acc/total*2*Math.PI, a1=(acc+v)/total*2*Math.PI; acc+=v;
    if(!v) return '';
    const large=(a1-a0)>Math.PI?1:0;
    const x0=80+58*Math.sin(a0),y0=80-58*Math.cos(a0),x1=80+58*Math.sin(a1),y1=80-58*Math.cos(a1);
    const lx=80+40*Math.sin((a0+a1)/2), ly=80-40*Math.cos((a0+a1)/2);
    return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A 58 58 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}"
      fill="none" stroke="${COL[k]}" stroke-width="20" stroke-linecap="butt"/>
      ${v>=1?`<text x="${lx.toFixed(1)}" y="${(ly+5).toFixed(1)}" text-anchor="middle" font-size="15" font-weight="700" fill="var(--text)">${v}</text>`:''}`;
  }).join('');

  const types=Object.entries(o.by_type).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxT=Math.max(1,...types.map(t=>t[1]));

  c.innerHTML=`
  <div class="grid kpis">
    <div class="kpi"><div class="k">📦 资产总数</div><div class="v num">${o.total_assets}</div><div class="d">存活 ${o.alive} · 分组 ${o.groups.length}</div></div>
    <div class="kpi danger"><div class="k">🐘 存在 PHP</div><div class="v num">${o.php_present}</div><div class="d">其中未修复 <b>${o.exposed}</b></div></div>
    <div class="kpi danger"><div class="k">⛔ 暴露待修复</div><div class="v num">${o.exposed}</div><div class="d">版本低于修复基线</div></div>
    <div class="kpi ok"><div class="k">✅ PHP 已修复</div><div class="v num">${o.patched}</div><div class="d">已达基线版本</div></div>
    <div class="kpi purple"><div class="k">🚫 不含 PHP</div><div class="v num">${o.not_php}</div><div class="d">与本漏洞无关</div></div>
    <div class="kpi"><div class="k">⏱ 扫描次数</div><div class="v num">${o.scan_count}</div><div class="d">历史任务</div></div>
  </div>

  <div class="chart-row">
    <div class="card">
      <div class="card-h"><h3>PHP 暴露面构成</h3><div class="sp"></div>
        <span class="pill mute">共 ${o.total_assets} 台</span></div>
      <div class="card-b" style="display:flex;gap:26px;align-items:center;flex-wrap:wrap">
        <svg viewBox="0 0 160 160" width="170" height="170" style="flex:0 0 170px">
          <circle cx="80" cy="80" r="58" fill="none" stroke="var(--surface-3)" stroke-width="20"/>
          ${arcs}
          <text x="80" y="72" text-anchor="middle" font-size="11" fill="var(--text-3)">受影响资产</text>
          <text x="80" y="96" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text)">${o.exposed}</text>
        </svg>
        <div class="legend" style="flex:1;min-width:150px">
          ${exp.map(([k,v])=>`<div><span class="sw" style="background:${COL[k]}"></span>${esc(EXP[k][1])}<span class="vv num">${v}</span></div>`).join('')}
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-h"><h3>设备类型分布</h3><div class="sp"></div>
        <button class="btn sm ghost" onclick="go('discover')">去发现 →</button></div>
      <div class="card-b">
        ${types.length?types.map(([k,v])=>`
          <div class="bar-line">
            <span class="nm" title="${esc(k)}">${esc(k)}</span>
            <span class="track"><i class="fill" style="width:${(v/maxT*100).toFixed(1)}%"></i></span>
            <span class="n num">${v}</span>
          </div>`).join(''):'<div class="empty" style="padding:24px"><p>还没有资产，去「设备发现」跑一次</p></div>'}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-h"><h3>最近扫描</h3><div class="sp"></div>
      <button class="btn sm ghost" onclick="go('reports')">全部报告 →</button></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始时间</th><th></th></tr></thead>
      <tbody>${(o.recent_scans||[]).map(s=>`<tr>
        <td class="t-host">${esc(s.scan_id)}</td><td>${esc(s.kind)}</td>
        <td>${pill((RISK[s.risk]||['mute','未知'])[0],(RISK[s.risk]||['mute','未知'])[1].toUpperCase())}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td>
        <td class="num">${s.severity_counts?.high||0}</td>
        <td class="t-mute t-sm num">${esc(s.started_at)}</td>
        <td class="row-actions"><button class="btn sm" onclick="viewReport('${esc(s.scan_id)}')">查看</button></td>
      </tr>`).join('')||'<tr><td colspan="8"><div class="empty"><div class="ico">◌</div><b>暂无扫描记录</b></div></td></tr>'}</tbody>
    </table></div>
  </div>`;
}

/* ==================== 设备发现 ==================== */
async function loadDiscover(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>设备发现</h2><p>输入网段或主机列表，逐台完成 端口 → 服务 → 设备类型 → PHP 暴露面 四层收敛</p></div></div>
  <div class="grid" style="grid-template-columns:minmax(0,1fr)">
    <div class="card">
      <div class="card-h"><h3>扫描目标</h3><div class="sp"></div>
        <span class="pill info">L0 → L1 → L2 → L3</span></div>
      <div class="card-b">
        <div class="field"><label>网段 CIDR</label>
          <input id="d-cidr" placeholder="192.168.1.0/24  （最多 1024 台）"></div>
        <div class="field"><label>或 主机列表（每行一个）</label>
          <textarea id="d-hosts" placeholder="192.168.1.229&#10;192.168.1.188"></textarea></div>
        <div class="row">
          <div class="narrow"><label style="font-size:11.5px;font-weight:640;color:var(--text-2)">TCP 超时(s)</label>
            <input id="d-timeout" type="number" value="1.2" step="0.1"></div>
          <div class="narrow"><label style="font-size:11.5px;font-weight:640;color:var(--text-2)">HTTP 超时(s)</label>
            <input id="d-htimeout" type="number" value="8" step="1"></div>
          <div style="flex:0 0 auto;align-self:flex-end;display:flex;gap:8px">
            <label class="pill mute" style="cursor:pointer"><input type="checkbox" id="d-save" checked style="width:auto;margin-right:5px">保存到台账</label>
            <button class="btn primary" id="d-run">开始发现</button></div>
        </div>
        <div class="progress hide" id="d-prog"><i></i></div>
        <div id="d-status" class="t-sm t-mute" style="margin-top:6px"></div>
      </div>
    </div>
  </div>
  <div class="grid dev-grid" id="d-results" style="margin-top:16px"></div>`;

  $('#d-run').onclick=async()=>{
    const hosts=$('#d-hosts').value.split('\n').map(x=>x.trim()).filter(Boolean);
    const cidr=$('#d-cidr').value.trim();
    if(!hosts.length&&!cidr){toast('请填写网段或主机列表','warn');return}
    const btn=$('#d-run'); btn.disabled=true; btn.textContent='扫描中…';
    $('#d-prog').classList.remove('hide');
    $('#d-status').textContent='正在探测端口与服务，请稍候…';
    try{
      const r=await api('/api/discover',{method:'POST',body:JSON.stringify({
        hosts,cidr,timeout:parseFloat($('#d-timeout').value)||1.2,
        http_timeout:parseFloat($('#d-htimeout').value)||8,
        save:$('#d-save').checked})});
      $('#d-prog').querySelector('i').style.width='100%';
      $('#d-status').textContent=`完成：${r.count} 台目标`;
      toast(`发现完成，识别 ${r.count} 台设备`,'ok');
      renderDevices($('#d-results'),r.assets);
    }catch(e){toast('扫描失败: '+e.message,'err');$('#d-status').textContent=''}
    finally{btn.disabled=false;btn.textContent='开始发现';setTimeout(()=>$('#d-prog').classList.add('hide'),600)}
  };
  const saved=(await api('/api/assets')).assets;
  if(saved.length) renderDevices($('#d-results'),saved);
}

function renderDevices(box,assets){
  if(!assets||!assets.length){box.innerHTML='<div class="empty" style="grid-column:1/-1"><div class="ico">⌖</div><b>暂无设备</b><p>输入网段或主机列表后点击「开始发现」</p></div>';return}
  box.innerHTML=assets.map(a=>{
    const exp=EXP[a.exposure]||['mute',a.exposure||'未知'];
    const ico=DEVI[a.device_type]||'❔';
    const phpPorts=(a.services||[]).filter(s=>s.php_hint).map(s=>s.port);
    return `<div class="dev" onclick="openAsset('${esc(a.host)}')">
      <div class="dev-top">
        <div class="dev-ico">${ico}</div>
        <div style="min-width:0;flex:1">
          <h4>${esc(a.device_label||'未识别设备')}</h4>
          <div class="ip">${esc(a.host)}</div>
        </div>
        ${pill(exp[0],exp[1])}
      </div>
      <div class="dev-meta">
        ${a.vendor?pill('pur',a.vendor):''}
        ${a.os_hint?pill('mute',a.os_hint):''}
        ${a.php_version?pill('crit','PHP '+esc(a.php_version)):a.php_present?pill('warn','PHP 版本未知'):''}
        ${a.sapi?pill('info',SAPI_RISK[a.sapi]||a.sapi):''}
      </div>
      <div class="ports" style="margin-top:10px">
        ${(a.open_ports||[]).slice(0,18).map(p=>`<span class="port ${phpPorts.includes(p)?'php':(/^(80|443|8080|8443|2000|8888|10000)$/.test(p)?'web':'')}">${p}</span>`).join('')}
        ${(a.open_ports||[]).length>18?`<span class="port">+${a.open_ports.length-18}</span>`:''}
      </div>
      <div class="dev-foot">
        <span>置信度 ${((a.confidence||0)*100).toFixed(0)}%</span><span>·</span>
        <span>${(a.evidence||[]).length} 条证据</span><span style="margin-left:auto">详情 →</span>
      </div>
    </div>`;
  }).join('');
}/* ==================== 资产台账 ==================== */
async function loadAssets(c){
  const a=(await api('/api/assets')).assets; STATE.assets=a;
  c.innerHTML=`
  <div class="page-head"><div><h2>资产台账</h2><p>共 ${a.length} 台设备</p></div><div class="sp"></div>
    <button class="btn" onclick="location.hash='discover'">＋ 发现设备</button>
    <button class="btn" id="a-export">⇩ 导出 CSV</button></div>
  <div class="card">
    <div class="card-h">
      <div class="seg" id="a-filter">
        <button class="on" data-f="all">全部</button>
        <button data-f="exposed">暴露</button>
        <button data-f="patched">已修复</button>
        <button data-f="not_php">无 PHP</button>
        <button data-f="unknown">待确认</button>
      </div>
      <div class="sp"></div>
      <input id="a-search" placeholder="搜索 IP / 厂商 / 设备类型" style="max-width:250px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>设备类型</th><th>厂商</th><th>PHP</th><th>SAPI</th><th>暴露面</th><th>风险</th><th>分组</th><th>负责人</th><th></th></tr></thead>
      <tbody id="a-body"></tbody>
    </table></div>
  </div>`;

  const draw=()=>{
    const f=$('#a-filter .on').dataset.f, q=$('#a-search').value.trim().toLowerCase();
    let rows=a.filter(x=>{
      if(f==='exposed'&&x.exposure!=='exposed')return false;
      if(f==='patched'&&x.exposure!=='patched')return false;
      if(f==='not_php'&&x.exposure!=='not_php')return false;
      if(f==='unknown'&&x.exposure!=='unknown')return false;
      if(q&&!((x.host||'')+(x.device_label||'')+(x.vendor||'')+(x.php_version||'')).toLowerCase().includes(q))return false;
      return true;
    });
    $('#a-body').innerHTML=rows.map(x=>`<tr>
      <td class="t-host">${esc(x.host)}</td>
      <td>${DEVI[x.device_type]||'❔'} ${esc(x.device_label||'-')}</td>
      <td>${x.vendor?esc(x.vendor):'<span class="t-mute">-</span>'}</td>
      <td class="num">${x.php_version?'<b>'+esc(x.php_version)+'</b>':(x.php_present?'<span class="pill warn">未知</span>':'<span class="t-mute">无</span>')}</td>
      <td class="t-sm">${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'<span class="t-mute">-</span>'}</td>
      <td>${pill((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
      <td>${pill((RISK[x.risk]||['mute','?'])[0],(RISK[x.risk]||['mute','?'])[1])}</td>
      <td class="t-sm">${esc(x.group||'-')}</td>
      <td class="t-sm">${esc(x.owner||'-')}</td>
      <td class="row-actions">
        <button class="btn sm" onclick="event.stopPropagation();openAsset('${esc(x.host)}')">详情</button>
        <button class="btn sm ghost" onclick="event.stopPropagation();rescan('${esc(x.host)}')">复扫</button>
      </td></tr>`).join('')||'<tr><td colspan="10"><div class="empty"><div class="ico">▤</div><b>没有匹配的资产</b></div></td></tr>';
  };
  $$('#a-filter button').forEach(b=>b.onclick=()=>{$$('#a-filter button').forEach(x=>x.classList.remove('on'));b.classList.add('on');draw()});
  $('#a-search').oninput=draw; draw();
  $('#a-export').onclick=()=>{window.location='/api/assets/export'};
}

/* ==================== 抽屉：资产详情 ==================== */
async function openAsset(host){
  let x=STATE.assets.find(y=>y.host===host);
  if(!x){STATE.assets=(await api('/api/assets')).assets;x=STATE.assets.find(y=>y.host===host)}
  if(!x){toast('未找到资产','err');return}
  $('#drawer-title').textContent=x.host;
  const exp=EXP[x.exposure]||['mute','未知'];
  const svcRows=(x.services||[]).filter(s=>s.http_status||s.banner||s.tls_subject);
  $('#drawer-body').innerHTML=`
    <div class="sect">
      <div class="sect-t">设备画像</div>
      <div class="row" style="margin-bottom:11px">
        ${pill(exp[0],exp[1])} ${pill((RISK[x.risk]||['mute','?'])[0],(RISK[x.risk]||['mute','?'])[1])}
        ${x.vendor?pill('pur',x.vendor):''} ${x.os_hint?pill('mute',x.os_hint):''}
      </div>
      <dl class="kv">
        <dt>设备类型</dt><dd>${DEVI[x.device_type]||''} ${esc(x.device_label||'-')}</dd>
        <dt>判定置信度</dt><dd class="num">${((x.confidence||0)*100).toFixed(0)}%</dd>
        <dt>PHP</dt><dd>${x.php_version?'<b>PHP '+esc(x.php_version)+'</b>':(x.php_present?'存在但版本未知':'未检测到')}</dd>
        <dt>SAPI</dt><dd>${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</dd>
        <dt>开放端口</dt><dd><div class="ports">${(x.open_ports||[]).map(p=>`<span class="port">${p}</span>`).join('')||'-'}</div></dd>
        <dt>分组/负责人</dt><dd>${esc(x.group||'-')} / ${esc(x.owner||'-')}</dd>
        <dt>最后检测</dt><dd class="num t-mute">${esc(x.last_checked||'-')}</dd>
      </dl>
    </div>
    ${(x.remediation||[]).length?`<div class="sect"><div class="sect-t">处置建议</div>
      <div class="fixbox ${x.exposure==='exposed'?'warn':''}">
        <b>${x.exposure==='exposed'?'需立即处置':'说明'}</b>
        <ul>${(x.remediation||[]).map(r=>`<li>${esc(r)}</li>`).join('')}</ul></div></div>`:''}
    ${svcRows.length?`<div class="sect"><div class="sect-t">服务明细</div>
      <div class="tbl-wrap"><table><thead><tr><th>端口</th><th>协议</th><th>状态</th><th>Server</th><th>标题/证书</th></tr></thead>
      <tbody>${svcRows.map(s=>`<tr>
        <td class="num">${s.port}</td><td class="t-sm">${esc(s.proto||'-')}</td>
        <td class="num">${s.http_status||'-'}</td>
        <td class="t-sm">${esc(s.server||'-')}</td>
        <td class="t-sm">${esc(s.http_title||s.tls_subject||s.banner||'-')}</td></tr>`).join('')}</tbody></table></div></div>`:''}
    <div class="sect"><div class="sect-t">判定证据（${(x.evidence||[]).length}）</div>
      ${(x.evidence||[]).map(e=>`<div class="evi">${esc(e)}</div>`).join('')||'<div class="t-mute t-sm">无</div>'}</div>
    ${(x.errors||[]).length?`<div class="sect"><div class="sect-t">错误</div>
      ${(x.errors||[]).map(e=>`<div class="evi" style="border-left-color:var(--danger)">${esc(e)}</div>`).join('')}</div>`:''}`;
  $('#drawer-foot').innerHTML=`
    <button class="btn" onclick="rescan('${esc(x.host)}')">↻ 重新检测</button>
    <button class="btn ghost" onclick="delAsset('${esc(x.host)}')">移出台账</button>
    <div class="sp"></div>
    <button class="btn primary" onclick="closeDrawer()">完成</button>`;
  $('#drawer').classList.add('on'); $('#drawer-bg').classList.add('on');
}
function closeDrawer(){$('#drawer').classList.remove('on');$('#drawer-bg').classList.remove('on')}
$('#drawer-close').onclick=closeDrawer; $('#drawer-bg').onclick=closeDrawer;
async function rescan(host){toast('正在重新检测 '+host+'…');
  try{await api('/api/assets/rescan',{method:'POST',body:JSON.stringify({host})});
    toast('复扫完成','ok');go(location.hash.slice(1)||'overview')}
  catch(e){toast('复扫失败: '+e.message,'err')}}
async function delAsset(host){if(!confirm('将 '+host+' 移出台账？'))return;
  try{await api('/api/assets?host='+encodeURIComponent(host),{method:'DELETE'});toast('已移除','ok');closeDrawer();go(location.hash.slice(1)||'overview')}
  catch(e){toast('删除失败: '+e.message,'err')}}

/* ==================== PHP 暴露面 ==================== */
async function loadPhp(c){
  const r=await api('/api/php-exposure');
  c.innerHTML=`
  <div class="page-head"><div><h2>PHP 暴露面</h2><p>只列出真正跑 PHP 的资产 —— 其它设备与本漏洞无关，不必处置</p></div>
    <div class="sp"></div>
    <span class="pill info">修复基线 ${Object.values(r.fixed_releases).join(' / ')}</span></div>
  <div class="grid kpis">
    <div class="kpi danger"><div class="k">⛔ 暴露</div><div class="v num">${r.rows.filter(x=>x.exposure==='exposed').length}</div><div class="d">版本低于基线</div></div>
    <div class="kpi ok"><div class="k">✅ 已修复</div><div class="v num">${r.rows.filter(x=>x.exposure==='patched').length}</div><div class="d">已达基线</div></div>
    <div class="kpi warn"><div class="k">⚠ 待确认</div><div class="v num">${r.rows.filter(x=>x.exposure==='unknown').length}</div><div class="d">有 PHP 迹象无版本</div></div>
    <div class="kpi"><div class="k">🐘 PHP 资产总数</div><div class="v num">${r.rows.length}</div><div class="d"></div></div>
  </div>
  <div class="card">
    <div class="card-h"><h3>受影响资产明细</h3></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>设备</th><th>PHP 版本</th><th>SAPI</th><th>修复基线</th><th>状态</th><th>判定说明</th><th>负责人</th></tr></thead>
      <tbody>${r.rows.map(x=>`<tr>
        <td class="t-host">${esc(x.host)}</td>
        <td>${esc(x.device_label||'-')}</td>
        <td class="num"><b>${esc(x.php_version||'?')}</b></td>
        <td class="t-sm">${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</td>
        <td class="num t-mute">${esc(x.fixed_release||'-')}</td>
        <td>${pill((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
        <td class="t-sm t-mute">${esc(x.reason||'')}</td>
        <td class="t-sm">${esc(x.owner||'-')}</td></tr>`).join('')
        ||'<tr><td colspan="8"><div class="empty"><div class="ico">🐘</div><b>没有跑 PHP 的资产</b><p>所有已发现设备均与 php2shell 无关</p></div></td></tr>'}
      </tbody></table></div>
  </div>`;
}

/* ==================== 日志分析 ==================== */
async function loadLogs(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>日志分析</h2><p>被动检测，零风险 · 支持 CLF / JSON / KV 三种格式自动识别</p></div></div>
  <div class="card" style="margin-bottom:16px">
    <div class="card-h"><h3>选择日志文件</h3></div>
    <div class="card-b">
      <div class="row">
        <input id="l-path" placeholder="日志文件绝对路径，例如 /var/log/nginx/access.log">
        <button class="btn primary" id="l-run" style="flex:0 0 auto">开始分析</button>
      </div>
      <div class="t-sm t-mute" style="margin-top:8px">提示：标准访问日志<b>不记录请求体</b>，因此 <code>PHP_SESSION_UPLOAD_PROGRESS</code> 类规则需要开启请求体落盘（WAF 日志 / <code>$request_body</code>）才能覆盖。报告会明确标出覆盖缺口。</div>
    </div>
  </div>
  <div id="l-out"></div>`;
  $('#l-run').onclick=async()=>{
    const p=$('#l-path').value.trim(); if(!p){toast('请填写日志路径','warn');return}
    $('#l-out').innerHTML='<div class="card"><div class="card-b"><div class="empty"><div class="ico">◌</div><b>分析中…</b></div></div></div>';
    try{const r=await api('/api/scan/logs',{method:'POST',body:JSON.stringify({path:p})});STATE.lastLog=r;renderLog(r)}
    catch(e){$('#l-out').innerHTML=`<div class="card"><div class="card-b"><div class="empty"><div class="ico">⚠</div><b>分析失败</b><p>${esc(e.message)}</p></div></div></div>`}
  };
  if(STATE.lastLog) renderLog(STATE.lastLog);
}
function renderLog(r){
  const c=$('#l-out');
  const cov=r.coverage||{};
  c.innerHTML=`
  <div class="grid kpis">
    <div class="kpi ${r.risk==='critical'?'danger':''}"><div class="k">总体风险</div><div class="v" style="font-size:22px">${esc((r.risk||'').toUpperCase())}</div><div class="d">${r.findings.length} 条命中</div></div>
    <div class="kpi danger"><div class="k">严重</div><div class="v num">${r.severity_counts?.critical||0}</div></div>
    <div class="kpi warn"><div class="k">高危</div><div class="v num">${r.severity_counts?.high||0}</div></div>
    <div class="kpi"><div class="k">解析记录</div><div class="v num">${cov.parsed_records||0}</div><div class="d">共 ${cov.total_lines||0} 行</div></div>
    <div class="kpi ${(cov.uncovered||[]).length?'warn':'ok'}"><div class="k">规则覆盖缺口</div><div class="v num">${(cov.uncovered||[]).length}</div><div class="d">条规则无法命中</div></div>
  </div>
  <div class="card">
    <div class="card-h"><h3>命中明细</h3><div class="sp"></div>
      <button class="btn sm" onclick="viewReport('${esc(r.scan_id)}')">导出报告</button></div>
    <div class="tbl-wrap"><table><thead><tr><th>规则</th><th>名称</th><th>等级</th><th>维度</th><th>时间</th><th>来源 IP</th><th>URI</th><th>证据</th></tr></thead>
      <tbody>${(r.findings||[]).map(f=>`<tr>
        <td class="t-host">${esc(f.rule_id)}</td><td class="t-sm">${esc(f.rule_name)}</td>
        <td>${pill((RISK[f.severity]||['mute',f.severity])[0],(RISK[f.severity]||['mute',f.severity])[1])}</td>
        <td class="t-sm t-mute">${esc(f.dimension)}</td>
        <td class="t-sm t-mute num">${esc((f.ts||'').replace('T',' ').slice(0,19))}</td>
        <td class="t-host">${esc(f.ip||'-')}</td>
        <td class="t-sm">${esc((f.uri||'-').slice(0,48))}</td>
        <td class="t-sm t-mute">${esc(f.evidence||'')}</td></tr>`).join('')
        ||'<tr><td colspan="8"><div class="empty"><div class="ico">✓</div><b>未发现异常</b></div></td></tr>'}</tbody></table></div>
  </div>
  ${(cov.uncovered||[]).length?`<div class="card" style="margin-top:16px">
    <div class="card-h"><h3>覆盖缺口</h3><div class="sp"></div><span class="pill warn">需开启请求体/响应体落盘</span></div>
    <div class="card-b"><div class="row">${cov.uncovered.map(r=>`<span class="pill mute">${esc(r)}</span>`).join('')}</div>
    <div class="t-sm t-mute" style="margin-top:10px">这些规则依赖请求体或响应体字段，普通访问日志不含这些内容，因此无法命中。建议在 WAF 或反代层开启请求体记录。</div></div></div>`:''}`;
}

/* ==================== 主机侧 ==================== */
async function loadHost(c){
  c.innerHTML=`
  <div class="page-head"><div><h2>主机侧检测</h2><p>读取本机 PHP 安装点、生效配置、可疑文件、进程与连接 —— 全部只读</p></div>
    <div class="sp"></div><button class="btn primary" id="h-run">执行检测</button></div>
  <div id="h-out"><div class="card"><div class="card-b"><div class="empty"><div class="ico">⛨</div><b>尚未执行</b><p>点击右上角按钮开始检测当前这台机器</p></div></div></div></div>`;
  $('#h-run').onclick=async()=>{
    $('#h-out').innerHTML='<div class="card"><div class="card-b"><div class="empty"><div class="ico">◌</div><b>检测中…</b></div></div></div>';
    try{const r=await api('/api/scan/host',{method:'POST'});renderHost(r)}
    catch(e){$('#h-out').innerHTML=`<div class="card"><div class="card-b"><div class="empty"><div class="ico">⚠</div><p>${esc(e.message)}</p></div></div></div>`}
  };
}
function renderHost(r){
  const h=(r.host_reports||[])[0]||{};
  $('#h-out').innerHTML=`
  <div class="grid kpis">
    <div class="kpi ${h.risk==='critical'?'danger':(h.risk==='high'?'warn':'')}"><div class="k">主机风险</div><div class="v" style="font-size:22px">${esc((h.risk||'').toUpperCase())}</div><div class="d">${esc(h.hostname||'')}</div></div>
    <div class="kpi"><div class="k">PHP 安装点</div><div class="v num">${(h.installs||[]).length}</div></div>
    <div class="kpi ${(h.artifacts||[]).length?'danger':'ok'}"><div class="k">可疑痕迹</div><div class="v num">${(h.artifacts||[]).length}</div></div>
    <div class="kpi"><div class="k">配置项</div><div class="v num">${(h.settings||[]).length}</div><div class="d">生效值核查</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
    <div class="card"><div class="card-h"><h3>PHP 安装点</h3></div>
      <div class="tbl-wrap"><table><thead><tr><th>版本</th><th>SAPI</th><th>路径</th><th>状态</th></tr></thead>
        <tbody>${(h.installs||[]).map(i=>`<tr><td class="num"><b>${esc(i.version||'?')}</b></td>
          <td class="t-sm">${esc(i.sapi||'-')}</td><td class="t-sm t-mute">${esc(i.path)}</td>
          <td>${i.needs_action?pill('crit','需升级'):pill('ok','已修复')}</td></tr>`).join('')
          ||'<tr><td colspan="4" class="t-mute t-sm" style="padding:18px">本机未发现 PHP</td></tr>'}</tbody></table></div></div>
    <div class="card"><div class="card-h"><h3>关键配置生效值</h3></div>
      <div class="tbl-wrap"><table><thead><tr><th>配置项</th><th>实际值</th><th>期望</th><th></th></tr></thead>
        <tbody>${(h.settings||[]).map(s=>`<tr><td class="t-sm">${esc(s.name)}</td>
          <td class="num">${esc(s.actual||'-')}</td><td class="t-sm t-mute num">${esc(s.expected)}</td>
          <td>${s.ok?pill('ok','OK'):pill('warn','需调整')}</td></tr>`).join('')
          ||'<tr><td colspan="4" class="t-mute t-sm" style="padding:18px">无</td></tr>'}</tbody></table></div></div>
  </div>
  <div class="card" style="margin-top:16px"><div class="card-h"><h3>可疑痕迹</h3><div class="sp"></div>
    <span class="pill ${(h.artifacts||[]).length?'crit':'ok'}">${(h.artifacts||[]).length}</span></div>
    <div class="card-b">${(h.artifacts||[]).length?(h.artifacts||[]).map(a=>`
      <div class="evi" style="border-left-color:var(--danger)">${pill((RISK[a.severity]||['mute',a.severity])[0],a.kind)} ${esc(a.path)}<br><span class="t-mute">${esc(a.detail||'')}</span></div>`).join('')
      :'<div class="empty" style="padding:26px"><div class="ico">✓</div><b>未发现可疑痕迹</b></div>'}</div></div>`;
}/* ==================== 规则中心 ==================== */
async function loadRules(c){
  const r=await api('/api/rules'); STATE.rules=r.rules;
  c.innerHTML=`
  <div class="page-head"><div><h2>规则中心</h2><p>${r.count} 条数据驱动检测规则 · 可一键导出到 SIEM / WAF / IDS</p></div>
    <div class="sp"></div>
    <button class="btn" onclick="exportRules('sigma')">Sigma</button>
    <button class="btn" onclick="exportRules('modsecurity')">ModSecurity</button>
    <button class="btn" onclick="exportRules('suricata')">Suricata</button></div>
  <div class="card">
    <div class="card-h"><h3>规则列表</h3><div class="sp"></div>
      <span class="pill mute">维度：request / response / host / behavior / recon</span></div>
    <div class="tbl-wrap"><table><thead><tr><th>ID</th><th>名称</th><th>等级</th><th>维度</th><th>需要字段</th><th>涉及 CVE</th><th>说明</th></tr></thead>
      <tbody>${r.rules.map(x=>`<tr>
        <td class="t-host">${esc(x.id)}</td>
        <td style="font-weight:600">${esc(x.name)}</td>
        <td>${pill((RISK[x.severity]||['mute',x.severity])[0],x.severity)}</td>
        <td class="t-sm t-mute">${esc(x.dimension)}</td>
        <td><code>${esc(x.requires)}</code></td>
        <td class="t-sm">${(x.cves||[]).map(c=>`<span class="pill mute">${esc(c)}</span>`).join(' ')}</td>
        <td class="t-sm t-mute">${esc(x.description)}</td></tr>`).join('')}</tbody></table></div>
  </div>`;
}
async function exportRules(fmt){
  try{const t=await (await fetch('/api/rules/export/'+fmt)).text();
    const b=new Blob([t],{type:'text/plain'});const u=URL.createObjectURL(b);
    const a=document.createElement('a');a.href=u;a.download='p2s-php2shell.'+fmt;a.click();
    toast('已导出 '+fmt+' 规则','ok')}
  catch(e){toast('导出失败: '+e.message,'err')}}

/* ==================== IOC ==================== */
async function loadIoc(c){
  const r=await api('/api/ioc'); STATE.ioc=r;
  c.innerHTML=`
  <div class="page-head"><div><h2>IOC 中心</h2><p>来源：TU Delft INTELLAB 蜜罐观测 / NCSC-NL / CISA KEV · 更新于 ${esc(r.summary.updated)}</p></div></div>
  <div class="grid kpis">
    <div class="kpi danger"><div class="k">攻击者 IP</div><div class="v num">${r.summary.ips}</div></div>
    <div class="kpi warn"><div class="k">域名</div><div class="v num">${r.summary.domains}</div></div>
    <div class="kpi"><div class="k">URL</div><div class="v num">${r.summary.urls}</div></div>
    <div class="kpi purple"><div class="k">样本哈希</div><div class="v num">${r.summary.hashes}</div></div>
    <div class="kpi"><div class="k">UA 特征</div><div class="v num">${r.summary.user_agents}</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr;gap:16px">
    <div class="card"><div class="card-h"><h3>基础设施</h3></div><div class="card-b">
      <div class="sect-t">IP</div>${r.ips.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:14px">域名</div>${r.domains.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:14px">User-Agent 特征</div>${r.user_agents.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
    </div></div>
    <div class="card"><div class="card-h"><h3>Dropper URL</h3></div><div class="card-b">
      ${r.urls.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:14px">恶意样本</div>
      ${Object.entries(r.hashes).map(([h,d])=>`<div class="evi"><b>${esc(d)}</b><br><span class="t-mute">${esc(h)}</span></div>`).join('')}
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
        <td class="t-host">${esc(s.scan_id)}</td><td>${esc(s.kind)}</td>
        <td>${pill((RISK[s.risk]||['mute','?'])[0],(RISK[s.risk]||['mute','?'])[1])}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td><td class="num">${s.severity_counts?.high||0}</td>
        <td class="t-sm t-mute num">${esc(s.started_at)}</td>
        <td class="row-actions">
          <button class="btn sm" onclick="viewReport('${esc(s.scan_id)}')">查看</button>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=md" target="_blank">MD</a>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=html" target="_blank">HTML</a>
        </td></tr>`).join('')||'<tr><td colspan="8"><div class="empty"><div class="ico">◲</div><b>暂无报告</b></div></td></tr>'}</tbody></table></div></div>`;
}
async function viewReport(id){
  const t=await (await fetch('/api/scans/'+id+'/report?fmt=md')).text();
  $('#drawer-title').textContent='报告 · '+id;
  $('#drawer-body').innerHTML='<pre>'+esc(t)+'</pre>';
  $('#drawer-foot').innerHTML=`<a class="btn" href="/api/scans/${id}/report?fmt=md" target="_blank">⇩ 下载 Markdown</a>
    <a class="btn" href="/api/scans/${id}/report?fmt=html" target="_blank">⇩ 下载 HTML</a>
    <div class="sp"></div><button class="btn primary" onclick="closeDrawer()">关闭</button>`;
  $('#drawer').classList.add('on');$('#drawer-bg').classList.add('on');
}

/* ==================== 启动 ==================== */
go(location.hash.slice(1)||'overview');
</script>
</body>
</html>
"""