/* ==================== 基础 ==================== */
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
const KIND={discover:'设备发现',logs:'日志分析',host:'主机侧检测',url:'URL 探测',agent:'Agent 上报'};
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
$('#btn-menu').onclick=()=>$('.sidebar').classList.toggle('open');
$$('.nav a').forEach(a=>a.addEventListener('click',()=>$('.sidebar').classList.remove('open')));
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='b'){e.preventDefault();$('.sidebar').classList.toggle('mini')}
  if(e.key==='Escape')closeDrawer();
});
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
    renderSideStat();
    if(location.hash.slice(1)==='tasks' && $('#jobs-body')) renderJobs();
    if(location.hash.slice(1)==='discover' && $('#d-jobs')){
      const before = S.jobs.map(j=>j.id+':'+j.state).join(',');
      renderDiscoverJobs();
      if(before !== S._lastJobSig){ S._lastJobSig = before; refreshDiscoverResults(); }
    }
  }catch(e){}
  S.timer=setTimeout(pollJobs,1500);
}

function renderSideStat(){
  const el=$('#side-stat-body'); if(!el) return;
  const o=STATE.overview; if(!o){el.textContent='—';return}
  el.innerHTML = o.exposed>0
    ? `<span class="r">${o.exposed} 台</span> 暴露待修复<br><span class="o">${o.unknown||0} 台</span> 版本待确认`
    : (o.unknown>0 ? `<span class="o">${o.unknown} 台</span> 版本待确认<br>其余 ${o.not_php||0} 台无关`
                    : `<span class="g">无暴露</span><br>${o.total_assets||0} 台已核查`);
}

/* ==================== 表格排序 ==================== */
function makeSortable(tableId,rowSel,getVal){
  const tbl=document.getElementById(tableId); if(!tbl) return;
  tbl.querySelectorAll('th.sortable').forEach((th,i)=>{
    th.onclick=()=>{
      const dir=th.classList.contains('asc')?'desc':'asc';
      tbl.querySelectorAll('th').forEach(x=>x.classList.remove('asc','desc'));
      th.classList.add(dir);
      const body=tbl.querySelector('tbody');
      const rows=[...body.querySelectorAll(rowSel)];
      rows.sort((a,b)=>{
        const va=String(getVal(a,i)??''), vb=String(getVal(b,i)??'');
        const na=parseFloat(va), nb=parseFloat(vb);
        if(va!==''&&vb!==''&&!isNaN(na)&&!isNaN(nb)) return dir==='asc'?na-nb:nb-na;
        return dir==='asc'?va.localeCompare(vb,'zh'):vb.localeCompare(va,'zh');
      });
      rows.forEach(r=>body.appendChild(r));
    };
  });
}

/* ==================== 态势总览 ==================== */
async function loadOverview(c){
  const o=await api('/api/overview');
  S.assets=(await api('/api/assets')).assets;
  const exp=[['exposed',o.exposed],['unknown',o.unknown],['patched',o.patched],['not_php',o.not_php]];
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
  ${o.exposed>0
    ? `<div class="alert">${ico('alert')}<div class="body"><b>${o.exposed} 台资产暴露于 CVE-2026-109618 / 109619</b>
        PHP 版本低于修复基线（8.5.12 / 8.4.27 / 8.3.36 / 8.2.35）。该漏洞已被 CISA 列入 KEV，存在在野利用，需立即处置。</div>
        <div class="act"><button class="btn sm" onclick="location.hash='php'">查看清单</button></div></div>`
    : (o.php_present>0
      ? `<div class="alert warn">${ico('alert')}<div class="body"><b>${o.php_present} 台资产运行 PHP，其中 ${o.unknown} 台版本待确认</b>
          这些设备不暴露 PHP 版本号，需人工确认后判定是否受影响。</div>
          <div class="act"><button class="btn sm" onclick="location.hash='php'">查看</button></div></div>`
      : (o.total_assets>0
        ? `<div class="alert ok">${ico('check')}<div class="body"><b>当前未发现暴露资产</b>
            已核查 ${o.total_assets} 台，其中 ${o.not_php} 台不运行 PHP，其余均已达到修复基线。</div></div>`
        : ''))}
  <div class="grid kpis">
    <div class="kpi ${o.exposed?'primary':'quiet'}"><div class="k">${ico('alert','s12')}暴露待修复</div><div class="v num">${o.exposed}</div>
      <div class="d">${o.exposed?'版本低于修复基线，需立即处置':'当前无暴露资产'}</div></div>
    <div class="kpi ${o.php_present?'':'quiet'}"><div class="k">${ico('code','s12')}含 PHP 资产</div><div class="v num">${o.php_present}</div>
      <div class="d">${o.unknown?`${o.unknown} 台版本待确认`:'版本均已确认'}</div></div>
    <div class="kpi quiet"><div class="k">${ico('check','s12')}已修复</div><div class="v num">${o.patched}</div><div class="d">已达基线版本</div></div>
    <div class="kpi quiet"><div class="k">${ico('shield','s12')}不含 PHP</div><div class="v num">${o.not_php}</div><div class="d">与本漏洞无关</div></div>
    <div class="kpi quiet"><div class="k">${ico('box','s12')}资产总数</div><div class="v num">${o.total_assets}</div>
      <div class="d">存活 ${o.alive} · ${o.groups.length} 个分组</div></div>
    <div class="kpi quiet"><div class="k">${ico('clock','s12')}运行中任务</div><div class="v num">${runJobs}</div><div class="d">累计 ${o.scan_count} 次扫描</div></div>
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
        <button class="btn sm ghost" onclick="location.hash='discover'">设备发现 →</button></div>
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
      <button class="btn sm ghost" onclick="location.hash='reports'">全部报告 →</button></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始时间</th><th></th></tr></thead>
      <tbody>${(o.recent_scans||[]).map(s=>`<tr>
        <td class="mono">${esc(s.scan_id)}</td><td>${esc(KIND[s.kind]||s.kind)}</td>
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
  const off = latest && latest.result && latest.result.offline !== undefined ? latest.result.offline : null;
  box.innerHTML=`<div style="grid-column:1/-1;display:flex;align-items:center;gap:9px;margin-bottom:2px">
      <span style="font-size:12.5px;font-weight:600">${esc(label)}</span>
      <span class="muted" style="font-size:11.5px">在线 ${S.assets.length} 台</span>
      ${off!==null?`<span class="muted" style="font-size:11.5px">· 已排除 ${off} 台无有效响应（离线 / NAT 拦截）</span>`:''}
      </div>`+
    (latest?`<div style="grid-column:1/-1" class="hint">下方为本次扫描识别到的在线设备；端口可连但无协议响应的目标（出口 NAT / tarpit）已自动排除。台账完整列表见「资产台账」。</div>`:'');
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
    '<b>还没有扫描过任何设备</b><div class="guide"><ol>'+'<li>在上方填入<strong>网段</strong>（如 <code>192.168.1.0/24</code>）或<strong>主机列表</strong></li>'+'<li>选扫描深度：<strong>快速</strong>约 1.4 秒/台；<strong>深度</strong>约 2.5 秒/台（110+ 端口 + TLS 证书 + 登录路径）</li>'+'<li>点击<strong>开始扫描</strong>，后台执行，可随时切页或取消</li>'+'<li><strong>离线主机会自动排除</strong>，只有真正在线的设备进入台账</li>'+'</ol></div></div>';return}
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
        ${a.product?tag('info',a.product):''}
        ${a.vendor?tag('pur',a.vendor):''}
        ${a.os_hint?tag('mute',a.os_hint):''}
        ${(a.tech_stack||[]).map(x=>tag('crit',x)).join('')}
        ${a.php_version?tag('crit','PHP '+esc(a.php_version)):a.php_present?tag('warn','PHP 版本未知'):''}
        ${a.mac_vendor?tag('mute',a.mac_vendor):''}
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
  const selected=new Set();
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
      <select id="a-type" style="max-width:190px;margin-left:8px"></select>
      <div class="sp"></div>
      <input id="a-search" placeholder="搜索 IP / 厂商 / 设备类型" style="max-width:230px">
    </div>
    <div class="bulk hide" id="a-bulk">
      <span class="n">已选 <b id="a-sel-n">0</b> 台</span>
      <button class="btn sm" id="a-bulk-group">改分组</button>
      <button class="btn sm" id="a-bulk-owner">改负责人</button>
      <button class="btn sm danger" id="a-bulk-del">移出台账</button>
      <div class="sp"></div>
      <button class="btn sm ghost" id="a-bulk-clear">取消选择</button>
    </div>
    <div class="tbl-wrap"><table id="a-table">
      <thead><tr>
        <th style="width:34px"><input type="checkbox" id="a-all"></th>
        <th class="sortable">主机</th><th class="sortable">设备类型</th><th class="sortable">产品</th>
        <th class="sortable">厂商</th><th class="sortable">技术栈</th><th class="sortable">PHP</th>
        <th class="sortable">暴露面</th><th class="sortable">置信度</th><th>分组</th><th>负责人</th><th></th></tr></thead>
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

  const types=[...new Set(a.map(x=>x.device_label||'未识别设备'))].sort();
  $('#a-type').innerHTML='<option value="">全部设备类型</option>'+types.map(t=>`<option value="${esc(t)}">${esc(t)}</option>`).join('');

  const draw=()=>{
    const f=$('#a-filter .on').dataset.f, q=$('#a-search').value.trim().toLowerCase();
    const ty=$('#a-type').value;
    const rows=a.filter(x=>{
      if(f==='exposed'&&x.exposure!=='exposed')return false;
      if(f==='patched'&&x.exposure!=='patched')return false;
      if(f==='not_php'&&x.exposure!=='not_php')return false;
      if(f==='unknown'&&x.exposure!=='unknown')return false;
      if(ty&&(x.device_label||'未识别设备')!==ty)return false;
      if(q&&!((x.host||'')+(x.device_label||'')+(x.vendor||'')+(x.php_version||'')+(x.product||'')).toLowerCase().includes(q))return false;
      return true;
    });
    $('#a-body').innerHTML=rows.map(x=>`<tr>
      <td><input type="checkbox" class="a-chk" data-h="${esc(x.host)}" ${selected.has(x.host)?'checked':''}></td>
      <td class="mono h">${esc(x.host)}</td>
      <td>${ico(DEV_ICON[x.device_type]||'box','s12')} ${esc(x.device_label||'-')}</td>
      <td style="font-size:11.5px">${esc(x.product||'-')}</td>
      <td style="font-size:11.5px">${x.vendor?esc(x.vendor):'<span class="muted">-</span>'}</td>
      <td>${(x.tech_stack||[]).map(s=>tag('crit',s)).join(' ')||'<span class="muted">-</span>'}</td>
      <td class="num">${x.php_version?'<b>'+esc(x.php_version)+'</b>':(x.php_present?tag('warn','未知'):'<span class="muted">无</span>')}</td>
      <td>${tag((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
      <td class="num muted" style="font-size:11.5px">${((x.confidence||0)*100).toFixed(0)}%</td>
      <td><span class="editable" contenteditable="true" data-k="group" data-h="${esc(x.host)}">${esc(x.group||'')}</span></td>
      <td><span class="editable" contenteditable="true" data-k="owner" data-h="${esc(x.host)}">${esc(x.owner||'')}</span></td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn sm" onclick="event.stopPropagation();openAsset('${esc(x.host)}')">详情</button>
        <button class="btn sm ghost" onclick="event.stopPropagation();rescan('${esc(x.host)}')">复扫</button></td></tr>`).join('')
      ||'<tr><td colspan="11"><div class="empty">'+ico('list')+'<b>没有匹配的资产</b><p>换个筛选条件或清空搜索关键字试试</p></div></td></tr>';
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
  $('#a-type').onchange=draw;
  $('#a-search').oninput=draw; draw();
  makeSortable('a-table','tr',(tr,i)=>{
    const tds=tr.querySelectorAll('td');
    return (tds[i+1]?.textContent||'').trim();
  });
  const syncBulk=()=>{ $('#a-sel-n').textContent=selected.size;
    $('#a-bulk').classList.toggle('hide',selected.size===0); };
  $('#a-body').addEventListener('change',e=>{
    if(e.target.classList.contains('a-chk')){
      if(e.target.checked) selected.add(e.target.dataset.h); else selected.delete(e.target.dataset.h);
      syncBulk();
    }
  });
  $('#a-all').onchange=e=>{
    $$('#a-body .a-chk').forEach(c=>{c.checked=e.target.checked;
      if(e.target.checked) selected.add(c.dataset.h); else selected.delete(c.dataset.h)});
    syncBulk();
  };
  $('#a-bulk-clear').onclick=()=>{selected.clear();draw();};
  $('#a-bulk-group').onclick=async()=>{
    const v=prompt('将选中的 '+selected.size+' 台资产改到哪个分组？','default');
    if(v===null) return;
    for(const h of selected) await api('/api/assets',{method:'PATCH',body:{host:h,group:v}});
    toast('已更新 '+selected.size+' 台的分组','ok'); selected.clear(); await loadAssets($('#content'));
  };
  $('#a-bulk-owner').onclick=async()=>{
    const v=prompt('将选中的 '+selected.size+' 台资产负责人改为什么？');
    if(v===null) return;
    for(const h of selected) await api('/api/assets',{method:'PATCH',body:{host:h,owner:v}});
    toast('已更新 '+selected.size+' 台的负责人','ok'); selected.clear(); await loadAssets($('#content'));
  };
  $('#a-bulk-del').onclick=async()=>{
    if(!confirm('将选中的 '+selected.size+' 台资产移出台账？')) return;
    for(const h of selected) await api('/api/assets?host='+encodeURIComponent(h),{method:'DELETE'});
    toast('已移除 '+selected.size+' 台','ok'); selected.clear(); await loadAssets($('#content'));
  };
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
        <dt>具体产品</dt><dd>${esc(x.product||'-')}</dd>
        <dt>技术栈</dt><dd>${(x.tech_stack||[]).map(s=>tag('crit',s)).join(' ')||'<span class="muted">-</span>'}</dd>
        <dt>置信度</dt><dd class="num">${((x.confidence||0)*100).toFixed(0)}%</dd>
        <dt>MAC 厂商</dt><dd>${esc(x.mac_vendor||'-')} ${x.mac?`<span class="mono muted" style="font-size:11px">${esc(x.mac)}</span>`:''}</dd>
        <dt>有效端口</dt><dd class="num">${(x.meaningful_ports||[]).join(', ')||'-'}</dd>
        <dt>噪声端口</dt><dd class="num muted">${(x.noise_ports||[]).join(', ')||'-'}</dd>
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
    ${(x.candidates||[]).length?`<div class="sect"><div class="sect-t">其他候选</div>
      <div class="row">${(x.candidates||[]).map(c=>tag('mute',c.label+' ('+c.score+')')).join('')}</div></div>`:''}
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
    <div class="kpi"><div class="k">${ico('code','s12')}PHP 资产</div><div class="v num">${r.rows.length}</div><div class="d">总量</div></div>
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
  <div id="h-out"><div class="card"><div class="card-b"><div class="empty">'+ico('server')+'<b>尚未执行</b><div class="guide"><ol>'+'<li>检查本机<strong>PHP 安装点</strong>与版本（是否低于修复基线）</li>'+'<li>核查<strong>关键配置的生效值</strong>：upload_progress / fatal_error_backtraces / memory_limit / post_max_size</li>'+'<li>扫描临时与上传目录的<strong>可疑落地文件</strong>，比对已知恶意样本哈希</li>'+'<li>枚举 <strong>PHP 派生的 shell 子进程</strong>与外部连接</li></ol>'+'<p style="margin-top:10px">全部只读，不修改任何配置或文件。</p></div></div></div></div>`;
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
        <td class="mono">${esc(s.scan_id)}</td><td>${esc(KIND[s.kind]||s.kind)}</td>
        <td>${tag((RISK[s.risk]||['mute','?'])[0],(RISK[s.risk]||['mute','?'])[1])}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td><td class="num">${s.severity_counts?.high||0}</td>
        <td class="muted num" style="font-size:11.5px">${esc(s.started_at)}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="btn sm" onclick="viewReport('${esc(s.scan_id)}')">查看</button>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=md" target="_blank">MD</a>
          <a class="btn sm ghost" href="/api/scans/${esc(s.scan_id)}/report?fmt=html" target="_blank">HTML</a>
          <button class="btn sm ghost" onclick="delReport('${esc(s.scan_id)}')" title="删除">${ico('trash','s12')}</button>
        </td></tr>`).join('')||'<tr><td colspan="8"><div class="empty">'+ico('file')+'<b>还没有扫描报告</b><p>发起一次扫描后，这里会列出全部历史报告，可随时下载或删除</p></div></td></tr>'}</tbody></table></div></div>`;
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
