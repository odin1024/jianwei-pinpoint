async function loadOverview(c){
  const o=await api('/api/overview');
  S.assets=(await api('/api/assets')).assets;
  STATE.overview=o; renderSideStat();
  const exp=[['exposed',o.exposed],['unknown',o.unknown],['patched',o.patched],['not_php',o.not_php]];
  const COL={'exposed':'var(--danger)','patched':'var(--text-2)','not_php':'var(--chart-mute)','unknown':'var(--text-3)'};
  const total=Math.max(1,exp.reduce((s,x)=>s+x[1],0));
  let acc=0;
  const arcs=exp.map(([k,v])=>{
    const a0=acc/total*2*Math.PI,a1=(acc+v)/total*2*Math.PI;acc+=v;
    if(!v) return '';
    const large=(a1-a0)>Math.PI?1:0;
    const GAP=0.018;
    const a0g=a0+GAP/2,a1g=Math.max(a0g+0.001,a1-GAP/2);
    const x0=80+58*Math.sin(a0g),y0=80-58*Math.cos(a0g),x1=80+58*Math.sin(a1g),y1=80-58*Math.cos(a1g);
    const lx=80+36*Math.sin((a0+a1)/2),ly=80-36*Math.cos((a0+a1)/2);
    return `<path d="M ${x0.toFixed(2)} ${y0.toFixed(2)} A 56 56 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}"
      fill="none" stroke="${COL[k]}" stroke-width="11" stroke-linecap="butt"/>
      ${v/total>=0.08?`<text x="${lx.toFixed(1)}" y="${(ly+5).toFixed(1)}" text-anchor="middle" font-size="14" font-weight="620" fill="var(--text)">${v}</text>`:''}`;
  }).join('');
  const types=Object.entries(o.by_type).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxT=Math.max(1,...types.map(t=>t[1]));
  const runJobs=S.jobs.filter(j=>j.active).length;

  c.innerHTML=`
  <div class="grid kpis">
    <div class="kpi ${o.exposed?'primary':'quiet'}"><div class="k">${ico('alert','s12')}暴露待修复</div><div class="v num">${o.exposed}</div>
      <div class="d">${o.exposed?'版本低于修复基线，需立即处置':'当前无暴露资产'}</div></div>
    <div class="kpi ${o.php_present?'':'quiet'}"><div class="k">${ico('code','s12')}含 PHP 资产</div><div class="v num">${o.php_present}</div>
      <div class="d">${o.unknown?`${o.unknown} 台版本待确认`:'版本均已确认'}</div></div>
    <div class="kpi quiet"><div class="k">${ico('check','s12')}已修复</div><div class="v num">${o.patched}</div><div class="d">已达基线版本</div></div>
    <div class="kpi quiet"><div class="k">${ico('shield','s12')}不含 PHP</div><div class="v num">${o.not_php}</div><div class="d">与本漏洞无关</div></div>
    <div class="kpi quiet"><div class="k">${ico('box','s12')}资产总数</div><div class="v num">${o.total_assets}</div>
      <div class="d">存活 ${o.alive} · ${o.groups.length} 个分组</div></div>
    <div class="kpi ${(o.changes&&(o.changes.new||o.changes.changed))?'':'quiet'}"><div class="k">${ico('refresh','s12')}资产变化</div>
      <div class="v num">${o.changes?(o.changes.new+o.changes.changed):0}</div>
      <div class="d">新增 ${o.changes?o.changes.new:0} · 变更 ${o.changes?o.changes.changed:0} · 运行中 ${runJobs}${o.changes&&o.changes.gone?` · 消失 ${o.changes.gone}`:''}</div></div>
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

  <div class="card" style="margin-bottom:14px">
    <div class="card-h"><h3>修复进度</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">按资产口径统计</span></div>
    <div class="card-b">
      ${(()=>{
        const tot=(o.exposed||0)+(o.unknown||0)+(o.patched||0)+(o.not_php||0)||1;
        const seg=[
          ['暴露',o.exposed||0,'var(--danger)'],
          ['待确认',o.unknown||0,'var(--text-3)'],
          ['已修复',o.patched||0,'var(--text-2)'],
          ['不涉及',o.not_php||0,'var(--chart-mute)'],
        ];
        return `<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;
            background:var(--surface-3);margin-bottom:11px">
          ${seg.map(([n,v,c])=>v?`<i title="${n} ${v} 台" style="width:${(v/tot*100).toFixed(2)}%;background:${c}"></i>`:'').join('')}
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
          ${seg.map(([n,v,c])=>`<div style="display:flex;align-items:center;gap:7px">
            <span style="width:7px;height:7px;border-radius:50%;background:${c};display:inline-block"></span>
            <span class="muted" style="font-size:11.5px">${n}</span>
            <b class="num" style="font-size:12.5px;font-weight:600">${v}</b>
            <span class="muted num" style="font-size:11.5px">${Math.round(v/tot*100)}%</span>
          </div>`).join('')}
        </div>`;
      })()}
    </div>
  </div>

  <div class="card">
    <div class="card-h"><h3>最近扫描</h3><div class="sp"></div>
      <button class="btn sm ghost" onclick="location.hash='reports'">全部报告 →</button></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>扫描 ID</th><th>类型</th><th>风险</th><th>目标</th><th>严重</th><th>高危</th><th>开始时间</th><th></th></tr></thead>
      <tbody>${(()=>{
        // 同类型 + 同风险 + 同一小时内的扫描合并成一行：Agent 反复上报时不再刷屏
        const groups=[];
        for(const s of (o.recent_scans||[])){
          const ts=Date.parse((s.started_at||'').replace(' ','T'));
          const key=[s.kind,s.risk,isNaN(ts)?0:Math.floor(ts/3600000)].join('|');
          const hit=groups.find(g=>g.key===key);
          if(hit){hit.count++;} else groups.push({key,count:1,s});
        }
        return groups.map(g=>{const s=g.s;return `<tr>
        <td class="mono">${esc(s.scan_id)}${g.count>1?` <span class="tag mute" title="同类型同期共 ${g.count} 次">+${g.count-1}</span>`:''}</td>
        <td>${esc(KIND[s.kind]||s.kind)}</td>
        <td>${tag((RISK[s.risk]||['mute','未知'])[0],(RISK[s.risk]||['mute','未知'])[1])}</td>
        <td class="num">${s.target_count}</td>
        <td class="num">${s.severity_counts?.critical||0}</td>
        <td class="num">${s.severity_counts?.high||0}</td>
        <td class="muted num" style="font-size:11.5px" title="${esc(s.started_at||'')}">${fmtTime(s.started_at)}</td>
        <td style="text-align:right"><button class="btn sm" onclick="viewReport(${jss(s.scan_id)})">查看</button></td>
      </tr>`}).join('');
      })()||'<tr><td colspan="8">'+emptyState('clock','暂无扫描记录')+'</td></tr>'}</tbody>
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
        <div class="f150"><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">TCP 超时(秒)</label>
<input id="d-timeout" type="number" value="1.2" step="0.1"></div>
        <div class="f150"><label style="font-size:11.5px;font-weight:560;color:var(--text-2);display:block;margin-bottom:4px">HTTP 超时(秒)</label>
<input id="d-htimeout" type="number" value="8" step="1"></div>
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
    $('#d-est').innerHTML=n?`预计 <b>${n}</b> 台目标 · 快速模式约 <b>${Math.max(1,Math.round(n*per/60))}</b> 分钟（快速仅探测 20 个常见端口与 SSH banner；深度探测 110+ 端口、HTTP 指纹与 TLS 证书）`:'填写网段或主机列表后开始 · <b>快速模式</b>并发高，200 台以上网段可能漏掉响应慢的设备（实测 254 台一次漏 3 台，单独复扫均可恢复）；正式评估请用<b>深度</b>模式';
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
  const allDisc=S.jobs.filter(j=>j.kind==='discover');
  const list=allDisc.slice(0,4);
  if(!list.length){box.innerHTML='';return}
  box.innerHTML=list.map(j=>jobRow(j)).join('')
    + (allDisc.length>4
        ? `<div class="row" style="justify-content:center;margin-top:6px">
             <a class="btn sm ghost" href="#tasks" onclick="go('tasks');return false">
               还有 ${allDisc.length-4} 条历史任务，去任务中心查看 →</a></div>`
        : '');
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
      ${active?`<button class="btn sm" onclick="cancelJob(${jss(j.id)})">${ico('stop','s12')}取消</button>`:''}
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
    return `<div class="dev" onclick="openAsset(${jss(a.host)})">
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
