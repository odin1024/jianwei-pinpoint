
/* 重复分析守卫：同一目标刚分析过就先提示，避免堆出一堆相同报告 */
async function dupGuard(kind,label){
  try{
    const r=await api('/api/scans/duplicate?kind='+encodeURIComponent(kind)+'&label='+encodeURIComponent(label));
    if(!r.hit) return true;
    const h=r.hit;
    toastAction(label+' 在 '+h.age_hours+' 小时前分析过，命中 '+h.findings+' 条','查看上次',
      ()=>viewReport(h.scan_id));
    return await askConfirm({title:'该目标刚分析过',
      body:label+' 在 '+h.age_hours+' 小时前已分析过（报告 '+h.scan_id+'，命中 '+h.findings+' 条）。'
           +'重复分析会再生成一份内容相同的报告。',
      okText:'仍要重新分析'});
  }catch(e){ return true }
}

async function loadLogs(c){
  c.innerHTML=`
  <div class="page-narrow"><div class="page-head">
<div><h2>日志分析</h2><p>被动检测，零风险 · 支持 CLF / JSON / KV 三种格式自动识别</p></div></div>
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
  <div class="card">
    <div class="card-b"><div class="empty" style="padding:24px 16px">
      ${ico('list')}<b>还没有分析任何日志</b>
      <p>支持 CLF / JSON / KV 三种格式自动识别；也可直接点上方虚线框选择本地文件上传。</p>
      <ol class="steps">
        <li><b>格式</b>：nginx / apache 的 access.log、JSON 行日志、键值对日志，混排也能识别</li>
        <li><b>大小</b>：单文件建议 ≤ 100MB；超大文件请先在服务器上切分</li>
        <li><b>覆盖</b>：请求体类规则需要 WAF / 反代记录 <code>request_body</code> 才能命中</li>
      </ol>
    </div></div>
  </div>

  <div class="card" style="margin-bottom:12px">
    <div class="card-h"><h3>历史分析</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">最多 30 条 · 点选即回看</span></div>
    <div class="card-b">
      <div class="row" style="margin-bottom:10px">
        <div class="field" style="flex:1 1 320px"><label>选择一次日志分析</label>
          <select id="l-hist"><option value="">（加载中…）</option></select></div>
      </div>
      <div class="row">
        <div class="field" style="flex:0 0 150px"><label>时间范围</label>
          <select id="l-range">
            <option value="all">全部</option><option value="1h">最近 1 小时</option>
            <option value="24h">最近 24 小时</option><option value="7d">最近 7 天</option>
          </select></div>
        <div class="field" style="flex:0 0 150px"><label>等级</label>
          <select id="l-sev">
            <option value="all">全部</option><option value="critical">严重</option>
            <option value="high">高危</option><option value="medium">中危</option>
            <option value="low">低危</option>
          </select></div>
        <div class="field" style="flex:1 1 240px"><label>关键字（IP / URI / 规则）</label>
          <input id="l-kw" placeholder="例如 10.0.0.5 或 admin.php"></div>
        <span class="muted" id="l-count" style="align-self:flex-end;padding-bottom:6px;font-size:12px"></span>
      </div>
    </div>
  </div>

  <div id="l-out"></div>`;

  $('#l-run').onclick=async()=>{
    const p=$('#l-path').value.trim();
    if(!p){toast('请填写日志路径','warn');return}
    const label=p.replace(/\\/g,'/').split('/').pop();
    if(!await dupGuard('logs',label)) return;
    $('#l-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('clock','分析中…')+'</div></div>';
    try{const r=await api('/api/jobs',{method:'POST',body:{kind:'logs',path:p}});
      toast('任务已提交 '+r.id,'ok');watchJob(r.id,'logs')}
    catch(e){$('#l-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('alert','分析失败',e.message)+'</div></div>'}
  };
  loadLogHistory();

  const rng=$('#l-range'), sev=$('#l-sev'), kw=$('#l-kw');
  if(rng) rng.onchange=e=>{LOG_STATE.filter.range=e.target.value; rerenderLog()};
  if(sev) sev.onchange=e=>{LOG_STATE.filter.sev=e.target.value; rerenderLog()};
  let kwTimer=null;
  if(kw) kw.oninput=e=>{
    clearTimeout(kwTimer);
    kwTimer=setTimeout(()=>{LOG_STATE.filter.kw=e.target.value.trim(); rerenderLog()},200);
  };

  const dz=$('#l-drop'),fi=$('#l-file');
  dz.onclick=()=>fi.click();
  dz.ondragover=e=>{e.preventDefault();dz.classList.add('over')};
  dz.ondragleave=()=>dz.classList.remove('over');
  dz.ondrop=e=>{e.preventDefault();dz.classList.remove('over');if(e.dataTransfer.files[0])uploadFile(e.dataTransfer.files[0])};
  fi.onchange=()=>{if(fi.files[0])uploadFile(fi.files[0])};
  async function loadLogHistory(){
  const sel=$('#l-hist'); if(!sel) return;
  try{
    const d=await api('/api/scans?limit=100');
    const rows=(d.scans||[]).filter(x=>x.kind==='logs');
    const opts=rows.slice(0,30).map(x=>{
      const name=x.target_label||x.scan_id;
      const when=(x.started_at||'').replace('T',' ').slice(5,16);
      const sc=x.severity_counts||{};
      const n=(sc.critical||0)+(sc.high||0)+(sc.medium||0)+(sc.low||0);
      const brief=n?`严重 ${sc.critical||0}/高危 ${sc.high||0} · 共 ${n} 条`:'无命中';
      return `<option value="${esc(x.scan_id)}">${esc(when)} · ${esc(name)} · ${brief}</option>`;
    }).join('');
    sel.innerHTML=opts||'<option value="">（还没有历史分析）</option>';
    sel.onchange=async()=>{
      const id=sel.value; if(!id) return;
      $('#l-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('clock','加载中…')+'</div></div>';
      try{
        const data=await api('/api/scans/'+id+'/data');
        LOG_STATE.data=data; LOG_STATE.findings=data.findings||[];
        rerenderLog();
      }catch(e){ $('#l-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('alert','加载失败',e.message)+'</div></div>' }
    };
    if(rows.length){ sel.value=rows[0].scan_id; sel.onchange(); }
  }catch(e){ sel.innerHTML='<option value="">（加载历史失败）</option>' }
}

async function uploadFile(file){
    if(!await dupGuard('logs', file.name)) return;
    $('#l-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('clock','上传并分析中…')+'</div></div>';
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
let LOG_STATE={data:null, findings:[], filter:{range:'all', sev:'all', kw:''}};

function logFiltered(){
  const f=LOG_STATE.filter;
  const now=Date.now();
  const span={'1h':3600e3,'24h':86400e3,'7d':7*86400e3}[f.range]||0;
  const kw=(f.kw||'').toLowerCase();
  return (LOG_STATE.data&&LOG_STATE.data.findings||[]).filter(x=>{
    if(f.sev!=='all' && x.severity!==f.sev) return false;
    if(span){
      const t=Date.parse(String(x.ts||'').replace(' ','T'));
      if(!isNaN(t) && now-t>span) return false;
    }
    if(kw){
      const hay=((x.ip||'')+' '+(x.uri||'')+' '+(x.rule_id||'')+' '+(x.rule_name||'')).toLowerCase();
      if(!hay.includes(kw)) return false;
    }
    return true;
  });
}

function rerenderLog(){
  if(!LOG_STATE.data) return;
  const all=(LOG_STATE.data.findings||[]).length;
  const shown=logFiltered().length;
  const el=document.getElementById('l-count');
  if(el) el.textContent=`显示 ${shown} / ${all} 条`;
  renderLog(LOG_STATE.data, logFiltered());
}

function renderLog(r, list){
  const cov=r.coverage||{};
  const findings=list!==undefined?list:(r.findings||[]);
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
      <button class="btn sm" onclick="viewReport(${jss(r.scan_id)})">${ico('file','s12')}查看报告</button></div>
    <div class="tbl-wrap"><table><thead><tr><th>规则</th><th>名称</th><th>等级</th><th>维度</th><th>时间</th><th>来源 IP</th><th>URI</th><th>证据</th></tr></thead>
      <tbody>${findings.map(f=>`<tr>
        <td class="mono">${esc(f.rule_id)}</td><td style="font-size:12px">${esc(f.rule_name)}</td>
        <td>${tag((RISK[f.severity]||['mute',f.severity])[0],(RISK[f.severity]||['mute',f.severity])[1])}</td>
        <td class="muted" style="font-size:11.5px">${esc(f.dimension)}</td>
        <td class="muted num" style="font-size:11.5px">${esc((f.ts||'').replace('T',' ').slice(0,19))}</td>
        <td class="mono">${esc(f.ip||'-')}</td>
        <td style="font-size:11.5px">${esc((f.uri||'-').slice(0,44))}</td>
        <td class="muted" style="font-size:11.5px">${esc(f.evidence||'')}</td></tr>`).join('')
        ||'<tr><td colspan="8">'+emptyState('check','未发现异常')+'</td></tr>'}</tbody></table></div>
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
  <div class="card" style="margin-bottom:12px">
    <div class="card-h"><h3>在其他业务主机上检测（下载即用，无需安装 Python）</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">脚本内已写入本平台地址与上报令牌</span></div>
    <div class="card-b">
      <div class="row" style="margin-bottom:10px">
        <button class="btn primary" id="h-dl-win">下载 Windows 脚本（.ps1）</button>
        <button class="btn" id="h-dl-linux">下载 Linux 脚本（.sh）</button>
        <span class="muted" style="font-size:12px">Windows 7 / Server 2008R2 及以上 · CentOS 6+ / Ubuntu 14.04+ / Debian 8+ / Alpine / 麒麟</span>
      </div>
      <div class="hint">下载后在目标主机执行：
        <code>powershell -ExecutionPolicy Bypass -File p2s-agent.ps1</code>
        或 <code>sh p2s-agent.sh</code>，采集结果自动上报并写入资产台账（标记「本地取证」）。</div>
    </div>
  </div>
  <div id="h-out"><div class="card"><div class="card-b"><div class="empty">${ico('server')}<b>尚未执行主机侧检测</b><p>只读取证，不修改任何文件；结果会写入资产台账并标记「本地取证」。</p><ol class="steps"><li>检查本机 <b>PHP 安装点</b>与版本，判断是否低于修复基线</li><li>核查关键配置生效值：upload_progress / fatal_error_backtraces / memory_limit / post_max_size</li><li>扫描近 7 天新增的可疑落地文件，对比常见 webshell 特征</li><li>收集 PHP 派生的 shell 子进程与外联连接</li></ol><div class="row" style="justify-content:center;align-items:center;margin-top:16px"><button class="btn primary" id="h-run2">${ico('play','s12')}立即检测本机</button></div></div></div></div>`;
  $('#h-run').onclick=async()=>{
    $('#h-out').innerHTML='<div class="card"><div class="card-b">'+emptyState('clock','检测中…')+'</div></div>';
    try{const j=await api('/api/jobs',{method:'POST',body:{kind:'host'}});
      toast('任务已提交 '+j.id,'ok');watchHost(j.id)}
    catch(e){$('#h-out').innerHTML='<div class="card"><div class="card-b"><div class="empty">'+ico('alert')+'<p>'+esc(e.message)+'</p></div></div></div>'}
  };
  const _hr=$('#h-run2'); if(_hr) _hr.onclick=()=>$('#h-run').click();
  $('#h-export').onclick=()=>{window.location='/api/host/export'};
  $('#h-dl-win').onclick=()=>{window.location='/api/agent/download?os=windows'};
  $('#h-dl-linux').onclick=()=>{window.location='/api/agent/download?os=linux'};
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
