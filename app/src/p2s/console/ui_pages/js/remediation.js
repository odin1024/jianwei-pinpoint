const REM_LABEL={pending:['warn','待处理'],in_progress:['info','处理中'],
  fixed:['ok','已修复'],ignored:['mute','已忽略']};
let remFilter='all';
async function loadRemediation(c){
  const r=await api('/api/remediation');
  const g=r.groups||{}, cnt=r.counts||{};
  c.innerHTML=`
  <div class="page-head"><div><h2>整改跟踪</h2>
    <p>按处置状态跟踪每台资产的整改进度 · 复扫发现已修复会自动更新</p></div></div>

  <div class="job-stat">
    <div class="jstat"><b>${r.done_ratio||0}%</b><span>整改完成率</span></div>
    <div class="jstat ${cnt.pending?'crit':''}"><b>${cnt.pending||0}</b><span>待处理</span></div>
    <div class="jstat"><b>${cnt.in_progress||0}</b><span>处理中</span></div>
    <div class="jstat ok"><b>${cnt.fixed||0}</b><span>已修复</span></div>
    <div class="jstat"><b>${cnt.ignored||0}</b><span>已忽略</span></div>
  </div>

  <div class="card">
    <div class="card-h">
      <div class="seg" id="rem-filter">
        <button class="on" data-f="all">全部</button>
        <button data-f="pending">待处理</button>
        <button data-f="in_progress">处理中</button>
        <button data-f="fixed">已修复</button>
        <button data-f="ignored">已忽略</button>
      </div>
      <div class="sp"></div>
      <input id="rem-search" placeholder="搜索主机 / 责任人" style="max-width:220px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>类型</th><th>暴露面</th><th>责任人</th>
        <th>状态</th><th>更新时间</th><th style="width:190px">操作</th></tr></thead>
      <tbody id="rem-body"></tbody>
    </table></div>
  </div>`;

  const rows=[]; Object.keys(g).forEach(k=>(g[k]||[]).forEach(a=>rows.push({...a,st:k})));

  const draw=()=>{
    const q=($('#rem-search').value||'').trim().toLowerCase();
    const list=rows.filter(a=>{
      if(remFilter!=='all'&&a.st!==remFilter) return false;
      if(q&&!((a.host||'')+(a.owner||'')).toLowerCase().includes(q)) return false;
      return true;
    });
    $('#rem-body').innerHTML=list.map(a=>`<tr>
      <td class="mono h">${esc(a.host)}
        ${a.auto_fixed?'<span class="tag ok" title="复扫已确认修复">自动</span>':''}</td>
      <td style="font-size:11.5px">${esc(a.device_label||'-')}</td>
      <td>${tag((EXP[a.exposure]||['mute','?'])[0],(EXP[a.exposure]||['mute','?'])[1])}</td>
      <td style="font-size:12px">${a.owner?esc(a.owner):'<span class="muted">未指派</span>'}</td>
      <td>${tag(REM_LABEL[a.st][0],REM_LABEL[a.st][1])}
        ${a.st==='ignored'&&a.ignored_reason?`<div class="muted" style="font-size:11px">${esc(a.ignored_reason)}</div>`:''}</td>
      <td class="muted num" style="font-size:11.5px">${a.updated_at?fmtTime(a.updated_at):'-'}</td>
      <td style="text-align:right">
        <button class="btn sm" onclick="remSet(${jss(a.host)},'in_progress')">处理中</button>
        <button class="btn sm" onclick="remSet(${jss(a.host)},'fixed')">修复</button>
        <button class="btn sm ghost" onclick="remIgnore(${jss(a.host)})">忽略</button></td>
    </tr>`).join('')||`<tr><td colspan="7">${emptyState('check','该状态下没有资产','换个筛选条件看看')}</td></tr>`;
  };

  $('#rem-filter').onclick=e=>{
    const b=e.target.closest('button'); if(!b) return;
    $$('#rem-filter button').forEach(x=>x.classList.toggle('on',x===b));
    remFilter=b.dataset.f; draw();
  };
  $('#rem-search').oninput=draw;
  draw();
}
async function remSet(host,status,owner,reason){
  try{
    await api('/api/assets/remediation',{method:'PATCH',
      body:{host,status,owner:owner??undefined,ignored_reason:reason}});
    toast(host+' → '+(REM_LABEL[status]||[0,status])[1],'ok');
    loadRemediation($('#content'));
  }catch(e){toast('更新失败: '+e.message,'err')}
}
async function remIgnore(host){
  const reason=await askConfirm({title:'标记为已忽略',
    body:`将 ${host} 标记为「已忽略」。请在下一步填写原因，便于后续审计。`,
    okText:'继续'});
  if(!reason) return;
  const why=prompt('忽略原因（必填，会记入台账）：','业务方确认该主机不上线');
  if(why===null) return;
  if(!why.trim()){toast('必须填写忽略原因','warn');return}
  remSet(host,'ignored',undefined,why.trim());
}
