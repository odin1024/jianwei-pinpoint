let TASK_PAGE=20, taskPage=0;
async function loadTasks(c){
  const r=await api('/api/jobs'); S.jobs=r.jobs||[];
  c.innerHTML=`
  <div class="page-head"><div><h2>任务中心</h2><p>后台任务状态持久化到 p2s-data/jobs.json，控制台重启后历史仍在</p></div>
    <div class="sp"></div>
    <button class="btn" id="t-clean">${ico('trash','s12')}清理已完成</button>
    <button class="btn" id="t-refresh">${ico('refresh','s12')}刷新</button></div>
  <div id="jobs-stat" class="job-stat"></div>
  <div class="card">
    <div class="card-h">
      <div class="seg" id="t-filter">
        <button class="on" data-f="all">全部</button><button data-f="active">运行中</button>
        <button data-f="done">已完成</button><button data-f="failed">失败</button></div>
      <div class="sp"></div>
      <input id="t-search" placeholder="搜索标题 / ID" style="max-width:220px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th style="width:36%">任务</th><th>类型</th><th>状态</th>
        <th style="width:150px">进度</th><th style="width:110px">时间</th><th style="width:72px"></th></tr></thead>
      <tbody id="jobs-body"></tbody>
    </table></div>
    <div class="row" id="t-pager" style="justify-content:flex-end;gap:8px;padding:9px 12px;border-top:1px solid var(--border)"></div>
  </div>`;
  $('#t-refresh').onclick=()=>loadTasks($('#content'));
  $('#t-filter').onclick=e=>{
    const b=e.target.closest('button'); if(!b) return;
    $$('#t-filter button').forEach(x=>x.classList.toggle('on',x===b));
    taskPage=0; renderJobs();
  };
  $('#t-search').oninput=()=>{taskPage=0;renderJobs()};
  $('#t-clean').onclick=async()=>{
    const hist=S.jobs.filter(j=>j.state!=='running'&&j.state!=='queued');
    if(!hist.length){toast('没有可清理的历史任务','warn');return}
    const ok=await askConfirm({title:'清理历史任务',
      body:`将删除 ${hist.length} 条已结束的任务记录（不影响扫描报告与资产台账）。`,
      okText:'清理',danger:true});
    if(!ok) return;
    for(const j of hist){try{await api('/api/jobs/'+j.id,{method:'DELETE'})}catch(e){}}
    toast('已清理 '+hist.length+' 条','ok'); loadTasks($('#content'));
  };
  renderJobs();
}
function taskMatch(j){
  const el=$('#t-filter .on'); const f=(el&&el.dataset.f)||'all';
  const q=(($('#t-search')||{}).value||'').trim().toLowerCase();
  if(f==='active'&&!(j.state==='running'||j.state==='queued')) return false;
  if(f==='done'&&j.state!=='done') return false;
  if(f==='failed'&&j.state!=='failed') return false;
  if(q&&!((j.title||'')+(j.id||'')).toLowerCase().includes(q)) return false;
  return true;
}
function renderJobs(){
  const box=$('#jobs-body'); if(!box) return;
  const all=S.jobs||[];
  const n={active:0,done:0,failed:0,cancelled:0};
  all.forEach(j=>{
    if(j.state==='running'||j.state==='queued') n.active++;
    else if(n[j.state]!==undefined) n[j.state]++;
  });
  const stat=$('#jobs-stat');
  if(stat) stat.innerHTML=`
    <div class="jstat"><b>${n.active}</b><span>运行中</span></div>
    <div class="jstat ok"><b>${n.done}</b><span>已完成</span></div>
    <div class="jstat crit"><b>${n.failed}</b><span>失败</span></div>
    <div class="jstat"><b>${all.length}</b><span>总计</span></div>`;

  const rows=all.filter(taskMatch);
  const pager=$('#t-pager');
  if(!rows.length){
    box.innerHTML='<tr><td colspan="6">'+emptyState('clock','没有匹配的任务','调整筛选条件或换一个搜索关键字')+'</td></tr>';
    if(pager) pager.innerHTML='';
    return;
  }
  const pages=Math.max(1,Math.ceil(rows.length/TASK_PAGE));
  if(taskPage>pages-1) taskPage=pages-1;
  const shown=rows.slice(taskPage*TASK_PAGE,(taskPage+1)*TASK_PAGE);
  const barW=j=>{const t=j.total||0,d=j.done||0;
    if(j.state==='failed'||j.state==='cancelled') return t?Math.round(d/t*100):0;
    return Math.round((j.progress||0)*100)};
  box.innerHTML=shown.map(j=>`<tr>
    <td>
      <div style="display:flex;align-items:center;gap:6px">
        ${ico(j.state==='done'?'check':j.state==='failed'?'x':j.state==='running'?'play':'stop','s12')}
        <span style="font-weight:560">${esc(j.title||j.kind)}</span>
      </div>
      <div class="mono muted" style="font-size:11px">${esc(j.id)}</div></td>
    <td style="font-size:11.5px">${esc(KIND[j.kind]||j.kind)}</td>
    <td>${tag((JOBS[j.state]||['mute',j.state])[0],(JOBS[j.state]||['mute',j.state])[1])}</td>
    <td>
      <div class="pbar ${JOB_STYLE[j.state]||''}"><i style="width:${barW(j)}%"></i></div>
      <div class="muted num" style="font-size:11px">${j.done||0}/${j.total||0}</div></td>
    <td class="muted num" style="font-size:11.5px" title="${esc(j.finished_at||j.started_at||'')}">${fmtTime(j.finished_at||j.started_at)}</td>
    <td style="text-align:right"><button class="btn sm ghost" title="删除" onclick="deleteJob(${jss(j.id)})">${ico('trash','s12')}</button></td>
  </tr>`).join('');
  if(pager) pager.innerHTML=
    `<span class="muted" style="font-size:11.5px;margin-right:auto">共 ${rows.length} 条`+
    (pages>1?`，第 ${taskPage+1}/${pages} 页`:'')+`</span>`+
    `<button class="btn sm ghost" id="t-prev" ${taskPage<=0?'disabled':''}>上一页</button>`+
    `<button class="btn sm ghost" id="t-next" ${taskPage>=pages-1?'disabled':''}>下一页</button>`;
  const pv=$('#t-prev'), nx=$('#t-next');
  if(pv) pv.onclick=()=>{if(taskPage>0){taskPage--;renderJobs()}};
  if(nx) nx.onclick=()=>{if(taskPage<pages-1){taskPage++;renderJobs()}};
}
async function deleteJob(id){
  try{await api('/api/jobs/'+id,{method:'DELETE'});toast('已删除','ok');
    S.jobs=S.jobs.filter(j=>j.id!==id);renderJobs()}
  catch(e){toast('删除失败: '+e.message,'err')}
}
/* ==================== 资产台账 ==================== */
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
      <button class="icon-btn" id="import-close" aria-label="关闭导入面板"><svg class="i"><use href="#i-x"/></svg></button></div>
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
      <select id="a-group" style="max-width:150px;margin-left:8px"></select>
      <select id="a-ev" style="max-width:140px;margin-left:8px">
        <option value="">全部来源</option>
        <option value="host">仅本地取证</option>
        <option value="remote">仅远程探测</option>
      </select>
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
        <th class="sortable">暴露面</th><th>变化</th><th>最后检测</th><th class="sortable">置信度</th><th>分组</th><th>负责人</th><th></th></tr></thead>
      <tbody id="a-body"></tbody>
    </table></div>
    <div class="row" id="a-pager" style="justify-content:flex-end;gap:8px;padding:9px 12px;border-top:1px solid var(--border)"></div>
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
  const groups=[...new Set(a.map(x=>x.group||'未分组'))].sort();
  $('#a-group').innerHTML='<option value="">全部分组</option>'+groups.map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join('');
  let page=0; const PAGE=50;

  const draw=()=>{
    const f=$('#a-filter .on').dataset.f, q=$('#a-search').value.trim().toLowerCase();
    const ty=$('#a-type').value, gp=$('#a-group').value, ev=$('#a-ev').value;
    const rows=a.filter(x=>{
      if(f==='exposed'&&x.exposure!=='exposed')return false;
      if(f==='patched'&&x.exposure!=='patched')return false;
      if(f==='not_php'&&x.exposure!=='not_php')return false;
      if(f==='unknown'&&x.exposure!=='unknown')return false;
      if(ty&&(x.device_label||'未识别设备')!==ty)return false;
      if(gp&&(x.group||'未分组')!==gp)return false;
      if(ev==='host'&&x.evidence_level!=='host')return false;
      if(ev==='remote'&&x.evidence_level==='host')return false;
      if(q&&!((x.host||'')+(x.device_label||'')+(x.vendor||'')+(x.php_version||'')+(x.product||'')).toLowerCase().includes(q))return false;
      return true;
    });
    $('#a-table').classList.toggle('no-tech', !a.some(x=>(x.tech_stack||[]).length));
    const pageCount=Math.max(1,Math.ceil(rows.length/PAGE));
    if(page>pageCount-1) page=pageCount-1;
    const shown=rows.slice(page*PAGE,(page+1)*PAGE);
    $('#a-pager').innerHTML=
      `<span class="muted" style="font-size:11.5px;margin-right:auto">共 ${rows.length} 台`+
      (rows.length?`，第 ${page+1}/${pageCount} 页`:'')+`</span>`+
      `<button class="btn sm ghost" id="a-prev" ${page<=0?'disabled':''}>上一页</button>`+
      `<button class="btn sm ghost" id="a-next" ${page>=pageCount-1?'disabled':''}>下一页</button>`;
    const pv=$('#a-prev'), nx=$('#a-next');
    if(pv) pv.onclick=()=>{if(page>0){page--;draw()}};
    if(nx) nx.onclick=()=>{if(page<pageCount-1){page++;draw()}};
    $('#a-body').innerHTML=shown.map(x=>`<tr>
      <td><input type="checkbox" class="a-chk" data-h="${esc(x.host)}" ${selected.has(x.host)?'checked':''}></td>
      <td class="mono h">${esc(x.host)} ${x.evidence_level==='host'?tag('ok','本地取证'):''}</td>
      <td>${ico(DEV_ICON[x.device_type]||'box','s12')} ${esc(x.device_label||'-')}</td>
      <td style="font-size:11.5px">${esc(x.product||'-')}</td>
      <td style="font-size:11.5px">${x.vendor?esc(x.vendor):'<span class="muted">-</span>'}</td>
      <td>${(x.tech_stack||[]).map(s=>tag('crit',s)).join(' ')||'<span class="muted">-</span>'}</td>
      <td class="num">${x.php_version?'<b>'+esc(x.php_version)+'</b>':(x.php_present?tag('warn','未知'):'<span class="muted">无</span>')}
          ${(x.php_instances||[]).length>1?`<span class="muted" style="font-size:10.5px;margin-left:5px;white-space:nowrap"
            title="${esc((x.php_instances||[]).map(i=>':'+i.port+'='+i.version).join('  '))}">${x.php_instances.length}个</span>`:''}</td>
      <td>${tag((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
      <td>${(x.change && (x.change.kind==='new'
            || Object.keys(x.change.fields||{}).some(k=>['exposure','php_version','risk','sapi','alive'].includes(k))))
        ? (x.change.kind==='new'
            ? tag('ok','新增')
            : `<span title="${esc(JSON.stringify(x.change.fields||{}))}">${tag('warn','变更')}</span>`)
        : '<span class="muted">-</span>'}</td>
      <td class="num muted" style="font-size:11.5px" title="${esc(x.last_checked||'')}">${fmtTime(x.last_checked)}</td>
      <td class="num muted" style="font-size:11.5px">${((x.confidence||0)*100).toFixed(0)}%</td>
      <td><span class="editable" contenteditable="true" data-k="group" data-h="${esc(x.host)}">${esc(x.group||'未分组')}</span></td>
      <td><span class="editable" contenteditable="true" data-k="owner" data-h="${esc(x.host)}">${esc(x.owner||'')}</span></td>
      <td style="text-align:right">
        <div class="act-row">
        <button class="btn sm icon-btn" title="查看详情"
          onclick="event.stopPropagation();openAsset(${jss(x.host)})">${ico('search','s12')}</button>
        <button class="btn sm ghost icon-btn" title="复扫该主机"
          onclick="event.stopPropagation();rescan(${jss(x.host)})">${ico('refresh','s12')}</button>
        <button class="btn sm ghost icon-btn" title="配置加固"
          onclick="event.stopPropagation();hardenDialog(${jss(x.host)})">${ico('shield','s12')}</button>
        </div></td></tr>`).join('')
      ||'<tr><td colspan="13">'+emptyState('list','没有匹配的资产','换个筛选条件或清空搜索关键字试试')+'</td></tr>';
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
  $('#a-search').oninput=()=>{page=0;draw()}; draw();
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
    const n=selected.size;
    const ok=await askConfirm({title:'移出台账',
      body:`将从台账移除 ${n} 台资产。移除后仍可通过「设备发现」重新扫描入库。`,
      okText:'移出',danger:true});
    if(!ok) return;
    const backup=[...selected].map(h=>(S.assets||[]).find(a=>a.host===h)).filter(Boolean);
    for(const h of selected) await api('/api/assets?host='+encodeURIComponent(h),{method:'DELETE'});
    selected.clear(); await loadAssets($('#content'));
    toastAction('已移除 '+n+' 台','撤销',async()=>{
      for(const a of backup) await api('/api/assets/restore',{method:'POST',body:a});
      await loadAssets($('#content')); toast('已恢复 '+backup.length+' 台','ok');
    });
  };
  $('#a-export').onclick=()=>{window.location='/api/assets/export'};
}
