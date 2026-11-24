let rpPage=0; const RP_PAGE=20;
async function loadReports(c){
  const r=await api('/api/scans?limit=500');
  const all=r.scans||[];
  const kinds=[...new Set(all.map(x=>x.kind))];
  c.innerHTML=`
  <div class="page-head"><div><h2>报告中心</h2><p>共 ${r.total||all.length} 份扫描报告，可按类型/风险筛选</p></div></div>
  <div class="card">
    <div class="card-h">
      <div class="seg" id="r-kind">
        <button class="on" data-k="all">全部</button>
        ${kinds.map(k=>`<button data-k="${esc(k)}">${esc(KIND[k]||k)}</button>`).join('')}
      </div>
      <select id="r-risk" style="max-width:130px;margin-left:8px">
        <option value="">全部风险</option>
        <option value="critical">严重</option><option value="high">高危</option>
        <option value="medium">中危</option><option value="low">低危</option>
      </select>
      <div class="sp"></div>
      <input id="r-search" placeholder="搜索扫描 ID" style="max-width:220px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>报告</th><th>类型</th><th>目标</th><th>风险</th><th class="num">发现</th>
        <th class="num">严重</th><th class="num">高危</th><th>开始</th><th style="width:190px"></th></tr></thead>
      <tbody id="r-body"></tbody>
    </table></div>
    <div class="row" id="r-pager" style="justify-content:flex-end;gap:8px;padding:9px 12px;border-top:1px solid var(--border)"></div>
  </div>`;
  const draw=()=>{
    const k=$('#r-kind .on').dataset.k, risk=$('#r-risk').value;
    const q=($('#r-search').value||'').trim().toLowerCase();
    const flat=all.filter(s=>
      (k==='all'||s.kind===k) && (!risk||s.risk===risk) &&
      (!q||((s.scan_id||'')+(s.target_label||'')).toLowerCase().includes(q)));
    // 同一输入 + 同一结果 → 折叠为一条，角标显示重复次数
    const seen=new Map();
    flat.forEach(s=>{
      const key=s.dedupe_key||s.scan_id;
      if(seen.has(key)){seen.get(key).count++}
      else seen.set(key,{latest:s,count:1});
    });
    const rows=[...seen.values()];
    const pages=Math.max(1,Math.ceil(rows.length/RP_PAGE));
    if(rpPage>pages-1) rpPage=pages-1;
    const shown=rows.slice(rpPage*RP_PAGE,(rpPage+1)*RP_PAGE);
    $('#r-body').innerHTML=shown.map(g=>{const s=g.latest;
      const sc=s.severity_counts||{};
      const kindLabel=KIND[s.kind]||s.kind;
      const raw=(s.target_label||'').trim();
      // 目标与类型相同（历史日志未存文件名）时不重复显示，避免两列内容一模一样
      const target=(!raw||raw==='未记录目标'||raw===kindLabel||raw===s.kind)
        ? '<span class="muted" title="历史记录未保存目标名称">—</span>'
        : esc(raw);
      return `<tr>
      <td class="mono">${esc(s.scan_id)}
        ${g.count>1?`<span class="tag mute" style="margin-left:4px" title="同一输入重复分析 ${g.count} 次">×${g.count}</span>`:''}</td>
      <td>${esc(kindLabel)}</td>
      <td style="font-size:11.5px">${target}</td>
      <td>${tag((RISK[s.risk]||['mute',s.risk])[0],(RISK[s.risk]||['mute',s.risk])[1])}</td>
      <td class="num">${s.finding_count||0}</td>
      <td class="num${sc.critical?'':' muted'}">${sc.critical||0}</td>
      <td class="num${sc.high?'':' muted'}">${sc.high||0}</td>
      <td class="muted num" style="font-size:11.5px" title="${esc(s.started_at||'')}">${fmtTime(s.started_at)}</td>
      <td style="text-align:right">
        <div class="act-row">
          <button class="btn sm" onclick="viewReport(${jss(s.scan_id)})">查看</button>
          <button class="btn sm ghost icon-btn" onclick="delReport(${jss(s.scan_id)})"
            title="删除该报告">${ico('trash','s12')}</button>
        </div>
      </td></tr>`}).join('');
    if(!shown.length){$('#r-body').innerHTML='<tr><td colspan="9">'+emptyState('file','没有匹配的报告','调整筛选条件或换一个搜索关键字')+'</td></tr>'}
    $('#r-pager').innerHTML=`<span class="muted" style="font-size:11.5px;margin-right:auto">共 ${rows.length} 组`+
      (pages>1?`，第 ${rpPage+1}/${pages} 页`:'')+`</span>`+
      `<button class="btn sm ghost" id="r-prev" ${rpPage<=0?'disabled':''}>上一页</button>`+
      `<button class="btn sm ghost" id="r-next" ${rpPage>=pages-1?'disabled':''}>下一页</button>`;
    const pv=$('#r-prev'),nx=$('#r-next');
    if(pv)pv.onclick=()=>{if(rpPage>0){rpPage--;draw()}};
    if(nx)nx.onclick=()=>{if(rpPage<pages-1){rpPage++;draw()}};
  };
  $('#r-kind').onclick=e=>{const b=e.target.closest('button'); if(!b)return;
    $$('#r-kind button').forEach(x=>x.classList.toggle('on',x===b)); rpPage=0; draw()};
  $('#r-risk').onchange=()=>{rpPage=0;draw()};
  $('#r-search').oninput=()=>{rpPage=0;draw()};
  draw();
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
  const ok=await askConfirm({title:'删除报告',
    body:`将永久删除报告 ${id} 的 JSON / Markdown / HTML 三份文件，不可恢复。`,
    okText:'删除',danger:true});
  if(!ok) return;
  try{await api('/api/scans/'+id,{method:'DELETE'});toast('已删除','ok');loadReports($('#content'))}
  catch(e){toast('删除失败: '+e.message,'err')}
}
