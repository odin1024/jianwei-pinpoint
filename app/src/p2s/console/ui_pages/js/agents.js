async function loadAgents(c){
  const r=await api('/api/assets');
  const all=(r.assets||[]).filter(a=>a.evidence_level==='host');
  const remote=(r.assets||[]).filter(a=>a.evidence_level!=='host'&&a.alive);
  const now=Date.now();
  const ageDays=a=>{const t=Date.parse((a.last_checked||'').replace(' ','T'));return isNaN(t)?null:Math.floor((now-t)/86400000)};
  const offline=all.filter(a=>{const d=ageDays(a);return d!==null&&d>=7});
  c.innerHTML=`
  <div class="page-head"><div><h2>Agent 管理</h2>
    <p>已接入采集脚本的主机 · 超过 7 天未上报视为离线</p></div>
    <div class="sp"></div>
    <a class="btn" href="/api/agent/download?os=linux">${ico('download','s12')}Linux 脚本</a>
    <a class="btn" href="/api/agent/download?os=windows">${ico('download','s12')}Windows 脚本</a>
    <button class="btn" id="ag-import">${ico('upload','s12')}导入离线报告</button>
    <input type="file" id="ag-file" accept=".json" style="display:none"></div>
  <div class="job-stat">
    <div class="jstat"><b>${all.length}</b><span>已接入</span></div>
    <div class="jstat ok"><b>${all.filter(a=>a.exposure==='patched').length}</b><span>确认修复</span></div>
    <div class="jstat crit"><b>${all.filter(a=>a.exposure==='exposed').length}</b><span>确认受影响</span></div>
    <div class="jstat ${offline.length?'crit':''}"><b>${offline.length}</b><span>离线</span></div>
  </div>
  <div class="card">
    <div class="card-h"><h3>已接入主机（${all.length}）</h3><div class="sp"></div>
      <input id="ag-search" placeholder="搜索主机名" style="max-width:200px"></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>PHP</th><th>结论</th><th>配置风险</th><th>最后上报</th><th>状态</th><th></th></tr></thead>
      <tbody id="ag-body"></tbody>
    </table></div>
  </div>
  <div class="card" style="margin-top:14px">
    <div class="card-h"><h3>尚未接入（${remote.length}）</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">仅有远程推断，结论未经本地核实</span></div>
    <div class="card-b">
      ${remote.length?`<div class="tbl-wrap"><table>
        <thead><tr><th style="width:180px">主机</th><th>设备类型</th><th>厂商</th>
          <th>产品</th><th>最后检测</th><th></th></tr></thead>
        <tbody>${remote.map(a=>`<tr>
          <td class="mono h">${esc(a.host)}</td>
          <td style="font-size:11.5px">${esc(a.device_label||'-')}</td>
          <td style="font-size:11.5px">${esc(a.vendor||'-')}</td>
          <td style="font-size:11.5px">${esc(a.product||'-')}</td>
          <td class="muted num" style="font-size:11.5px" title="${esc(a.last_checked||'')}">${fmtTime(a.last_checked)}</td>
          <td style="text-align:right"><button class="btn sm ghost" onclick="openAsset(${jss(a.host)})">详情</button></td>
        </tr>`).join('')}</tbody></table></div>`
        :emptyState('check','全部主机都已接入 Agent','远程推断主机为 0 台')}
    </div>
  </div>`;
  const draw=()=>{
    const q=($('#ag-search').value||'').trim().toLowerCase();
    const rows=all.filter(a=>!q||(a.host||'').toLowerCase().includes(q));
    $('#ag-body').innerHTML=rows.map(a=>{
      const d=ageDays(a), stale=d!==null&&d>=7, issues=(a.host_issues||[]).length;
      return `<tr>
        <td class="mono h">${esc(a.host)}</td>
        <td class="mono">${esc(a.php_version||'-')}</td>
        <td>${tag((EXP[a.exposure]||['mute','?'])[0],(EXP[a.exposure]||['mute','?'])[1])}</td>
        <td>${issues?tag('warn',issues+' 项'):'<span class="muted">-</span>'}</td>
        <td class="muted num" style="font-size:11.5px" title="${esc(a.last_checked||'')}">${fmtTime(a.last_checked)}</td>
        <td>${stale?tag('crit','离线'):tag('ok','在线')}</td>
        <td style="text-align:right">
          <button class="btn sm" onclick="openAsset(${jss(a.host)})">详情</button>
          <button class="btn sm ghost" onclick="rescan(${jss(a.host)})">复扫</button></td>
      </tr>`;
    }).join('')||`<tr><td colspan="7">${emptyState('server','还没有主机接入','在目标机执行下载的脚本后自动出现')}</td></tr>`;
  };
  $('#ag-import').onclick=()=>$('#ag-file').click();
  $('#ag-file').onchange=async e=>{
    const f=e.target.files&&e.target.files[0]; if(!f) return;
    try{
      const text=await f.text();
      let rep; try{rep=JSON.parse(text)}catch(_){toast('不是有效的 JSON 文件','err');return}
      const r=await api('/api/agent/import',{method:'POST',body:{report:rep}});
      toast(`已导入 ${r.host}（${r.exposure}）`,'ok');
      loadAgents($('#content'));
    }catch(err){toast('导入失败: '+err.message,'err')}
    finally{e.target.value=''}
  };
  $('#ag-search').oninput=draw;
  draw();
}
