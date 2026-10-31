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
        <td class="num"><b>${esc(x.php_version||'?')}</b>${(x.php_instances||[]).length>1?`<div class="muted" style="font-size:10.5px" title="${esc((x.php_instances||[]).map(i=>':'+i.port+'='+i.version).join('  '))}">${x.php_instances.length} 个实例</div>`:''}</td>
        <td style="font-size:11.5px">${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</td>
        <td class="num muted">${esc(x.fixed_release||'-')}</td>
        <td>${tag((EXP[x.exposure]||['mute','?'])[0],(EXP[x.exposure]||['mute','?'])[1])}</td>
        <td class="muted" style="font-size:11.5px">${esc(x.reason||'')}</td>
        <td>${esc(x.owner||'-')}</td></tr>`).join('')
        ||'<tr><td colspan="8"><div class="empty">'+ico('code')+'<b>没有跑 PHP 的资产</b><p>所有已发现设备均与 php2shell 无关</p></div></td></tr>'}
      </tbody></table></div>
  </div>`;
}
