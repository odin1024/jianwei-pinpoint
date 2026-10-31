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
