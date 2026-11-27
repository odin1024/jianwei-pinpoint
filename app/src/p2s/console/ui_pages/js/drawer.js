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
        <dt>厂商</dt><dd>${esc(x.vendor||'未识别')}${x.vendor_source?` <span class="muted" style="font-size:11px">（依据：${esc({title:'页面标题',cert:'TLS 证书',path:'登录路径',www_auth:'认证域',server:'Server 头',banner:'协议 banner',cookie:'Cookie',body:'响应正文',candidate:'关联证据',port:'端口推断'}[x.vendor_source]||x.vendor_source)}）</span>`:''}</dd>
        <dt>技术栈</dt><dd>${(x.tech_stack||[]).map(s=>tag('crit',s)).join(' ')||'<span class="muted">-</span>'}</dd>
        <dt>置信度</dt><dd class="num">${((x.confidence||0)*100).toFixed(0)}%${x.product_source==='port'?' <span class="muted" style="font-size:11px">（端口推断，仅供参考）</span>':''}</dd>
        <dt>网卡厂商</dt><dd>${esc(x.mac_vendor||'-')} ${x.mac?`<span class="mono muted" style="font-size:11px">${esc(x.mac)}</span>`:''} <span class="muted" style="font-size:11px">（OUI，仅代表网卡/代工厂，不等于设备品牌）</span></dd>
        <dt>favicon 指纹</dt><dd>${x.favicon_mmh3!=null?`<span class="mono">mmh3 ${esc(String(x.favicon_mmh3))}</span> <span class="muted" style="font-size:11px">（可直接在 Shodan / Fofa 检索）</span>`:'<span class="muted">-</span>'}
          ${x.favicon?`<div class="mono muted" style="font-size:11px">sha256 ${esc(x.favicon.slice(0,32))}…</div>`:''}</dd>
        <dt>有效端口</dt><dd class="num">${(x.meaningful_ports||[]).join(', ')||'-'}</dd>
        <dt>噪声端口</dt><dd class="num muted">${(x.noise_ports||[]).join(', ')||'-'}</dd>
        <dt>PHP</dt><dd>${x.php_version?'<b>PHP '+esc(x.php_version)+'</b>':(x.php_present?'存在但版本未知':'未检测到')}
        ${(x.php_instances||[]).length>1?`<div class="muted" style="font-size:11px;margin-top:3px;line-height:1.7">按最差版本判定，共 ${x.php_instances.length} 个实例：<br>
          ${(x.php_instances||[]).slice().sort((a,b)=>a.port-b.port).map(i=>esc(':'+i.port+' → '+(i.version||'未知'))).join('，')}</div>`:''}</dd>
        <dt>SAPI</dt><dd>${x.sapi?esc(SAPI_RISK[x.sapi]||x.sapi):'-'}</dd>
        <dt>开放端口</dt><dd><div class="ports">${(x.open_ports||[]).map(p=>`<span class="port">${p}</span>`).join('')||'-'}</div></dd>
        <dt>分组 / 负责人</dt><dd>${esc(x.group||'-')} / ${esc(x.owner||'-')}</dd>
        <dt>最后检测</dt><dd class="num muted" title="${esc(x.last_checked||'')}">${fmtTime(x.last_checked)}</dd></dl>
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
    <div class="sect"><div class="sect-t">判定证据（${(x.evidence||[]).length}）
        ${(x.evidence||[]).length?`<button class="btn sm ghost" style="float:right;margin-top:-4px"
          onclick="copyText(${(x.evidence||[]).map(e=>jss(e)).join(',')},'已复制全部证据')">${ico('copy','s12')}复制全部</button>`:''}
      </div>
      ${(x.evidence||[]).map(e=>`<div class="evi" title="点击复制这一条" style="cursor:pointer"
        onclick="copyText(${jss(e)},'已复制')">${esc(e)}</div>`).join('')||'<div class="muted" style="font-size:12px">无</div>'}</div>
    ${(x.errors||[]).length?`<div class="sect"><div class="sect-t">错误</div>
      ${(x.errors||[]).map(e=>`<div class="evi" style="border-left-color:var(--danger-border)">${esc(e)}</div>`).join('')}</div>`:''}`;
  $('#drawer-foot').innerHTML=`
    <button class="btn" onclick="rescan(${jss(x.host)})">${ico('refresh','s12')}重新检测</button>
    <button class="btn danger" onclick="delAsset(${jss(x.host)})">${ico('trash','s12')}移出台账</button>
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
  const ok=await askConfirm({title:'移出台账',
    body:`将 ${host} 从台账移除？移除后仍可通过「设备发现」重新扫描入库。`,
    okText:'移出',danger:true});
  if(!ok) return;
  const backup=(S.assets||[]).find(a=>a.host===host);
  try{
    await api('/api/assets?host='+encodeURIComponent(host),{method:'DELETE'});
    closeDrawer(); S.assets=S.assets.filter(a=>a.host!==host);
    go(location.hash.slice(1)||'overview');
    toastAction('已移除 '+host,'撤销',async()=>{
      if(backup) await api('/api/assets/restore',{method:'POST',body:backup});
      go(location.hash.slice(1)||'overview'); toast('已恢复 '+host,'ok');
    });
  }catch(e){toast('删除失败: '+e.message,'err')}
}
