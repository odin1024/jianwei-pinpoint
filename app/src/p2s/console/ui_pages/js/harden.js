/* ==================== 配置加固 ==================== */
async function loadHarden(c){
  let ov, rules;
  try{
    [ov, rules] = await Promise.all([
      api('/api/hardening/overview'),
      api('/api/hardening/rules').catch(()=>({rules:[],categories:[]})),
    ]);
  }catch(e){
    c.innerHTML='<div class="card"><div class="card-b">'+emptyState('alert','读取加固信息失败',e.message)+'</div></div>';
    return;
  }
  const st = ov.stats || {};
  const rows = ov.rows || [];
  const allRules = rules.rules || [];
  const cats = rules.categories || [];

  const STATUS = {
    pending:  ['crit','待加固'],
    verified: ['ok','已加固'],
    none:     ['mute','无需加固'],
  };

  c.innerHTML=`
  <div class="page-head"><div><h2>配置加固</h2>
    <p>生成加固包 → 你在目标机执行 → 贴回执校验。平台不会直连任何主机。</p></div></div>

  <div class="grid kpis">
    <div class="kpi ${st.pending?'primary':'quiet'}"><div class="k">${ico('shield','s12')}待加固主机</div>
      <div class="v num">${st.pending||0}</div>
      <div class="d">${st.pending?'存在低于基线的配置项，需生成加固包':'当前没有待加固项'}</div></div>
    <div class="kpi quiet"><div class="k">${ico('check','s12')}已加固</div>
      <div class="v num">${st.verified||0}</div><div class="d">回执已校验通过</div></div>
    <div class="kpi quiet"><div class="k">${ico('file','s12')}规则库</div>
      <div class="v num">${st.rules||allRules.length}</div><div class="d">${cats.length} 个分类 · 可自动执行项另有标注</div></div>
    <div class="kpi ${st.with_ticket?'':'quiet'}"><div class="k">${ico('clock','s12')}未使用票据</div>
      <div class="v num">${st.with_ticket||0}</div><div class="d">下载包时签发，回执后作废</div></div>
    <div class="kpi ${st.pool_warn?'':'quiet'}"><div class="k">${ico('alert','s12')}pool 覆盖</div>
      <div class="v num">${st.pool_warn||0}</div><div class="d">这些主机的 pool 配置会盖过 php.ini</div></div>
  </div>

  <div class="card">
    <div class="card-h"><h3>主机与动作</h3><div class="sp"></div>
      <span class="muted" style="font-size:var(--fs-xs)">共 ${rows.length} 台 · 按待加固优先排序</span></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>主机</th><th>设备</th><th>PHP</th><th>目标文件</th>
        <th class="num">待执行</th><th>状态</th><th>上次验证</th><th style="width:150px"></th></tr></thead>
      <tbody>${rows.map(r=>{
        const stl = STATUS[r.status] || ['mute', r.status];
        return `<tr>
        <td class="mono">${esc(r.host)}</td>
        <td class="muted" style="font-size:var(--fs-xs)">${esc(r.device_label||'-')}</td>
        <td class="num">${r.php_version?`<b>${esc(r.php_version)}</b>`:'<span class="muted">-</span>'}</td>
        <td class="mono" style="font-size:var(--fs-xs)">${esc(r.target||'-')}
          ${r.pool_overrides?`<div class="muted" style="color:var(--warn)">${r.pool_overrides} 处 pool 覆盖</div>`:''}</td>
        <td class="num">${r.actions||'-'}</td>
        <td>${tag(stl[0], stl[1])}${r.ticket&&!r.ticket_used?tag('info','有票据'):''}</td>
        <td class="muted" style="font-size:var(--fs-xs)">${r.verified_at?esc(String(r.verified_at).replace('T',' ')):'-'}</td>
        <td><div class="act-row">
          ${r.actions?`<button class="btn sm primary" data-plan="${esc(r.host)}">查看方案</button>`
                     :`<button class="btn sm" disabled title="当前没有可执行动作">无动作</button>`}
        </div></td></tr>`}).join('')
        ||`<tr><td colspan="8">${emptyState('shield','没有可加固的主机','先在「设备发现」扫描网段，或让 Agent 上报主机配置')}</td></tr>`}
      </tbody></table></div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-h"><h3>规则库</h3><div class="sp"></div>
      <select id="rl-cat" style="max-width:180px"><option value="">全部分类</option>
        ${cats.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('')}</select>
      <input id="rl-kw" placeholder="搜索配置项 / 关键字" style="max-width:220px;margin-left:8px">
    </div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>编号</th><th>分类</th><th>配置项</th><th>建议值</th>
        <th>风险</th><th>执行</th><th>说明</th></tr></thead>
      <tbody id="rl-body"></tbody></table></div>
  </div>`;

  const RISK={critical:'crit',high:'high',medium:'warn',low:'mute'};
  const drawRules=()=>{
    const cat=$('#rl-cat').value, kw=($('#rl-kw').value||'').trim().toLowerCase();
    const list=allRules.filter(r=>{
      if(cat && r.category!==cat) return false;
      if(kw){
        const hay=(r.id+' '+r.key+' '+r.category+' '+r.why).toLowerCase();
        if(!hay.includes(kw)) return false;
      }
      return true;
    });
    $('#rl-body').innerHTML=list.slice(0,80).map(r=>`<tr>
      <td class="mono" style="font-size:var(--fs-xs)">${esc(r.id)}</td>
      <td class="muted" style="font-size:var(--fs-xs)">${esc(r.category)}</td>
      <td class="mono" style="font-size:var(--fs-xs)">${esc(r.key)}</td>
      <td class="mono" style="font-size:var(--fs-xs)">${esc(r.recommended||'-')}</td>
      <td>${tag(RISK[r.risk]||'mute', {critical:'严重',high:'高危',medium:'中危',low:'低危'}[r.risk]||r.risk)}</td>
      <td>${r.auto?tag('ok','自动'):tag('mute','人工')}</td>
      <td class="muted" style="font-size:var(--fs-xs)">${esc((r.why||'').slice(0,60))}</td>
    </tr>`).join('')
      ||`<tr><td colspan="7">${emptyState('filter','没有匹配的规则','换个分类或关键字')}</td></tr>`;
    if(list.length>80)
      $('#rl-body').innerHTML+=`<tr><td colspan="7" class="muted" style="font-size:var(--fs-xs)">仅显示前 80 条，共 ${list.length} 条 — 请用筛选缩小范围</td></tr>`;
  };
  $('#rl-cat').onchange=drawRules;
  $('#rl-kw').oninput=drawRules;
  drawRules();

  c.querySelectorAll('[data-plan]').forEach(b=>b.onclick=()=>hardenDialog(b.dataset.plan));
}
