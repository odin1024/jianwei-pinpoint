let auHideAnon=true, auMerge=true;
async function loadAudit(c){
  const r=await api('/api/audit?limit=300');
  const rows=r.rows||[];
  c.innerHTML=`
  <div class="page-head"><div><h2>审计日志</h2>
    <p>记录所有写操作（新增/修改/删除/导出）· 存于 ${esc(r.file||'')}</p></div>
    <div class="sp"></div>
    <label class="check" style="flex:0 0 auto"><input type="checkbox" id="au-hide"
      ${auHideAnon?'checked':''}>隐藏未登录请求</label>
    <label class="check" style="flex:0 0 auto"><input type="checkbox" id="au-merge"
      ${auMerge?'checked':''}>合并连续重复</label>
    <input id="au-search" placeholder="搜索路径 / 操作人" style="max-width:220px"></div>
  <div class="card">
    <div class="tbl-wrap"><table>
      <thead><tr><th style="width:150px">时间</th><th style="width:90px">操作人</th>
        <th style="width:70px">来源</th><th style="width:90px">方法</th><th>接口</th><th style="width:70px">状态</th></tr></thead>
      <tbody id="au-body"></tbody>
    </table></div>
  </div>`;
  const draw=()=>{
    const q=($('#au-search').value||'').trim().toLowerCase();
    let list=rows.filter(e=>{
      if(auHideAnon&&(e.actor||'anonymous')==='anonymous') return false;
      return !q||JSON.stringify(e).toLowerCase().includes(q);
    });
    if(auMerge){   // 连续完全相同的「接口+方法」合并成一条，带次数
      const merged=[];
      list.forEach(e=>{
        const prev=merged[merged.length-1];
        if(prev&&prev.path===e.path&&prev.method===e.method&&prev.actor===e.actor){prev.n=(prev.n||1)+1}
        else merged.push({...e,n:1});
      });
      list=merged;
    }
    $('#au-body').innerHTML=list.map(e=>`<tr>
      <td class="mono" style="font-size:11.5px">${esc((e.ts||'').replace('T',' '))}</td>
      <td>${esc(e.actor||'-')}</td>
      <td class="mono muted" style="font-size:11px">${esc(e.ip||'-')}</td>
      <td><span class="tag ${/DELETE|PATCH|PUT/.test(e.method||'')?'warn':'info'}">${esc(e.method)}</span></td>
      <td class="mono" style="font-size:11.5px">${esc(e.path)}${e.n>1?` <span class="tag mute">×${e.n}</span>`:''}</td>
      <td class="num">${e.status}</td>
    </tr>`).join('')||`<tr><td colspan="6">${emptyState('list','还没有审计记录','执行一次写入操作后就会出现在这里')}</td></tr>`;
  };
  $('#au-search').oninput=draw;
  $('#au-hide').onchange=e=>{auHideAnon=e.target.checked;draw()};
  $('#au-merge').onchange=e=>{auMerge=e.target.checked;draw()};
  draw();
}

/* ==================== 计划任务 ==================== */
async function loadSchedule(c){
  const s=await api('/api/schedule');
  let hist=[];
  try{
    const all=await api('/api/jobs?limit=60');
    const list=Array.isArray(all)?all:(all&&all.jobs)||[];
    hist=list
      .filter(j=>['auto','自动'].includes((j.params||{}).group))
      .slice(0,6);
  }catch(e){ hist=[] }
  const next = s.enabled
    ? (s.next_run_in>0 ? Math.ceil(s.next_run_in/60)+' 分钟后' : '即将执行')
    : '未启用';
  const stateTag = s.enabled ? tag('ok','已启用') : tag('mute','未启用');

  c.innerHTML=`
  <div class="page-narrow"><div class="page-head"><div><h2>计划任务</h2>
    <p>按固定间隔自动发起设备发现 · 与手动扫描走完全相同的任务路径</p></div></div>
  <div class="card">
    <div class="card-h"><h3>定时扫描</h3>${stateTag}<div class="sp"></div>
      <span class="muted" style="font-size:11.5px">下次执行：${esc(next)}</span></div>
    <div class="card-b">
      <div class="field" style="margin-bottom:12px">
        <label class="check" for="sc-on">
          <input type="checkbox" id="sc-on" ${s.enabled?'checked':''}>
          <span>启用定时扫描（按间隔自动发起，结果入「自动」分组）</span>
        </label>
      </div>

      <div class="row" style="margin-bottom:14px">
        <div class="field" style="flex:2 1 320px">
          <label for="sc-cidr">扫描网段</label>
          <input id="sc-cidr" placeholder="例如 192.168.1.0/24；也可以填单个 IP"
                 value="${esc(s.cidr||'')}">
        </div>
        <div class="field" style="flex:0 0 150px">
          <label for="sc-every">间隔（分钟）</label>
          <input id="sc-every" type="number" min="5" max="10080"
                 value="${esc(String(s.every_minutes||60))}">
        </div>
        <button class="btn primary" id="sc-save">保存</button>
        <button class="btn" id="sc-run" ${s.cidr||(s.hosts||[]).length?'':'disabled'}
                title="用当前配置立刻跑一次，不影响定时计划">立即执行一次</button>
      </div>

      <div class="field" style="margin-bottom:12px">
        <label class="check" for="sc-save-db">
          <input type="checkbox" id="sc-save-db" ${s.save!==false?'checked':''}>
          <span>结果写入资产台账（关闭则只跑任务、不留资产画像）</span>
        </label>
      </div>

      <div id="sc-err" class="hint" style="color:var(--danger);display:none;margin-bottom:8px"></div>

      <div class="hint">
        上次执行：${s.last_run?esc(s.last_run.replace('T',' ')):'从未'}
        ${s.last_job?`· 任务 <span class="mono">${esc(s.last_job)}</span>`:''}<br>
        定时任务按「自动」分组入库，可在任务中心查看进度与结果；间隔最小 5 分钟。
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-h"><h3>最近自动扫描</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">最多显示 6 条 · 完整历史见任务中心</span></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>任务</th><th>状态</th><th>结果</th><th>开始时间</th><th style="width:70px"></th></tr></thead>
      <tbody>${hist.map(j=>`<tr>
        <td class="mono" style="font-size:11.5px">${esc(j.title||j.id)}</td>
        <td>${tag(j.state==='done'?'ok':(j.state==='failed'?'crit':'mute'),
                  j.state==='done'?'已完成':(j.state==='failed'?'失败':'运行中'))}</td>
        <td class="muted" style="font-size:11.5px">${esc((j.message||'').slice(0,40))}</td>
        <td class="muted" style="font-size:11.5px">${esc(fmtTime(j.created_at))}</td>
        <td><button class="btn ghost" data-job="${esc(j.id)}">查看</button></td>
      </tr>`).join('')||`<tr><td colspan="5">${emptyState('clock','还没有自动扫描记录','启用定时任务或点「立即执行一次」后出现')}</td></tr>`}</tbody>
    </table></div>
  </div>`;

  c.querySelectorAll('[data-job]').forEach(b=>b.onclick=()=>go('tasks'));

  const showErr=(m)=>{const e=$('#sc-err'); e.textContent=m; e.style.display=m?'block':'none'};
  const validCidr=(v)=>{
    if(!v) return '请填写网段或 IP';
    if(!/^[0-9a-fA-F:.\/]+$/.test(v)) return '网段只允许数字、点、冒号与斜杠';
    const m=v.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
    if(m){
      const ok=m[1].split('.').every(x=>Number(x)<=255);
      if(!ok) return 'IPv4 每段必须在 0-255 之间';
      if(m[2]!==undefined && Number(m[2])>32) return '掩码不能大于 /32';
      return '';
    }
    return '';   // 交给后端判断（IPv6 / 主机名）
  };

  $('#sc-save').onclick=async()=>{
    const cidr=$('#sc-cidr').value.trim();
    const err=validCidr(cidr);
    if(err){ showErr(err); return }
    showErr('');
    const btn=$('#sc-save'); btn.disabled=true;
    try{
      await api('/api/schedule',{method:'POST',body:{
        enabled:$('#sc-on').checked,
        every_minutes:parseInt($('#sc-every').value||'60',10),
        cidr, quick:true, save:$('#sc-save-db').checked, group:'auto'}});
      toast('已保存','ok'); loadSchedule($('#content'));
    }catch(e){toast('保存失败: '+e.message,'err')}
    finally{btn.disabled=false}
  };

  $('#sc-run').onclick=async()=>{
    const cidr=$('#sc-cidr').value.trim();
    const err=validCidr(cidr);
    if(err){ showErr(err); return }
    showErr('');
    const btn=$('#sc-run'); btn.disabled=true; btn.textContent='已提交…';
    try{
      const r=await api('/api/jobs',{method:'POST',body:{
        kind:'discover', hosts:[cidr], quick:true, save:true, group:'自动'}});
      toast('已提交任务 '+(r.id||''),'ok');
    }catch(e){toast('提交失败: '+e.message,'err')}
    finally{btn.disabled=false; btn.textContent='立即执行一次'}
  };
}

/* ==================== 配置加固 ==================== */
async function hardenDialog(host){
  let plan;
  try{ plan = await api('/api/hardening/plan/'+encodeURIComponent(host)); }
  catch(e){ toast('读取加固方案失败：'+e.message,'err'); return }

  const bg=document.createElement('div'); bg.className='modal-bg';
  const box=document.createElement('div'); box.className='modal wide';
  const rows=(plan.actions||[]).map(a=>`<div class="hd-item">
      <div class="hd-k"><code>${esc(a.key)}</code>
        <span class="hd-v">${esc(a.from)} → ${esc(a.value)}</span></div>
      <div class="hd-why">${esc(a.why||'')}</div>
    </div>`).join('');

  const drift=(plan.drift||[]).map(d=>`<li><code>${esc(d.key)}</code>
      期望 ${esc(d.expected)}，实际 ${esc(d.actual)} —— ${esc(d.note)}</li>`).join('');

  const pool=(plan.pool_overrides||[]).length?`<div class="hint" style="margin:8px 0;border-color:var(--warn-border);background:var(--warn-soft)">
       <b>注意：${plan.pool_overrides.length} 处 FPM pool 级配置会盖过 php.ini</b>
       <div style="margin-top:4px;font-size:12px;line-height:1.7">
         ${plan.pool_overrides.map(x=>esc(x.path.split('/').pop()+' → '+x.key+' = '+x.value)).join('<br>')}
       </div>
       <div style="margin-top:4px;font-size:12px">只改 php.ini 对使用这些 pool 的实例无效，需同时修改 FPM pool 配置。</div>
     </div>`:'';

  box.innerHTML=`<h3>配置加固 · ${esc(host)}</h3>
    <div class="mbody">
      <div class="hint" style="margin-bottom:10px">
        平台**不会**直接修改业务主机。生成加固包 → 你在目标机执行 → 把回执贴回来校验。
        包里自带预检（容器/权限/sha/配置管理托管）与回滚脚本。
      </div>
      ${plan.target?`<div class="muted" style="font-size:11.5px;margin-bottom:8px">目标文件：<code>${esc(plan.target)}</code></div>`
        :'<div class="warn" style="margin-bottom:8px">该主机还没有 Agent 上报，无法生成方案</div>'}
      ${rows?`<div class="hd-list">${rows}</div>`:'<div class="muted">当前没有需要加固的配置项</div>'}
      ${pool}
      ${drift?`<div class="warn" style="margin-top:10px"><b>检测到配置漂移</b><ul style="margin:6px 0 0 18px">${drift}</ul></div>`:''}
      <div class="row" style="margin-top:14px">
        ${rows?`<a class="btn primary" href="/api/hardening/pack/${encodeURIComponent(host)}">${ico('download','s12')}下载加固包</a>`:''}
        ${rows?`<button class="btn" id="hd-req">${ico('key','s12')}签发执行令牌</button>`:''}
        <div class="sp"></div>
        <span class="muted" style="font-size:11.5px">状态：${esc(plan.status)}${plan.last_verified_at?' · 校验于 '+esc(plan.last_verified_at):''}</span>
      </div>
      <div style="margin-top:14px">
        <label style="font-size:11.5px;color:var(--text-2);display:block;margin-bottom:4px">加固回执（把目标机 /tmp 下生成的 JSON 内容贴到这里）</label>
        <textarea id="hd-receipt" rows="4" placeholder='{"host":"...","applied":[...],"before_sha":"...","after_sha":"..."}'></textarea>
        <div class="row" style="margin-top:8px"><button class="btn" id="hd-verify">校验回执</button>
          <span class="muted" style="font-size:11.5px">校验通过后资产会标记为「已加固」，并记录基线用于漂移检测</span></div>
      </div>
    </div>
    <div class="mfoot"><button class="btn" data-close>关闭</button></div>`;

  document.body.append(bg, box);
  requestAnimationFrame(()=>{bg.classList.add('on');box.classList.add('on')});
  const done=()=>{bg.remove();box.remove()};
  bg.onclick=done;
  box.querySelector('[data-close]').onclick=done;

  const reqBtn=box.querySelector('#hd-req');
  if(reqBtn) reqBtn.onclick=async()=>{
    try{
      const r=await api('/api/hardening/request',{method:'POST',body:{host}});
      toast('令牌已签发，10 分钟内有效', 'ok');
      box.querySelector('#hd-req').insertAdjacentHTML('afterend',
        `<span class="mono" style="font-size:11px;padding:4px 6px;border:1px solid var(--border);border-radius:4px">${esc(r.token)}</span>`);
    }catch(e){toast('签发失败：'+e.message,'err')}
  };

  box.querySelector('#hd-verify').onclick=async()=>{
    const txt=box.querySelector('#hd-receipt').value.trim();
    if(!txt){ toast('请先粘贴回执','warn'); return }
    let rec; try{ rec=JSON.parse(txt) }catch(_){ toast('回执不是合法 JSON','err'); return }
    try{
      const r=await api('/api/hardening/receipt',{method:'POST',body:{receipt:rec}});
      toast(`校验通过：${r.host} 已应用 ${r.applied} 项`,'ok');
      done(); go('assets');
    }catch(e){toast('校验失败：'+e.message,'err')}
  };
}
