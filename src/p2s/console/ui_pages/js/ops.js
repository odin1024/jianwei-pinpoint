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
  const next = s.enabled
    ? (s.next_run_in>0 ? Math.ceil(s.next_run_in/60)+' 分钟后' : '即将执行')
    : '未启用';
  c.innerHTML=`
  <div class="page-narrow"><div class="page-head"><div><h2>计划任务</h2>

    <p>按固定间隔自动发起设备发现 · 与手动扫描走完全相同的任务路径</p></div></div>
  <div class="card">
    <div class="card-h"><h3>定时扫描</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">下次执行：${esc(next)}</span></div>
    <div class="card-b">
      <div class="row" style="margin-bottom:12px">
        <label class="chk"><input type="checkbox" id="sc-on" ${s.enabled?'checked':''}> 启用定时扫描</label>
      </div>
      <div class="row" style="margin-bottom:12px">
        <input id="sc-cidr" placeholder="网段 CIDR，例如 192.168.1.0/24" value="${esc(s.cidr||'')}">
        <input id="sc-every" type="number" min="5" value="${esc(String(s.every_minutes||60))}" style="max-width:120px">
        <span class="muted" style="font-size:12px">分钟/次（最小 5）</span>
        <div class="sp"></div>
        <button class="btn primary" id="sc-save">保存</button>
      </div>
      <div class="hint">
        上次执行：${s.last_run?esc(s.last_run.replace('T',' ')):'从未'} ·
        上次任务：<span class="mono">${esc(s.last_job||'-')}</span><br>
        定时任务按「自动」分组入库，可在任务中心查看进度与结果。
      </div>
    </div>
  </div>`;
  $('#sc-save').onclick=async()=>{
    const btn=$('#sc-save'); btn.disabled=true;
    try{
      await api('/api/schedule',{method:'POST',body:{
        enabled:$('#sc-on').checked,
        every_minutes:parseInt($('#sc-every').value||'60',10),
        cidr:$('#sc-cidr').value.trim(), quick:true, save:true}});
      toast('已保存','ok'); loadSchedule($('#content'));
    }catch(e){toast('保存失败: '+e.message,'err')}
    finally{btn.disabled=false}
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

  box.innerHTML=`<h3>配置加固 · ${esc(host)}</h3>
    <div class="mbody">
      <div class="hint" style="margin-bottom:10px">
        平台**不会**直接修改业务主机。生成加固包 → 你在目标机执行 → 把回执贴回来校验。
        包里自带预检（容器/权限/sha/配置管理托管）与回滚脚本。
      </div>
      ${plan.target?`<div class="muted" style="font-size:11.5px;margin-bottom:8px">目标文件：<code>${esc(plan.target)}</code></div>`
        :'<div class="warn" style="margin-bottom:8px">该主机还没有 Agent 上报，无法生成方案</div>'}
      ${rows?`<div class="hd-list">${rows}</div>`:'<div class="muted">当前没有需要加固的配置项</div>'}
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
