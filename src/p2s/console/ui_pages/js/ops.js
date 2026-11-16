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
  if(window._p2sSchedTimer){ clearInterval(window._p2sSchedTimer); window._p2sSchedTimer=null }

  const [res, jobsRes] = await Promise.all([
    api('/api/schedules'),
    api('/api/jobs?limit=80').catch(()=>({jobs:[]})),
  ]);
  const list = res.schedules || [];
  const allJobs = Array.isArray(jobsRes) ? jobsRes : (jobsRes.jobs || []);
  const autoJobs = allJobs.filter(j=>(j.params||{}).group &&
        ['auto','自动'].includes((j.params||{}).group)).slice(0,6);

  const mmss = (sec)=>{
    if(sec < 0) return '—';
    if(sec === 0) return '即将执行';
    const m=Math.floor(sec/60), s=sec%60;
    return m>0 ? `${m} 分 ${String(s).padStart(2,'0')} 秒` : `${s} 秒`;
  };

  c.innerHTML=`
  <div class="page-full"><div class="page-head"><div><h2>计划任务</h2>
    <p>多条计划并存 · 各自独立间隔与分组 · 与手动扫描走完全相同的任务路径</p></div></div>

  <div class="card">
    <div class="card-h"><h3>扫描计划</h3>
      ${tag(list.length?'info':'mute', list.length+' 条')}
      <div class="sp"></div>
      <button class="btn primary" id="sc-add">新增计划</button></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>名称</th><th>网段</th><th class="num">间隔</th><th>分组</th>
        <th>状态</th><th>下次执行</th><th>最近一次</th><th style="width:150px"></th></tr></thead>
      <tbody>${list.map(x=>`<tr data-id="${esc(x.id)}">
        <td><b>${esc(x.name||x.id)}</b></td>
        <td class="mono" style="font-size:11.5px">${esc(x.cidr||((x.hosts||[]).join(', ')||'-'))}</td>
        <td class="num">${x.every_minutes} 分钟</td>
        <td><span class="tag mute">${esc(x.group||'auto')}</span></td>
        <td>${x.enabled?tag('ok','已启用'):tag('mute','已停用')}</td>
        <td class="muted" style="font-size:11.5px" data-count="${x.next_run_in}">
          ${x.enabled?mmss(x.next_run_in):'—'}</td>
        <td class="muted" style="font-size:11.5px">
          ${x.last_run?esc(x.last_run.replace('T',' ')):'从未'}
          ${x.next_retry_at?`<div style="color:var(--warn)">重试 ${x.retry_count}/${x.retry_max} · ${esc(String(x.next_retry_at).slice(11,16))}</div>`:''}</td>
        <td><div class="act-row">
          <button class="btn sm" data-act="toggle">${x.enabled?'停用':'启用'}</button>
          <button class="btn sm" data-act="run">立即执行</button>
          <button class="btn sm ghost" data-act="del">删除</button>
        </div></td></tr>`).join('')
        ||`<tr><td colspan="8">${emptyState('clock','还没有扫描计划','点右上角「新增计划」创建第一条')}</td></tr>`}
      </tbody></table></div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-h"><h3>最近自动扫描</h3><div class="sp"></div>
      <span class="muted" style="font-size:11.5px">最多 6 条 · 完整历史见任务中心</span></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th>任务</th><th>状态</th><th>结果</th><th>开始时间</th></tr></thead>
      <tbody>${autoJobs.map(j=>`<tr>
        <td class="mono" style="font-size:11.5px">${esc(j.title||j.id)}</td>
        <td>${tag(j.state==='done'?'ok':(j.state==='failed'?'crit':'mute'),
                  j.state==='done'?'已完成':(j.state==='failed'?'失败':'运行中'))}</td>
        <td class="muted" style="font-size:11.5px">${esc((j.message||'').slice(0,40))}</td>
        <td class="muted" style="font-size:11.5px">${esc(fmtTime(j.created_at))}</td>
      </tr>`).join('')||`<tr><td colspan="4">${emptyState('clock','还没有自动扫描记录','启用计划后到点会自动触发')}</td></tr>`}</tbody>
    </table></div>
  </div>`;

  // 倒计时：每秒 -1，不重新请求
  window._p2sSchedTimer=setInterval(()=>{
    c.querySelectorAll('[data-count]').forEach(el=>{
      let v=parseInt(el.dataset.count,10);
      if(isNaN(v)||v<0) return;
      v=Math.max(0,v-1); el.dataset.count=v; el.textContent=mmss(v);
    });
  },1000);

  c.querySelectorAll('tr[data-id]').forEach(tr=>{
    const id=tr.dataset.id;
    tr.querySelectorAll('[data-act]').forEach(b=>{
      b.onclick=async()=>{
        const act=b.dataset.act;
        b.disabled=true;
        try{
          if(act==='run'){
            const r=await api('/api/schedules/'+id+'/run',{method:'POST'});
            toast('已提交任务 '+(r.job&&r.job.id||''),'ok');
          }else if(act==='toggle'){
            const cur=list.find(x=>x.id===id);
            await api('/api/schedules/'+id,{method:'PATCH',body:{enabled:!cur.enabled}});
            toast(cur.enabled?'已停用':'已启用','ok');
          }else if(act==='del'){
            const ok=await askConfirm({title:'删除计划',
              message:'删除后不会再自动扫描，已产生的历史记录不受影响。',confirm:'删除'});
            if(!ok){ b.disabled=false; return }
            await api('/api/schedules/'+id,{method:'DELETE'});
            toast('已删除','ok');
          }
          loadSchedule(c);
        }catch(e){ toast('操作失败: '+e.message,'err'); b.disabled=false }
      };
    });
  });

  $('#sc-add').onclick=()=>scheduleDialog(null,()=>loadSchedule(c));
}

/* 新增 / 编辑计划 */
function scheduleDialog(item, done){
  const it=item||{enabled:true,every_minutes:60,cidr:'',group:'auto',save:true,notify_url:''};
  const bg=document.createElement('div'); bg.className='modal-bg on';
  const box=document.createElement('div'); box.className='modal wide';
  box.innerHTML=`<h3>${item?'编辑计划':'新增计划'}</h3>
    <div class="mbody">
      <div class="field" style="margin-bottom:10px"><label>名称（可选）</label>
        <input id="sd-name" placeholder="例如：办公网段" value="${esc(it.name||'')}"></div>
      <div class="row" style="margin-bottom:10px">
        <div class="field" style="flex:2 1 260px"><label>扫描网段 / IP</label>
          <input id="sd-cidr" placeholder="192.168.1.0/24" value="${esc(it.cidr||'')}"></div>
        <div class="field" style="flex:0 0 140px"><label>间隔（分钟）</label>
          <input id="sd-every" type="number" min="5" max="10080" value="${esc(String(it.every_minutes||60))}"></div>
      </div>
      <div class="row" style="margin-bottom:10px">
        <div class="field" style="flex:1 1 160px"><label>入库分组</label>
          <input id="sd-group" placeholder="auto" value="${esc(it.group||'auto')}"></div>
        <div class="field" style="flex:2 1 260px"><label>失败通知 Webhook（可选）</label>
          <input id="sd-url" placeholder="https://hooks.example.com/p2s" value="${esc(it.notify_url||'')}"></div>
      </div>
      <div class="row" style="margin-bottom:10px">
        <div class="field" style="flex:0 0 150px"><label>失败重试次数</label>
          <input id="sd-retry" type="number" min="0" max="5" value="${esc(String(it.retry_max??1))}"></div>
        <div class="field" style="flex:0 0 160px"><label>重试间隔（分钟）</label>
          <input id="sd-delay" type="number" min="1" max="1440" value="${esc(String(it.retry_delay_minutes??5))}"></div>
        <div class="hint" style="flex:1;align-self:center;padding-top:14px">
          任务失败后按此间隔再跑，最多重试 N 次；0 表示不重试</div>
      </div>
      <label class="check" style="margin-bottom:8px"><input type="checkbox" id="sd-save" ${it.save!==false?'checked':''}>
        <span>结果写入资产台账</span></label>
      <label class="check"><input type="checkbox" id="sd-on" ${it.enabled?'checked':''}>
        <span>保存后立即启用</span></label>
      <div id="sd-err" class="hint" style="color:var(--danger);display:none;margin-top:8px"></div>
    </div>
    <div class="mfoot"><button class="btn" id="sd-cancel">取消</button>
      <button class="btn primary" id="sd-ok">保存</button></div>`;
  bg.appendChild(box); document.body.appendChild(bg);
  const close=()=>bg.remove();
  bg.onclick=e=>{ if(e.target===bg) close() };
  $('#sd-cancel').onclick=close;
  $('#sd-ok').onclick=async()=>{
    const err=$('#sd-err'); err.style.display='none';
    const cidr=$('#sd-cidr').value.trim();
    if(!cidr){ err.textContent='请填写扫描网段'; err.style.display='block'; return }
    const body={
      name:$('#sd-name').value.trim(), cidr,
      every_minutes:parseInt($('#sd-every').value||'60',10),
      group:$('#sd-group').value.trim()||'auto',
      notify_url:$('#sd-url').value.trim(),
      save:$('#sd-save').checked, enabled:$('#sd-on').checked, quick:true,
      retry_max:parseInt($('#sd-retry').value||'0',10),
      retry_delay_minutes:parseInt($('#sd-delay').value||'5',10),
    };
    const btn=$('#sd-ok'); btn.disabled=true;
    try{
      if(item) await api('/api/schedules/'+item.id,{method:'PATCH',body});
      else await api('/api/schedules',{method:'POST',body});
      toast('已保存','ok'); close(); done&&done();
    }catch(e){ err.textContent=e.message; err.style.display='block'; btn.disabled=false }
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
