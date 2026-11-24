/* ==================== 关于 ==================== */
async function loadAbout(c){
  let a;
  try{ a = await api('/api/about'); }
  catch(e){
    c.innerHTML='<div class="card"><div class="card-b">'+emptyState('alert','读取产品信息失败',e.message)+'</div></div>';
    return;
  }
  const sc=a.scope||{}, rt=a.runtime||{}, ru=a.rules||{}, da=a.data||{};
  const mk=a.patch_markers||{};

  c.innerHTML=`
  <div class="page-head"><div><h2>关于</h2>
    <p>${esc(a.tagline||'')} · 版本 ${esc(a.version)}</p></div></div>

  <div class="grid kpis">
    <div class="kpi hero"><div class="k">${ico('shield','s12')}当前版本</div>
      <div class="v num" style="font-size:var(--fs-l)">${esc(a.version)}</div>
      <div class="d">${esc(rt.python||'')} · ${esc((rt.platform||'').slice(0,32))}</div></div>
    <div class="kpi quiet"><div class="k">${ico('file','s12')}加固规则</div>
      <div class="v num">${ru.total||0}</div>
      <div class="d">${ru.auto||0} 条可自动执行 · ${ru.categories||0} 个分类</div></div>
    <div class="kpi quiet"><div class="k">${ico('list','s12')}已纳管资产</div>
      <div class="v num">${da.assets||0}</div><div class="d">扫描记录 ${da.scans||0} 份</div></div>
    <div class="kpi quiet"><div class="k">${ico('alert','s12')}覆盖 CVE</div>
      <div class="v num">${(sc.cves||[]).length}</div>
      <div class="d">${esc((sc.cves||[]).join(' / '))}</div></div>
  </div>

  <div class="card">
    <div class="card-h"><h3>能力</h3><div class="sp"></div>
      <span class="muted" style="font-size:var(--fs-xs)">每一段都可追溯到具体实现</span></div>
    <div class="tbl-wrap"><table>
      <thead><tr><th style="width:90px">环节</th><th>实现</th></tr></thead>
      <tbody>${(a.capabilities||[]).map(x=>`<tr>
        <td><b>${esc(x.k)}</b></td><td class="muted">${esc(x.v)}</td></tr>`).join('')}</tbody>
    </table></div>
  </div>

  <div class="card" style="margin-top:14px">
    <div class="card-h"><h3>补丁标记库</h3><div class="sp"></div>
      <span class="muted" style="font-size:var(--fs-xs)">
        ${mk.all_branches_distinguishable
          ? '实测 ' + esc(mk.verified_on || '') + ' · 三分支全部可区分'
          : '⚠ 存在不可区分的标记'}</span></div>
    <div class="card-b">
      <div style="font-size:var(--fs-xs);color:var(--text-2);line-height:1.9">
        判定「是否已打补丁」靠二进制标记与运行时探针，<b>不只看版本号</b> ——
        版本号是声明，标记是证据。来源：官方镜像配对提取
        （${(mk.branches||[]).map(x=>`${esc(x.unpatched)} vs ${esc(x.patched)}`).join(' · ')}）。
      </div>
      <div style="margin-top:8px;display:flex;gap:16px;flex-wrap:wrap;font-size:var(--fs-xs)">
        <span>二进制标记 <b>${mk.binary_markers||0}</b> 条</span>
        <span>运行时探针 <b>${mk.runtime_probes||0}</b> 条</span>
        <span>覆盖分支 <b>${(mk.branches||[]).length}</b> 个</span>
      </div>
    </div>
  </div>

  <div class="row" style="margin-top:14px;align-items:stretch">
    <div class="card" style="flex:1 1 320px">
      <div class="card-h"><h3>覆盖范围</h3></div>
      <div class="card-b">
        <div class="kv">
          <dt>修复基线</dt><dd class="mono">
            ${Object.entries(sc.fixed_releases||{}).map(([k,v])=>`${esc(k)} → <b>${esc(v)}</b>`).join(' · ')}
          </dd>
          <dt>加固层次</dt><dd>${(sc.layers||[]).map(x=>tag('mute',x)).join(' ')}</dd>
          <dt>数据目录</dt><dd class="mono" style="font-size:var(--fs-xs)">${esc(da.dir||'')}</dd>
        </div>
      </div>
    </div>
    <div class="card" style="flex:1 1 320px">
      <div class="card-h"><h3>使用边界</h3><div class="sp"></div>
        ${tag('warn','请勿忽略')}</div>
      <div class="card-b">
        <ul style="margin:0 0 0 16px;padding:0;line-height:1.9;font-size:var(--fs-xs);color:var(--text-2)">
          ${(a.boundaries||[]).map(x=>`<li>${esc(x)}</li>`).join('')}
        </ul>
      </div>
    </div>
  </div>`;
}
