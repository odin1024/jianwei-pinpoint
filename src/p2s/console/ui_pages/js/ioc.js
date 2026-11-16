async function loadIoc(c){
  const r=await api('/api/ioc');
  c.innerHTML=`
  <div class="page-head"><div><h2>IOC 库</h2><p>来源：TU Delft INTELLAB 蜜罐观测 / NCSC-NL / CISA KEV · 更新于 ${esc(r.summary.updated)}</p></div></div>
  <div class="grid kpis">
    <div class="kpi"><div class="k">攻击者 IP</div><div class="v num danger">${r.summary.ips}</div></div>
    <div class="kpi"><div class="k">域名</div><div class="v num">${r.summary.domains}</div></div>
    <div class="kpi"><div class="k">URL</div><div class="v num">${r.summary.urls}</div></div>
    <div class="kpi"><div class="k">样本哈希</div><div class="v num">${r.summary.hashes}</div></div>
    <div class="kpi"><div class="k">UA 特征</div><div class="v num">${r.summary.user_agents}</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr;gap:12px">
    <div class="card"><div class="card-h"><h3>基础设施</h3></div><div class="card-b">
      <div class="row" style="margin-bottom:10px"><input id="ioc-filter" placeholder="搜索 IP / 域名 / URL / 哈希 / UA 特征" style="max-width:420px"></div>
<div class="sect-t">IP</div>${r.ips.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">域名</div>${r.domains.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">User-Agent 特征</div>${r.user_agents.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
    </div></div>
    <div class="card"><div class="card-h"><h3>Dropper URL 与样本</h3></div><div class="card-b">
      ${r.urls.map(i=>`<div class="evi">${esc(i)}</div>`).join('')}
      <div class="sect-t" style="margin-top:12px">恶意样本</div>
      ${Object.entries(r.hashes).map(([h,d])=>`<div class="evi"><b>${esc(d)}</b><br><span class="muted">${esc(h)}</span></div>`).join('')}
    </div></div>
  </div>`;
}

/* IOC 本地过滤：数据量小，纯前端匹配，不发请求 */
(function(){
  function bind(){
    var inp=document.getElementById('ioc-filter');
    if(!inp||inp.dataset.bound) return;
    inp.dataset.bound='1';
    inp.oninput=function(){
      var q=inp.value.trim().toLowerCase();
      document.querySelectorAll('#ioc-filter ~ .sect-t, .evi').forEach(function(el){
        if(el.classList.contains('evi'))
          el.style.display=(!q||el.textContent.toLowerCase().indexOf(q)>=0)?'':'none';
      });
    };
  }
  document.addEventListener('click',function(){setTimeout(bind,60)},true);
  setInterval(bind,900);
})();
