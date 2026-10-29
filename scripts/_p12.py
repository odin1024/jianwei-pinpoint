import pathlib

p = pathlib.Path(r"C:\Users\<用户名>\Documents\Codex\2026-10-29\zui\php2shell-sentinel\src\p2s\console\ui.py")
t = p.read_text(encoding="utf-8")

# 1) 轮询时：任务状态变化 -> 刷新设备发现页的结果网格
old = """    if(location.hash.slice(1)==='tasks' && $('#jobs-body')) renderJobs();
    if(location.hash.slice(1)==='discover' && $('#d-jobs')) renderDiscoverJobs();"""
new = """    if(location.hash.slice(1)==='tasks' && $('#jobs-body')) renderJobs();
    if(location.hash.slice(1)==='discover' && $('#d-jobs')){
      const before = S.jobs.map(j=>j.id+':'+j.state).join(',');
      renderDiscoverJobs();
      if(before !== S._lastJobSig){ S._lastJobSig = before; refreshDiscoverResults(); }
    }"""
assert old in t
t = t.replace(old, new)

# 2) 设备发现页：区分「本次任务结果」与「台账中的设备」
old2 = """  S.assets=(await api('/api/assets')).assets;
  renderDevices($('#d-results'),S.assets);
  renderDiscoverJobs();
}"""
new2 = """  await refreshDiscoverResults();
  renderDiscoverJobs();
}

async function refreshDiscoverResults(){
  S.assets=(await api('/api/assets')).assets;
  const box=$('#d-results'); if(!box) return;
  const running=S.jobs.filter(j=>j.kind==='discover'&&(j.state==='running'||j.state==='queued')).length;
  const latest=S.jobs.find(j=>j.kind==='discover'&&j.state==='done'&&j.result&&j.result.assets);
  const label=running?`扫描进行中（${running} 个任务）`:
    (latest?`最近一次扫描结果 · ${latest.id}`:'台账中的设备');
  box.innerHTML=`<div style="grid-column:1/-1;display:flex;align-items:center;gap:9px;margin-bottom:2px">
      <span style="font-size:12.5px;font-weight:600">${esc(label)}</span>
      <span class="muted" style="font-size:11.5px">共 ${S.assets.length} 台</span></div>`+
    (latest?`<div style="grid-column:1/-1" class="hint">下方为本次扫描识别到的设备；台账完整列表见「资产台账」。</div>`:'');
  renderDevices(box,S.assets);
}"""
assert old2 in t
t = t.replace(old2, new2)

p.write_text(t, encoding="utf-8")
print("ui.py: 任务完成自动刷新 + 结果区标题")