import pathlib

p = pathlib.Path(r"C:\Users\<用户名>\Documents\Codex\2026-10-29\zui\php2shell-sentinel\src\p2s\console\app.py")
t = p.read_text(encoding="utf-8")

# ---- 1) 导入 JobManager 与相关 ----
t = t.replace(
    "from ..core import discovery, hostcheck, logscan, probe as probe_mod, report as report_mod",
    "from ..core import discovery, hostcheck, logscan, probe as probe_mod, report as report_mod\n"
    "from ..core.jobs import JobManager, JobState",
)
t = t.replace(
    "_lock = threading.Lock()",
    "_lock = threading.Lock()\nJOBS = JobManager(DATA_DIR, max_workers=1)",
)

# ---- 2) 新增：任务中心 API + 日志上传 + 删除/导出 ----
new_api = '''

# --------------------------------------------------------------------------
# 任务中心（长耗时操作走后台队列，支持进度、取消、持久化）
# --------------------------------------------------------------------------
class JobIn(BaseModel):
    kind: str                       # discover | logs | host | url
    hosts: list[str] = []
    cidr: str = ""
    group: str = "default"
    owner: str = ""
    note: str = ""
    timeout: float = 1.2
    http_timeout: float = 8.0
    quick: bool = False
    save: bool = True
    path: str = ""
    url: str = ""


def _resolve_hosts(hosts: list[str], cidr: str) -> list[str]:
    out = [h.strip() for h in hosts if h and h.strip()]
    if cidr:
        out.extend(_expand_cidr(cidr))
    return list(dict.fromkeys(out))


def _run_discover(job, params: dict) -> dict:
    hosts = _resolve_hosts(params.get("hosts", []), params.get("cidr", ""))
    total = len(hosts)
    job.total = total
    results: list[dict] = []
    for idx, host in enumerate(hosts, 1):
        if job.cancel_requested:
            break
        job.message = f"正在检测 {host}（{idx}/{total}）"
        prof = discovery.discover(
            host,
            timeout=params.get("timeout", 1.2),
            http_timeout=params.get("http_timeout", 8.0),
            deep=not params.get("quick", False),
        )
        rec = _asset_from_profile(
            prof, params.get("group", "default"), params.get("owner", ""), params.get("note", "")
        )
        results.append(rec)
        JOBS.progress(job.id, idx, total, f"{idx}/{total}  {host} → {prof.device_label}")
    if params.get("save", True) and results:
        with _lock:
            assets = _load_assets()
            by_host = {a["host"]: a for a in assets}
            for rec in results:
                old = by_host.get(rec["host"])
                if old:
                    rec.update({
                        "id": old.get("id", rec["id"]),
                        "group": old.get("group", rec["group"]),
                        "owner": old.get("owner", rec["owner"]),
                    })
                by_host[rec["host"]] = rec
            _save_assets(list(by_host.values()))
    res = _new_scan("discover")
    res.target_count = len(results)
    res.assets = results
    _persist(res)
    return {"scan_id": res.scan_id, "count": len(results), "assets": results}


def _run_logs(job, params: dict) -> dict:
    path = params.get("path", "")
    job.message = f"正在解析 {path}"
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"日志文件不存在: {path}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    job.total = len(lines) or 1
    records = list(logscan.iter_records(lines))
    JOBS.progress(job.id, len(lines), job.total, "规则匹配中")
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    res = _new_scan("logs")
    res.target_count = len(records)
    res.coverage = coverage_report(fields)
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    res.findings = [f.to_dict() for f in logscan.scan_records(records)]
    _persist(res)
    return res.to_dict()


def _run_host(job, params: dict) -> dict:
    job.message = "正在检查 PHP 安装点与生效配置"
    rep = hostcheck.run_host_check(deep=True)
    res = _new_scan("host")
    res.target_count = 1
    res.host_reports = [rep.to_dict()]
    for a in rep.artifacts:
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.get('kind')}",
            "severity": a.get("severity", "medium"),
            "dimension": "host",
            "cves": list(("CVE-2026-109618", "CVE-2026-109619")),
            "ts": rep.checked_at,
            "ip": rep.hostname,
            "uri": a.get("path"),
            "evidence": a.get("detail"),
        })
    _persist(res)
    return res.to_dict()


def _run_url(job, params: dict) -> dict:
    url = params.get("url", "")
    if not url:
        raise ValueError("缺少 url")
    if not url.startswith("http"):
        url = f"http://{url}"
    job.message = f"正在探测 {url}"
    res = _new_scan("url")
    res.target_count = 1
    asm = probe_mod.assess(url, timeout=15.0, do_probe=True)
    res.assets.append(asm.to_dict())
    _persist(res)
    return res.to_dict()


@app.post("/api/jobs")
def api_create_job(body: JobIn) -> dict:
    kind = body.kind
    if kind == "discover":
        hosts = _resolve_hosts(body.hosts, body.cidr)
        if not hosts:
            raise HTTPException(status_code=400, detail="请提供主机或网段")
        if len(hosts) > 1024:
            raise HTTPException(status_code=400, detail=f"目标过多（{len(hosts)} 台），上限 1024 台")
        title = f"设备发现 · {len(hosts)} 台目标"
        params = body.model_dump()
        params["hosts"] = hosts
        params["cidr"] = ""
        total = len(hosts)
    elif kind == "logs":
        if not body.path:
            raise HTTPException(status_code=400, detail="缺少日志路径")
        title = f"日志分析 · {Path(body.path).name}"
        params = body.model_dump()
        total = 0
    elif kind == "host":
        title = "主机侧检测"
        params = body.model_dump()
        total = 0
    elif kind == "url":
        if not body.url:
            raise HTTPException(status_code=400, detail="缺少 url")
        title = f"URL 探测 · {body.url}"
        params = body.model_dump()
        total = 0
    else:
        raise HTTPException(status_code=400, detail=f"未知任务类型: {kind}")

    runner = {"discover": _run_discover, "logs": _run_logs, "host": _run_host, "url": _run_url}[kind]
    job = JOBS.submit(kind, title, runner, params, total)
    return job.to_dict()


@app.get("/api/jobs")
def api_jobs(limit: int = 50) -> dict:
    return {"jobs": [j.to_dict() for j in JOBS.list(limit)]}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str) -> dict:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="任务不存在")
    return job.to_dict()


@app.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str) -> dict:
    ok = JOBS.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="任务不存在或已结束")
    return {"ok": True, "job_id": job_id}


@app.delete("/api/jobs/{job_id}")
def api_job_delete(job_id: str) -> dict:
    if not JOBS.delete(job_id):
        raise HTTPException(status_code=400, detail="任务仍在执行，无法删除")
    return {"ok": True}


# --------------------------------------------------------------------------
# 日志文件上传（客户未必能访问服务器本地路径）
# --------------------------------------------------------------------------
@app.post("/api/scan/logs/upload")
def api_upload_logs(file: UploadFile = File(...)) -> dict:
    name = file.filename or "upload.log"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[-80:]
    dest_dir = DATA_DIR / "uploads"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{uuid.uuid4().hex[:8]}_{safe}"
    data = file.file.read()
    dest.write_bytes(data)
    res = _new_scan("logs")
    lines = dest.read_text(encoding="utf-8", errors="replace").splitlines()
    records = list(logscan.iter_records(lines))
    res.target_count = len(records)
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    res.coverage = coverage_report(fields)
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    res.coverage["source_file"] = name
    res.findings = [f.to_dict() for f in logscan.scan_records(records)]
    _persist(res)
    return res.to_dict()


# --------------------------------------------------------------------------
# 删除与导出
# --------------------------------------------------------------------------
@app.delete("/api/scans/{scan_id}")
def api_delete_scan(scan_id: str) -> dict:
    removed = []
    for fmt in ("json", "md", "html"):
        f = SCANS_DIR / f"{scan_id}.{fmt}"
        if f.exists():
            f.unlink()
            removed.append(fmt)
    if not removed:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"ok": True, "removed": removed}


@app.get("/api/php-exposure/export")
def api_php_export() -> str:
    rows = api_php_exposure()["rows"]
    out = ["host,device,php_version,sapi,fixed_release,status,exposure,risk,owner,group"]
    for r in rows:
        out.append(",".join(str(x).replace(",", " ") for x in [
            r.get("host", ""), r.get("device_label", ""), r.get("php_version") or "",
            r.get("sapi") or "", r.get("fixed_release") or "", r.get("status", ""),
            r.get("exposure", ""), r.get("risk", ""), r.get("owner") or "", r.get("group") or "",
        ]))
    return "\\n".join(out)


@app.get("/api/host/export")
def api_host_export() -> str:
    assets = _load_assets()
    out = ["host,device_type,device_label,vendor,os_hint,php_present,php_version,sapi,exposure,risk,group,owner,note"]
    for a in assets:
        out.append(",".join(str(x).replace(",", " ") for x in [
            a.get("host", ""), a.get("device_type", ""), a.get("device_label", ""),
            a.get("vendor") or "", a.get("os_hint") or "", a.get("php_present"),
            a.get("php_version") or "", a.get("sapi") or "", a.get("exposure", ""),
            a.get("risk", ""), a.get("group") or "", a.get("owner") or "", a.get("note") or "",
        ]))
    return "\\n".join(out)


@app.get("/api/host/report")
def api_host_report() -> dict:
    """最近一次主机侧检测报告（用于导出）。"""
    scans = []
    if SCANS_DIR.exists():
        for p in sorted(SCANS_DIR.glob("host-*.json")):
            try:
                scans.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
    if not scans:
        raise HTTPException(status_code=404, detail="还没有主机侧检测记录")
    return scans[-1]
'''

anchor = "\n\n# --------------------------------------------------------------------------\n# 界面\n# --------------------------------------------------------------------------"
assert anchor in t
t = t.replace(anchor, new_api + anchor)

# ---- 3) 需要的额外 import ----
t = t.replace(
    "import ipaddress\nimport json",
    "import ipaddress\nimport json\nimport re",
)
t = t.replace(
    "from fastapi import FastAPI, HTTPException",
    "from fastapi import FastAPI, File, HTTPException, UploadFile",
)

p.write_text(t, encoding="utf-8")
print("app.py: 任务中心 / 上传 / 删除 / 导出 API 已接入")