"""扫描与任务路由：发现 / 日志 / 主机检测 / URL 检测 / 任务队列 / 报告。

从 app.py 拆出（第四阶段）。依赖方向：scan_api → deps（+ core）。
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from ..core import discovery, hostcheck, identification, logscan
from ..core import report as report_mod
from ..core.rules import coverage_report
from .deps import *  # noqa: F401,F403

router = APIRouter()

@router.get("/api/scans")
def api_scans(limit: int = 50, offset: int = 0, full: bool = False) -> dict:
    """历史报告列表。

    默认返回**摘要**并分页：以前把每份报告里的 assets/findings 全量返回，
    71 份就有 1.1 MB，报告中心每打开一次都要拉一遍。
    需要完整内容时用 ?full=1（或直接取 /api/scans/{id}/report）。
    """
    total = _scan_signature()[0]
    scans = _load_scans(None, full=full)[offset: offset + max(1, min(limit, 200))]
    return {"scans": scans, "total": total, "offset": offset, "limit": limit}


@router.get("/api/scans/{scan_id}/data")
def api_scan_data(scan_id: str) -> dict:
    """取某次扫描的完整结果（历史回看用，日志分析页需要 findings 明细）。"""
    p = SCANS_DIR / f"{scan_id}.json"
    if not p.exists():
        raise HTTPException(status_code=404, detail="扫描记录不存在")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        raise HTTPException(status_code=500, detail="扫描记录损坏") from None


@router.get("/api/scans/{scan_id}/report", response_class=PlainTextResponse)
def api_report(scan_id: str, fmt: str = "md") -> str:
    p = SCANS_DIR / f"{scan_id}.{fmt}"
    if not p.exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    if fmt == "html":
        return HTMLResponse(p.read_text(encoding="utf-8"))  # type: ignore[return-value]
    return p.read_text(encoding="utf-8")


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


_T1_SOURCES = {"title", "cert", "path", "www_auth", "brand"}


def _kb_load() -> dict:
    if not KB_FILE.exists():
        return {}
    try:
        return json.loads(KB_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _kb_save(kb: dict) -> None:
    try:
        _atomic_write(KB_FILE, json.dumps(kb, ensure_ascii=False, indent=2, sort_keys=True))
    except OSError:
        pass


def _fp_keys(asset: dict) -> list[str]:
    """一台设备可用于检索知识库的指纹键。"""
    keys: list[str] = []
    if asset.get("favicon_mmh3") is not None:
        keys.append(f"favicon:{asset['favicon_mmh3']}")
    for h in (asset.get("asset_fingerprints") or [])[:3]:
        keys.append(f"asset:{h[:16]}")
    return keys


def _is_specific_product(product: str | None) -> bool:
    """是不是「真型号」。占位标签（捷普设备 / xx（证书域名） / 端口推断）不学。"""
    if not product:
        return False
    generic_marks = ("设备（", "（端口推断）", "端口推断")
    if product.endswith("设备") or any(m in product for m in generic_marks):
        return False
    return product not in {"未识别设备", "PHP 会话", "堡垒机", "防火墙系统"}


def _kb_learn(results: list[dict]) -> int:
    """把本次有产品级证据、且型号足够具体的设备写成知识库条目。"""
    kb = _kb_load()
    learned = 0
    for r in results:
        product = r.get("product")
        if not product or r.get("product_source") not in _T1_SOURCES:
            continue
        if not _is_specific_product(product):
            continue      # 只学具体型号，避免把"捷普设备（未知）"固化进知识库
        for key in _fp_keys(r):
            entry = kb.setdefault(key, {"products": {}, "vendor": r.get("vendor") or ""})
            products = entry.setdefault("products", {})
            products[product] = int(products.get(product, 0)) + 1
            if r.get("vendor"):
                entry["vendor"] = r["vendor"]
            learned += 1
    if learned:
        _kb_save(kb)
    return learned


def _kb_apply(results: list[dict]) -> int:
    """用知识库里「唯一且被确认过两次以上」的指纹补齐型号。"""
    kb = _kb_load()
    if not kb:
        return 0
    fixed = 0
    for r in results:
        if r.get("product_source") in _T1_SOURCES:
            continue
        for key in _fp_keys(r):
            entry = kb.get(key) or {}
            products = {k: v for k, v in (entry.get("products") or {}).items() if v >= 2}
            if len(products) != 1:
                continue
            product = next(iter(products))
            r["evidence"] = list(r.get("evidence") or []) + [
                f"指纹知识库：{key} 已在本机被确认过 {products[product]} 次 → 同款『{product}』"
            ]
            r["product"] = product
            r["product_source"] = "kb"
            if not r.get("vendor") and entry.get("vendor"):
                r["vendor"] = entry["vendor"]
                r["vendor_source"] = "kb"
            r["confidence"] = round(min(0.7, max(r.get("confidence") or 0.0, 0.5)), 2)
            fixed += 1
            break
    return fixed


def _apply_favicon_clusters(results: list[dict]) -> int:
    """同款设备互证：favicon 完全相同 → 同一套管理界面 → 大概率同型号。

    只在两种情况下补型号，避免瞎猜：
      1) 该 favicon 在**本批次内**有且只有一个已知产品（多个就不补）；
      2) 目标设备自己没有产品级证据（只有 Server 头/证书域名/banner）。
    这是跨主机证据传播，比单机硬猜可靠得多；置信度封顶 0.6 并写明依据。
    """
    fav_known: dict[str, set[tuple[str, str]]] = {}
    for r in results:
        if not r.get("alive"):
            continue
        fav = r.get("favicon")
        if fav and r.get("product_source") in _T1_SOURCES and r.get("product"):
            fav_known.setdefault(fav, set()).add((r["product"], r.get("vendor") or ""))

    fixed = 0
    for r in results:
        fav = r.get("favicon")
        if not fav or r.get("product_source") in _T1_SOURCES:
            continue
        known = fav_known.get(fav) or set()
        if len(known) != 1:
            continue
        product, vendor = next(iter(known))
        if product == r.get("product"):
            continue
        r["evidence"] = list(r.get("evidence") or []) + [
            f"favicon 聚类：本批次有同款指纹且已确认型号『{product}』的设备，判定为同款"
        ]
        r["product"] = product
        r["product_source"] = "favicon"
        if not r.get("vendor") and vendor:
            r["vendor"] = vendor
            r["vendor_source"] = "favicon"
        r["confidence"] = round(min(0.6, max(r.get("confidence") or 0.0, 0.45)), 2)
        fixed += 1
    return fixed


def _run_discover(job, params: dict) -> dict:
    hosts = _resolve_hosts(params.get("hosts", []), params.get("cidr", ""))
    total = len(hosts)
    job.total = total
    profiles: list[Any] = []
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
        profiles.append(prof)
        JOBS.progress(job.id, idx, total, f"{idx}/{total}  {host} → {prof.device_label}")

    # 跨主机统计噪声端口（单台看不出"这片网段每个 IP 都开着 25/110/143"）
    noise = identification.apply_noise_ports(profiles)

    results = [
        _asset_from_profile(p, params.get("group", "default"),
                            params.get("owner", ""), params.get("note", ""))
        for p in profiles
    ]

    # 型号补全：先用本机知识库（跨批次），再用本批次 favicon 聚类
    kb_fixed = _kb_apply(results)
    same_model = _apply_favicon_clusters(results)
    _kb_learn(results)

    changes: list[dict] = []
    now = datetime.now().isoformat(timespec="seconds")
    if params.get("save", True) and results and not job.cancel_requested:
        with _lock:
            assets = _load_assets()
            by_host = {a["host"]: a for a in assets}
            for rec in results:
                host = rec["host"]
                old = by_host.get(host)
                if not rec.get("alive"):
                    # 离线 / 无有效协议响应：不写入台账；若之前存在，记为「消失」
                    if old is not None:
                        by_host.pop(host, None)
                        changes.append({"host": host, "kind": "gone", "at": now, "fields": {}})
                    continue
                diff = _diff_asset(old, rec)
                if diff:
                    rec["change"] = {"at": now, **diff}
                    if old and old.get("change_history"):
                        rec["change_history"] = (old["change_history"] or [])[-9:] + [rec["change"]]
                    else:
                        rec["change_history"] = [rec["change"]]
                    changes.append({"host": host, "at": now, **diff})
                if old:
                    rec.update({
                        "id": old.get("id", rec["id"]),
                        "group": old.get("group", rec["group"]),
                        "owner": old.get("owner", rec["owner"]),
                        "first_seen": old.get("first_seen", now),
                    })
                    if not diff:
                        rec["change"] = old.get("change")
                        rec["change_history"] = old.get("change_history", [])
                else:
                    rec["first_seen"] = now
                by_host[host] = rec
            _save_assets(list(by_host.values()))

    online = [r for r in results if r.get("alive")]
    offline = len(results) - len(online)
    res = _new_scan("discover")
    res.target_label = _label_of(params)
    res.target_count = len(results)
    res.assets = online
    res.changes = changes
    res.errors.append(f"扫描 {len(results)} 个目标，{len(online)} 个在线，{offline} 个无有效响应（已排除）")
    if noise:
        res.errors.append(
            "跨主机噪声端口：" + "/".join(str(p) for p in sorted(noise))
            + "（在 >30% 可达主机上出现且无有效响应，已从端口清单剔除）"
        )
    if same_model:
        res.errors.append(f"favicon 聚类：{same_model} 台设备据同款指纹补齐了型号")
    if kb_fixed:
        res.errors.append(f"指纹知识库：{kb_fixed} 台设备据历史确认结果补齐了型号")
    _persist(res)
    return {
        "scan_id": res.scan_id,
        "count": len(online),
        "total": len(results),
        "offline": offline,
        "noise_ports": sorted(noise),
        "same_model": same_model,
        "changes": changes,
        "assets": online,
    }


def _analyze_log_file(p: Path, source_name: str | None = None) -> report_mod.ScanResult:
    """日志分析单一路径实现：CLI 任务与上传共用，避免两份逻辑漂移。"""
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    records = list(logscan.iter_records(lines))
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    res = _new_scan("logs")
    res.target_label = source_name or "日志分析"
    res.target_count = len(records)
    res.coverage = coverage_report(fields)
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    if source_name:
        res.coverage["source_file"] = source_name
    res.findings = [f.to_dict() for f in logscan.scan_records(records)]
    return res


def _run_logs(job, params: dict) -> dict:
    path = params.get("path", "")
    job.message = f"正在解析 {Path(path).name}"
    p = _resolve_log_path(path)
    if job.cancel_requested:
        raise RuntimeError("任务已取消")
    res = _analyze_log_file(p)
    job.total = res.coverage.get("total_lines", 0) or 1
    JOBS.progress(job.id, job.total, job.total, "规则匹配完成")
    _persist(res)
    return res.to_dict()


def _run_host(job, params: dict) -> dict:
    job.message = "正在检查 PHP 安装点与生效配置"
    rep = hostcheck.run_host_check(deep=True)
    data = rep.to_dict()
    host = data.get("hostname") or "localhost"
    # 本机检测同样要进台账 —— 本地证据能够覆盖远程推断
    return _ingest_host_report(data, host, source="host")


def _run_url(job, params: dict) -> dict:
    url = params.get("url", "")
    if not url:
        raise ValueError("缺少 url")
    if not url.startswith("http"):
        url = f"http://{url}"
    job.message = f"正在探测 {url}"
    res = _new_scan("url")
    res.target_label = _label_of(params)
    res.target_count = 1
    asm = probe_mod.assess(url, timeout=15.0, do_probe=True)
    res.assets.append(asm.to_dict())
    _persist(res)
    return res.to_dict()


@router.post("/api/jobs")
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
        p = _resolve_log_path(body.path)   # 提交时就校验，别等排队完才失败
        title = f"日志分析 · {p.name}"
        params = body.model_dump()
        params["path"] = str(p)
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


@router.get("/api/jobs")
def api_jobs(limit: int = 50) -> dict:
    """任务列表。

    列表**不带 result**：单条发现任务的 result 可达数百 KB，而前端每 1.5 秒轮询一次，
    带上就等于每秒传半兆。需要结果时用 /api/jobs/{id}。
    """
    jobs = []
    for j in JOBS.list(limit):
        d = j.to_dict()
        d["has_result"] = d.pop("result", None) is not None
        jobs.append(d)
    return {"jobs": jobs}


@router.get("/api/jobs/{job_id}")
def api_job(job_id: str) -> dict:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="任务不存在")
    return job.to_dict()


@router.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str) -> dict:
    ok = JOBS.cancel(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="任务不存在或已结束")
    return {"ok": True, "job_id": job_id}


@router.delete("/api/jobs/{job_id}")
def api_job_delete(job_id: str) -> dict:
    if not JOBS.delete(job_id):
        raise HTTPException(status_code=400, detail="任务仍在执行，无法删除")
    return {"ok": True}


@router.post("/api/scan/logs/upload")
def api_upload_logs(file: UploadFile = File(...)) -> dict:  # noqa: B008
    name = file.filename or "upload.log"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[-80:]
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{safe}"

    data = bytearray()
    while True:
        chunk = file.file.read(1 << 20)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"文件超过上限 {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
            )
    if not data:
        raise HTTPException(status_code=400, detail="文件为空")
    dest.write_bytes(bytes(data))

    # 上传目录只保留最近 50 个文件，避免长期运行把磁盘吃满
    uploads = sorted(UPLOAD_DIR.glob("*_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in uploads[50:]:
        try:
            old.unlink()
        except OSError:
            pass

    res = _analyze_log_file(dest, source_name=name)
    _persist(res)
    return res.to_dict()


@router.delete("/api/scans/{scan_id}")
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

def _label_of(params: dict) -> str:
    """把任务参数压成一句"目标"，写进报告。"""
    kind = params.get("kind") or ""
    if kind == "logs":
        path = (params.get("path") or "").replace("\\", "/")
        return path.rsplit("/", 1)[-1] or "日志分析"
    cidr = params.get("cidr") or ""
    if cidr:
        return str(cidr)
    hosts = params.get("hosts") or []
    if len(hosts) == 1:
        return str(hosts[0])
    if hosts:
        return f"{hosts[0]} 等 {len(hosts)} 台"
    if params.get("url"):
        return str(params["url"])
    return kind or "-"
