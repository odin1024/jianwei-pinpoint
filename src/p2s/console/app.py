"""p2s Web 控制台 API（FastAPI）。

形态定位：给客户交付时的主要交互界面。
  - 总览：全局风险视图
  - 设备发现：网段/批量主机 -> 设备类型 + PHP 暴露面
  - 资产台账：设备画像持久化、分组、负责人、导出
  - PHP 暴露面：只看跑 PHP 的资产，版本 vs 修复基线矩阵
  - 日志分析 / 主机侧 / 规则中心 / IOC 中心 / 报告中心
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from ..core import discovery, hostcheck, logscan
from ..core import probe as probe_mod
from ..core import report as report_mod
from ..core.ioc import IocLibrary
from ..core.rules import RULES, coverage_report
from ..core.versions import FIXED_RELEASES, classify
from .ui import DASHBOARD_HTML

app = FastAPI(
    title="p2s — php2shell 检测控制台",
    description="CVE-2026-109618 / CVE-2026-109619 检测与暴露面评估",
    version="0.2.0",
)

DATA_DIR = Path(os.environ.get("P2S_DATA_DIR", "./p2s-data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_FILE = DATA_DIR / "assets.json"
SCANS_DIR = DATA_DIR / "scans"

_lock = threading.Lock()


# --------------------------------------------------------------------------
# 存储
# --------------------------------------------------------------------------
def _load_assets() -> list[dict]:
    if not ASSETS_FILE.exists():
        return []
    try:
        return json.loads(ASSETS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_assets(assets: list[dict]) -> None:
    ASSETS_FILE.write_text(json.dumps(assets, ensure_ascii=False, indent=2), encoding="utf-8")


def _new_scan(kind: str) -> report_mod.ScanResult:
    return report_mod.ScanResult(
        scan_id=f"{kind}-{uuid.uuid4().hex[:10]}",
        kind=kind,
        started_at=datetime.now().isoformat(timespec="seconds"),
    )


def _persist(res: report_mod.ScanResult) -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    base = SCANS_DIR / res.scan_id
    report_mod.to_json(res, base.with_suffix(".json"))
    report_mod.to_markdown(res, base.with_suffix(".md"))
    report_mod.to_html(res, base.with_suffix(".html"))
    res.finished_at = datetime.now().isoformat(timespec="seconds")


def _asset_from_profile(prof: discovery.DeviceProfile, group: str, owner: str, note: str) -> dict:
    return {
        "id": uuid.uuid4().hex[:12],
        "host": prof.host,
        "group": group,
        "owner": owner,
        "note": note,
        "alive": prof.alive,
        "device_type": prof.device_type,
        "device_label": prof.device_label,
        "vendor": prof.vendor,
        "os_hint": prof.os_hint,
        "open_ports": prof.open_ports,
        "services": [s.to_dict() for s in prof.services],
        "php_present": prof.php_present,
        "php_version": prof.php_version,
        "sapi": prof.sapi,
        "exposure": prof.exposure,
        "risk": prof.risk,
        "confidence": prof.confidence,
        "evidence": prof.evidence,
        "remediation": prof.remediation,
        "errors": prof.errors,
        "last_checked": prof.scanned_at,
    }


# --------------------------------------------------------------------------
# 模型
# --------------------------------------------------------------------------
class DiscoverIn(BaseModel):
    hosts: list[str] = []
    cidr: str = ""
    group: str = "default"
    owner: str = ""
    note: str = ""
    timeout: float = 1.2
    http_timeout: float = 8.0
    quick: bool = False
    save: bool = True


class AssetIn(BaseModel):
    host: str
    group: str = "default"
    owner: str = ""
    note: str = ""
    discover: bool = True


class ImportIn(BaseModel):
    text: str
    group: str = "default"
    owner: str = ""


class UrlScanIn(BaseModel):
    url: str
    do_probe: bool = True
    timeout: float = 15.0


class LogScanIn(BaseModel):
    path: str


class AgentReportIn(BaseModel):
    hostname: str = ""
    data: dict[str, Any] = {}


def _expand_cidr(cidr: str, limit: int = 1024) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if net.num_addresses > limit:
        raise HTTPException(status_code=400, detail=f"网段过大（{net.num_addresses} 台），上限 {limit} 台")
    return [str(h) for h in net.hosts()]


# --------------------------------------------------------------------------
# 总览
# --------------------------------------------------------------------------
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now().isoformat(timespec="seconds"), "version": "0.2.0"}


@app.get("/api/overview")
def api_overview() -> dict:
    assets = _load_assets()
    scans: list[dict] = []
    if SCANS_DIR.exists():
        for p in sorted(SCANS_DIR.glob("*.json")):
            try:
                scans.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue

    by_type: dict[str, int] = {}
    by_exposure: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "medium": 0, "low": 0}
    php_versions: dict[str, int] = {}
    for a in assets:
        by_type[a.get("device_label", "未识别设备")] = by_type.get(a.get("device_label", "未识别设备"), 0) + 1
        exp = a.get("exposure", "unknown")
        by_exposure[exp] = by_exposure.get(exp, 0) + 1
        r = a.get("risk", "low")
        by_risk[r] = by_risk.get(r, 0) + 1
        if a.get("php_version"):
            php_versions[a["php_version"]] = php_versions.get(a["php_version"], 0) + 1

    return {
        "total_assets": len(assets),
        "alive": sum(1 for a in assets if a.get("alive")),
        "php_present": sum(1 for a in assets if a.get("php_present")),
        "exposed": sum(1 for a in assets if a.get("exposure") == "exposed"),
        "patched": sum(1 for a in assets if a.get("exposure") == "patched"),
        "not_php": sum(1 for a in assets if a.get("exposure") == "not_php"),
        "unknown": sum(1 for a in assets if a.get("exposure") == "unknown"),
        "by_type": by_type,
        "by_exposure": by_exposure,
        "by_risk": by_risk,
        "php_versions": php_versions,
        "fixed_releases": FIXED_RELEASES,
        "scan_count": len(scans),
        "recent_scans": scans[:8],
        "groups": sorted({a.get("group", "default") for a in assets}),
    }


# --------------------------------------------------------------------------
# 设备发现
# --------------------------------------------------------------------------
@app.post("/api/discover")
def api_discover(body: DiscoverIn) -> dict:
    hosts = [h.strip() for h in body.hosts if h and h.strip()]
    if body.cidr:
        hosts.extend(_expand_cidr(body.cidr))
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        raise HTTPException(status_code=400, detail="请提供主机或网段")

    profiles: list[dict] = []
    for h in hosts:
        prof = discovery.discover(
            h, timeout=body.timeout, http_timeout=body.http_timeout, deep=not body.quick
        )
        profiles.append(_asset_from_profile(prof, body.group, body.owner, body.note))

    if body.save and profiles:
        with _lock:
            assets = _load_assets()
            by_host = {a["host"]: a for a in assets}
            for pr in profiles:
                old = by_host.get(pr["host"])
                if old:
                    pr.update({"id": old["id"], "group": old.get("group", body.group),
                               "owner": old.get("owner", body.owner)})
                by_host[pr["host"]] = pr
            _save_assets(list(by_host.values()))

    res = _new_scan("discover")
    res.target_count = len(profiles)
    res.assets = profiles
    _persist(res)
    return {"scan_id": res.scan_id, "count": len(profiles), "assets": profiles}


# --------------------------------------------------------------------------
# 资产台账
# --------------------------------------------------------------------------
@app.get("/api/assets")
def api_assets() -> dict:
    return {"assets": _load_assets()}


@app.post("/api/assets")
def api_add_asset(body: AssetIn) -> dict:
    host = body.host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="主机不能为空")
    prof = discovery.discover(host, timeout=1.2, http_timeout=8.0)
    rec = _asset_from_profile(prof, body.group, body.owner, body.note)
    with _lock:
        assets = _load_assets()
        assets = [a for a in assets if a.get("host") != host]
        assets.append(rec)
        _save_assets(assets)
    return {"ok": True, "asset": rec, "total": len(assets)}


@app.post("/api/assets/import")
def api_import_assets(body: ImportIn) -> dict:
    hosts = [h.strip() for h in body.text.replace(",", "\n").splitlines() if h.strip() and not h.startswith("#")]
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        raise HTTPException(status_code=400, detail="没有解析到有效主机")
    added = 0
    with _lock:
        assets = _load_assets()
        by_host = {a["host"]: a for a in assets}
        for h in hosts:
            if h in by_host:
                continue
            prof = discovery.discover(h, timeout=1.0, http_timeout=6.0, deep=False)
            by_host[h] = _asset_from_profile(prof, body.group, body.owner, "")
            added += 1
        _save_assets(list(by_host.values()))
    return {"ok": True, "added": added, "total": len(by_host)}


@app.delete("/api/assets")
def api_del_asset(host: str) -> dict:
    with _lock:
        assets = _load_assets()
        before = len(assets)
        assets = [a for a in assets if a.get("host") != host]
        _save_assets(assets)
    return {"ok": True, "removed": before - len(assets), "total": len(assets)}


@app.patch("/api/assets")
def api_update_asset(payload: dict) -> dict:
    host = payload.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    with _lock:
        assets = _load_assets()
        found = False
        for a in assets:
            if a.get("host") == host:
                for k in ("group", "owner", "note"):
                    if k in payload:
                        a[k] = payload[k]
                found = True
        _save_assets(assets)
    if not found:
        raise HTTPException(status_code=404, detail="资产不存在")
    return {"ok": True}


@app.post("/api/assets/rescan")
def api_rescan(body: dict) -> dict:
    host = body.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    prof = discovery.discover(host, timeout=1.2, http_timeout=8.0)
    rec = _asset_from_profile(prof, body.get("group", "default"), body.get("owner", ""), body.get("note", ""))
    with _lock:
        assets = _load_assets()
        out = []
        replaced = False
        for a in assets:
            if a.get("host") == host:
                rec["id"] = a.get("id", rec["id"])
                rec["group"] = a.get("group", rec["group"])
                rec["owner"] = a.get("owner", rec["owner"])
                out.append(rec)
                replaced = True
            else:
                out.append(a)
        if not replaced:
            out.append(rec)
        _save_assets(out)
    return {"ok": True, "asset": rec}


@app.get("/api/assets/export")
def api_export_assets() -> str:
    assets = _load_assets()
    rows = ["host,device_type,device_label,vendor,php_present,php_version,sapi,exposure,risk,open_ports"]
    for a in assets:
        rows.append(
            ",".join(
                str(x).replace(",", " ") for x in [
                    a.get("host", ""), a.get("device_type", ""), a.get("device_label", ""),
                    a.get("vendor") or "", a.get("php_present"), a.get("php_version") or "",
                    a.get("sapi") or "", a.get("exposure", ""), a.get("risk", ""),
                    " ".join(str(p) for p in a.get("open_ports", [])),
                ]
            )
        )
    return "\n".join(rows)


# --------------------------------------------------------------------------
# PHP 暴露面
# --------------------------------------------------------------------------
@app.get("/api/php-exposure")
def api_php_exposure() -> dict:
    assets = [a for a in _load_assets() if a.get("php_present")]
    rows = []
    for a in assets:
        v = classify(a.get("php_version")) if a.get("php_version") else None
        rows.append({
            "host": a.get("host"),
            "device_label": a.get("device_label"),
            "php_version": a.get("php_version"),
            "sapi": a.get("sapi"),
            "status": v.status if v else "unknown",
            "fixed_release": v.fixed_release if v else None,
            "reason": v.reason if v else "未能确定版本",
            "exposure": a.get("exposure"),
            "risk": a.get("risk"),
            "owner": a.get("owner", ""),
            "group": a.get("group", ""),
            "remediation": a.get("remediation", []),
        })
    rows.sort(key=lambda r: ({"critical": 0, "medium": 1, "low": 2}.get(r.get("risk", "low"), 3), r.get("host") or ""))
    return {"rows": rows, "fixed_releases": FIXED_RELEASES}


# --------------------------------------------------------------------------
# 扫描
# --------------------------------------------------------------------------
@app.post("/api/scan/url")
def api_scan_url(body: UrlScanIn) -> dict:
    url = body.url if body.url.startswith("http") else f"http://{body.url}"
    res = _new_scan("url")
    res.target_count = 1
    asm = probe_mod.assess(url, timeout=body.timeout, do_probe=body.do_probe)
    res.assets.append(asm.to_dict())
    _persist(res)
    return res.to_dict()


@app.post("/api/scan/logs")
def api_scan_logs(body: LogScanIn) -> dict:
    p = Path(body.path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"日志文件不存在: {body.path}")
    res = _new_scan("logs")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    records = list(logscan.iter_records(lines))
    res.target_count = len(records)
    fields: set[str] = set()
    for r in records:
        fields |= r.fields()
    res.coverage = coverage_report(fields)
    res.coverage["parsed_records"] = len(records)
    res.coverage["total_lines"] = len(lines)
    res.findings = [f.to_dict() for f in logscan.scan_records(records)]
    _persist(res)
    return res.to_dict()


@app.post("/api/scan/host")
def api_scan_host() -> dict:
    res = _new_scan("host")
    rep = hostcheck.run_host_check(deep=True)
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


# --------------------------------------------------------------------------
# 规则 / IOC / 报告
# --------------------------------------------------------------------------
@app.get("/api/rules")
def api_rules() -> dict:
    return {"count": len(RULES), "rules": [r.to_dict() for r in RULES]}


@app.get("/api/rules/export/{fmt}")
def api_rules_export(fmt: str) -> str:
    """导出规则：sigma / modsecurity / suricata。"""
    if fmt == "sigma":
        out: list[str] = []
        for r in RULES:
            out.append(f"""---
title: {r.name}
id: {uuid.uuid5(uuid.NAMESPACE_DNS, r.id).hex}
status: experimental
description: >
  {r.description}
author: p2s
date: {datetime.now().date().isoformat()}
logsource:
  category: webserver
detection:
  selection:
    keyword:
{chr(10).join('      - ' + k for k in ['PHP_SESSION_UPLOAD_PROGRESS', 'PHPSESSID', '<?php', '|O:', 'chunked', 'sess_', 'Allowed memory size', 'Session object destruction failed', 'php2shell'])}
  condition: selection
level: {r.severity}
tags:
  - cve.2026.109618
  - cve.2026.109619
""")
        return "\n".join(out)

    if fmt == "modsecurity":
        lines = [
            "# p2s — php2shell ModSecurity 规则",
            "# 放置到 modsecurity conf.d 目录后 reload 即可",
            "",
            'SecRule REQUEST_METHOD "POST" \\',
            '    "id:9900100,phase:2,deny,status:403,log,',
            "    msg:'p2s: php2shell upload_progress 探测',",
            "    tag:'CVE-2026-109618',tag:'CVE-2026-109619',severity:'CRITICAL',chain'",
            '    SecRule REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" \\',
            '        "chain"',
            '        SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data"',
            "",
            'SecRule MULTIPART_FILENAME "@rx <\\?(?:php|=)" \\',
            '    "id:9900102,phase:2,deny,status:403,log,',
            "    msg:'p2s: 上传文件名含 PHP 代码',severity:'CRITICAL'",
            "",
            'SecRule MULTIPART_FILENAME "@rx \\|(?:O|C|a|r):\\d+:" \\',
            '    "id:9900103,phase:2,deny,status:403,log,',
            "    msg:'p2s: 上传文件名含序列化对象',severity:'CRITICAL'",
            "",
            'SecRule RESPONSE_BODY "@contains Session object destruction failed" \\',
            '    "id:9900105,phase:4,log,pass,',
            "    msg:'p2s: 会话销毁失败（陈旧状态利用证据）',severity:'CRITICAL'",
        ]
        return "\n".join(lines)

    if fmt == "suricata":
        lines = ["# p2s — php2shell Suricata 规则"]
        for i, r in enumerate(RULES):
            lines.append(
                f'alert http any any -> any any (msg:"p2s {r.id} {r.name}"; '
                f'flow:established,to_server; content:"PHP_SESSION_UPLOAD_PROGRESS"; '
                f"nocase; classtype:{r.severity}; sid:9900{100 + i}; rev:1;)"
            )
        return "\n".join(lines)

    raise HTTPException(status_code=400, detail="仅支持 sigma / modsecurity / suricata")


@app.get("/api/ioc")
def api_ioc() -> dict:
    lib = IocLibrary()
    return {
        "summary": lib.summary(),
        "ips": list(lib.ips),
        "domains": list(lib.domains),
        "urls": list(lib.urls),
        "hashes": lib.hashes,
        "user_agents": list(lib.user_agents),
    }


@app.get("/api/scans")
def api_scans() -> dict:
    out = []
    if SCANS_DIR.exists():
        for p in sorted(SCANS_DIR.glob("*.json")):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
    return {"scans": out}


@app.get("/api/scans/{scan_id}/report", response_class=PlainTextResponse)
def api_report(scan_id: str, fmt: str = "md") -> str:
    p = SCANS_DIR / f"{scan_id}.{fmt}"
    if not p.exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    if fmt == "html":
        return HTMLResponse(p.read_text(encoding="utf-8"))  # type: ignore[return-value]
    return p.read_text(encoding="utf-8")


@app.post("/api/agent/report")
def api_agent_report(body: AgentReportIn) -> dict:
    res = _new_scan("agent")
    res.target_count = 1
    data = body.data or {}
    data.setdefault("hostname", body.hostname)
    res.host_reports = [data]
    for a in data.get("artifacts", []):
        res.findings.append({
            "rule_id": "P2S-HOST-001",
            "rule_name": f"主机侧痕迹: {a.get('kind')}",
            "severity": a.get("severity", "medium"),
            "dimension": "host",
            "cves": list(("CVE-2026-109618", "CVE-2026-109619")),
            "ts": data.get("checked_at"),
            "ip": data.get("hostname"),
            "uri": a.get("path"),
            "evidence": a.get("detail"),
        })
    _persist(res)
    return {"ok": True, "scan_id": res.scan_id}


# --------------------------------------------------------------------------
# 界面
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML