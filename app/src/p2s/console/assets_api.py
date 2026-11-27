"""资产台账路由：CRUD / 重扫 / 撤销删除 / 导出 / PHP 暴露面。

从 app.py 拆出（第三阶段）。依赖方向：assets_api → deps。
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from ..core import discovery
from ..core.versions import FIXED_RELEASES, classify
from .deps import (  # noqa: F401  —— 显式导入，避免星号导入掩盖未定义名
    _asset_from_profile,
    _count_assets,
    _csv_response,
    _delete_asset,
    _get_asset,
    _load_assets,
    _lock,
    _save_assets,
    _upsert_asset,
)

router = APIRouter()

class AssetIn(BaseModel):
    host: str
    group: str = "default"
    owner: str = ""
    note: str = ""
    discover: bool = True


@router.get("/api/assets")
def api_assets() -> dict:
    return {"assets": _load_assets()}


@router.post("/api/assets")
def api_add_asset(body: AssetIn) -> dict:
    host = body.host.strip()
    if not host:
        raise HTTPException(status_code=400, detail="主机不能为空")
    prof = discovery.discover(host, timeout=1.2, http_timeout=8.0)
    rec = _asset_from_profile(prof, body.group, body.owner, body.note)
    with _lock:
        # 增量写：只动这一行，代价与台账规模无关。
        # （旧实现是「读全部 -> 改内存 -> 写全部」，台账越大越慢）
        _upsert_asset(rec)
        total = _count_assets()
    return {"ok": True, "asset": rec, "total": total}


@router.delete("/api/assets")
def api_del_asset(host: str) -> dict:
    with _lock:
        removed = 1 if _delete_asset(host) else 0
        total = _count_assets()
    return {"ok": True, "removed": removed, "total": total}


@router.patch("/api/assets")
def api_update_asset(payload: dict) -> dict:
    host = payload.get("host")
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    with _lock:
        # 按 host 取单条（O(1)），改完增量写回 —— 不再全量读 + 全量写
        updated = _get_asset(host)
        if updated is None:
            raise HTTPException(status_code=404, detail="资产不存在")
        for k in ("group", "owner", "note"):
            if k in payload:
                updated[k] = payload[k]
        _upsert_asset(updated)
    return {"ok": True}


@router.post("/api/assets/rescan")
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


@router.post("/api/assets/restore")
def api_restore_asset(body: dict[str, Any]) -> dict:
    """撤销删除：把前端快照里的资产原样写回台账（按 host 幂等）。"""
    host = str(body.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    with _lock:
        assets = _load_assets()
        by_host = {a["host"]: a for a in assets}
        rec = dict(body)
        rec["host"] = host
        rec.setdefault("id", uuid.uuid4().hex[:12])
        by_host[host] = rec
        _save_assets(list(by_host.values()))
    return {"ok": True, "host": host}


@router.get("/api/assets/export")
def api_export_assets() -> Response:
    assets = _load_assets()
    rows: list[list[Any]] = [[
        "host", "device_type", "device_label", "vendor", "php_present",
        "php_version", "sapi", "exposure", "risk", "open_ports", "group", "owner",
    ]]
    for a in assets:
        rows.append([
            a.get("host", ""), a.get("device_type", ""), a.get("device_label", ""),
            a.get("vendor") or "", a.get("php_present"), a.get("php_version") or "",
            a.get("sapi") or "", a.get("exposure", ""), a.get("risk", ""),
            " ".join(str(p) for p in a.get("open_ports", [])),
            a.get("group") or "", a.get("owner") or "",
        ])
    return _csv_response(rows, "p2s-assets.csv")


# --------------------------------------------------------------------------
# PHP 暴露面
# --------------------------------------------------------------------------
@router.get("/api/php-exposure")
def api_php_exposure() -> dict:
    assets = [a for a in _load_assets() if a.get("php_present")]
    rows = []
    # 状态与原因必须同源：
    # 资产上的 exposure/host_reason 才是**权威结论**（它已经过 changelog / 补丁标志校正），
    # 单凭版本号重新 classify 会和它打架（出现过"已修复"配"低于基线，受影响"）。
    _EXPOSURE2STATUS = {
        "exposed": "vulnerable", "patched": "patched",
        "unknown": "unknown", "not_php": "not_php",
    }
    for a in assets:
        v = classify(a.get("php_version")) if a.get("php_version") else None
        status = _EXPOSURE2STATUS.get(str(a.get("exposure") or ""), "")
        reason = ""
        if a.get("host_reason"):
            reason = str(a["host_reason"])
        elif v:
            reason = v.reason
        if not status:
            status = v.status if v else "unknown"
        rows.append({
            "host": a.get("host"),
            "device_label": a.get("device_label"),
            "php_version": a.get("php_version"),
            "php_instances": a.get("php_instances") or [],
            "sapi": a.get("sapi"),
            "status": status,
            "fixed_release": v.fixed_release if v else None,
            "reason": reason or "未能确定版本",
            "exposure": a.get("exposure"),
            "risk": a.get("risk"),
            "owner": a.get("owner", ""),
            "group": a.get("group", ""),
            "remediation": a.get("remediation", []),
        })
    rows.sort(key=lambda r: ({"critical": 0, "medium": 1, "low": 2}.get(r.get("risk", "low"), 3), r.get("host") or ""))
    return {"rows": rows, "fixed_releases": FIXED_RELEASES}


# --------------------------------------------------------------------------
# 整改跟踪
#
# 设计：状态存在资产记录里（remediation_status），不新建表 —— 资产本身就是主键。
# 「复扫联动」用**读时归一**实现：exposure 变成 patched 就视为 fixed，
# 不依赖扫描链路去写库，避免漏改任何一条写入路径。
# --------------------------------------------------------------------------
REM_STATUSES = ("pending", "in_progress", "fixed", "ignored")


def _effective_status(a: dict) -> str:
    """资产的有效整改状态（复扫已修复 → 自动视为 fixed）。"""
    raw = str(a.get("remediation_status") or "").strip()
    if raw in REM_STATUSES:
        if raw != "ignored" and a.get("exposure") == "patched":
            return "fixed"
        return raw
    # 未显式设置时按暴露面推断
    return "fixed" if a.get("exposure") == "patched" else "pending"


@router.get("/api/remediation")
def api_remediation() -> dict:
    """整改跟踪看板：按状态分组 + 统计。"""
    assets = _load_assets()
    buckets: dict[str, list[dict]] = {k: [] for k in REM_STATUSES}
    for a in assets:
        st = _effective_status(a)
        buckets[st].append({
            "host": a.get("host"),
            "device_label": a.get("device_label"),
            "vendor": a.get("vendor"),
            "exposure": a.get("exposure"),
            "risk": a.get("risk"),
            "php_version": a.get("php_version"),
            "owner": a.get("owner") or "",
            "ignored_reason": a.get("ignored_reason") or "",
            "updated_at": a.get("remediation_updated_at") or "",
            "remediation": (a.get("remediation") or [])[:3],
            "auto_fixed": (a.get("exposure") == "patched"
                           and a.get("remediation_status") in (None, "", "pending", "in_progress")),
        })
    total = len(assets)
    return {
        "groups": buckets,
        "counts": {k: len(v) for k, v in buckets.items()},
        "total": total,
        "done_ratio": round(len(buckets["fixed"]) / total * 100, 1) if total else 0.0,
    }


@router.patch("/api/assets/remediation")
def api_set_remediation(payload: dict) -> dict:
    """设置单个资产的整改状态 / 责任人 / 忽略原因。"""
    host = str(payload.get("host") or "").strip()
    status = str(payload.get("status") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    if status not in REM_STATUSES:
        raise HTTPException(status_code=400, detail=f"status 必须是 {'/'.join(REM_STATUSES)}")

    now = datetime.now().isoformat(timespec="seconds")
    with _lock:
        assets = _load_assets()
        by_host = {a["host"]: a for a in assets}
        rec = by_host.get(host)
        if rec is None:
            raise HTTPException(status_code=404, detail="资产不存在")
        rec["remediation_status"] = status
        rec["remediation_updated_at"] = now
        if "owner" in payload:
            rec["owner"] = str(payload.get("owner") or "").strip()
        if status == "ignored":
            rec["ignored_reason"] = str(payload.get("ignored_reason") or "").strip()
        else:
            rec.pop("ignored_reason", None)
        _save_assets(assets)
    return {"ok": True, "host": host, "status": status, "updated_at": now}
