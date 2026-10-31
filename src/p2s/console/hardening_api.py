"""加固接口：方案(L1) / 回执校验 / 受控执行(L2)。

信任模型（与 README 保持一致）
------------------------------
平台不持有业务主机的写权限：
  · 加固以"包"的形式下载，由运维执行；
  · 若启用受控执行，平台只签发**一次性令牌 + 白名单动作**，由 Agent 主动拉取执行；
  · 执行完必须回执，平台校验 sha256 后才改状态。
"""
from __future__ import annotations

import hmac
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from ..core import hardening as H
from ..core import rulebook
from .deps import (
    ADMIN_USER,
    DATA_DIR,
    _atomic_write,
    _load_assets,
    _lock,
    _save_assets,
)

router = APIRouter()

HARDEN_DIR = DATA_DIR / "hardening"
TOKEN_TTL_MINUTES = 10


def _dir():
    HARDEN_DIR.mkdir(parents=True, exist_ok=True)
    return HARDEN_DIR


def _record_path(host: str):
    safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)
    return _dir() / f"{safe}.json"


def _load_record(host: str) -> dict:
    p = _record_path(host)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_record(host: str, rec: dict) -> None:
    _atomic_write(_record_path(host), json.dumps(rec, ensure_ascii=False, indent=2))


def _find_asset(host: str) -> dict:
    for a in _load_assets():
        if a.get("host") == host:
            return a
    raise HTTPException(status_code=404, detail="资产不存在")


def _prefer_fpm(paths: list[str]) -> str:
    """优先选 fpm 的 php.ini —— cli 的改了线上不生效（实测过这个坑）。"""
    for p in paths:
        if "/fpm/" in p:
            return p
    for p in paths:
        if "/apache2/" in p:
            return p
    return paths[0] if paths else ""


def _target_of(asset: dict, override: str = "") -> str:
    """php.ini 路径：显式指定 > fpm 候选 > 顶层字段 > 第一个安装点。"""
    if override:
        return override
    hr = asset.get("host_report") or {}
    cands = [str(p) for p in (hr.get("ini_candidates") or []) if p]
    if cands:
        return _prefer_fpm(cands)
    if hr.get("ini_path"):
        return str(hr["ini_path"])
    for i in hr.get("installs") or []:
        if i.get("ini"):
            return str(i["ini"])
    return ""


def _ini_sha(asset: dict) -> str:
    hr = asset.get("host_report") or {}
    return str(hr.get("ini_sha256") or "")


@router.get("/api/hardening/plan/{host}")
def api_hardening_plan(host: str) -> dict:
    """给出一台主机的加固方案：待改项、原因、漂移、当前状态。"""
    a = _find_asset(host)
    hr = a.get("host_report") or {}
    target = _target_of(a)
    actions = _actions_for(a, target) if hr else []
    rec = _load_record(host)
    return {
        "host": host,
        "target": target or None,
        "actions": actions,
        "pending": len(actions),
        "drift": H.drift(hr, (rec.get("baseline") or None)),
        # pool 级 php_admin_value 会盖过 php.ini：改了 ini 也可能不生效，必须提前告知
        "pool_overrides": [x for x in (hr.get("pool_overrides") or []) if x.get("key")],
        "status": a.get("hardening_status") or ("pending" if actions else "ok"),
        "last_verified_at": a.get("hardening_verified_at") or "",
        "note": "" if hr else "该主机还没有 Agent 上报，无法生成加固方案",
    }


@router.get("/api/hardening/pack/{host}")
def api_hardening_pack(host: str) -> Response:
    """下载加固包（zip）。平台不执行任何变更。"""
    a = _find_asset(host)
    hr = a.get("host_report") or {}
    target = _target_of(a)
    if not target:
        raise HTTPException(status_code=400, detail="缺少 php.ini 路径，无法生成加固包")
    actions = _actions_for(a, target)
    if not actions:
        raise HTTPException(status_code=400, detail="当前没有需要加固的配置项")
    files = H.build_pack(host, hr, target, actions)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o755 << 16 if name.endswith(".sh") else 0o644 << 16
            z.writestr(info, content)
    _save_record(host, {**_load_record(host), "issued_at": H._now(),
                        "target": target, "actions": actions})
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition":
                             f'attachment; filename="p2s-harden-{host}.zip"'})


@router.post("/api/hardening/receipt")
def api_hardening_receipt(payload: dict) -> dict:
    """校验运维回执：sha/动作/主机都对得上，才把资产标成已加固。"""
    rec = payload.get("receipt") if isinstance(payload.get("receipt"), dict) else payload
    host = str(rec.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="回执缺少 host")
    _find_asset(host)
    issued = _load_record(host)
    if not issued:
        raise HTTPException(status_code=400, detail="该主机没有签发过加固包")

    # 1) 动作必须是我们签发过的
    applied = {x.get("key"): str(x.get("value")) for x in (rec.get("applied") or []) if x.get("key")}
    expected = {x.get("key"): str(x.get("value")) for x in (issued.get("actions") or [])}
    if not applied:
        raise HTTPException(status_code=400, detail="回执里没有 applied 条目")
    unknown = sorted(set(applied) - set(expected))
    if unknown:
        raise HTTPException(status_code=400, detail=f"回执包含未签发的动作：{unknown}")
    mismatch = {k: (applied[k], expected[k]) for k in applied if expected.get(k) != applied[k]}
    if mismatch:
        raise HTTPException(status_code=400, detail=f"动作取值与签发不一致：{mismatch}")

    # 2) 改前 sha 必须与签发时一致
    if rec.get("before_sha") and issued.get("before_sha256") and \
            rec["before_sha"] != issued["before_sha256"]:
        raise HTTPException(status_code=400, detail="回执的 before_sha 与签发时不一致")

    now = H._now()
    with _lock:
        assets = _load_assets()
        for x in assets:
            if x.get("host") != host:
                continue
            x["hardening_status"] = "verified"
            x["hardening_verified_at"] = now
            x["hardening_applied"] = [{"key": k, "value": v} for k, v in applied.items()]
            x["hardening_after_sha256"] = str(rec.get("after_sha") or "")
            _save_assets(assets)
            break
    _save_record(host, {**issued, "verified_at": now,
                        "baseline": {k: v for k, v in applied.items()},
                        "after_sha256": str(rec.get("after_sha") or "")})
    return {"ok": True, "host": host, "verified_at": now, "applied": len(applied)}


# --------------------------------------------------------------------------
# L2：受控执行（一次性令牌 + 白名单动作）
# --------------------------------------------------------------------------
def _sign(host: str, action_hash: str, exp: str) -> str:
    msg = f"{host}|{action_hash}|{exp}".encode()
    return hmac.new(b"p2s-hardening-v1", msg, "sha256").hexdigest()


@router.post("/api/hardening/request")
def api_hardening_request(payload: dict) -> dict:
    """申请受控执行：签发一次性令牌（10 分钟有效，绑定主机+动作哈希）。"""
    host = str(payload.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="缺少 host")
    a = _find_asset(host)
    target = _target_of(a)
    actions = _actions_for(a, target)
    if not actions:
        raise HTTPException(status_code=400, detail="没有可执行的加固动作")

    action_hash = H.sha256_text(json.dumps(actions, sort_keys=True, ensure_ascii=False))
    exp = (datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES)) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    token = _sign(host, action_hash, exp)

    rec = _load_record(host)
    rec.update({
        "target": target, "actions": actions, "before_sha256": _ini_sha(a),
        "token": token, "exp": exp, "issued_at": H._now(),
        "requested_by": ADMIN_USER, "state": "issued",
    })
    _save_record(host, rec)
    return {"ok": True, "host": host, "exp": exp, "token": token,
            "action_hash": action_hash, "actions": len(actions),
            "note": "令牌一次有效，绑定主机与动作；执行脚本会让 Agent 校验"}


@router.get("/api/hardening/pending/{host}")
def api_hardening_pending(host: str) -> dict:
    """Agent 主动拉取待执行动作（只返回当前有效的令牌）。"""
    rec = _load_record(host)
    if not rec.get("token"):
        return {"pending": None}
    try:
        exp = datetime.strptime(rec["exp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return {"pending": None}
    if datetime.now(timezone.utc) > exp:
        return {"pending": None, "expired": True}
    return {"pending": {"token": rec["token"], "exp": rec["exp"],
                        "target": rec.get("target"), "actions": rec.get("actions") or []}}


@router.post("/api/hardening/revoke/{host}")
def api_hardening_revoke(host: str) -> dict:
    """撤销未执行的令牌。"""
    rec = _load_record(host)
    rec.pop("token", None)
    rec.pop("exp", None)
    rec["state"] = "revoked"
    _save_record(host, rec)
    return {"ok": True, "host": host}

def _actions_for(asset: dict, target: str) -> list[dict]:
    """按**目标 ini 文件里的实际值**生成动作。

    之前用的是 Agent 采集到的"运行值"，那是 CLI 的（php -r 走 cli/php.ini）；
    而生产跑的是 FPM，两边的 ini 常常不一样——实测过 cli 已关、fpm 仍开着。
    """
    hr = asset.get("host_report") or {}
    for f in hr.get("ini_files") or []:
        if str(f.get("path")) == target:
            vals = f.get("values") or {}
            synth = {"settings": [{"name": k, "actual": v} for k, v in vals.items()]}
            return H.plan_actions(synth, target)
    return H.plan_actions(hr, target)


@router.get("/api/hardening/rules")
def api_hardening_rules(category: str = "", auto: bool | None = None) -> dict:
    """规则库清单：可按分类与是否可自动执行过滤。"""
    rules = list(rulebook.ALL)
    if category:
        rules = [r for r in rules if r.category == category]
    if auto is not None:
        rules = [r for r in rules if r.auto is auto]
    return {
        "total": len(rules),
        "stats": rulebook.stats(),
        "categories": list(rulebook.CATEGORIES),
        "rules": [r.to_dict() for r in rules],
    }
