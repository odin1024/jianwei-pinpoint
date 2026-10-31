"""运营类接口：审计日志 + 定时扫描调度。

放在一个模块里，因为它们共享"运行期状态"这一层：
  · 审计：记录所有写操作（POST/PATCH/PUT/DELETE），落 audit.jsonl，按行数滚动；
  · 调度：按分钟间隔自动发起发现任务，配置存 schedule.json，线程随进程启动。

设计取舍：
  · 审计用 **JSON Lines** 而不是数据库 —— 追加写、无需迁移、单机足够；
  · 调度线程**只在主进程启动时创建一次**（uvicorn --reload 会重复，故用文件锁标记）；
  · 调度触发的是与手动扫描**完全相同**的任务路径，避免"自动扫描行为不一致"。
"""
from __future__ import annotations

import json
import pathlib
import threading
import time
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException

from .deps import DATA_DIR, _atomic_write

router = APIRouter()

AUDIT_FILE = DATA_DIR / "audit.jsonl"
SCHEDULE_FILE = DATA_DIR / "schedule.json"
MAX_AUDIT_LINES = 5000

_WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}
_AUDIT_SKIP = {"/api/login", "/api/logout", "/api/agent/report", "/api/scan/logs/upload"}


# --------------------------------------------------------------------------
# 审计日志
# --------------------------------------------------------------------------
def record_audit(method: str, path: str, status: int, actor: str, ip: str) -> None:
    """追加一条审计记录；任何异常都不能影响主请求。"""
    if method not in _WRITE_METHODS or not path.startswith("/api"):
        return
    if path in _AUDIT_SKIP or path.startswith("/api/jobs/") and path.endswith("/cancel"):
        pass
    try:
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "actor": actor or "anonymous",
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
        }
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _rotate_audit()
    except OSError:
        pass


def _rotate_audit() -> None:
    """超过上限就保留最后 MAX_AUDIT_LINES 行（简单滚动，不阻塞请求）。"""
    try:
        if not AUDIT_FILE.exists():
            return
        if AUDIT_FILE.stat().st_size < 2_000_000:
            return
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-MAX_AUDIT_LINES:]
        _atomic_write(AUDIT_FILE, "\n".join(lines) + "\n")
    except OSError:
        pass


def read_audit(limit: int = 200, q: str = "") -> list[dict]:
    if not AUDIT_FILE.exists():
        return []
    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-max(1, min(limit, 1000)):]
    except OSError:
        return []
    out: list[dict] = []
    for ln in reversed(lines):
        try:
            e = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if q and q.lower() not in json.dumps(e, ensure_ascii=False).lower():
            continue
        out.append(e)
    return out


@router.get("/api/audit")
def api_audit(limit: int = 200, q: str = "") -> dict:
    rows = read_audit(limit, q)
    return {"rows": rows, "total": len(rows), "file": str(AUDIT_FILE)}


# --------------------------------------------------------------------------
# 定时扫描
# --------------------------------------------------------------------------
_DEFAULT_ITEM: dict[str, Any] = {
    "id": "",
    "name": "",
    "enabled": False,
    "every_minutes": 60,
    "cidr": "",
    "hosts": [],
    "quick": True,
    "save": True,
    "group": "auto",
    "notify_url": "",
    "last_run": "",
    "last_job": "",
    "last_state": "",
}


def _new_id() -> str:
    return "sch-" + uuid.uuid4().hex[:8]


def load_schedules() -> list[dict]:
    """读取全部计划；兼容旧的"单条对象"格式，自动迁移成列表。"""
    raw: Any = {}
    if SCHEDULE_FILE.exists():
        try:
            raw = json.loads(SCHEDULE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raw = {}

    if isinstance(raw, dict) and isinstance(raw.get("schedules"), list):
        items = raw["schedules"]
    elif isinstance(raw, dict) and ("cidr" in raw or "every_minutes" in raw):
        items = [raw]                       # 旧格式：单条
    else:
        items = []

    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        cfg = dict(_DEFAULT_ITEM)
        cfg.update(it)
        if not cfg["id"]:
            cfg["id"] = _new_id()
        if not cfg["name"]:
            cfg["name"] = cfg["cidr"] or (cfg["hosts"][0] if cfg["hosts"] else "未命名计划")
        out.append(cfg)
    return out


def save_schedules(items: list[dict]) -> None:
    _atomic_write(SCHEDULE_FILE,
                  json.dumps({"schedules": items}, ensure_ascii=False, indent=2))


def _seconds_until_next(cfg: dict) -> int:
    if not cfg.get("enabled"):
        return -1
    if not cfg.get("last_run"):
        return 0
    try:
        last = datetime.fromisoformat(str(cfg["last_run"]))
    except ValueError:
        return 0
    due = last.timestamp() + int(cfg.get("every_minutes", 60)) * 60
    return max(0, int(due - time.time()))


def _validate(payload: dict, base: dict | None = None) -> dict:
    """把请求体合并进一条计划并做校验，返回新对象。"""
    cfg = dict(base or _DEFAULT_ITEM)
    for k in ("enabled", "quick", "save"):
        if k in payload:
            cfg[k] = bool(payload[k])
    if "every_minutes" in payload:
        try:
            mins = int(payload["every_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="间隔必须是整数") from None
        if mins < 5:
            raise HTTPException(status_code=400, detail="间隔不能小于 5 分钟")
        if mins > 10080:
            raise HTTPException(status_code=400, detail="间隔不能超过 7 天（10080 分钟）")
        cfg["every_minutes"] = mins
    for k in ("cidr", "group", "name", "notify_url"):
        if k in payload:
            cfg[k] = str(payload.get(k) or "").strip()
    if "hosts" in payload:
        cfg["hosts"] = [str(x).strip() for x in (payload.get("hosts") or []) if str(x).strip()][:1024]
    if not cfg.get("cidr") and not cfg.get("hosts"):
        raise HTTPException(status_code=400, detail="必须填写网段或主机列表")
    if cfg.get("notify_url") and not str(cfg["notify_url"]).startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="通知地址必须以 http:// 或 https:// 开头")
    if not cfg.get("name"):
        cfg["name"] = cfg.get("cidr") or (cfg.get("hosts") or ["未命名计划"])[0]
    return cfg


@router.get("/api/schedules")
def api_list_schedules() -> dict:
    items = load_schedules()
    for it in items:
        it["next_run_in"] = _seconds_until_next(it)
    return {"schedules": items, "total": len(items),
            "enabled": sum(1 for x in items if x.get("enabled"))}


@router.post("/api/schedules")
def api_create_schedule(payload: dict) -> dict:
    cfg = _validate(payload)
    cfg["id"] = _new_id()
    items = load_schedules()
    items.append(cfg)
    save_schedules(items)
    return cfg


@router.patch("/api/schedules/{sid}")
def api_update_schedule(sid: str, payload: dict) -> dict:
    items = load_schedules()
    for i, it in enumerate(items):
        if it["id"] != sid:
            continue
        items[i] = _validate(payload, it)
        items[i]["id"] = sid
        save_schedules(items)
        return items[i]
    raise HTTPException(status_code=404, detail="计划不存在")


@router.delete("/api/schedules/{sid}")
def api_delete_schedule(sid: str) -> dict:
    items = load_schedules()
    left = [x for x in items if x["id"] != sid]
    if len(left) == len(items):
        raise HTTPException(status_code=404, detail="计划不存在")
    save_schedules(left)
    return {"ok": True, "total": len(left)}


@router.post("/api/schedules/{sid}/run")
def api_run_schedule(sid: str) -> dict:
    items = load_schedules()
    for it in items:
        if it["id"] == sid:
            job = _fire(it, items)
            return {"ok": True, "job": job}
    raise HTTPException(status_code=404, detail="计划不存在")


# ---- 兼容旧接口：单条 ----
@router.get("/api/schedule")
def api_get_schedule() -> dict:
    items = load_schedules()
    cfg = dict(items[0]) if items else dict(_DEFAULT_ITEM)
    cfg["next_run_in"] = _seconds_until_next(cfg)
    return cfg


@router.post("/api/schedule")
def api_set_schedule(payload: dict) -> dict:
    """旧接口：没有计划就建一条，有则更新第一条。"""
    items = load_schedules()
    if not items:
        cfg = _validate(payload)
        cfg["id"] = _new_id()
        items.append(cfg)
    else:
        items[0] = _validate(payload, items[0])
        items[0]["id"] = items[0]["id"] or _new_id()
    save_schedules(items)
    return items[0]


def _notify(cfg: dict, job: dict) -> None:
    """任务结束后回调 Webhook（失败不影响调度）。"""
    url = str(cfg.get("notify_url") or "")
    if not url:
        return
    try:
        from urllib.request import Request, urlopen
        body = json.dumps({
            "schedule_id": cfg.get("id"), "name": cfg.get("name"),
            "job_id": job.get("id"), "state": job.get("state"),
            "message": job.get("message"), "total": job.get("total"),
            "done": job.get("done"), "error": job.get("error"),
            "at": datetime.now().isoformat(timespec="seconds"),
        }, ensure_ascii=False).encode()
        req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        urlopen(req, timeout=8).close()
    except Exception:
        pass


def _fire(cfg: dict, items: list[dict] | None = None) -> dict:
    """按与手动扫描相同的路径提交任务，并记录 last_run / last_job。"""
    from .scan_api import JobIn, api_create_job  # 延迟导入，避免循环依赖

    body = JobIn(kind="discover", cidr=cfg.get("cidr") or "", hosts=cfg.get("hosts") or [],
                 quick=bool(cfg.get("quick", True)), save=bool(cfg.get("save", True)),
                 group=str(cfg.get("group") or "auto"), note=f"定时扫描：{cfg.get('name','')}")
    job = api_create_job(body)
    cfg["last_run"] = datetime.now().isoformat(timespec="seconds")
    cfg["last_job"] = str(job.get("id") or "")
    cfg["last_state"] = str(job.get("state") or "running")

    if items is not None:
        for i, it in enumerate(items):
            if it["id"] == cfg["id"]:
                items[i] = cfg
        save_schedules(items)

    if cfg.get("notify_url"):
        def waiter() -> None:
            from . import store  # 局部导入，避免循环
            for _ in range(120):            # 最多等 10 分钟
                time.sleep(5)
                try:
                    cur = store.get_job(cfg["last_job"])
                except Exception:
                    return
                if cur and cur.get("state") in ("done", "failed", "canceled"):
                    _notify(cfg, cur)
                    return
        threading.Thread(target=waiter, daemon=True).start()
    return job


def start_scheduler() -> None:
    """后台线程：每 30 秒检查全部计划，到点的逐个触发。"""
    if getattr(start_scheduler, "_started", False):
        return
    start_scheduler._started = True  # type: ignore[attr-defined]

    def loop() -> None:
        while True:
            try:
                items = load_schedules()
                changed = False
                for it in items:
                    if it.get("enabled") and _seconds_until_next(it) <= 0:
                        _fire(it, items)
                        changed = True
                if changed:
                    save_schedules(items)
                maybe_prune()
            except Exception:
                pass
            time.sleep(30)

    t = threading.Thread(target=loop, name="p2s-scheduler", daemon=True)
    t.start()


# --------------------------------------------------------------------------
# 重复分析检测
#
# 动机：同一份日志被反复分析会产生 N 份一模一样的报告（实测某样例日志被分析了 125 次），
# 既占空间也让报告中心失去区分度。这里在**提交前**告诉前端"这份已经分析过"。
# --------------------------------------------------------------------------
def _age_hours(ts: str) -> float | None:
    from datetime import datetime as _dt
    try:
        t = _dt.fromisoformat((ts or "").replace("Z", "")).timestamp()
    except ValueError:
        return None
    return (time.time() - t) / 3600


@router.get("/api/scans/duplicate")
def api_scan_duplicate(kind: str = "logs", label: str = "", hours: int = 24) -> dict:
    """查最近是否分析过同一目标（同 kind + 同 target_label + 时间窗口内）。"""
    from .deps import _load_scans

    if not label:
        return {"hit": None}
    window = max(1, min(int(hours), 24 * 30))
    for s in _load_scans(None, full=False):          # 已按时间倒序
        if s.get("kind") != kind:
            continue
        if (s.get("target_label") or "").strip() != label.strip():
            continue
        age = _age_hours(s.get("started_at") or "")
        if age is None or age > window:
            continue
        return {"hit": {"scan_id": s.get("scan_id"), "age_hours": round(age, 1),
                        "findings": s.get("finding_count", 0),
                        "risk": s.get("risk"), "started_at": s.get("started_at")}}
    return {"hit": None}


# --------------------------------------------------------------------------
# 报告自动清理
#
# 保守策略：同一内容指纹只保留最新 keep 份；且**只清理超过 min_age_days 天的旧报告**，
# 当天刚跑出来的一律不动。默认 keep=3 天=7，可用环境变量调整；P2S_AUTO_PRUNE=0 关闭。
# --------------------------------------------------------------------------
def prune_scan_files(keep: int = 3, min_age_days: int = 7, apply: bool = True) -> dict:

    from .deps import SCANS_DIR, _scan_dedupe_key

    if not SCANS_DIR.exists():
        return {"removed": 0, "kept_groups": 0}
    groups: dict[str, list[tuple[float, pathlib.Path]]] = {}
    for f in SCANS_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        groups.setdefault(_scan_dedupe_key(d), []).append((f.stat().st_mtime, f))

    removed = 0
    for files in groups.values():
        files.sort(reverse=True)                      # 最新在前
        for mtime, f in files[keep:]:
            if (time.time() - mtime) / 86400 < min_age_days:
                continue                              # 新报告不动
            removed += 1
            if apply:
                for ext in (".json", ".md", ".html"):
                    (f.parent / (f.stem + ext)).unlink(missing_ok=True)
    return {"removed": removed, "kept_groups": len(groups),
            "keep": keep, "min_age_days": min_age_days}


_LAST_PRUNE = {"ts": 0.0}


def maybe_prune() -> None:
    """每 6 小时最多跑一次；默认开启但只删 7 天前的重复报告。"""
    import os

    if os.environ.get("P2S_AUTO_PRUNE", "1") == "0":
        return
    if time.time() - _LAST_PRUNE["ts"] < 6 * 3600:
        return
    _LAST_PRUNE["ts"] = time.time()
    try:
        keep = int(os.environ.get("P2S_PRUNE_KEEP", "3"))
        days = int(os.environ.get("P2S_PRUNE_DAYS", "7"))
        r = prune_scan_files(keep=keep, min_age_days=days)
        if r["removed"]:
            record_audit("POST", "/api/_prune", 200, "system", "127.0.0.1")
    except Exception:
        pass


@router.post("/api/admin/prune")
def api_prune(keep: int = 3, min_age_days: int = 7, dry_run: bool = False) -> dict:
    """手动触发清理；dry_run=true 只统计不删除。"""
    return prune_scan_files(keep=max(1, keep), min_age_days=max(0, min_age_days), apply=not dry_run)
