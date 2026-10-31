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
_DEFAULT_SCHEDULE: dict[str, Any] = {
    "enabled": False,
    "every_minutes": 60,
    "cidr": "",
    "hosts": [],
    "quick": True,
    "save": True,
    "last_run": "",
    "last_job": "",
}


def load_schedule() -> dict:
    cfg = dict(_DEFAULT_SCHEDULE)
    if SCHEDULE_FILE.exists():
        try:
            cfg.update(json.loads(SCHEDULE_FILE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_schedule(cfg: dict) -> None:
    _atomic_write(SCHEDULE_FILE, json.dumps(cfg, ensure_ascii=False, indent=2))


@router.get("/api/schedule")
def api_get_schedule() -> dict:
    cfg = load_schedule()
    cfg["next_run_in"] = _seconds_until_next(cfg)
    return cfg


@router.post("/api/schedule")
def api_set_schedule(payload: dict) -> dict:
    cfg = load_schedule()
    if "enabled" in payload:
        cfg["enabled"] = bool(payload["enabled"])
    if "every_minutes" in payload:
        try:
            mins = int(payload["every_minutes"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="every_minutes 必须是整数") from None
        if mins < 5:
            raise HTTPException(status_code=400, detail="间隔不能小于 5 分钟")
        cfg["every_minutes"] = mins
    if "cidr" in payload:
        cfg["cidr"] = str(payload.get("cidr") or "").strip()
    if "hosts" in payload:
        v = payload.get("hosts") or []
        cfg["hosts"] = [str(x).strip() for x in v if str(x).strip()][:1024]
    if "quick" in payload:
        cfg["quick"] = bool(payload["quick"])
    if "save" in payload:                 # 结果是否写入资产台账（此前被忽略，导致定时扫描不入库）
        cfg["save"] = bool(payload["save"])
    if "group" in payload:
        cfg["group"] = str(payload.get("group") or "auto")
    if not cfg.get("cidr") and not cfg.get("hosts"):
        raise HTTPException(status_code=400, detail="必须填写网段或主机列表")
    save_schedule(cfg)
    return cfg


def _seconds_until_next(cfg: dict) -> int:
    if not cfg.get("enabled") or not cfg.get("last_run"):
        return 0 if cfg.get("enabled") else -1
    try:
        last = datetime.fromisoformat(str(cfg["last_run"]))
    except ValueError:
        return 0
    due = last.timestamp() + int(cfg.get("every_minutes", 60)) * 60
    return max(0, int(due - time.time()))


def _fire(cfg: dict) -> None:
    """按与手动扫描相同的路径提交任务。"""
    from .scan_api import JobIn, api_create_job  # 延迟导入，避免循环依赖

    body = JobIn(kind="discover", cidr=cfg.get("cidr") or "", hosts=cfg.get("hosts") or [],
                 quick=bool(cfg.get("quick", True)), save=bool(cfg.get("save", True)),
                 group="auto", note="定时扫描")
    job = api_create_job(body)
    cfg["last_run"] = datetime.now().isoformat(timespec="seconds")
    cfg["last_job"] = str(job.get("id") or "")
    save_schedule(cfg)


def start_scheduler() -> None:
    """后台线程：每 30 秒检查一次是否到点。幂等，重复调用不会起多个。"""
    if getattr(start_scheduler, "_started", False):
        return
    start_scheduler._started = True  # type: ignore[attr-defined]

    def loop() -> None:
        while True:
            try:
                cfg = load_schedule()
                if cfg.get("enabled") and _seconds_until_next(cfg) <= 0:
                    _fire(cfg)
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
