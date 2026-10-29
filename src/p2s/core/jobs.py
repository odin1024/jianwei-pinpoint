"""后台任务队列。

为什么需要任务队列：
  设备发现 / 日志分析 / 主机侧检测 都是**长耗时**操作。
  早先直接在 HTTP 请求里同步跑，导致三个问题：
    1. 网段扫描动辄几分钟，浏览器与反向代理会超时，用户看到"没反应"
    2. 没有任何进度反馈
    3. 切换页面 = 请求中断 = 任务丢失

设计：
  - 单工作线程串行执行（避免并发扫描把自己的网络打满）
  - 状态持久化到 p2s-data/jobs.json —— **进程重启后历史任务仍在**
  - 进度可查询、可取消
"""
from __future__ import annotations

import json
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional


def _now() -> str:
    """毫秒精度时间戳 —— 秒级精度会让同一秒内的多个任务排序不稳定。"""
    return datetime.now().isoformat(timespec="milliseconds")


class JobState:
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """一个后台任务。"""

    id: str
    kind: str
    title: str
    params: dict[str, Any] = field(default_factory=dict)
    state: str = JobState.QUEUED
    progress: float = 0.0          # 0~1
    message: str = ""
    total: int = 0
    done: int = 0
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    cancel_requested: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def active(self) -> bool:
        return self.state in (JobState.QUEUED, JobState.RUNNING)


class JobManager:
    """线程安全的任务管理器。"""

    def __init__(self, data_dir: Path, max_workers: int = 1) -> None:
        self.data_dir = data_dir
        self.jobs_file = data_dir / "jobs.json"
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="p2s-job")
        self._load()

    # ---------- 持久化 ----------
    def _load(self) -> None:
        if not self.jobs_file.exists():
            return
        try:
            raw = json.loads(self.jobs_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        with self._lock:
            for item in raw.get("jobs", []):
                job = Job(**item)
                # 重启后处于运行态的任务不可能继续，标记为已中断
                if job.state in (JobState.QUEUED, JobState.RUNNING):
                    job.state = JobState.FAILED
                    job.error = "控制台重启导致任务中断，请重新发起"
                    job.finished_at = _now()
                self._jobs[job.id] = job

    def _persist(self) -> None:
        with self._lock:
            payload = {"jobs": [j.to_dict() for j in self._jobs.values()]}
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.jobs_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

    # ---------- API ----------
    def submit(
        self,
        kind: str,
        title: str,
        func: Callable[[Job], dict],
        params: dict | None = None,
        total: int = 0,
    ) -> Job:
        job = Job(
            id=f"{kind}-{uuid.uuid4().hex[:10]}",
            kind=kind,
            title=title,
            params=params or {},
            total=total,
            created_at=_now(),
        )
        with self._lock:
            self._jobs[job.id] = job
        self._pool.submit(self._run, job.id, func)
        self._persist()
        return job

    def _run(self, job_id: str, func: Callable[[Job], dict]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            if job.cancel_requested:
                job.state = JobState.CANCELLED
                job.finished_at = _now()
                self._persist()
                return
            job.state = JobState.RUNNING
            job.started_at = _now()
        try:
            result = func(job, dict(job.params))
            with self._lock:
                job.result = result
                if job.cancel_requested:
                    job.state = JobState.CANCELLED
                    job.message = "已取消"
                else:
                    job.state = JobState.DONE
                    job.progress = 1.0
                    job.done = job.total or job.done
                    if not job.message:
                        job.message = "已完成"
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                job.state = JobState.FAILED
                job.error = f"{type(exc).__name__}: {exc}"
                job.message = "执行失败"
                job.finished_at = _now()
                job.result = {"traceback": traceback.format_exc()[-2000:]}
        with self._lock:
            job.finished_at = _now()
        self._persist()

    def update(self, job_id: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            for k, v in fields.items():
                if hasattr(job, k):
                    setattr(job, k, v)
        self._persist()

    def progress(self, job_id: str, done: int, total: int, message: str = "") -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.done = done
            job.total = total
            job.progress = (done / total) if total else 0.0
            if message:
                job.message = message
        self._persist()

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 50) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or not job.active:
                return False
            job.cancel_requested = True
            if job.state == JobState.QUEUED:
                job.state = JobState.CANCELLED
                job.message = "已取消"
                job.finished_at = _now()
        self._persist()
        return True

    def delete(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            if job.active:
                return False
            del self._jobs[job_id]
        self._persist()
        return True