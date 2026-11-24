import time

from p2s.core.jobs import JobManager, JobState


def _wait(manager, job_id, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        job = manager.get(job_id)
        if job and not job.active:
            return job
        time.sleep(0.05)
    return manager.get(job_id)


def test_job_runs_and_completes(tmp_path):
    m = JobManager(tmp_path)
    job = m.submit("test", "测试任务", lambda j, p: {"ok": True, "echo": p.get("x")}, {"x": 42})
    done = _wait(m, job.id)
    assert done.state == JobState.DONE
    assert done.result == {"ok": True, "echo": 42}
    assert done.progress == 1.0


def test_job_failure_captured(tmp_path):
    m = JobManager(tmp_path)

    def boom(j, p):
        raise ValueError("炸了")

    job = m.submit("test", "会失败的任务", boom)
    done = _wait(m, job.id)
    assert done.state == JobState.FAILED
    assert "炸了" in done.error


def test_job_cancel(tmp_path):
    m = JobManager(tmp_path)
    def slow(j, p):
        for _ in range(100):
            if j.cancel_requested:
                return {"cancelled": True}
            time.sleep(0.05)
        return {"cancelled": False}

    job = m.submit("test", "长任务", slow)
    time.sleep(0.2)
    assert m.cancel(job.id) is True
    done = _wait(m, job.id, timeout=15)
    assert done.state == JobState.CANCELLED


def test_job_persists_across_manager_restart(tmp_path):
    m1 = JobManager(tmp_path)
    job = m1.submit("test", "历史任务", lambda j, p: {"v": 1})
    _wait(m1, job.id)
    # 重新实例化 = 模拟控制台重启
    m2 = JobManager(tmp_path)
    restored = m2.get(job.id)
    assert restored is not None
    assert restored.state == JobState.DONE
    assert restored.result == {"v": 1}


def test_running_job_marked_failed_after_restart(tmp_path):
    m1 = JobManager(tmp_path)
    job = m1.submit("test", "中断的任务", lambda j, p: time.sleep(5))
    time.sleep(0.2)
    m2 = JobManager(tmp_path)
    restored = m2.get(job.id)
    assert restored.state == JobState.FAILED
    assert "重启" in restored.error


def test_progress_updates(tmp_path):
    m = JobManager(tmp_path)

    def work(j, p):
        for i in range(1, 4):
            m.progress(j.id, i, 3, f"{i}/3")
        return {"done": True}

    job = m.submit("test", "带进度", work)
    done = _wait(m, job.id)
    assert done.state == JobState.DONE
    assert done.done == 3
    assert done.total == 3
    assert done.progress == 1.0


def test_delete_only_when_finished(tmp_path):
    m = JobManager(tmp_path)
    job = m.submit("test", "可删任务", lambda j, p: {"v": 2})
    _wait(m, job.id)
    assert m.delete(job.id) is True
    assert m.get(job.id) is None


def test_list_sorted_newest_first(tmp_path):
    m = JobManager(tmp_path)
    a = m.submit("test", "任务A", lambda j, p: {"n": "A"})
    time.sleep(0.02)
    b = m.submit("test", "任务B", lambda j, p: {"n": "B"})
    _wait(m, a.id)
    _wait(m, b.id)
    ids = [j.id for j in m.list()]
    assert ids.index(b.id) < ids.index(a.id)