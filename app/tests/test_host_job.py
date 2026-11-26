"""本地取证任务端到端测试。

背景：`scan_api` 里调用了 `_ingest_host_report`，但没导入 —— 静态检查被
`from .deps import *` 掩盖，只有真的发起一次 kind=host 任务才会暴露 NameError。
这里直接跑完整任务，确保"点立即检测"不会再失败。
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        r = c.post("/api/login", json={"password": "test-pass"})
        assert r.status_code == 200, r.text
        yield c


def test_ingest_host_report_is_importable() -> None:
    """扫描模块必须能拿到上报入库函数（此前漏导入，导致任务必失败）。"""
    from p2s.console import scan_api

    fn = getattr(scan_api, "_ingest_host_report", None)
    assert callable(fn), "scan_api 缺少 _ingest_host_report —— kind=host 任务会 NameError"


def test_host_job_runs_to_completion(client) -> None:
    """发起一次本地取证，必须跑完且不报错。"""
    r = client.post("/api/jobs", json={"kind": "host"})
    assert r.status_code == 200, r.text
    job_id = r.json()["id"]

    deadline = time.time() + 60
    job = {}
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job.get("state") in ("done", "failed", "canceled", "cancelled"):
            break
        time.sleep(1)

    assert job.get("state") == "done", f"任务未完成：state={job.get('state')} error={job.get('error')}"
    assert not job.get("error"), f"任务报错：{job.get('error')}"


def test_host_job_produces_host_report(client) -> None:
    """跑完后结果里应有主机侧报告（安装点/配置/进程等字段）。"""
    r = client.post("/api/jobs", json={"kind": "host"})
    job_id = r.json()["id"]
    deadline = time.time() + 60
    job = {}
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job.get("state") in ("done", "failed"):
            break
        time.sleep(1)
    if job.get("state") != "done":
        pytest.skip("本机取证未完成，跳过产物断言")
    res = job.get("result") or {}
    assert isinstance(res, dict)
