"""接口冒烟测试：每个路由至少被真实调用一次，不得 5xx。

动机（真实事故）：`assets_api` 里调用 `discovery.discover()` 却没导入
`discovery` —— 因为顶部是 `from .deps import *`，而 deps 定义了 `__all__`，
`discovery` 不在其中，星号导入不会带进来。结果"手工添加资产并扫描"这个接口
**一直是 500**，而 pytest / ruff / 验收脚本全都没发现（那条路径从没被跑过）。
`scan_api` 的 `probe_mod` 同样问题。

修法有两部分：
  1. 消除星号导入 → ruff 的 F821 重新生效（已做）；
  2. 这份冒烟测试 → 保证每个路由至少被真的调用一次。

注意：本测试只做"不破坏数据"的调用；删除类接口单独用临时数据验证。
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


# (method, path, body) —— 只列只读或幂等的接口
READ_ENDPOINTS = [
    ("GET", "/api/health", None),
    ("GET", "/api/overview", None),
    ("GET", "/api/assets", None),
    ("GET", "/api/php-exposure", None),
    ("GET", "/api/php-exposure/export", None),
    ("GET", "/api/hardening/overview", None),
    ("GET", "/api/hardening/rules", None),
    ("GET", "/api/about", None),
    ("GET", "/api/schedules", None),
    ("GET", "/api/jobs", None),
    ("GET", "/api/scans?limit=5", None),
    ("GET", "/api/agent/kits", None),
    ("GET", "/api/agent/list", None),
    ("GET", "/api/schedule", None),
    ("GET", "/api/audit?limit=5", None),
    ("GET", "/api/remediation", None),
    ("GET", "/api/ioc", None),
    ("GET", "/api/rules", None),
]


@pytest.mark.parametrize("method,path,body", READ_ENDPOINTS,
                         ids=[f"{m} {p}" for m, p, _ in READ_ENDPOINTS])
def test_read_endpoint_not_5xx(client, method, path, body) -> None:
    r = client.request(method, path, json=body)
    assert r.status_code < 500, f"{method} {path} → {r.status_code} {r.text[:300]}"


def test_add_asset_endpoint_works(client) -> None:
    """真实事故回归：这条路径曾因 `discovery` 未导入而必然 500。"""
    r = client.post("/api/assets", json={"host": "127.0.0.1", "group": "smoke"})
    assert r.status_code < 500, f"添加资产失败：{r.status_code} {r.text[:300]}"
    assert r.status_code == 200


def test_url_job_endpoint_works(client) -> None:
    """真实事故回归：`_run_url` 曾因 `probe_mod` 未导入而失败。"""
    r = client.post("/api/jobs", json={"kind": "url", "url": "http://127.0.0.1:1/"})
    assert r.status_code < 500, f"URL 任务提交失败：{r.status_code} {r.text[:200]}"
    job_id = r.json()["id"]

    deadline = time.time() + 60
    job = {}
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job.get("state") in ("done", "failed", "canceled"):
            break
        time.sleep(1)
    # 目标不可达可以有业务错误，但**不能是 NameError 这类代码缺陷**
    err = str(job.get("error") or "")
    assert "NameError" not in err, f"URL 任务出现 NameError：{err}"
    assert "is not defined" not in err, f"URL 任务出现未定义名：{err}"


def test_hardening_plan_for_unknown_host(client) -> None:
    r = client.get("/api/hardening/plan/192.0.2.1")
    assert r.status_code < 500


def test_agent_download_rejects_bad_base(client) -> None:
    r = client.get('/api/agent/download?os=linux&base=http://x"; echo PWNED; #')
    assert r.status_code < 500
