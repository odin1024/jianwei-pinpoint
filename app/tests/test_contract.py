"""端点契约测试：锁定每个接口的**响应结构**，拆分代码时用它兜底。

原则：
  · 只断言"形状"（状态码 + 顶层键 + 类型），不断言具体数值 —— 数据会变，契约不该变；
  · GET 全量覆盖，写操作只覆盖"校验失败"路径（避免污染真实台账）；
  · 任何一次重构（拆路由、改存储）后跑一遍，结构变了立刻红。
"""
from __future__ import annotations

import pytest

#: (路径, 期望状态, 必须存在的顶层键)
CONTRACTS = [
    ("/api/health", 200, {"status", "time", "version"}),
    ("/api/overview", 200, {
        "total_assets", "alive", "php_present", "exposed", "patched", "not_php",
        "unknown", "by_type", "by_exposure", "by_risk", "php_versions",
        "fixed_releases", "scan_count", "recent_scans", "groups",
        "changes", "recent_changes",
    }),
    ("/api/assets", 200, {"assets"}),
    ("/api/php-exposure", 200, {"rows", "fixed_releases"}),
    ("/api/rules", 200, {"count", "rules"}),
    ("/api/ioc", 200, {"summary", "ips", "domains", "urls", "hashes", "user_agents"}),
    ("/api/scans", 200, {"scans", "total", "offset", "limit"}),
    ("/api/jobs", 200, {"jobs"}),
    ("/api/agent/kits", 200, {"base_url", "kits"}),
]

#: 导出类接口：断言 Content-Type 与文件名，而不是 JSON 结构
EXPORTS = [
    ("/api/assets/export", "text/csv", "p2s-assets.csv"),
    ("/api/php-exposure/export", "text/csv", "p2s-php-exposure.csv"),
    ("/api/host/export", "text/csv", "p2s-host-assets.csv"),
    ("/api/rules/export/sigma", "text/yaml", "sigma"),
    ("/api/rules/export/modsecurity", "text/plain", "modsecurity"),
    ("/api/rules/export/suricata", "text/plain", "suricata"),
    ("/api/agent/download?os=linux", "text/x-shellscript", "p2s-agent.sh"),
    ("/api/agent/download?os=windows", "text/plain", "p2s-agent.ps1"),
]


@pytest.mark.parametrize("path,status,keys", CONTRACTS)
def test_json_contract(auth_client, path, status, keys):
    r = auth_client.get(path)
    assert r.status_code == status, f"{path} -> {r.status_code} {r.text[:200]}"
    body = r.json()
    assert isinstance(body, dict), f"{path} 应返回 JSON 对象"
    missing = keys - set(body)
    assert not missing, f"{path} 缺少字段：{sorted(missing)}"


@pytest.mark.parametrize("path,ctype,filename", EXPORTS)
def test_export_contract(auth_client, path, ctype, filename):
    r = auth_client.get(path)
    assert r.status_code == 200, f"{path} -> {r.status_code}"
    assert ctype in r.headers.get("content-type", ""), f"{path} 类型不对：{r.headers.get('content-type')}"
    assert "attachment" in r.headers.get("content-disposition", ""), f"{path} 缺下载头"
    assert filename in r.headers["content-disposition"], f"{path} 文件名不对"
    assert r.content, f"{path} 内容为空"


def test_overview_recent_scans_are_summaries(auth_client):
    """列表类接口只返回摘要：不能把每份报告的 assets/findings 塞回来（曾占 1.1MB）。"""
    body = auth_client.get("/api/overview").json()
    for s in body.get("recent_scans", []):
        assert "assets" not in s, "recent_scans 应只含摘要"
        assert "scan_id" in s and "kind" in s and "risk" in s


def test_scans_endpoint_is_paginated(auth_client):
    body = auth_client.get("/api/scans?limit=3").json()
    assert len(body["scans"]) <= 3
    assert body["limit"] == 3
    for s in body["scans"]:
        assert "assets" not in s, "默认应返回摘要，full=1 才给完整内容"
    full = auth_client.get("/api/scans?limit=1&full=1").json()
    if full["scans"]:
        assert "assets" in full["scans"][0]


def test_job_dict_contract(auth_client):
    """任务字典必须带 active（前端 KPI 依赖），且状态是已知枚举。"""
    jobs = auth_client.get("/api/jobs").json()["jobs"]
    for j in jobs:
        assert "active" in j
        assert j["state"] in {"queued", "running", "done", "failed", "cancelled"}


def test_unauthenticated_all_api_return_401(client):
    """除了白名单，所有 /api/* 未登录都应 401。"""
    from fastapi.testclient import TestClient

    from p2s.console.app import app
    from p2s.console.deps import _UNAUTH_OK

    with TestClient(app, follow_redirects=False) as c:
        for path, _status, _keys in CONTRACTS:
            if path in _UNAUTH_OK:
                continue
            assert c.get(path).status_code == 401, path


def test_write_endpoints_validate_input(auth_client):
    """写接口的参数校验路径（不产生副作用）。"""
    assert auth_client.post("/api/jobs", json={"kind": "nope"}).status_code == 400
    assert auth_client.post("/api/jobs", json={"kind": "logs", "path": ""}).status_code == 400
    assert auth_client.delete("/api/assets?host=__no_such_host__").status_code in (200, 404)
