"""日志分析页的筛选控件与数据接口测试。"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        r = c.post("/api/login", json={"password": "test-pass"})
        assert r.status_code == 200, r.text
        yield c


def test_logs_page_has_filter_controls(client) -> None:
    """页面必须包含历史选择与三个筛选控件（此前只加了 JS，HTML 漏插导致白屏）。"""
    html = client.get("/").text
    for ctrl in ('id="l-hist"', 'id="l-range"', 'id="l-sev"', 'id="l-kw"', 'id="l-count"'):
        assert ctrl in html, f"日志页缺少控件 {ctrl}"


def test_scan_data_endpoint(client) -> None:
    """历史回看需要完整 findings，摘要接口不提供。"""
    scans = client.get("/api/scans", params={"limit": 50}).json()["scans"]
    logs = [x for x in scans if x.get("kind") == "logs"]
    if not logs:
        pytest.skip("测试库没有日志类扫描")
    sid = logs[0]["scan_id"]
    d = client.get(f"/api/scans/{sid}/data")
    assert d.status_code == 200
    body = d.json()
    assert body.get("scan_id") == sid
    assert "findings" in body


def test_scan_data_404(client) -> None:
    assert client.get("/api/scans/logs-doesnotexist/data").status_code == 404


def test_summary_has_severity_counts(client) -> None:
    """历史下拉用 severity_counts 显示命中数（摘要里没有 findings）。"""
    scans = client.get("/api/scans", params={"limit": 20}).json()["scans"]
    logs = [x for x in scans if x.get("kind") == "logs"]
    if not logs:
        pytest.skip("测试库没有日志类扫描")
    assert isinstance(logs[0].get("severity_counts"), dict)


def test_scans_json_serialisable(client) -> None:
    json.dumps(client.get("/api/scans", params={"limit": 5}).json())
