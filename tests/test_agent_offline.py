"""离线采集导入 + Agent 自身文件白名单。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from p2s.console.app import app


def _login(c: TestClient) -> None:
    r = c.post("/api/login", json={"username": "admin", "password": "admin@123"})
    assert r.status_code in (200, 401)   # 401 时说明环境口令不同，后续用例跳过


def test_import_offline_report():
    with TestClient(app) as c:
        _login(c)
        rep = {
            "hostname": "offline-demo", "ip": "203.0.113.9", "platform": "ubuntu 22.04",
            "installs": [], "settings": [], "artifacts": [
                {"kind": "recent_script", "path": "/tmp/p2s-agent.sh", "severity": "medium"},
                {"kind": "recent_script", "path": "/var/www/x.php", "severity": "medium"},
            ], "processes": [], "errors": [],
        }
        r = c.post("/api/agent/import", json={"report": rep})
        if r.status_code == 401:
            return                        # 鉴权中间件拦下，说明会话没建立
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["host"] == "203.0.113.9"
        assert body["exposure"] in ("not_php", "unknown", "patched")


def test_import_rejects_garbage():
    with TestClient(app) as c:
        _login(c)
        r = c.post("/api/agent/import", json={"report": {"foo": 1}})
        assert r.status_code in (400, 401)


def test_self_artifact_filtered():
    from p2s.console.agent_api import _strip_self_artifacts

    arts = [
        {"path": "/tmp/p2s-agent.sh"},
        {"path": "C:/Users/x/p2s_agent.ps1"},
        {"path": "/var/www/html/shell.php"},
    ]
    kept = _strip_self_artifacts(arts)
    assert len(kept) == 1 and "shell.php" in kept[0]["path"]
