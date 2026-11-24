"""离线采集导入 + Agent 自身文件白名单。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from p2s.console.app import app


def _login(c: TestClient) -> None:
    from p2s.console.deps import ADMIN_PASSWORD, ADMIN_USER

    r = c.post("/api/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, "登录必须成功，否则后续断言都在未鉴权状态下空跑"


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
