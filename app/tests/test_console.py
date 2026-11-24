"""控制台安全与接口回归测试。

覆盖本轮修复：
  - 未登录访问页面/接口被拦截，登录后放行
  - 日志路径白名单（任意文件读取）
  - Agent 上报令牌
  - CSV 导出（MIME/文件名/公式注入）
  - 规则导出可用性（Sigma 可被 YAML 解析、Suricata classtype 合法）
  - 报告结束时间非空
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


# --------------------------------------------------------------------------
# 认证
# --------------------------------------------------------------------------
def test_health_is_public(client):
    assert client.get("/api/health").status_code == 200


def test_login_page_is_public(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "见微" in r.text


def test_api_requires_auth(client):
    # 用一个独立 client，避免受已登录 fixture 影响
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        assert c.get("/api/assets").status_code == 401
        assert c.get("/api/overview").status_code == 401


def test_dashboard_redirects_to_login(client):
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/")
        assert r.status_code in (302, 307)
        assert r.headers["location"] == "/login"


def test_login_wrong_password(client):
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        assert c.post("/api/login", json={"password": "nope"}).status_code == 401


def test_login_then_access(auth_client):
    assert auth_client.get("/api/assets").status_code == 200
    assert auth_client.get("/api/overview").status_code == 200


def test_security_headers(auth_client):
    r = auth_client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"


def test_logout_invalidates_session():
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        c.post("/api/login", json={"password": "test-pass"})
        assert c.get("/api/assets").status_code == 200
        c.post("/api/logout")
        assert c.get("/api/assets").status_code == 401


# --------------------------------------------------------------------------
# 日志路径白名单
# --------------------------------------------------------------------------
def test_log_path_outside_allowlist_rejected(auth_client):
    r = auth_client.post("/api/jobs", json={"kind": "logs", "path": r"C:\Windows\win.ini"})
    assert r.status_code == 403
    assert "允许的目录" in r.json()["detail"]


def test_log_path_missing_rejected(auth_client):
    r = auth_client.post("/api/jobs", json={"kind": "logs", "path": "no/such/file.log"})
    assert r.status_code == 400


def test_log_path_inside_allowlist_accepted(auth_client, tmp_path):
    from p2s.console.deps import _LOG_ROOTS, _resolve_log_path

    root = _LOG_ROOTS[0]
    root.mkdir(parents=True, exist_ok=True)
    f = root / "unit-test.log"
    f.write_text("127.0.0.1 - - [21/Oct/2026:13:30:12 +0000] \"GET / HTTP/1.1\" 200 12\n",
                 encoding="utf-8")
    assert _resolve_log_path(str(f)) == f.resolve()


def test_non_log_suffix_rejected_even_inside_allowlist():
    """在允许目录里也不读 .ini / .key 这类文件。"""
    from fastapi import HTTPException

    from p2s.console.deps import _LOG_ROOTS, _resolve_log_path

    root = _LOG_ROOTS[0]
    root.mkdir(parents=True, exist_ok=True)
    f = root / "php.ini"
    f.write_text("[PHP]\n", encoding="utf-8")
    try:
        _resolve_log_path(str(f))
    except HTTPException as exc:
        assert exc.status_code == 403
        assert "不像日志" in exc.detail
    else:
        raise AssertionError("应拒绝非日志后缀")


def test_sync_log_endpoint_removed(auth_client):
    """同步扫描端点必须已删除（它们绕过队列且构成任意文件读取）。"""
    assert auth_client.post("/api/scan/logs", json={"path": "x"}).status_code in (404, 405)
    assert auth_client.post("/api/discover", json={"hosts": ["127.0.0.1"]}).status_code in (404, 405)


# --------------------------------------------------------------------------
# Agent 上报
# --------------------------------------------------------------------------
def test_agent_report_requires_token(client):
    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        c.post("/api/login", json={"password": "test-pass"})
        r = c.post("/api/agent/report", json={"hostname": "h", "data": {}})
        assert r.status_code == 401


def test_agent_report_with_token(auth_client):
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "unit-test-host", "data": {"risk": "low"}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


# --------------------------------------------------------------------------
# 本地取证（Agent / 主机侧）必须进台账，并覆盖远程推断
# --------------------------------------------------------------------------
def _host_report(version: str, status: str, needs_action: bool) -> dict:
    return {
        "hostname": "web-01.lab",
        "platform": "Linux x86_64",
        "platform_release": "6.8",
        "checked_at": "2026-10-29T18:00:00",
        "risk": "high" if needs_action else "low",
        "installs": [{
            "path": "/usr/sbin/php-fpm8.4",
            "version": version,
            "sapi": "fpm-fcgi",
            "verdict_status": status,
            "needs_action": needs_action,
            "reason": "测试数据",
        }],
        "settings": [{"name": "session.upload_progress.enabled", "actual": "On",
                      "expected": "0", "ok": False, "note": "应关闭"}],
        "artifacts": [],
        "processes": [],
        "connections": [],
        "errors": [],
    }


def test_agent_report_enters_ledger_as_host_evidence(auth_client):
    """R-05：本地结论要进台账，不能只躺在一条 scan 里。"""
    payload = _host_report("8.4.20", "vulnerable", True)
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "web-01.lab", "data": {"ip": "10.9.9.9", **payload}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["exposure"] == "exposed"

    assets = {a["host"]: a for a in auth_client.get("/api/assets").json()["assets"]}
    a = assets["10.9.9.9"]
    assert a["evidence_level"] == "host"
    assert a["host_verified"] is True
    assert a["php_version"] == "8.4.20"
    assert a["exposure"] == "exposed"
    assert a["confidence"] >= 0.9
    assert a["host_report"]["installs"][0]["path"].endswith("php-fpm8.4")


def test_agent_report_patched_overrides_remote(auth_client):
    payload = _host_report("8.4.27", "patched", False)
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "web-02.lab", "data": {"ip": "10.9.9.10", **payload}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["exposure"] == "patched"
    assets = {a["host"]: a for a in auth_client.get("/api/assets").json()["assets"]}
    assert assets["10.9.9.10"]["exposure"] == "patched"


def test_agent_report_without_php(auth_client):
    payload = _host_report("8.4.27", "patched", False)
    payload["installs"] = []
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "db-01.lab", "data": {"ip": "10.9.9.11", **payload}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["exposure"] == "not_php"


def test_agent_report_requires_host_identifier(auth_client):
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "", "data": {}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# CSV 导出
# --------------------------------------------------------------------------
def test_csv_formula_injection_escaped():
    from p2s.console.deps import _csv_cell

    assert _csv_cell("=1+1") == "'=1+1"
    assert _csv_cell("+86") == "'+86"
    assert _csv_cell("@cmd") == "'@cmd"
    assert _csv_cell("普通值") == "普通值"
    assert _csv_cell('a,b') == '"a,b"'
    assert _csv_cell('say "hi"') == '"say ""hi"""'


def test_csv_export_headers(auth_client):
    r = auth_client.get("/api/assets/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    assert r.content.startswith("\ufeff".encode())


# --------------------------------------------------------------------------
# 规则导出
# --------------------------------------------------------------------------
def test_sigma_export_is_valid_yaml():
    yaml = pytest.importorskip("yaml")
    from p2s.console.app import _export_sigma
    from p2s.core.rules import RULES

    docs = list(yaml.safe_load_all(_export_sigma()))
    assert len(docs) == len(RULES)
    for d in docs:
        assert d["detection"]["keywords"]
        assert d["detection"]["condition"] == "keywords"
        assert d["level"] in {"critical", "high", "medium", "low", "info"}


def test_suricata_export_has_valid_classtype():
    from p2s.console.app import _export_suricata
    from p2s.core.rules import RULES

    text = _export_suricata()
    lines = [ln for ln in text.splitlines() if ln.startswith("alert ")]
    assert len(lines) == len(RULES)
    valid = {"web-application-attack", "policy-violation", "misc-activity"}
    for ln in lines:
        ct = ln.split("classtype:", 1)[1].split(";")[0]
        assert ct in valid
        assert "sid:" in ln


def test_modsecurity_export_wellformed():
    from p2s.console.app import _export_modsecurity
    from p2s.core.rules import RULES

    text = _export_modsecurity()
    header_lines = [ln for ln in text.splitlines() if ln.startswith("SecRule ")]
    assert len(header_lines) == len(RULES)
    # 每条规则跨两行：SecRule 变量 + 动作块，所以按整篇统计 id
    assert text.count("id:9900") == len(RULES)
    for ln in header_lines:
        assert ln.count('"') % 2 == 0, ln       # 引号成对


# --------------------------------------------------------------------------
# 报告落盘
# --------------------------------------------------------------------------
def test_first_persist_sets_finished_at():
    # 这些是 deps 的内部工具函数，从定义处导入（原来靠 app 的星号导入顺带再导出）
    from p2s.console.deps import SCANS_DIR, _new_scan, _persist

    res = _new_scan("logs")
    assert res.finished_at == ""
    _persist(res)
    assert res.finished_at != ""
    p = SCANS_DIR / f"{res.scan_id}.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["finished_at"], "落盘报告里结束时间不能为空"

def test_agent_report_generates_remediation(auth_client):
    """配置不达标 + 版本受影响时，必须给出可执行的整改动作（不只是复述问题）。"""
    payload = _host_report("8.4.20", "vulnerable", True)
    payload["settings"] = [
        {"name": "session.upload_progress.enabled", "actual": "1"},
        {"name": "post_max_size", "actual": "32M"},
    ]
    r = auth_client.post(
        "/api/agent/report",
        json={"hostname": "web-rm.lab", "data": {"ip": "10.9.9.20", **payload}},
        headers={"X-P2S-Token": "test-agent-token"},
    )
    assert r.status_code == 200, r.text
    a = {x["host"]: x for x in auth_client.get("/api/assets").json()["assets"]}["10.9.9.20"]

    assert a["exposure"] == "exposed"
    assert len(a["host_issues"]) == 1
    assert a["host_issues"][0]["name"] == "session.upload_progress.enabled"

    text = " ".join(a["remediation"])
    assert "升级" in text and "8.4.27" in text          # 版本整改
    assert "session.upload_progress.enabled=0" in text  # 配置整改（含具体动作）
    assert "重启" in text                                # 必须说明改完要重启
