"""Agent 采集脚本生成与上报归一化的回归测试。"""
from __future__ import annotations


def test_render_linux_embeds_platform_and_token():
    from p2s.core import agentkit

    s = agentkit.render("linux", "http://10.0.0.5:18080", "tok-123")
    assert "http://10.0.0.5:18080" in s
    assert "tok-123" in s
    assert s.startswith("#!/bin/sh")
    assert "api/agent/report" in s
    # 不能残留未替换的占位
    assert "{base_url}" not in s and "{token}" not in s


def test_render_windows_has_utf8_bom():
    """PS 5.1 没有 BOM 会按 GBK 解析中文 .ps1，中文会乱码甚至吞掉换行。"""
    from p2s.core import agentkit

    s = agentkit.render("windows", "http://10.0.0.5:18080", "tok-123")
    assert s.startswith("\ufeff")
    assert "$BaseUrl = \"http://10.0.0.5:18080\"" in s
    assert "$Token   = \"tok-123\"" in s
    # 中文 Windows 兼容处理
    assert "[Console]::OutputEncoding" in s
    assert "UTF8.GetBytes" in s


def test_render_unknown_kind():
    import pytest

    from p2s.core import agentkit

    with pytest.raises(KeyError):
        agentkit.render("solaris", "http://x", "t")


def test_download_endpoint_requires_auth(client):
    from fastapi.testclient import TestClient

    from p2s.console.app import app

    with TestClient(app, follow_redirects=False) as c:
        assert c.get("/api/agent/download?os=linux").status_code == 401


def test_download_endpoint_returns_script(auth_client):
    r = auth_client.get("/api/agent/download?os=linux")
    assert r.status_code == 200
    assert "text/x-shellscript" in r.headers["content-type"]
    assert "attachment" in r.headers["content-disposition"]
    assert "p2s-agent.sh" in r.headers["content-disposition"]
    assert "api/agent/report" in r.text


def test_download_windows_has_bom(auth_client):
    r = auth_client.get("/api/agent/download?os=windows")
    assert r.status_code == 200
    assert r.content.startswith(b"\xef\xbb\xbf")


def test_download_bad_os(auth_client):
    assert auth_client.get("/api/agent/download?os=plan9").status_code == 400


def test_download_uses_requested_base(auth_client):
    r = auth_client.get("/api/agent/download?os=linux&base=https://p2s.corp.local")
    assert "https://p2s.corp.local" in r.text


# --------------------------------------------------------------------------
# 上报归一化：脚本只报事实，判定由服务端算
# --------------------------------------------------------------------------
def test_normalize_computes_verdict_from_version():
    from p2s.console.app import _normalize_host_report

    rep = {"installs": [{"path": "/usr/bin/php", "version": "8.4.20", "sapi": "cli"}]}
    out = _normalize_host_report(rep)
    inst = out["installs"][0]
    assert inst["verdict_status"] == "vulnerable"
    assert inst["needs_action"] is True
    assert inst["fixed_release"] == "8.4.27"


def test_normalize_patched_version():
    from p2s.console.app import _normalize_host_report

    rep = {"installs": [{"path": "/usr/bin/php", "version": "8.4.27"}]}
    inst = _normalize_host_report(rep)["installs"][0]
    assert inst["verdict_status"] == "patched"
    assert inst["needs_action"] is False


def test_normalize_changelog_hit_wins_over_version():
    """发行版回移补丁：版本号低但 changelog 命中，应判已修复。"""
    from p2s.console.app import _normalize_host_report

    rep = {"php_changelog_hit": "php-common",
           "installs": [{"path": "/usr/bin/php", "version": "8.1.31"}]}
    inst = _normalize_host_report(rep)["installs"][0]
    assert inst["verdict_status"] == "patched"
    assert inst["needs_action"] is False
    assert "changelog" in inst["reason"]


def test_normalize_settings_fills_expectations():
    from p2s.console.app import _normalize_host_report

    rep = {"settings": [
        {"name": "session.upload_progress.enabled", "actual": "On"},
        {"name": "post_max_size", "actual": "32M"},
    ]}
    out = _normalize_host_report(rep)["settings"]
    assert out[0]["ok"] is False and out[0]["expected"] == "0"
    assert out[1]["ok"] is True
