"""安全回归：默认口令与采集脚本注入。

覆盖两个 v1.0.4 之前存在的高危问题：
  1. 登录口令硬编码兜底 admin@123（注释却宣称随机生成）
  2. /api/agent/download?base= 未校验即拼进要在生产主机执行的 sh / ps1
"""

from __future__ import annotations

import importlib
import os
import unittest.mock

import pytest
from fastapi.testclient import TestClient

from p2s.core import agentkit

# 能突破 sh / PowerShell 字符串字面量的向量
INJECTION_VECTORS = [
    'http://x"; echo PWNED; #',
    "http://x$(id)",
    "http://x`id`",
    "http://x\nrm -rf /",
    'http://x"; Write-Output PWNED; #',
    "http://x\\",
    "http://x/a b",
    "http://x'; cat /etc/passwd; '",
    "http://x/a?b=1",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "",
]

LEGIT_BASES = [
    "http://127.0.0.1:8848",
    "https://p2s.corp.local",
    "http://[::1]:8848",
    "https://example.local/p2s",
]


@pytest.mark.parametrize("kind", ["linux", "windows"])
@pytest.mark.parametrize("evil", INJECTION_VECTORS)
def test_injection_rejected(kind, evil):
    with pytest.raises(ValueError):
        agentkit.render(kind, evil, "tok")


@pytest.mark.parametrize("kind", ["linux", "windows"])
@pytest.mark.parametrize("base", LEGIT_BASES)
def test_legit_base_accepted(kind, base):
    out = agentkit.render(kind, base, "tok-abc_1.2")
    assert base in out


def test_render_bundle_also_guarded():
    """render_bundle 直接调用子函数，不能绕过校验。"""
    with pytest.raises(ValueError):
        agentkit.render_bundle('http://x"; echo PWNED; #', "tok")


def test_bad_token_rejected():
    """跨行的令牌会结束脚本里的那一行，必须拒绝。"""
    with pytest.raises(ValueError):
        agentkit.render("linux", "http://x.local", "bad\ntoken")
    with pytest.raises(ValueError):
        agentkit.render("windows", "http://x.local", "bad\rtoken")


TOKEN_VECTORS = [
    'bad"token',
    "bad`token`",
    "bad$token",
    "bad\\token",
    "bad; rm -rf /",
    "p@ssw0rd!",
    "口令 with 空格",
    "}",
]


@pytest.mark.parametrize("kind", ["linux", "windows"])
@pytest.mark.parametrize("token", TOKEN_VECTORS)
def test_token_with_metacharacters_is_escaped_not_injected(kind, token):
    """令牌是管理员自定的口令，符号杂很正常 —— 但必须被转义，不能突破字面量。"""
    out = agentkit.render(kind, "http://x.local", token)
    # 反引号 / 双引号 / $ 在两种 shell 里都会改变字面量含义；反斜杠只在 sh 里是转义符
    dangerous = ['"', "`", "$"] + (["\\"] if kind == "linux" else [])
    if any(c in token for c in dangerous):
        assert token not in out, "令牌未转义就写进了脚本"


@pytest.mark.parametrize("token", ["bad\"token", "bad`token`", "bad$token", "a b c"])
def test_sh_token_roundtrip(token):
    """sh 脚本取出的令牌必须与原始令牌逐字节相同。"""
    import shutil
    import subprocess

    if not shutil.which("sh"):
        pytest.skip("环境里没有 sh")

    out = agentkit.render("linux", "http://x.local", token)
    lines = [ln for ln in out.splitlines()
             if ln.startswith("_P2S_TOKEN_DEFAULT=") or ln.startswith("TOKEN=")]
    harness = "\n".join(lines) + '\nprintf "%s" "$TOKEN"\n'
    r = subprocess.run(["sh", "-c", harness], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout == token


def test_no_hardcoded_default_password(monkeypatch):
    """未配置口令时必须随机生成，绝不能回落到固定字符串。"""
    monkeypatch.delenv("P2S_CONSOLE_PASSWORD", raising=False)
    monkeypatch.delenv("P2S_ADMIN_PASSWORD", raising=False)
    import p2s.console.deps as deps

    importlib.reload(deps)
    try:
        assert deps.ADMIN_PASSWORD not in ("admin@123", "admin", "password", "")
        assert len(deps.ADMIN_PASSWORD) >= 12
        assert deps.ADMIN_PASSWORD == deps.CONSOLE_PASSWORD
    finally:
        # 还原成测试环境口令，避免污染后续用例
        monkeypatch.setenv("P2S_CONSOLE_PASSWORD", "test-pass")
        importlib.reload(deps)


def test_login_rejects_legacy_default_password():
    from p2s.console.app import app
    from p2s.console.deps import ADMIN_PASSWORD

    with TestClient(app) as c:
        r = c.post("/api/login", json={"username": "admin", "password": "admin@123"})
        if ADMIN_PASSWORD != "admin@123":
            assert r.status_code == 401


def test_download_endpoint_rejects_injection():
    from p2s.console.app import app
    from p2s.console.deps import ADMIN_PASSWORD, ADMIN_USER

    with TestClient(app) as c:
        assert c.post("/api/login",
                      json={"username": ADMIN_USER, "password": ADMIN_PASSWORD}).status_code == 200
        r = c.get("/api/agent/download",
                  params={"os": "linux", "base": 'http://x"; echo PWNED; #'})
        assert r.status_code == 400
        assert "PWNED" not in r.text


# ---------------------------------------------------------------- P2 回归

def test_hardening_secret_not_hardcoded():
    """签名密钥必须是每部署随机、可持久化，不能是源码常量。"""
    from p2s.console.deps import signing_secret

    k = signing_secret()
    assert k != b"p2s-hardening-v1"
    assert len(k) >= 32
    assert signing_secret() == k          # 同进程内稳定，令牌才可校验


def test_hardening_token_unforgeable_with_old_constant():
    import hashlib
    import hmac as _hmac

    from p2s.console.hardening_api import _sign

    host, ah, exp = "10.0.0.7", "deadbeef", "2026-11-09T00:00:00Z"
    forged = _hmac.new(b"p2s-hardening-v1", f"{host}|{ah}|{exp}".encode(),
                       hashlib.sha256).hexdigest()
    assert _sign(host, ah, exp) != forged


_FAKE_DNS = {
    "open.feishu.cn": "123.58.106.77",
    "hooks.example.com": "93.184.216.34",
    "metadata.attacker.test": "169.254.169.254",
    "loopback.attacker.test": "127.0.0.1",
}


@pytest.fixture
def offline_dns(monkeypatch):
    """把域名解析钉死，避免用例依赖真实 DNS（IP 字面量不触发查询）。"""
    import socket

    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        return real(_FAKE_DNS.get(host, host), port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8848/api/assets",
    "http://[::1]/",
    "ftp://example.com/x",
    "not-a-url",
    "http://metadata.attacker.test/",   # DNS 指向元数据地址
    "http://loopback.attacker.test/",
])
def test_webhook_ssrf_blocked(url, offline_dns):
    from fastapi import HTTPException

    from p2s.console.deps import validate_webhook_url

    with pytest.raises(HTTPException):
        validate_webhook_url(url)


@pytest.mark.parametrize("url", [
    "https://open.feishu.cn/open-apis/bot/v2/hook/abc",
    "http://10.20.30.40:8080/hook",       # 内网 IM 机器人是正常用法
    "https://hooks.example.com/x",
])
def test_webhook_legit_allowed(url, offline_dns):
    from p2s.console.deps import validate_webhook_url

    validate_webhook_url(url)


def test_asset_redaction_preserves_hashes():
    """整体脱敏会把 SHA256 当 blob 抹掉，必须只动自由文本字段。"""
    import hashlib

    from p2s.console.deps import _redact_asset_text

    # 拼接构造，避免源码含完整 PHP 载荷被杀毒/EDR 误报（check_payload_literals.py）
    open_tag, close_tag = "<" + "?php", "?" + ">"
    cmd = open_tag + " system($_GET[1]); " + close_tag
    code = open_tag + " eval($_POST[x]); " + close_tag

    h = hashlib.sha256(b"fixture").hexdigest()
    src = {
        "host": "10.0.0.1", "favicon": h, "asset_fingerprints": [h],
        "php_version": "8.4.27", "note": "正常备注",
        "processes": [{"cmdline": cmd}],
        "evidence": [code],
    }
    out = _redact_asset_text(src)
    assert out["favicon"] == h
    assert out["asset_fingerprints"] == [h]
    assert out["php_version"] == "8.4.27"
    assert out["note"] == "正常备注"
    assert "PHP-CODE-BLOCK" in out["processes"][0]["cmdline"]
    assert "PHP-CODE-BLOCK" in out["evidence"][0]


# ---------------------------------------------------------------- 并发写入回归

def test_atomic_write_uses_unique_temp_name(tmp_path):
    """共用固定 .tmp 名会让并发写互相覆盖，正文件可能变成半截内容。"""

    from p2s.console.deps import _atomic_write

    seen: list[str] = []
    real_replace = os.replace

    def spy(src, dst):
        seen.append(str(src))
        return real_replace(src, dst)

    target = tmp_path / "x.json"
    with unittest.mock.patch("p2s.console.deps.os.replace", spy):
        _atomic_write(target, "1")
        _atomic_write(target, "2")

    assert len(set(seen)) == 2, "两次写入用了同一个临时文件名"


def test_concurrent_atomic_write_keeps_file_parseable(tmp_path):
    """并发写同一个文件时，任何时刻读到的都必须是完整 JSON。"""
    import json as _json
    import threading

    from p2s.console.deps import _atomic_write

    target = tmp_path / "concurrent.json"
    payload = _json.dumps({"schedules": [{"id": "sch-1"}]})
    errors: list[str] = []

    def writer() -> None:
        for _ in range(30):
            try:
                _atomic_write(target, payload)
            except OSError as exc:
                errors.append(str(exc))

    def reader() -> None:
        for _ in range(60):
            if target.exists():
                try:
                    _json.loads(target.read_text(encoding="utf-8"))
                except _json.JSONDecodeError as exc:
                    errors.append(f"读到半截 JSON: {exc}")

    ts = [threading.Thread(target=writer) for _ in range(4)]
    ts.append(threading.Thread(target=reader))
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors[:5]
    assert _json.loads(target.read_text(encoding="utf-8"))["schedules"]


def test_schedule_corrupt_file_is_quarantined_not_wiped(tmp_path, monkeypatch):
    """坏掉的 schedule.json 不能被当成「没有计划」直接覆盖掉。"""
    from p2s.console import ops_api

    monkeypatch.setattr(ops_api, "SCHEDULE_FILE", tmp_path / "schedule.json")
    ops_api.SCHEDULE_FILE.write_text("{ this is not json", encoding="utf-8")
    assert ops_api.load_schedules() == []
    leftovers = list(tmp_path.glob("schedule.json.corrupt-*"))
    assert leftovers, "损坏文件没有被留证"


def test_schedule_write_is_serialized():
    """调度线程与 API 线程的读-改-写必须串行，否则互相覆盖。"""
    from p2s.console import ops_api

    assert ops_api._sched_lock is not None


@pytest.mark.parametrize("token", ["bad\"token", "bad`token`", "bad$token", "p@ss w0rd!"])
def test_powershell_token_roundtrip(token):
    """PowerShell 脚本取出的令牌必须与原始令牌逐字符相同。"""
    import shutil
    import subprocess

    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        pytest.skip("环境里没有 PowerShell")

    out = agentkit.render("windows", "http://x.local", token)
    line = next(ln for ln in out.splitlines() if "if (-not $Token)" in ln)
    r = subprocess.run([ps, "-NoProfile", "-Command", line + "; [Console]::Out.Write($Token)"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout == token
