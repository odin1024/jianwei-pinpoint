"""httpx 客户端工厂回归测试。

锁死 v1.0.4 之前的一类静默故障：NO_PROXY 含带方括号 IPv6 时，
httpx 构造阶段抛 InvalidURL，被上层吞成「端口开放但无协议响应」，
导致存活主机被判为不存活。
"""

from __future__ import annotations

import httpx
import pytest

from p2s.core.httpclient import make_client, proxy_mounts, tls_verify


@pytest.fixture
def clean_proxy_env(monkeypatch):
    for k in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
              "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "P2S_VERIFY_TLS"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_bracketed_ipv6_no_proxy_does_not_crash(clean_proxy_env):
    """原始崩溃环境：这是 httpx 自身会构造出 all://*[::1] 的输入。"""
    clean_proxy_env.setenv("NO_PROXY", "localhost,.localhost,127.0.0.1,127.0.0.0/8,[::1],::1")
    # 先确认裸 httpx 在该环境下确实会崩，否则本测试失去意义
    with pytest.raises(httpx.InvalidURL):
        httpx.Client(trust_env=True)
    with make_client(timeout=3) as c:
        assert isinstance(c, httpx.Client)


def test_ipv6_bypass_entry_is_preserved(clean_proxy_env):
    """IPv6 条目不能被整条丢弃，否则 ::1 的流量会错误地走代理。"""
    clean_proxy_env.setenv("NO_PROXY", "[::1],::1")
    m = proxy_mounts()
    assert "all://[::1]" in m
    assert m["all://[::1]"] is None


def test_proxy_still_honoured(clean_proxy_env):
    clean_proxy_env.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    clean_proxy_env.setenv("NO_PROXY", "localhost,[::1]")
    m = proxy_mounts()
    assert m.get("https://") == "http://127.0.0.1:9999"
    assert m.get("all://localhost") is None


def test_wildcard_no_proxy_disables_all(clean_proxy_env):
    clean_proxy_env.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    clean_proxy_env.setenv("NO_PROXY", "*")
    assert proxy_mounts().get("all://") is None


def test_malformed_entries_skipped_not_fatal(clean_proxy_env):
    clean_proxy_env.setenv("NO_PROXY", "ok.local,]]bad[[, ,[::1]")
    m = proxy_mounts()
    assert "all://ok.local" in m
    assert "all://[::1]" in m
    with make_client(timeout=3):
        pass


def test_explicit_kwargs_win(clean_proxy_env):
    clean_proxy_env.setenv("P2S_VERIFY_TLS", "1")
    with make_client(timeout=3, verify=False, trust_env=True, mounts={}) as c:
        assert c is not None


def test_tls_verify_switch(clean_proxy_env):
    assert tls_verify() is False          # 内网自签场景默认不校验
    assert tls_verify(default=True) is True
    clean_proxy_env.setenv("P2S_VERIFY_TLS", "1")
    assert tls_verify() is True
    clean_proxy_env.setenv("P2S_VERIFY_TLS", "0")
    assert tls_verify(default=True) is False
