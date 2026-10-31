"""指纹技术回归测试：favicon mmh3、页面元数据提取、TLS 取证字段。"""
from __future__ import annotations

from p2s.core.discovery import _extract_labels, _mmh3_32, favicon_fingerprints


def test_mmh3_matches_reference_vector():
    """MurmurHash3 x86_32 的公认测试向量：mmh3.hash("hello") == 613153351。"""
    assert _mmh3_32(b"hello") == 613153351
    assert _mmh3_32(b"") == 0


def test_favicon_fingerprints_pair():
    sha, mmh3 = favicon_fingerprints(b"\x00\x01\x02\x03gif")
    assert isinstance(sha, str) and len(sha) == 64
    assert isinstance(mmh3, int)
    # 同样的输入必须稳定
    assert favicon_fingerprints(b"\x00\x01\x02\x03gif") == (sha, mmh3)


def test_meta_application_name_wins_over_generic_title():
    """SPA 设备：<title>登录</title> 是通用词，meta application-name 才是产品名。"""
    body = """
    <html><head><title>登录</title>
    <meta name="application-name" content="捷普安全管理系统">
    </head><body><div id=app></div></body></html>
    """
    title, meta = _extract_labels(body)
    assert title == "捷普安全管理系统"
    assert meta == "捷普安全管理系统"


def test_og_site_name_used_when_title_empty():
    body = '<html><head><title></title><meta property="og:site_name" content="Acme Firewall"></head></html>'
    title, meta = _extract_labels(body)
    assert title == "Acme Firewall"
    assert meta == "Acme Firewall"


def test_generator_meta_fallback():
    body = '<html><head><meta name="generator" content="WordPress 6.8"></head></html>'
    title, meta = _extract_labels(body)
    assert title == "WordPress 6.8"


def test_real_title_beats_meta():
    body = ('<html><head><title>捷普WEB应用防火墙</title>'
            '<meta name="generator" content="Vue"></head></html>')
    title, meta = _extract_labels(body)
    assert title == "捷普WEB应用防火墙"
    assert meta == "Vue"


def test_h1_fallback_when_no_title_no_meta():
    body = "<html><body><h1>iBMC Login</h1></body></html>"
    title, _meta = _extract_labels(body)
    assert title == "iBMC Login"


def test_generic_title_without_meta_is_kept():
    body = "<html><head><title>登录</title></head></html>"
    title, meta = _extract_labels(body)
    assert title == "登录"      # 保留，便于人工判断；但签名不会因此误判
    assert meta is None
