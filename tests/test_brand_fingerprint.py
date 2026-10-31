"""品牌词 / 静态资源 / 指纹知识库的回归测试。"""
from __future__ import annotations

from p2s.core.discovery import _asset_refs, _brand_hints


def test_brand_hints_from_page_text():
    assert _brand_hints("本站由西安捷普信息技术有限公司提供") == {"捷普"}
    assert _brand_hints("<div>Powered by Sangfor</div>") == {"深信服"}
    assert _brand_hints("hello world") == set()


def test_brand_hints_case_insensitive():
    assert "Fortinet" in _brand_hints("SERVER: FORTIGATE-100D")


def test_asset_refs_same_origin_only():
    html = '''
    <link rel="stylesheet" href="/static/css/app.css">
    <script src="static/js/app.js?v=3"></script>
    <script src="https://cdn.example.com/analytics.js"></script>
    '''
    refs = _asset_refs(html, "http://10.0.0.1:2000")
    assert len(refs) == 2
    assert refs[0].startswith("http://10.0.0.1:2000/")
    assert all("cdn.example.com" not in r for r in refs)


def test_asset_refs_limit_and_dedup():
    html = "".join(f'<script src="/a{i}.js"></script>' for i in range(10))
    assert len(_asset_refs(html, "http://h", limit=3)) == 3
    dup = '<script src="/a.js"></script><script src="/a.js"></script>'
    assert len(_asset_refs(dup, "http://h")) == 1


def test_specific_product_filter():
    from p2s.console.app import _is_specific_product

    assert _is_specific_product("捷普 WEB 应用防火墙")
    assert _is_specific_product("华为 Quidway 交换机")
    assert not _is_specific_product("捷普设备")
    assert not _is_specific_product("捷普设备（证书域名）")
    assert not _is_specific_product("邮件网关 / 中继（端口推断）")
    assert not _is_specific_product(None)
