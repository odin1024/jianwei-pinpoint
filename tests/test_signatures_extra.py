"""扩展规则库测试：用真实产品标识验证识别，且**不允许**误伤。"""
from __future__ import annotations

import pytest

from p2s.core.discovery import Service
from p2s.core.identification import classify


def _svc(**kw) -> Service:
    s = Service(port=kw.pop("port", 80), proto=kw.pop("proto", "http"))
    s.http_status = 200
    for k, v in kw.items():
        setattr(s, k, v)
    return s


@pytest.mark.parametrize("field,expect_vendor,expect_product", [
    # 打印 / 复合机（实测：证书 CN=FX- 是富士施乐真实特征）
    ({"tls_subject": "CN=FX-1C7D224333FF"}, "Fuji Xerox", "富士施乐复合机"),
    ({"http_title": "ApeosPort 3560"}, "Fuji Xerox", "富士施乐 ApeosPort"),
    ({"http_title": "HP LaserJet M404"}, "HP", "惠普 LaserJet"),
    ({"http_title": "Canon imageRUNNER 2530"}, "Canon", "佳能 imageRUNNER"),
    # NAS
    ({"http_title": "Synology DiskStation"}, "Synology", "群晖 DiskStation"),
    ({"http_title": "QNAP Turbo NAS"}, "QNAP", "威联通 Turbo NAS"),
    # 带外管理
    ({"http_title": "Integrated Lights-Out 4"}, "HPE", "HPE iLO"),
    ({"http_title": "Integrated Dell Remote Access Controller"}, "Dell", "Dell iDRAC"),
    # 国产安全设备
    ({"http_title": "深信服 SSL VPN"}, "深信服", "深信服 SSL VPN"),
    ({"http_title": "天融信防火墙"}, "天融信", "天融信防火墙"),
    ({"http_title": "绿盟科技"}, "绿盟", "绿盟设备"),
    ({"http_title": "Hillstone 安全网关"}, "Hillstone", "山石"),
    ({"http_title": "H3C S5130"}, "H3C", "新华三设备"),
    # 监控
    ({"http_title": "Hikvision IP Camera"}, "Hikvision", "海康威视"),
])
def test_extended_signatures(field, expect_vendor, expect_product):
    svc = _svc(**field)
    res = classify([svc], [80])
    assert res.vendor == expect_vendor, f"厂商应为 {expect_vendor}，实际 {res.vendor}"
    assert expect_product in res.product, f"产品应含 {expect_product}，实际 {res.product}"


def test_printer_by_port_profile():
    """只有 9100 开放、页面无特征时，也应落到打印机类型（端口语义是行业事实）。"""
    res = classify([], [80, 443, 9100])
    assert res.device_type == "printer"


def test_generic_word_does_not_misfire():
    """'canon' 出现在普通英文正文里不应把主机判成佳能复合机。"""
    svc = _svc(http_title="Documentation", body_sample="the canonical form of a request")
    res = classify([svc], [80])
    assert res.vendor != "Canon"


def test_signature_needles_unique_after_merge():
    from p2s.core.signatures import SIGNATURES

    seen = set()
    for s in SIGNATURES:
        key = (s.field, s.needle)
        assert key not in seen, f"重复签名 {key}"
        seen.add(key)
