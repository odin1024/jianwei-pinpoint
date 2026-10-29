from p2s.core.ioc import IocLibrary
from p2s.core.probe import build_control_request, build_header_amplification, build_nested_arrays


def test_control_request_is_tiny():
    body = build_control_request("B")
    assert len(body) < 200
    assert b"p2s_ctl" in body


def test_header_amplification_shape():
    body = build_header_amplification("B", headers=10, header_size=20)
    assert body.count(b"X-Pad-") == 10
    assert b"--B--" in body


def test_nested_arrays_shape():
    body = build_nested_arrays("B", depth=3, width=4)
    assert body.count(b'filename=""') == 4
    assert b"p2s_f[0][1][2]" in body


def test_probes_contain_no_exploit_payload():
    """红线测试：探针绝不能包含 PHP 代码或利用载荷。"""
    for payload in (build_header_amplification("B"), build_nested_arrays("B")):
        low = payload.lower()
        assert b"<?php" not in low
        assert b"system(" not in low
        assert b"eval(" not in low
        assert b"base64" not in low


def test_ioc_library_shape():
    lib = IocLibrary()
    s = lib.summary()
    assert s["ips"] > 0 and s["urls"] > 0 and s["hashes"] > 0
