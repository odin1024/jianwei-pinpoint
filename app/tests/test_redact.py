from p2s.core.redact import redact, redact_obj

PHP_OPEN = "<" + "?php"
PHP_CLOSE = "?" + ">"
GET_ARG = "$" + "_GET[0]"


def test_redact_removes_php_block():
    payload = PHP_OPEN + " system(" + GET_ARG + "); " + PHP_CLOSE
    out = redact(payload)
    assert "system(" not in out
    assert "PHP-CODE-BLOCK" in out
    assert PHP_OPEN not in out


def test_redact_keeps_structural_signal():
    """脱敏后仍要能判断"有代码"和"多长"，否则证据就没用了。"""
    payload = PHP_OPEN + " system(" + GET_ARG + "); " + PHP_CLOSE
    out = redact(payload)
    assert "len=" in out


def test_redact_serialized_object():
    out = redact('x|O:32:"Monolog":13:{}')
    assert "SERIALIZED-OBJ" in out


def test_redact_command_call():
    out = redact("passthru(" + GET_ARG + ")")
    # 保留函数名作为结构性信号，但必须抹掉参数
    assert "CALL" in out
    assert GET_ARG not in out


def test_redact_long_base64():
    out = redact("A" * 200)
    assert "BASE64-BLOB" in out


def test_redact_obj_recursive():
    obj = {"a": [{"b": PHP_OPEN + " echo 1; " + PHP_CLOSE}], "c": 1, "d": True}
    out = redact_obj(obj)
    assert PHP_OPEN not in str(out)
    assert out["c"] == 1
    assert out["d"] is True


def test_redact_empty_and_plain():
    assert redact("") == ""
    assert redact("hello world") == "hello world"


def test_report_evidence_has_no_raw_payload():
    """端到端：报告里的证据不得含原始载荷。"""
    import json
    import pathlib
    import tempfile

    from p2s.core.logscan import parse_line, scan_records
    from p2s.core.report import ScanResult, to_json

    payload = PHP_OPEN + " system(" + GET_ARG + "); " + PHP_CLOSE
    body = (
        "--B\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n"
        f"--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"{payload}\"\r\n\r\nZ\r\n--B--\r\n"
    )
    rec = parse_line(json.dumps({
        "remote_addr": "1.2.3.4", "request_method": "POST", "request_uri": "/a.php",
        "status": 200, "request_body": body,
    }))
    assert rec is not None
    findings = scan_records([rec])
    assert findings

    res = ScanResult(scan_id="t", kind="logs", started_at="now")
    res.findings = [f.to_dict() for f in findings]

    with tempfile.TemporaryDirectory() as td:
        p = to_json(res, pathlib.Path(td) / "r.json")
        text = p.read_text(encoding="utf-8")
        assert PHP_OPEN not in text
        assert "PHP-CODE-BLOCK" in text