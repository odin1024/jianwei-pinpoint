"""发现引擎的基础契约测试（分类逻辑见 test_identification.py）。"""
import socket
import threading

from p2s.core.discovery import (
    AMBIGUOUS_WEB_PORTS,
    FAST_PORT_SET,
    FULL_PORT_SET,
    PATH_LADDER,
    UA_LADDER,
    WEB_HTTP_PORTS,
    WEB_HTTPS_PORTS,
    DeviceProfile,
    discover,
    scan_ports,
)


def test_port_tables_are_disjoint_and_sane():
    assert 443 in WEB_HTTPS_PORTS
    assert 443 not in WEB_HTTP_PORTS      # 443 必须走 TLS，避免明文打 TLS 端口被回 400
    assert 80 in WEB_HTTP_PORTS
    assert 2000 in AMBIGUOUS_WEB_PORTS     # 安全设备管理端口，协议不固定
    assert len(FULL_PORT_SET) > 50
    assert len(set(FULL_PORT_SET)) == len(FULL_PORT_SET)
    assert set(FAST_PORT_SET) <= set(FULL_PORT_SET)


def test_path_ladder_covers_observed_login_paths():
    assert "/" in PATH_LADDER
    assert "/login.html" in PATH_LADDER        # 华为 iBMC
    assert "/simple/view/login.html" in PATH_LADDER   # 华为 Quidway 交换机


def test_ua_ladder_starts_with_realistic_browser():
    assert "Mozilla/5.0" in UA_LADDER[0]
    assert "Chrome" in UA_LADDER[0]


def test_scan_ports_detects_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    t = threading.Thread(target=lambda: srv.accept(), daemon=True)
    t.start()
    try:
        assert port in scan_ports("127.0.0.1", [port], timeout=1.0)
        assert port not in scan_ports("127.0.0.1", [port + 1], timeout=0.4)
    finally:
        srv.close()


def test_discover_offline_host():
    """不可达地址：必须判为离线、暴露面 not_applicable、无证据噪声。"""
    p = discover("192.0.2.123", ports=[1], timeout=0.3, http_timeout=1.0, deep=False)
    assert p.alive is False
    assert p.exposure == "not_applicable"
    assert p.device_type == "offline"
    assert p.errors


def test_discover_local_listener_is_alive():
    """本机起一个 HTTP 服务，必须判定为存活。"""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><head><title>p2s-test-app</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        p = discover("127.0.0.1", ports=[port], timeout=1.0, http_timeout=3.0, deep=False)
        assert p.alive is True
        assert port in p.meaningful_ports
        assert p.open_ports == [port]
        assert p.evidence
    finally:
        srv.shutdown()
        srv.server_close()


def test_device_profile_defaults_offline():
    p = DeviceProfile(host="1.2.3.4")
    assert p.alive is False
    assert p.risk == "low"
    assert p.exposure == "unknown"