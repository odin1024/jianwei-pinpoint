
from p2s.core.discovery import (
    AMBIGUOUS_WEB_PORTS,
    DEVICE_LABELS,
    FULL_PORT_SET,
    WEB_HTTP_PORTS,
    WEB_HTTPS_PORTS,
    Service,
    classify_device,
)


def test_port_tables_are_disjoint_and_sane():
    assert 443 in WEB_HTTPS_PORTS
    assert 443 not in WEB_HTTP_PORTS          # 443 必须是 TLS，避免明文请求打 TLS 端口
    assert 80 in WEB_HTTP_PORTS
    assert 2000 in AMBIGUOUS_WEB_PORTS          # 安全设备管理端口，协议不固定
    assert len(FULL_PORT_SET) > 50
    assert len(set(FULL_PORT_SET)) == len(FULL_PORT_SET)


def _svc(**kw) -> Service:
    return Service(**kw)


def test_classify_jumpserver_by_server_header():
    r = classify_device([_svc(port=2000, proto="https", server="Jump_server")], [2000, 443])
    assert r["device_type"] == "bastion"
    assert r["vendor"] == "JumpServer"


def test_classify_by_tls_cert():
    r = classify_device(
        [_svc(port=443, proto="https", tls_subject="CN=server,OU=yanfa,O=jump,ST=shan'xi,C=CN")],
        [443],
    )
    assert r["device_type"] == "bastion"
    assert r["vendor"] == "JumpServer"


def test_classify_linux_by_ssh_banner():
    r = classify_device(
        [_svc(port=22, proto="ssh", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20")],
        [22, 80],
    )
    assert r["device_type"] == "linux_host"
    assert r["os_hint"] == "Ubuntu"


def test_classify_by_title():
    r = classify_device([_svc(port=443, proto="https", http_title="开发测试防火墙系统")], [443, 2000])
    assert r["device_type"] == "firewall"


def test_classify_mail_gateway_by_ports():
    r = classify_device([], [25, 110, 143])
    assert r["device_type"] == "mail_gateway"


def test_classify_php_service_wins():
    r = classify_device([_svc(port=80, proto="http", php_hint="PHP/8.4.26")], [80])
    assert r["device_type"] == "php_app"


def test_classify_unknown_returns_something():
    r = classify_device([], [])
    assert r["device_type"] in DEVICE_LABELS
    assert r["confidence"] < 0.5


def test_evidence_is_always_populated():
    r = classify_device([_svc(port=80, proto="http", server="nginx/1.24.0")], [80])
    assert r["evidence"]
    assert isinstance(r["evidence"], list)


def test_confidence_is_bounded():
    r = classify_device(
        [
            _svc(port=22, proto="ssh", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu"),
            _svc(port=443, proto="https", server="Jump_server",
                 tls_subject="CN=server,O=jump", http_title="堡垒机"),
        ],
        [22, 443, 2000],
    )
    assert 0 <= r["confidence"] <= 1.0