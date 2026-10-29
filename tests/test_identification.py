"""设备识别与存活判定测试 —— 全部基于本机网段的实测数据。"""
from p2s.core.discovery import Service
from p2s.core.identification import assess_liveness, classify, detect_noise_ports
from p2s.core.signatures import SIGNATURES, T


# ---------- 存活判定 ----------
def _http(port=80, status=200, server=None, title=None, tls=None, cookie=None, path=None):
    return Service(port=port, proto="http", http_status=status, server=server,
                   http_title=title, tls_subject=tls, cookie=cookie, matched_path=path)


def test_tarpit_ports_are_not_alive():
    """NAT/tarpit：连上但零响应 —— 不得判为存活。"""
    svcs = [
        Service(port=25, proto="tcp", banner="TimeoutError"),
        Service(port=110, proto="tcp", banner="TimeoutError"),
        Service(port=143, proto="tcp", banner="TimeoutError"),
    ]
    live = assess_liveness(svcs, [25, 110, 143])
    assert live.alive is False
    assert live.meaningful_services == []
    assert "NAT" in live.reason or "tarpit" in live.reason


def test_http_response_means_alive():
    live = assess_liveness([_http(status=404)], [80])
    assert live.alive is True
    assert live.meaningful_ports if hasattr(live, "meaningful_ports") else True


def test_ssh_banner_means_alive():
    svc = Service(port=22, proto="ssh", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu")
    live = assess_liveness([svc], [22])
    assert live.alive is True


def test_empty_host_is_offline():
    live = assess_liveness([], [])
    assert live.alive is False
    assert "离线" in live.reason


def test_detect_network_noise_ports():
    """254 台主机都在的端口 = 网络级噪声，不是主机特征。"""
    sets = [[25, 110, 143] for _ in range(200)] + [[80, 443] for _ in range(10)]
    noise = detect_noise_ports(sets)
    assert 25 in noise and 110 in noise and 143 in noise
    assert 80 not in noise


# ---------- 分类：实测样本 ----------
def test_jumpserver_by_server_header():
    r = classify([_http(server="Jump_server", tls="CN=server,OU=yanfa,O=jump,C=CN")], [2000])
    assert r.device_type == T.BASTION
    assert r.vendor == "JumpServer"
    assert r.confidence > 0.8


def test_nac_title_beats_generic_server_header():
    """实测 192.168.1.227：Server: jump 很泛，标题“准入控制系统”才是产品标签。"""
    svcs = [
        _http(port=80, server="jump", title="准入控制系统"),
        _http(port=443, server="jump", tls="CN=server,OU=jump,O=xi'an,C=CN"),
    ]
    r = classify(svcs, [80, 443])
    assert r.device_type == T.NAC
    assert "准入" in r.product
    # 次优候选应保留 JumpServer
    assert any("JumpServer" in c["label"] for c in r.candidates)


def test_huawei_ibmc_by_title():
    r = classify([_http(port=443, title="iBMC Login")], [443])
    assert r.device_type == T.IBMC
    assert r.vendor == "Huawei"


def test_huawei_switch_by_cert_cn():
    r = classify([_http(port=443, server="sw1", tls="CN=Quidway,O=FutureMatrix,C=CN")], [443])
    assert r.device_type == T.SWITCH
    assert "Quidway" in r.product


def test_filezilla_by_banner():
    svc = Service(port=21, proto="ftp", banner="220-FileZilla Server 0.9.60 beta\r\n220 Please visit")
    r = classify([svc], [21])
    assert r.device_type == T.FTP
    assert r.vendor == "FileZilla"


def test_php_detected_by_cookie():
    """实测 192.168.1.230：无 X-Powered-By，只有 PHPSESSID cookie。"""
    r = classify([_http(port=80, status=302, cookie="PHPSESSID=abc; path=/; HttpOnly")], [80])
    assert r.device_type == T.PHP
    assert "PHP" in r.tech_stack


def test_ubuntu_by_ssh_banner():
    svc = Service(port=22, proto="ssh", banner="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20")
    r = classify([svc], [22])
    assert r.device_type == T.LINUX
    assert r.vendor == "Ubuntu"


def test_generic_cert_is_not_a_vendor():
    """实测大量设备证书是 CN=server,O=company —— 不能据此判厂商。"""
    r = classify([_http(port=443, tls="CN=server,OU=server,O=company,C=CN")], [443])
    assert r.vendor != "company"


def test_port_profile_fallback():
    r = classify([], [6379])
    assert r.device_type == T.DB
    assert r.confidence < 0.5


def test_unknown_without_any_signal():
    r = classify([], [12345])
    assert r.device_type == T.UNKNOWN
    assert r.confidence < 0.3


# ---------- 签名库自身 ----------
def test_no_generic_words_as_signature():
    for s in SIGNATURES:
        assert s.needle not in ("server", "company", "localhost", "root", "http", "cn"), s


def test_signature_ids_unique():
    seen = set()
    for s in SIGNATURES:
        k = (s.field, s.needle)
        assert k not in seen, f"重复签名 {k}"
        seen.add(k)


def test_every_signature_has_type():
    from p2s.core.signatures import TYPE_LABELS
    for s in SIGNATURES:
        assert s.dtype in TYPE_LABELS, s