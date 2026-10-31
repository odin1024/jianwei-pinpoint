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
def test_jiepu_server_header_is_not_jumpserver():
    """实测 192.168.1.226：Server: Jump_server + 证书 O=jump 是**捷普**的 Web 服务，
    不是 FIT2CLOUD 的 JumpServer。这条曾把 6 台捷普设备误判成 JumpServer 堡垒机。"""
    r = classify([_http(server="Jump_server", tls="CN=server,OU=yanfa,O=jump,ST=shan'xi,C=CN")], [2000])
    assert r.vendor == "捷普"
    assert "捷普" in r.product
    assert "JumpServer" not in (r.product or "")
    # 只有服务级证据，置信度不许显得很确定
    assert r.confidence <= 0.72


def test_nac_title_beats_generic_server_header():
    """实测 192.168.1.227：Server: jump 很泛，标题“准入控制系统”才是产品标签。"""
    svcs = [
        _http(port=80, server="jump", title="准入控制系统"),
        _http(port=443, server="jump", tls="CN=server,OU=jump,O=xi'an,C=CN"),
    ]
    r = classify(svcs, [80, 443])
    assert r.device_type == T.NAC
    assert "准入" in r.product
    assert r.vendor == "捷普"
    assert r.product_source == "title"


def test_jiepu_waf_title_wins_and_names_vendor():
    """实测 192.168.1.225：标题『捷普WEB应用防火墙』+ Server: Jump_server。"""
    svcs = [
        _http(port=2000, server="Jump_server", title="捷普WEB应用防火墙",
              tls="1.2.840.113549.1.9.1=jump@yanfa.net.cn,CN=server,OU=yanfa,O=jump,ST=shan'xi,C=CN"),
    ]
    r = classify(svcs, [22, 2000])
    assert r.device_type == T.WAF
    assert r.vendor == "捷普"
    assert "应用防火墙" in r.product
    assert r.confidence > 0.7


def test_real_jumpserver_by_brand():
    """真正的 JumpServer 靠厂商自报的名字（Fit2Cloud 证书 / jumpserver 品牌词）。"""
    r = classify([_http(port=443, title="JumpServer", tls="CN=*.fit2cloud.com,O=Fit2Cloud,C=CN")], [443])
    assert r.device_type == T.BASTION
    assert r.vendor == "JumpServer"


def test_oui_never_becomes_device_vendor():
    """MAC OUI 只说明网卡厂商。实测 8c:1c:da 被 OUI 表标成 Sangfor，
    但设备是捷普 —— 不能让 OUI 覆盖/冒充设备品牌。"""
    r = classify([_http(port=443, tls="CN=server,O=company,C=CN")], [443],
                 mac="8c1cda44ca4d", mac_vendor="深信服 Sangfor")
    assert r.vendor != "深信服 Sangfor"
    assert r.vendor == ""
    assert any("网卡厂商" in e for e in r.evidence)


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
    """端口画像只在「端口真的有过有效响应」时才允许兜底。"""
    r = classify([], [6379], meaningful_ports=[6379])
    assert r.device_type == T.DB
    assert r.confidence < 0.5
    assert "端口推断" in r.product
    assert r.product_source == "port"


def test_no_port_guess_without_response():
    """连得上但零响应的端口不能拿来猜设备类型（NAT/tarpit 会把 25/110/143 全判成邮件网关）。"""
    r = classify([], [25, 110, 143], meaningful_ports=[])
    assert r.device_type == T.UNKNOWN
    assert r.confidence <= 0.2


def test_tier2_only_conclusion_is_capped():
    """只有 Server 头这种服务级证据时，置信度必须被压住。"""
    r = classify([_http(port=80, server="nginx")], [80])
    assert r.confidence <= 0.72


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