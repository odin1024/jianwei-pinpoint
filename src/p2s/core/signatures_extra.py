"""扩展签名库：打印/网络/存储/带外/DevOps/国产安全设备。

收录原则（重要）
----------------
1. **只收真实存在且可验证的特征**：厂商官方产品名、页面自报标识、证书主体（O/CN）、
   标准服务端口。不收"猜测性"字符串（例如不能用 "canon" 这种会命中大量英文文本的词
   去匹配 BODY）。
2. **区分证据等级**：
   · 标题 / 证书 / 标准端口 → 产品级（T1），可定型号；
   · Server 头、页面正文 → 服务级（T2），只作为加权线索，不单独定厂商。
3. **宁可少认，不可错认**：判断不了就不写签名，交给"未识别"，
   这比把某台设备错标成别家产品要好（实测过把捷普认成 JumpServer 的教训）。
"""

from __future__ import annotations

from .signatures import Field, Sig, T

#: 新增设备类型（与 signatures.TYPE_LABELS 对应）
EXTRA_LABELS = {
    "nas": "NAS / 存储设备",
    "hypervisor": "虚拟化平台",
    "devops": "研发/运维平台",
    "printer": "打印机 / 复合机",
}


def _s(field: str, needle: str, dtype: str, vendor: str, product: str, weight: float) -> Sig:
    return Sig(field=field, needle=needle.lower(), dtype=dtype, vendor=vendor,
               product=product, weight=weight)


EXTRA_SIGNATURES: tuple = (
    # ==================== JS 渲染设备（服务级证据，权重低于标题）====================
    # 捷普产品线：i18n 资源里会反复出现产品线名称（实测 language.js 中"捷普防火墙"31 次）
    _s(Field.JS, "捷普防火墙", T.FIREWALL, "捷普", "捷普防火墙（静态资源）", 5.0),
    _s(Field.JS, "捷普信息审计", T.BASTION, "捷普", "捷普信息审计系统（静态资源）", 5.5),
    _s(Field.JS, "捷普准入控制", T.NAC, "捷普", "捷普准入控制系统（静态资源）", 5.5),
    _s(Field.JS, "捷普安全感知平台", T.APPLIANCE, "捷普", "捷普安全感知平台（静态资源）", 5.5),
    _s(Field.JS, "捷普管控平台", T.APPLIANCE, "捷普", "捷普管控平台（静态资源）", 4.5),
    _s(Field.JS, "捷普sslvpn", T.VPN, "捷普", "捷普 SSL VPN（静态资源）", 5.0),
    _s(Field.JS, "捷普运维审计", T.BASTION, "捷普", "捷普运维审计（静态资源）", 5.0),

    # ==================== 打印 / 复合机 ====================
    # 证书 CN 前缀是厂商真实使用的缩写（FX = Fuji Xerox，实测 ApeosPort 3560）
    _s(Field.CERT_CN, "fx-", T.PRINTER, "Fuji Xerox", "富士施乐复合机", 8.0),
    _s(Field.TITLE, "apeosport", T.PRINTER, "Fuji Xerox", "富士施乐 ApeosPort", 9.0),
    _s(Field.BODY, "apeosport", T.PRINTER, "Fuji Xerox", "富士施乐 ApeosPort", 7.5),
    _s(Field.TITLE, "fuji xerox", T.PRINTER, "Fuji Xerox", "富士施乐复合机", 8.5),
    _s(Field.TITLE, "富士施乐", T.PRINTER, "Fuji Xerox", "富士施乐复合机", 8.5),
    _s(Field.TITLE, "docucentre", T.PRINTER, "Fuji Xerox", "富士施乐 DocuCentre", 8.5),
    _s(Field.TITLE, "laserjet", T.PRINTER, "HP", "惠普 LaserJet", 8.5),
    _s(Field.TITLE, "officejet", T.PRINTER, "HP", "惠普 OfficeJet", 8.5),
    _s(Field.TITLE, "imageclass", T.PRINTER, "Canon", "佳能 imageCLASS", 8.5),
    _s(Field.TITLE, "imagerunner", T.PRINTER, "Canon", "佳能 imageRUNNER", 8.5),
    _s(Field.TITLE, "epson", T.PRINTER, "Epson", "爱普生打印机", 7.5),
    _s(Field.TITLE, "brother", T.PRINTER, "Brother", "兄弟打印机", 7.5),
    _s(Field.TITLE, "ricoh", T.PRINTER, "Ricoh", "理光复合机", 8.0),
    _s(Field.TITLE, "kyocera", T.PRINTER, "Kyocera", "京瓷复合机", 8.0),
    _s(Field.TITLE, "konica minolta", T.PRINTER, "Konica Minolta", "柯尼卡美能达复合机", 8.5),
    _s(Field.TITLE, "lexmark", T.PRINTER, "Lexmark", "利盟打印机", 8.0),
    # 注意：'xerox' 不单独匹配 BODY，避免命中"xerox 兼容"等文本

    # ==================== NAS / 存储 ====================
    _s(Field.TITLE, "synology diskstation", T.STORAGE, "Synology", "群晖 DiskStation", 9.0),
    _s(Field.TITLE, "synology", T.STORAGE, "Synology", "群晖 NAS", 8.0),
    _s(Field.BODY, "synology", T.STORAGE, "Synology", "群晖 NAS", 6.5),
    _s(Field.CERT_CN, "synology", T.STORAGE, "Synology", "群晖 NAS", 7.5),
    _s(Field.TITLE, "qnap turbo nas", T.STORAGE, "QNAP", "威联通 Turbo NAS", 9.0),
    _s(Field.TITLE, "qnap", T.STORAGE, "QNAP", "威联通 NAS", 8.0),
    _s(Field.TITLE, "truenas", T.STORAGE, "iXsystems", "TrueNAS", 9.0),
    _s(Field.TITLE, "freenas", T.STORAGE, "iXsystems", "FreeNAS", 9.0),
    _s(Field.TITLE, "netapp", T.STORAGE, "NetApp", "NetApp 存储", 8.5),

    # ==================== 带外管理 ====================
    _s(Field.TITLE, "integrated lights-out", T.IBMC, "HPE", "HPE iLO", 9.0),
    _s(Field.BODY, "ilo", T.IBMC, "HPE", "HPE iLO", 5.0),          # 短词，低权重
    _s(Field.TITLE, "integrated dell remote access controller", T.IBMC, "Dell", "Dell iDRAC", 9.0),
    _s(Field.TITLE, "idrac", T.IBMC, "Dell", "Dell iDRAC", 8.5),
    _s(Field.BODY, "idrac", T.IBMC, "Dell", "Dell iDRAC", 6.0),
    _s(Field.TITLE, "supermicro", T.IBMC, "Supermicro", "Supermicro BMC", 7.5),
    _s(Field.TITLE, "imm", T.IBMC, "Lenovo", "Lenovo IMM", 6.5),

    # ==================== 虚拟化 ====================
    _s(Field.TITLE, "vmware esxi", T.APPLIANCE, "VMware", "VMware ESXi", 9.0),
    _s(Field.BODY, "vmware esxi", T.APPLIANCE, "VMware", "VMware ESXi", 7.0),
    _s(Field.TITLE, "vcenter", T.APPLIANCE, "VMware", "VMware vCenter", 8.5),
    _s(Field.TITLE, "proxmox", T.APPLIANCE, "Proxmox", "Proxmox VE", 9.0),

    # ==================== 研发 / 运维平台 ====================
    _s(Field.TITLE, "jenkins", T.WEBAPP, "Jenkins", "Jenkins", 8.5),
    _s(Field.TITLE, "gitlab", T.WEBAPP, "GitLab", "GitLab", 9.0),
    _s(Field.TITLE, "nexus repository", T.WEBAPP, "Sonatype", "Nexus Repository", 9.0),
    _s(Field.TITLE, "harbor", T.WEBAPP, "CNCF", "Harbor", 8.5),
    _s(Field.TITLE, "grafana", T.WEBAPP, "Grafana Labs", "Grafana", 9.0),
    _s(Field.TITLE, "kibana", T.WEBAPP, "Elastic", "Kibana", 9.0),
    _s(Field.TITLE, "webmin", T.WEBAPP, "Webmin", "Webmin", 9.0),
    _s(Field.TITLE, "apache tomcat", T.WEBAPP, "Apache", "Apache Tomcat", 8.5),
    _s(Field.TITLE, "cpanel", T.WEBAPP, "cPanel", "cPanel", 9.0),
    _s(Field.TITLE, "plesk", T.WEBAPP, "Plesk", "Plesk", 9.0),
    _s(Field.TITLE, "宝塔", T.WEBAPP, "宝塔", "宝塔面板", 8.5),
    _s(Field.BODY, "bt.cn", T.WEBAPP, "宝塔", "宝塔面板", 6.5),

    # ==================== 视频监控 ====================
    _s(Field.TITLE, "hikvision", T.CAMERA, "Hikvision", "海康威视设备", 8.5),
    _s(Field.BODY, "hikvision", T.CAMERA, "Hikvision", "海康威视设备", 6.5),
    _s(Field.TITLE, "dahua", T.CAMERA, "Dahua", "大华设备", 8.5),
    _s(Field.BODY, "dahua", T.CAMERA, "Dahua", "大华设备", 6.0),

    # ==================== 国产网络安全设备 ====================
    _s(Field.TITLE, "深信服", T.APPLIANCE, "深信服", "深信服设备", 8.5),
    _s(Field.BODY, "sangfor", T.APPLIANCE, "深信服", "深信服设备", 7.0),
    _s(Field.TITLE, "ssl vpn", T.VPN, "深信服", "深信服 SSL VPN", 6.5),
    _s(Field.TITLE, "天融信", T.FIREWALL, "天融信", "天融信防火墙", 8.5),
    _s(Field.BODY, "topsec", T.FIREWALL, "天融信", "天融信设备", 7.0),
    _s(Field.TITLE, "绿盟", T.APPLIANCE, "绿盟", "绿盟设备", 8.5),
    _s(Field.BODY, "nsfocus", T.APPLIANCE, "绿盟", "绿盟设备", 7.0),
    _s(Field.TITLE, "启明星辰", T.APPLIANCE, "启明星辰", "启明星辰设备", 8.5),
    _s(Field.TITLE, "venustech", T.APPLIANCE, "启明星辰", "启明星辰设备", 8.0),
    _s(Field.TITLE, "安恒", T.APPLIANCE, "安恒", "安恒设备", 8.5),
    _s(Field.TITLE, "奇安信", T.APPLIANCE, "奇安信", "奇安信设备", 8.5),
    _s(Field.TITLE, "山石网科", T.FIREWALL, "Hillstone", "山石网科防火墙", 8.5),
    _s(Field.TITLE, "hillstone", T.FIREWALL, "Hillstone", "山石网科防火墙", 8.0),
    _s(Field.BODY, "hillstone", T.FIREWALL, "Hillstone", "山石网科设备", 7.0),
    _s(Field.TITLE, "dptech", T.FIREWALL, "DPtech", "迪普科技设备", 8.0),
    _s(Field.BODY, "dptech", T.FIREWALL, "DPtech", "迪普科技设备", 6.5),
    _s(Field.TITLE, "锐捷", T.SWITCH, "Ruijie", "锐捷网络设备", 8.0),
    _s(Field.BODY, "ruijie", T.SWITCH, "Ruijie", "锐捷网络设备", 6.5),
    _s(Field.TITLE, "h3c", T.SWITCH, "H3C", "新华三设备", 8.0),
    _s(Field.TITLE, "tplink", T.ROUTER, "TP-Link", "TP-Link 设备", 7.5),
    _s(Field.TITLE, "tp-link", T.ROUTER, "TP-Link", "TP-Link 设备", 8.0),
)

#: 标准服务端口 → 设备类型（这些端口语义是行业事实，不依赖品牌）
EXTRA_PORT_SIGNATURES: tuple = (
    ("9100", T.PRINTER, "打印服务"),
    ("515", T.PRINTER, "打印服务"),
    ("631", T.PRINTER, "打印服务"),
    ("554", T.CAMERA, "RTSP 视频流"),
    ("2049", T.STORAGE, "NFS 存储服务"),
    ("3260", T.STORAGE, "iSCSI 存储服务"),
    ("5060", T.VPN, "SIP 语音网关"),
    ("623", T.IBMC, "IPMI 带外管理"),
)
