"""设备识别签名库。

每个签名声明：**在哪个字段**、**匹配什么子串**、判定为什么**设备类型 / 厂商 / 具体产品**。

设计原则：
  1. 优先用**产品级特征**（Server 头、页面标题、TLS 证书 CN/O/OU、登录路径），
     它们比端口画像精确得多 —— 端口只能说明"有个 Web 服务"，标签能说明"是什么"。
  2. 每条签名带权重，分类引擎按加权得分选出最优结果。
  3. 只在**足够具体**时才匹配。通用词（server / company / localhost）绝不能作为
     厂商判据 —— 实测中大量设备的证书都是 CN=server,O=company。

签名来源：实测本机所在网段（192.168.1.0/24）的 200+ 台设备 + 行业通用指纹。
"""


class Field:
    SERVER = "server"
    TITLE = "title"
    #: 品牌词：从页面正文 / 静态资源内容 / 404 页里扫出来的厂商名
    BRAND = "brand"
    CERT = "cert"
    CERT_CN = "cert_cn"
    BANNER = "banner"
    COOKIE = "cookie"
    WWW_AUTH = "www_auth"
    PATH = "path"
    BODY = "body"
    #: 页面元数据（meta generator / application-name / og:site_name）
    META = "meta"
    UA = "ua"
    #: JS/CSS 静态资源里的产品线词（JS 渲染设备的兜底证据，服务级）
    JS = "js"


#: 品牌词典：页面正文、静态 JS/CSS、404 页里出现这些词，就足以确定厂商。
#: 它是"标题为空"设备的主要兜底手段 —— 标题可以没有，品牌词几乎总在源码里。
#:
#: 纪律：纯 ASCII 别名必须**整词**命中（见 discovery._brand_hints 的边界匹配），
#: 否则 "h3c" 会命中十六进制串、"edr" 会命中 hundred 这类单词。
BRAND_KEYWORDS: dict[str, tuple[str, ...]] = {
    "捷普": ("捷普", "jiepu", "jump.net.cn", "yanfa.net.cn"),
    "深信服": ("深信服", "sangfor"),
    "Huawei": ("华为", "huawei", "quidway"),
    "H3C": ("新华三", "h3c"),
    "天融信": ("天融信", "topsec"),
    "绿盟": ("绿盟", "nsfocus"),
    "启明星辰": ("启明星辰", "venustech"),
    "奇安信": ("奇安信", "qianxin"),
    "安恒": ("安恒", "dbappsecurity"),
    "Fortinet": ("fortinet", "fortigate"),
    "Cisco": ("cisco",),
    "Palo Alto": ("palo alto", "globalprotect"),
    "SonicWall": ("sonicwall",),
}


class T:
    #: Web 应用（CMS / 框架 / 面板）
    WEBAPP = "webapp"
    BASTION = "bastion"
    WAF = "waf"
    NAC = "nac"
    FIREWALL = "firewall"
    SWITCH = "switch"
    ROUTER = "router"
    VPN = "vpn"
    NET_MGMT = "net_mgmt"
    LOAD_BALANCER = "load_balancer"
    IBMC = "ibmc"
    STORAGE = "storage"
    CAMERA = "camera"
    PRINTER = "printer"
    MAIL = "mail"
    FTP = "ftp"
    DB = "database"
    LINUX = "linux_host"
    WINDOWS = "windows_host"
    WEB = "web_server"
    PHP = "php_app"
    JAVA = "java_app"
    DOTNET = "dotnet_app"
    CMS = "cms"
    MONITOR = "monitoring"
    DEVOPS = "devops"
    FILE_SVC = "file_service"
    CLOUD = "cloud"
    CONTAINER = "container"
    IOT = "iot_device"
    APPLIANCE = "appliance"
    UNKNOWN = "unknown"


TYPE_LABELS = {
    T.PRINTER: "打印机 / 复合机",
    "webapp": "Web 应用（PHP）",
    T.BASTION: "堡垒机 / 运维审计",
    T.WAF: "Web 应用防火墙",
    T.NAC: "准入控制系统",
    T.FIREWALL: "防火墙 / 安全网关",
    T.SWITCH: "交换机",
    T.ROUTER: "路由器",
    T.VPN: "VPN 网关",
    T.NET_MGMT: "网络管理平台",
    T.LOAD_BALANCER: "负载均衡",
    T.IBMC: "服务器带外管理",
    T.STORAGE: "存储设备",
    T.CAMERA: "摄像头 / 视频监控",
    T.MAIL: "邮件网关 / 中继",
    T.FTP: "FTP 文件服务",
    T.DB: "数据库服务",
    T.LINUX: "Linux 主机",
    T.WINDOWS: "Windows 主机",
    T.WEB: "Web 服务器（无 PHP）",
    T.PHP: "PHP 应用站点",
    T.JAVA: "Java 应用",
    T.DOTNET: ".NET 应用",
    T.CMS: "CMS 网站",
    T.MONITOR: "监控 / 运维平台",
    T.DEVOPS: "DevOps 平台",
    T.FILE_SVC: "文件共享服务",
    T.CLOUD: "云 / 虚拟化平台",
    T.CONTAINER: "容器平台",
    T.IOT: "IoT / 嵌入式设备",
    T.APPLIANCE: "网络 / 安全设备",
    T.UNKNOWN: "未识别设备",
}


class Sig:
    """一条签名。"""

    __slots__ = ("field", "needle", "dtype", "vendor", "product", "weight", "note")

    def __init__(self, field, needle, dtype, vendor="", product="", weight=3.0, note="") -> None:
        self.field = field
        self.needle = needle.lower()
        self.dtype = dtype
        self.vendor = vendor
        self.product = product
        self.weight = weight
        self.note = note

    def __repr__(self) -> str:
        return f"Sig({self.field}, {self.needle!r}, {self.dtype}, {self.vendor!r}, {self.product!r})"


def _s(field, needle, dtype, vendor="", product="", weight=3.0, note=""):
    return Sig(field, needle, dtype, vendor, product, weight, note)


SIGNATURES = (
    # ===== 捷普（JUMP）安全设备系列 =====
    #
    # 这一组是本机网段实测出来的**同一个厂商**的产品族。关键教训（v0.5.1 修复）：
    #   Server: Jump_server / Jumper / jump 是捷普自研 Web 服务的标识，
    #   证书里 O=jump、ST=shan'xi、jump.net.cn / yanfa.net.cn 是捷普的内部 PKI，
    #   这些**不是** FIT2CLOUD 的 JumpServer 开源堡垒机。
    #   把它们映射成别家产品，是「用服务级证据去推厂商级结论」的典型错误。
    # 因此：Server/CERT 里出现 jump，只能推出「捷普设备」，产品类型必须由标题决定。
    _s(Field.TITLE, "捷普web应用防火墙", T.WAF, "捷普", "捷普 WEB 应用防火墙", 8.0),
    _s(Field.TITLE, "捷普", T.APPLIANCE, "捷普", "捷普设备", 6.0,
       "厂商锚点：标题里出现品牌名即可确定厂商，具体型号交给更细的标题关键词"),
    _s(Field.TITLE, "信息审计管理系统", T.BASTION, "捷普", "捷普信息审计系统", 7.5),
    _s(Field.TITLE, "审计管理系统", T.BASTION, "捷普", "捷普信息审计系统", 7.0),
    _s(Field.TITLE, "捷普防火墙系统", T.FIREWALL, "捷普", "捷普防火墙", 7.5),
    _s(Field.TITLE, "防火墙系统", T.FIREWALL, "", "防火墙系统", 6.0),
    _s(Field.TITLE, "准入控制系统", T.NAC, "捷普", "捷普准入控制系统", 7.0),
    _s(Field.TITLE, "准入测试系统", T.NAC, "捷普", "捷普准入测试系统", 7.0),
    _s(Field.TITLE, "产品演示平台", T.APPLIANCE, "捷普", "捷普产品演示平台", 6.5),
    _s(Field.SERVER, "jump", T.APPLIANCE, "捷普", "捷普设备（Web 服务标识 Jump_server）", 3.0,
       "实测：捷普 WAF/防火墙/审计/准入的 Web 服务都返回 Jump_server / Jumper / jump"),
    _s(Field.CERT, "jump.net.cn", T.APPLIANCE, "捷普", "捷普设备（证书域名）", 4.5),
    _s(Field.CERT, "yanfa.net.cn", T.APPLIANCE, "捷普", "捷普设备（证书域名）", 4.0),
    _s(Field.CERT, "st=shan'xi", T.APPLIANCE, "捷普", "捷普设备（证书属地 陕西）", 2.0),

    # ===== JumpServer（FIT2CLOUD 开源堡垒机）真正的指纹 =====
    # 只有厂商自报的名字才算数：Fit2Cloud 的证书、页面里的 jumpserver 品牌词。
    _s(Field.TITLE, "jumpserver", T.BASTION, "JumpServer", "JumpServer 堡垒机", 8.0),
    _s(Field.BODY, "jumpserver", T.BASTION, "JumpServer", "JumpServer 堡垒机", 5.0),
    _s(Field.CERT, "fit2cloud", T.BASTION, "JumpServer", "JumpServer 堡垒机", 8.0),
    _s(Field.CERT, "o=jumpserver", T.BASTION, "JumpServer", "JumpServer 堡垒机", 7.0),

    # 捷普设备的管理口 SSH banner（实测 225/226/233 均为 SSH-2.0-JSH）
    _s(Field.BANNER, "ssh-2.0-jsh", T.APPLIANCE, "捷普", "捷普设备（SSH 标识 JSH）", 3.5),

    # ===== 品牌词（正文 / 静态资源 / 404 页）=====
    # 只定厂商，不定型号：型号仍要标题或知识库；但"厂商正确"已经比"未识别"有用得多。
    _s(Field.BRAND, "捷普", T.APPLIANCE, "捷普", "捷普设备（品牌词）", 5.0),
    _s(Field.BRAND, "深信服", T.APPLIANCE, "深信服", "深信服设备", 5.0),
    _s(Field.BRAND, "天融信", T.APPLIANCE, "天融信", "天融信设备", 5.0),
    _s(Field.BRAND, "绿盟", T.APPLIANCE, "绿盟", "绿盟设备", 5.0),
    _s(Field.BRAND, "启明星辰", T.APPLIANCE, "启明星辰", "启明星辰设备", 5.0),
    _s(Field.BRAND, "奇安信", T.APPLIANCE, "奇安信", "奇安信设备", 5.0),
    _s(Field.BRAND, "安恒", T.APPLIANCE, "安恒", "安恒设备", 5.0),
    _s(Field.BRAND, "H3C", T.APPLIANCE, "H3C", "新华三设备", 5.0),
    _s(Field.BRAND, "Fortinet", T.APPLIANCE, "Fortinet", "Fortinet 设备", 5.0),

    # 类型词（不带厂商）：说明"这是什么设备"，不能推出厂商
    _s(Field.TITLE, "堡垒机", T.BASTION, "", "堡垒机", 4.5),
    _s(Field.TITLE, "应用防火墙", T.WAF, "", "WEB 应用防火墙", 6.0),
    _s(Field.TITLE, "安全管理系统", T.NET_MGMT, "", "安全管理系统", 5.0),
    _s(Field.TITLE, "nac", T.NAC, "", "NAC 准入控制", 3.0),
    _s(Field.TITLE, "网络信息", T.NET_MGMT, "", "网络信息管理平台", 3.0),

    # ===== 华为 / H3C / 锐捷 =====
    _s(Field.TITLE, "ibmc", T.IBMC, "Huawei", "华为 iBMC 带外管理", 7.0, "实测：iBMC Login 页面"),
    _s(Field.TITLE, "idrac", T.IBMC, "Dell", "Dell iDRAC", 5.0),
    _s(Field.TITLE, "integrated dell", T.IBMC, "Dell", "Dell iDRAC", 5.0),
    _s(Field.TITLE, "xclarity", T.IBMC, "Lenovo", "联想 XClarity", 5.0),
    _s(Field.TITLE, "supermicro", T.IBMC, "Supermicro", "Supermicro BMC", 5.0),
    _s(Field.CERT_CN, "quidway", T.SWITCH, "Huawei", "华为 Quidway 交换机", 7.0,
       "实测：CN=Quidway,O=FutureMatrix"),
    _s(Field.CERT, "o=huawei", T.NET_MGMT, "Huawei", "华为设备", 4.0),
    _s(Field.CERT, "l=shenzhen", T.NET_MGMT, "Huawei", "华为设备", 3.5),
    _s(Field.SERVER, "sw1", T.SWITCH, "Huawei", "华为交换机", 4.0, "实测：Server: sw1 / sw3"),
    _s(Field.SERVER, "sw2", T.SWITCH, "Huawei", "华为交换机", 4.0),
    _s(Field.SERVER, "sw3", T.SWITCH, "Huawei", "华为交换机", 4.0),
    _s(Field.PATH, "/simple/view/login.html", T.SWITCH, "Huawei", "华为 Quidway 交换机", 5.0,
       "实测：华为交换机登录路径特征"),
    _s(Field.TITLE, "usg", T.FIREWALL, "Huawei", "华为 USG 防火墙", 4.0),
    _s(Field.TITLE, "secgate", T.FIREWALL, "Huawei", "华为 SecGate 防火墙", 4.0),
    _s(Field.TITLE, "h3c", T.NET_MGMT, "H3C", "新华三设备", 4.0),
    _s(Field.TITLE, "ruijie", T.NET_MGMT, "Ruijie", "锐捷网络设备", 4.0),
    _s(Field.TITLE, "sangfor", T.FIREWALL, "Sangfor", "深信服设备", 4.0),
    _s(Field.TITLE, "深信服", T.FIREWALL, "Sangfor", "深信服设备", 4.0),
    _s(Field.TITLE, "atrust", T.VPN, "Sangfor", "深信服 aTrust VPN", 5.0),
    _s(Field.TITLE, "小米路由器", T.ROUTER, "Xiaomi", "小米路由器", 8.0),
    _s(Field.TITLE, "ikuai", T.ROUTER, "iKuai", "爱快路由", 5.0),
    _s(Field.TITLE, "爱快", T.ROUTER, "iKuai", "爱快路由", 5.0),

    # ===== 国外安全 / 网络设备 =====
    _s(Field.SERVER, "fortigate", T.FIREWALL, "Fortinet", "FortiGate 防火墙", 5.0),
    _s(Field.SERVER, "fortiweb", T.WAF, "Fortinet", "FortiWeb WAF", 5.0),
    _s(Field.TITLE, "fortigate", T.FIREWALL, "Fortinet", "FortiGate 防火墙", 5.0),
    _s(Field.TITLE, "fortiweb", T.WAF, "Fortinet", "FortiWeb WAF", 5.0),
    _s(Field.TITLE, "cisco", T.NET_MGMT, "Cisco", "Cisco 设备", 3.5),
    _s(Field.TITLE, "palo alto", T.FIREWALL, "Palo Alto", "Palo Alto 防火墙", 5.0),
    _s(Field.TITLE, "globalprotect", T.VPN, "Palo Alto", "GlobalProtect VPN", 5.0),
    _s(Field.TITLE, "big-ip", T.LOAD_BALANCER, "F5", "F5 BIG-IP", 5.0),
    _s(Field.SERVER, "netscaler", T.LOAD_BALANCER, "Citrix", "Citrix NetScaler", 5.0),
    _s(Field.TITLE, "mikrotik", T.ROUTER, "MikroTik", "MikroTik 路由", 5.0),
    _s(Field.SERVER, "mikrotik", T.ROUTER, "MikroTik", "MikroTik RouterOS", 5.0),
    _s(Field.TITLE, "unifi", T.NET_MGMT, "Ubiquiti", "Ubiquiti UniFi", 5.0),
    _s(Field.TITLE, "openwrt", T.ROUTER, "OpenWrt", "OpenWrt 路由", 5.0),
    _s(Field.TITLE, "luci", T.ROUTER, "OpenWrt", "OpenWrt LuCI", 4.0),
    _s(Field.TITLE, "tp-link", T.ROUTER, "TP-Link", "TP-Link 设备", 4.0),
    _s(Field.TITLE, "zyxel", T.NET_MGMT, "Zyxel", "Zyxel 设备", 4.0),

    # ===== 中文通用设备名 =====
    _s(Field.TITLE, "防火墙", T.FIREWALL, "", "防火墙", 3.5),
    _s(Field.TITLE, "安全网关", T.FIREWALL, "", "安全网关", 3.5),
    _s(Field.TITLE, "上网行为", T.FIREWALL, "", "上网行为管理", 4.0),
    _s(Field.TITLE, "vpn", T.VPN, "", "VPN 网关", 3.0),
    _s(Field.TITLE, "交换机", T.SWITCH, "", "交换机", 3.5),
    _s(Field.TITLE, "路由器", T.ROUTER, "", "路由器", 3.5),
    _s(Field.TITLE, "负载均衡", T.LOAD_BALANCER, "", "负载均衡", 4.0),
    _s(Field.TITLE, "存储", T.STORAGE, "", "存储设备", 3.0),
    _s(Field.TITLE, "监控", T.MONITOR, "", "监控系统", 2.5),
    _s(Field.TITLE, "网关", T.ROUTER, "", "网关", 2.0),

    # ===== 摄像头 =====
    _s(Field.SERVER, "hikvision", T.CAMERA, "Hikvision", "海康威视", 5.0),
    _s(Field.SERVER, "dahua", T.CAMERA, "Dahua", "大华股份", 5.0),
    _s(Field.TITLE, "hikvision", T.CAMERA, "Hikvision", "海康威视", 5.0),
    _s(Field.TITLE, "大华", T.CAMERA, "Dahua", "大华股份", 5.0),
    _s(Field.TITLE, "uniview", T.CAMERA, "Uniview", "宇视科技", 5.0),

    # ===== Web / 应用平台 =====
    # 这些是**软件**，不是设备品牌：`Server: nginx` 只能说明"跑着 nginx"，
    # 不能说明这台设备是"nginx 牌的"。设备厂商交给标题/证书这类产品级证据。
    _s(Field.SERVER, "microsoft-iis", T.DOTNET, "", "Microsoft IIS", 5.0),
    _s(Field.SERVER, "tomcat", T.JAVA, "", "Apache Tomcat", 5.0),
    _s(Field.SERVER, "jetty", T.JAVA, "", "Jetty", 5.0),
    _s(Field.SERVER, "weblogic", T.JAVA, "", "WebLogic", 5.0),
    _s(Field.SERVER, "openresty", T.WEB, "", "OpenResty", 4.0),
    _s(Field.SERVER, "litespeed", T.WEB, "", "LiteSpeed", 4.0),
    _s(Field.SERVER, "caddy", T.WEB, "", "Caddy", 4.0),
    _s(Field.SERVER, "nginx", T.WEB, "", "nginx", 3.0),
    _s(Field.SERVER, "apache", T.WEB, "", "Apache httpd", 3.0),
    _s(Field.TITLE, "wordpress", T.CMS, "WordPress", "WordPress", 5.0),
    _s(Field.TITLE, "drupal", T.CMS, "Drupal", "Drupal", 5.0),
    _s(Field.TITLE, "joomla", T.CMS, "Joomla", "Joomla", 5.0),
    _s(Field.TITLE, "magento", T.CMS, "Adobe", "Magento", 5.0),
    _s(Field.TITLE, "typo3", T.CMS, "TYPO3", "TYPO3", 5.0),
    _s(Field.TITLE, "zabbix", T.MONITOR, "Zabbix", "Zabbix", 5.0),
    _s(Field.TITLE, "grafana", T.MONITOR, "Grafana", "Grafana", 5.0),
    _s(Field.TITLE, "prometheus", T.MONITOR, "Prometheus", "Prometheus", 5.0),
    _s(Field.TITLE, "nagios", T.MONITOR, "Nagios", "Nagios", 5.0),
    _s(Field.TITLE, "jenkins", T.DEVOPS, "Jenkins", "Jenkins", 5.0),
    _s(Field.TITLE, "gitlab", T.DEVOPS, "GitLab", "GitLab", 5.0),
    _s(Field.TITLE, "nexus", T.DEVOPS, "Sonatype", "Nexus", 5.0),
    _s(Field.TITLE, "confluence", T.DEVOPS, "Atlassian", "Confluence", 5.0),
    _s(Field.TITLE, "harbor", T.DEVOPS, "Harbor", "Harbor", 5.0),
    _s(Field.TITLE, "kubernetes", T.CONTAINER, "Kubernetes", "Kubernetes", 5.0),
    _s(Field.TITLE, "portainer", T.CONTAINER, "Portainer", "Portainer", 5.0),
    _s(Field.TITLE, "vcenter", T.CLOUD, "VMware", "VMware vCenter", 5.0),
    _s(Field.TITLE, "openstack", T.CLOUD, "OpenStack", "OpenStack", 5.0),
    _s(Field.TITLE, "nextcloud", T.FILE_SVC, "Nextcloud", "Nextcloud", 5.0),
    _s(Field.TITLE, "owncloud", T.FILE_SVC, "ownCloud", "ownCloud", 5.0),
    _s(Field.TITLE, "filezilla", T.FTP, "FileZilla", "FileZilla Server", 5.0),
    _s(Field.TITLE, "phpmyadmin", T.DB, "phpMyAdmin", "phpMyAdmin", 5.0),
    _s(Field.TITLE, "proxmox", T.CLOUD, "Proxmox", "Proxmox VE", 5.0),
    _s(Field.TITLE, "esxi", T.CLOUD, "VMware", "VMware ESXi", 4.5),
    _s(Field.TITLE, "vmware", T.CLOUD, "VMware", "VMware", 4.0),

    # ===== 技术栈（Cookie / 正文） =====
    _s(Field.COOKIE, "phpsessid", T.PHP, "", "PHP 会话", 5.0, "Set-Cookie 出现 PHPSESSID"),
    _s(Field.COOKIE, "think_lang", T.PHP, "", "ThinkPHP", 5.0),
    _s(Field.COOKIE, "jsessionid", T.JAVA, "", "Java 会话", 4.5),
    _s(Field.COOKIE, "asp.net_sessionid", T.DOTNET, "", ".NET 会话", 4.5),
    _s(Field.COOKIE, "laravel_session", T.PHP, "", "Laravel", 5.0),
    _s(Field.BODY, "powered by php", T.PHP, "", "PHP", 4.0),
    _s(Field.BODY, "thinkphp", T.PHP, "", "ThinkPHP", 4.5),

    # ===== 协议 banner =====
    _s(Field.BANNER, "ssh-2.0-openssh", T.LINUX, "", "Linux (OpenSSH)", 3.0),
    _s(Field.BANNER, "openssh", T.LINUX, "", "Linux (OpenSSH)", 2.5),
    _s(Field.BANNER, "ubuntu", T.LINUX, "Ubuntu", "Ubuntu Linux", 3.5),
    _s(Field.BANNER, "debian", T.LINUX, "Debian", "Debian Linux", 3.5),
    _s(Field.BANNER, "centos", T.LINUX, "CentOS", "CentOS Linux", 3.5),
    _s(Field.BANNER, "raspbian", T.IOT, "Raspbian", "Raspberry Pi OS", 4.0),
    _s(Field.BANNER, "busybox", T.IOT, "BusyBox", "嵌入式 Linux", 3.5),
    _s(Field.BANNER, "dropbear", T.IOT, "Dropbear", "嵌入式设备 (Dropbear SSH)", 3.5),
    _s(Field.BANNER, "filezilla", T.FTP, "FileZilla", "FileZilla Server", 4.0),
    _s(Field.BANNER, "vsftpd", T.FTP, "", "vsftpd", 4.0),
    _s(Field.BANNER, "proftpd", T.FTP, "", "ProFTPD", 4.0),
    _s(Field.BANNER, "microsoft ftp", T.WINDOWS, "Microsoft", "Windows FTP", 4.0),
    _s(Field.BANNER, "postfix", T.MAIL, "Postfix", "Postfix 邮件服务", 4.0),
    _s(Field.BANNER, "exim", T.MAIL, "Exim", "Exim 邮件服务", 4.0),

    # ===== 认证域 =====
    _s(Field.WWW_AUTH, "fortigate", T.FIREWALL, "Fortinet", "FortiGate 防火墙", 5.0),
    _s(Field.WWW_AUTH, "cisco", T.NET_MGMT, "Cisco", "Cisco 设备", 4.0),
    _s(Field.WWW_AUTH, "tomcat", T.JAVA, "Apache", "Apache Tomcat", 5.0),
)


#: 端口画像（信号弱，仅在没有标签/证书特征时兜底）
PORT_SIGNATURES = (
    ("9100,515,631", T.PRINTER, "打印设备"),
    ("25,110,143", T.MAIL, ""),
    ("445", T.WINDOWS, "Windows"),
    ("3389", T.WINDOWS, "Windows"),
    ("22", T.LINUX, ""),
    ("23", T.NET_MGMT, ""),
    ("161", T.NET_MGMT, ""),
    ("2049", T.LINUX, "NFS"),
    ("6379", T.DB, "Redis"),
    ("5432", T.DB, "PostgreSQL"),
    ("3306", T.DB, "MySQL"),
    ("27017", T.DB, "MongoDB"),
    ("9200", T.DB, "Elasticsearch"),
    ("11211", T.DB, "Memcached"),
    ("5985", T.WINDOWS, "CouchDB"),
    ("2375", T.CONTAINER, "Docker"),
    ("10250", T.CONTAINER, "Kubernetes"),
)


def find_signatures(field: str, value: str) -> list[Sig]:
    """在某个字段里查找所有命中的签名。"""
    if not value:
        return []
    low = value.lower()
    return [s for s in SIGNATURES if s.field == field and s.needle in low]



# ==========================================================================
# 应用指纹（CMS / 框架 / 面板）
#
# 这类指纹的价值：把"这是 PHP 站点"升级为"这是 WordPress 6.2"，
# 客户才知道该打哪个补丁、该查哪个插件。全部来自页面自报信息（generator/title/cookie/path），
# 属产品级证据，不会被服务级标识冒充。
# ==========================================================================

APP_SIGNATURES: list[Sig] = [
    # WordPress：generator 会写版本，cookie 有 wordpress_ 前缀
    _s(Field.META, "wordpress", T.WEBAPP, "WordPress", "WordPress", 8.0),
    _s(Field.BODY, "wp-content/", T.WEBAPP, "WordPress", "WordPress", 6.0),
    _s(Field.COOKIE, "wordpress_", T.WEBAPP, "WordPress", "WordPress", 6.5),
    _s(Field.TITLE, "wordpress", T.WEBAPP, "WordPress", "WordPress", 6.0),
    # Discuz / 帝国 / 织梦
    _s(Field.META, "discuz", T.WEBAPP, "Discuz!", "Discuz!", 8.0),
    _s(Field.BODY, "discuz_uid", T.WEBAPP, "Discuz!", "Discuz!", 6.5),
    _s(Field.META, "dedecms", T.WEBAPP, "DedeCMS", "DedeCMS", 8.0),
    _s(Field.META, "empirecms", T.WEBAPP, "帝国CMS", "帝国CMS", 8.0),
    # 框架
    _s(Field.META, "thinkphp", T.WEBAPP, "ThinkPHP", "ThinkPHP", 8.0),
    _s(Field.BODY, "thinkphp", T.WEBAPP, "ThinkPHP", "ThinkPHP", 6.0),
    _s(Field.COOKIE, "laravel_session", T.WEBAPP, "Laravel", "Laravel", 7.0),
    _s(Field.META, "laravel", T.WEBAPP, "Laravel", "Laravel", 7.5),
    _s(Field.META, "yii", T.WEBAPP, "Yii", "Yii", 6.0),
    _s(Field.COOKIE, "ci_session", T.WEBAPP, "CodeIgniter", "CodeIgniter", 6.0),
    _s(Field.META, "symfony", T.WEBAPP, "Symfony", "Symfony", 7.5),
    _s(Field.META, "drupal", T.WEBAPP, "Drupal", "Drupal", 8.0),
    _s(Field.COOKIE, "drupal", T.WEBAPP, "Drupal", "Drupal", 6.5),
    _s(Field.META, "joomla", T.WEBAPP, "Joomla", "Joomla", 8.0),
    # 组件与面板
    _s(Field.TITLE, "phpmyadmin", T.WEBAPP, "phpMyAdmin", "phpMyAdmin", 8.5),
    _s(Field.COOKIE, "phpmyadmin", T.WEBAPP, "phpMyAdmin", "phpMyAdmin", 7.0),
    _s(Field.TITLE, "adminer", T.WEBAPP, "Adminer", "Adminer", 8.0),
    _s(Field.TITLE, "nextcloud", T.WEBAPP, "Nextcloud", "Nextcloud", 8.5),
    _s(Field.TITLE, "宝塔", T.WEBAPP, "宝塔面板", "宝塔面板", 8.5),
    _s(Field.META, "宝塔", T.WEBAPP, "宝塔面板", "宝塔面板", 8.0),
    _s(Field.TITLE, "typecho", T.WEBAPP, "Typecho", "Typecho", 8.0),
    _s(Field.TITLE, "zabbix", T.WEBAPP, "Zabbix", "Zabbix", 8.5),
]

# 合并应用指纹：按 (字段, 特征, 类型, 厂商, 产品) 去重，避免与已有签名重复
def _merge_app_signatures(base, extra):
    # 同 (字段, 特征) 只保留一条：测试与识别逻辑都要求 needle 唯一，
    # 重复会让同一特征产生两个竞争结论。
    seen = {(x.field, x.needle) for x in base}
    out = list(base)
    for sig in extra:
        key = (sig.field, sig.needle)
        if key not in seen:
            seen.add(key)
            out.append(sig)
    return tuple(out)


SIGNATURES = _merge_app_signatures(SIGNATURES, APP_SIGNATURES)

# ==========================================================================
# 扩展签名库（打印/存储/带外/虚拟化/DevOps/国产安全设备）
# 放在文件末尾导入，避免与 signatures_extra 的循环导入问题。
# ==========================================================================
from .signatures_extra import (  # noqa: E402
    EXTRA_LABELS,
    EXTRA_PORT_SIGNATURES,
    EXTRA_SIGNATURES,
)

SIGNATURES = _merge_app_signatures(SIGNATURES, EXTRA_SIGNATURES)
PORT_SIGNATURES = tuple(PORT_SIGNATURES) + tuple(EXTRA_PORT_SIGNATURES)
TYPE_LABELS.update(EXTRA_LABELS)
