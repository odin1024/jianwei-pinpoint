"""IOC（失陷指标）库与匹配器。

数据来源：
  - TU Delft INTELLAB php2shell 实时观测面板（蜜罐捕获的 dropper URL 与落地样本）
  - NCSC-NL/php2shell 运营情报仓库
  - CISA KEV 目录
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Optional

#: 攻击者基础设施（IP）
IOC_IPS: tuple[str, ...] = (
    "45.74.7.227",
    "176.65.139.153",
    "217.60.102.5",
    "92.118.112.100",
    "217.15.162.38",
    "87.251.64.204",
    "185.225.191.232",
    "191.217.250.227",
    "45.115.26.26",
)

#: dropper / 落地托管
IOC_DOMAINS: tuple[str, ...] = (
    "hana.by",
    "pastebin.com",
    "webhook.site",
)

#: 完整 URL（含路径与参数）
IOC_URLS: tuple[str, ...] = (
    "http://45.74.7.227/collect/p2srun.php",
    "http://176.65.139.153/wget.sh",
    "https://217.60.102.5/sh",
    "https://pastebin.com/raw/wCYGVCBG",
    "http://92.118.112.100/p",
    "http://92.118.112.100/s",
    "http://92.118.112.100/nfs",
    "http://217.15.162.38:27182/",
    "http://87.251.64.204:7716/i",
    "http://185.225.191.232/c",
    "http://191.217.250.227:8081/b.php",
    "http://45.115.26.26:8000/cCmono",
    "http://45.115.26.26:8000/cClar",
    "https://webhook.site/0e7f04d6-7839-40d6-963e-a6d7744a4cd3",
)

#: 恶意样本 SHA-256
IOC_HASHES: dict[str, str] = {
    "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486":
        "nfs — Mirai 衍生 DDoS 机器人，加密 C2 + Ethereum ENS 备份",
    "7d9965deae0d3d9834a1299e98ce901329ae071f8744f97746137ea033f100a9":
        "x86_64(2) — Mirai 变种 2.0.4_socks5",
    "a5289abece66fbaf33a6186f315fb6901658e8551c68933e56e65838b95fc3af":
        "cb — Nim 植入体 crong3-agent，伪装 sysmon，ENS + Solana 取 C2",
    "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987":
        "f0aa — 未定性样本，DoT DNS 查询",
}

#: 扫描器 User-Agent 特征
IOC_USER_AGENTS: tuple[str, ...] = (
    "php2shell-scan",
    "p2srun",
)

#: webshell / 后门代码特征
WEBSHELL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"eval\s*\(\s*base64_decode", "eval(base64_decode(...)) 经典 webshell"),
    (r"assert\s*\(\s*base64_decode", "assert(base64_decode(...)) webshell"),
    (r"eval\s*\(\s*\$_(?:POST|GET|REQUEST)", "eval($_POST[...]) webshell"),
    (r"system\s*\(\s*\$_", "system($_...) 后门"),
    (r"shell_exec\s*\(\s*\$_(?:POST|GET|REQUEST)", "shell_exec 后门"),
    (r"passthru\s*\(\s*\$_", "passthru 后门"),
    (r"preg_replace\s*\(\s*['\"].*?/e['\"]", "preg_replace /e 代码执行"),
    (r"\$_=.{0,40}\bphpinfo\b", "phpinfo 探针"),
    (r"c2VjbmV0X2lkX3Rlc3Rpb25z", "base64('secret_id_tests') 泄露测试串"),
)

#: 需要重点关注的进程伪装名（已知攻击样本）
SUSPICIOUS_PROCESS_NAMES: tuple[str, ...] = (
    "sysmon",       # Nim 植入体 crong3-agent 伪装
    "crong3-agent",
)


@dataclass
class IocMatch:
    """一次 IOC 命中。"""

    ioc_type: str
    value: str
    severity: str
    source: str
    context: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IocLibrary:
    """IOC 库快照。"""

    ips: tuple[str, ...] = IOC_IPS
    domains: tuple[str, ...] = IOC_DOMAINS
    urls: tuple[str, ...] = IOC_URLS
    hashes: dict[str, str] = field(default_factory=lambda: dict(IOC_HASHES))
    user_agents: tuple[str, ...] = IOC_USER_AGENTS

    def summary(self) -> dict:
        return {
            "ips": len(self.ips),
            "domains": len(self.domains),
            "urls": len(self.urls),
            "hashes": len(self.hashes),
            "user_agents": len(self.user_agents),
            "source": "TU Delft INTELLAB / NCSC-NL / CISA KEV",
            "updated": "2026-10-29",
        }

    def match_text(self, text: str, *, context: str = "") -> list[IocMatch]:
        """在任意文本（日志行、命令行、文件内容）中匹配 IOC。"""
        out: list[IocMatch] = []
        if not text:
            return out
        low = text.lower()
        for ip in self.ips:
            if ip in low:
                out.append(IocMatch("ip", ip, "high", "TU Delft", context))
        for dom in self.domains:
            if dom in low:
                out.append(IocMatch("domain", dom, "medium", "TU Delft", context))
        for url in self.urls:
            if url.lower() in low:
                out.append(IocMatch("url", url, "critical", "TU Delft", context))
        for ua in self.user_agents:
            if ua.lower() in low:
                out.append(IocMatch("user_agent", ua, "medium", "TU Delft", context))
        for h, desc in self.hashes.items():
            if h.lower() in low:
                out.append(IocMatch("sha256", h, "critical", "TU Delft", f"{desc} | {context}"))
        return out

    def match_hash(self, digest: str) -> Optional[IocMatch]:
        d = (digest or "").lower()
        if d in self.hashes:
            return IocMatch("sha256", d, "critical", "TU Delft", self.hashes[d])
        return None

    def match_user_agent(self, ua: str) -> Optional[IocMatch]:
        low = (ua or "").lower()
        for pat in self.user_agents:
            if pat.lower() in low:
                return IocMatch("user_agent", pat, "medium", "TU Delft", ua[:200])
        return None


def scan_webshell(content: str) -> list[tuple[str, str]]:
    """检测 webshell / 后门代码特征，返回 [(名称, 证据)] 列表。"""
    hits = []
    for pattern, label in WEBSHELL_PATTERNS:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            start = max(0, m.start() - 30)
            hits.append((label, content[start:m.end() + 30].replace("\n", " ")[:160]))
    return hits


def match_iocs_in_lines(lines: Iterable[str], lib: IocLibrary | None = None) -> list[IocMatch]:
    lib = lib or IocLibrary()
    out: list[IocMatch] = []
    for line in lines:
        out.extend(lib.match_text(line))
    return out
