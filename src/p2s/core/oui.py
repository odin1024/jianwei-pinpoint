"""MAC 地址 → 厂商（OUI 查询）。

数据来源：
  1. 读取本机 ARP / 邻居表拿到 IP → MAC 映射（同网段最有效）
  2. 内置精简 OUI 表做厂商解析（可扩展）

为什么值得做：
  在同网段场景下，MAC 的 OUI 往往能一眼看出设备厂商，
  比任何端口或 HTTP 特征都直接 —— 例如 8c:1c:da 是深信服。
"""
from __future__ import annotations

import platform
import re
import subprocess
from typing import Optional

IS_WINDOWS = platform.system() == "Windows"

#: 精简 OUI 表（IEEE 前 24 位 → 厂商）。覆盖主流网络/安全设备与虚拟化厂商。
#: 可通过 p2s oui --update 或直接编辑本表扩展。
OUI_TABLE: dict[str, str] = {
    "00:00:0c": "Cisco",
    "00:03:93": "Sun Microsystems",
    "00:05:69": "VMware",
    "00:09:0f": "Fortinet",
    "00:09:49": "Allied Telesis",
    "00:0c:29": "VMware",
    "00:0d:48": "Hewlett Packard",
    "00:0f:4d": "Alcatel",
    "00:12:34": "Cameo Communications",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen / Citrix",
    "00:1a:2b": "Ayecom",
    "00:1b:78": "Hewlett Packard",
    "00:1c:42": "Parallels",
    "00:1e:c0": "Micro-Star International",
    "00:24:01": "D-Link",
    "00:26:08": "Hewlett Packard",
    "00:50:56": "VMware",
    "00:80:9f": "Antec",
    "08:00:27": "VirtualBox",
    "0c:42:a1": "Alibaba Cloud",
    "18:40:43": "Tyan",
    "1c:7d:22": "海康威视",
    "2c:f0:5d": "Intel / 服务器网卡",
    "3c:15:f2": "Apple",
    "3c:37:86": "Netgear",
    "44:38:39": "Cumulus Networks",
    "48:ea:63": "Aruba Networks",
    "4c:1f:cc": "Hangzhou Hikvision",
    "54:bf:64": "Hangzhou Hikvision",
    "64:90:c1": "Chongqing / 网络设备",
    "70:56:81": "Apple",
    "74:ac:b9": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "8c:1c:da": "深信服 Sangfor",
    "9c:8e:cd": "Apple",
    "a4:2b:b0": "Tp-Link",
    "b0:be:76": "Tp-Link",
    "bc:ad:28": "Hangzhou Hikvision",
    "c0:56:e3": "Hangzhou Hikvision",
    "d4:35:38": "",
    "e4:5f:01": "Raspberry Pi Foundation",
    "fc:44:82": "",
    "fc:ec:da": "Ubiquiti",
    "00:d8:61": "",
    "04:7c:16": "",
    "38:d5:47": "",
    "3c:15:fb": "",
}


def normalize_mac(mac: str) -> str:
    """把各种 MAC 写法统一成 aabbccddeeff 的小写形式。"""
    if not mac:
        return ""
    hexs = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexs) != 12:
        return ""
    return hexs.lower()


def oui_of(mac: str) -> str:
    """取 MAC 的 OUI（前 3 字节）。"""
    h = normalize_mac(mac)
    return f"{h[:2]}:{h[2:4]}:{h[4:6]}" if h else ""


def lookup(mac: str) -> Optional[str]:
    """OUI → 厂商名。"""
    oui = oui_of(mac)
    if not oui:
        return None
    return OUI_TABLE.get(oui)


def read_arp_table() -> dict[str, str]:
    """读取本机 ARP / 邻居表，返回 {IP: MAC}。

    Windows: `arp -a`；Linux: `ip neigh`；macOS: `arp -a`。
    """
    out: dict[str, str] = {}
    cmds: list[list[str]] = []
    if IS_WINDOWS:
        cmds = [["arp", "-a"], ["Get-NetNeighbor", "-AddressFamily", "IPv4"]]
    else:
        cmds = [["ip", "neigh"], ["arp", "-n"], ["arp", "-a"]]
    for cmd in cmds:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, errors="replace")
        except Exception:
            continue
        text = (p.stdout or "") + (p.stderr or "")
        for line in text.splitlines():
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", line)
            if m:
                out.setdefault(m.group(1), normalize_mac(m.group(2)))
                continue
            # ip neigh 格式：192.168.1.1 dev eth0 lladdr 8c:1c:da:45:25:68 REACHABLE
            m2 = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m2:
                out.setdefault(m2.group(1), normalize_mac(m2.group(2)))
        if out:
            break
    return out


def vendor_for_ip(ip: str, arp: dict[str, str] | None = None) -> tuple[Optional[str], Optional[str]]:
    """返回 (MAC, 厂商名)。"""
    arp = arp if arp is not None else read_arp_table()
    mac = arp.get(ip)
    if not mac:
        return None, None
    return mac, lookup(mac)
