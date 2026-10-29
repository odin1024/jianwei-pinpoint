import pathlib

p = pathlib.Path(r"C:\Users\<用户名>\Documents\Codex\2026-10-29\zui\php2shell-sentinel\src\p2s\core\discovery.py")
t = p.read_text(encoding="utf-8")

# probe_http 支持 quick（只打一个路径）
t = t.replace(
    "    paths: tuple[str, ...] = PATH_LADDER,\n) -> Optional[Service]:",
    "    paths: tuple[str, ...] = PATH_LADDER,\n    quick: bool = False,\n) -> Optional[Service]:",
)
t = t.replace(
    '    deadline = time.monotonic() + max(timeout * 2.5, 12.0)',
    '    if quick:\n        paths = ("/",)\n    deadline = time.monotonic() + max(timeout * 2.5, 12.0)',
)

# _probe_port 感知 deep
t = t.replace(
    "    def _probe_port(p: int) -> Optional[Service]:\n        \"\"\"探测单个端口的服务，返回 Service（失败返回 None）。\"\"\"\n        if p == 22:",
    "    def _probe_port(p: int) -> Optional[Service]:\n        \"\"\"探测单个端口的服务，返回 Service（失败返回 None）。\"\"\"\n        fast = not deep\n        if p == 22:",
)
t = t.replace(
    "            svc = probe_http(host, p, https=True, timeout=http_timeout)\n            if svc is None:\n                return None\n            subject, issuer, san, expired = _tls_info(host, p, timeout=http_timeout)",
    "            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast)\n            if svc is None:\n                return None\n            if fast:\n                return svc\n            subject, issuer, san, expired = _tls_info(host, p, timeout=http_timeout)",
)
t = t.replace(
    "            svc = probe_http(host, p, https=True, timeout=http_timeout)\n            if svc is None:\n                return None\n            if svc.http_status in (400, 404, 405, 501)",
    "            svc = probe_http(host, p, https=True, timeout=http_timeout, quick=fast)\n            if svc is None:\n                return None\n            if fast:\n                return svc\n            if svc.http_status in (400, 404, 405, 501)",
)
t = t.replace(
    "        if p in WEB_HTTP_PORTS:\n            return probe_http(host, p, https=False, timeout=http_timeout)",
    "        if p in WEB_HTTP_PORTS:\n            return probe_http(host, p, https=False, timeout=http_timeout, quick=fast)",
)

# 快速模式下缩减端口扫描范围
t = t.replace(
    "    port_list = list(ports) if ports is not None else list(FULL_PORT_SET)",
    "    if ports is not None:\n        port_list = list(ports)\n    elif not deep:\n        port_list = list(FAST_PORT_SET)\n    else:\n        port_list = list(FULL_PORT_SET)",
)

# 定义快速端口表
t = t.replace(
    "#: 完整端口表 = 通用 + 设备专属（去重排序）",
    """#: 快速模式端口表：只保留最常见的服务端口
FAST_PORT_SET: tuple[int, ...] = (
    22, 80, 443, 445, 3389, 3306, 5432, 6379, 8080, 8443, 8888, 9090,
    2000, 8000, 10000, 8081, 8088, 9000, 3000, 4243,
)

#: 完整端口表 = 通用 + 设备专属（去重排序）""",
)

p.write_text(t, encoding="utf-8")
print("discovery.py: 快速模式已加入")