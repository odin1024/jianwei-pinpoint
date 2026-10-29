import pathlib

p = pathlib.Path(r"C:\Users\<用户名>\Documents\Codex\2026-10-29\zui\php2shell-sentinel\src\p2s\core\discovery.py")
t = p.read_text(encoding="utf-8")

# ---- 1) 收敛 UA / 路径阶梯：只在失败时升级，且限制每端口总耗时 ----
old = '''    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        for ua in UA_LADDER:
            for path in paths:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    resp = client.get(url, headers={"User-Agent": ua, "Accept": "*/*"})
                except Exception as exc:  # noqa: BLE001
                    svc.banner = f"{type(exc).__name__}: {str(exc)[:120]}"
                    return svc
                if best is None or (resp.status_code in _OK_STATUS and best.status_code not in _OK_STATUS):
                    best, best_path = resp, path
                if resp.status_code in _OK_STATUS:
                    best, best_path = resp, path
                    break
            if best is not None and best.status_code in _OK_STATUS:
                break'''
new = '''    deadline = time.monotonic() + max(timeout * 2.5, 12.0)
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        for ua in UA_LADDER:
            for path in paths:
                if time.monotonic() > deadline:
                    break
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    resp = client.get(url, headers={"User-Agent": ua, "Accept": "*/*"})
                except Exception as exc:  # noqa: BLE001
                    svc.banner = f"{type(exc).__name__}: {str(exc)[:120]}"
                    if best is None:
                        return svc
                    continue
                if best is None or (resp.status_code in _OK_STATUS and best.status_code not in _OK_STATUS):
                    best, best_path = resp, path
                if resp.status_code in _OK_STATUS:
                    break
            # 拿到可用响应就收工；只有全部路径都失败才换 UA 重试
            if best is not None and best.status_code in _OK_STATUS:
                break
            if best is not None and best.status_code not in (404, 400, 403, 405, 501):
                break'''
assert old in t
t = t.replace(old, new)

# 路径阶梯缩短
t = t.replace(
    'PATH_LADDER: tuple[str, ...] = ("/", "/index.html", "/login", "/cgi-bin/", "/webui/", "/ui/")',
    'PATH_LADDER: tuple[str, ...] = ("/", "/index.html", "/login")',
)

# ---- 2) 端口服务探测并行化 ----
old_flow = '''    # 服务识别
    services: list[Service] = []
    for p in open_ports:
        if p in (22,):'''
new_flow = '''    # 服务识别（各端口并行，避免一台多端口设备串行等待）
    def _probe_port(p: int) -> Optional[Service]:
        if p in (22,):'''
assert old_flow in t
t = t.replace(old_flow, new_flow)

old_tail = '''        else:
            services.append(probe_banner(host, p, timeout=min(http_timeout, 4.0)))
    prof.services = [s for s in services if s is not None]'''
new_tail = '''        else:
            return probe_banner(host, p, timeout=min(http_timeout, 4.0))
        return None

    with ThreadPoolExecutor(max_workers=min(12, max(1, len(open_ports)))) as ex:
        futs = {ex.submit(_probe_port, p): p for p in open_ports}
        for f in as_completed(futs):
            try:
                svc = f.result()
            except Exception:
                svc = None
            if svc is not None:
                services.append(svc)
    services.sort(key=lambda s: s.port)
    prof.services = [s for s in services if s is not None]'''
assert old_tail in t
t = t.replace(old_tail, new_tail)

# services 列表初始化要在并行块之前
t = t.replace(
    "    # 服务识别（各端口并行，避免一台多端口设备串行等待）\n    def _probe_port(p: int) -> Optional[Service]:",
    "    # 服务识别（各端口并行，避免一台多端口设备串行等待）\n    services: list[Service] = []\n\n    def _probe_port(p: int) -> Optional[Service]:",
)

# ---- 3) 需要 time 与 ThreadPoolExecutor ----
t = t.replace("import ssl\n", "import ssl\nimport time\n")

p.write_text(t, encoding="utf-8")
print("discovery.py: 端口并行 + 阶梯收敛 已完成")