"""D3 主机事实采集

两种模式：
    local  —— 直接在本机执行只读命令（可测、无依赖）
    ssh    —— 远程执行（需 paramiko；缺失时明确降级，不静默跳过）

设计要点（03 文档 5.1）：
    CLI 的 PHP ≠ Web 的 PHP。必须用 /proc/<pid>/exe 或 apache 模块列表
    锁定「Web 实际加载的二进制」，否则会得出错误的「已修复」结论。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from ..models import Confidence, DetectionContext, DetectionResult, Evidence
from .d1_passive import parse_phpinfo_text, normalize_sapi

CVE_RE = re.compile(r"CVE-2026-10961[89]", re.I)
MAX_OUT = 256 * 1024

# 只读命令集（绝不包含任何写操作）
LOCAL_COMMANDS: list[tuple[str, str]] = [
    ("php_binary", "command -v php || true"),
    ("php_version", "php -v 2>&1 | head -2"),
    ("php_ini", "php --ini 2>&1 | head -5"),
    ("php_sapi", "php -r 'echo PHP_SAPI;' 2>&1 || true"),
    ("apache_modules", "apachectl -M 2>/dev/null | grep -i php || httpd -M 2>/dev/null | grep -i php || true"),
    ("fpm_listen", "ls -l /run/php/*.sock /var/run/php/*.sock 2>/dev/null || true"),
    ("php_procs", "ps -eo pid,ppid,lstart,cmd 2>/dev/null | grep -E 'php-fpm|php-cgi|frankenphp' | grep -v grep || true"),
    ("apache_loaded", "ps -eo pid,cmd 2>/dev/null | grep -E 'apache2|httpd' | grep -v grep | head -3 || true"),
    ("pkg_owner", "for b in $(command -v php php-fpm php-cgi 2>/dev/null); do rpm -qf $b 2>/dev/null || dpkg -S $b 2>/dev/null || true; done"),
    ("changelog_rpm", "for p in php php-common php-cli php-fpm; do rpm -q --changelog $p 2>/dev/null | grep -nE 'CVE-2026-10961[89]' && echo \"P2S_MATCH:$p\"; done 2>/dev/null || true"),
    ("changelog_dpkg", "for d in /usr/share/doc/php*-common /usr/share/doc/php*; do [ -f $d/changelog.Debian.gz ] && zcat $d/changelog.Debian.gz 2>/dev/null | grep -nE 'CVE-2026-10961[89]' && echo \"P2S_MATCH:$d\"; done 2>/dev/null || true"),
    ("changelog_apk", "apk info -a php* 2>/dev/null | grep -iE 'CVE-2026-10961[89]' || true"),
    ("service_state", "systemctl show php*-fpm -p Id,ActiveEnterTimestamp 2>/dev/null || true"),
    ("os_release", "cat /etc/os-release 2>/dev/null | head -4"),
    ("container", "ls /.dockerenv 2>/dev/null; grep -m1 -o 'docker\\|kubepods' /proc/1/cgroup 2>/dev/null || true"),
]


@dataclass
class CmdResult:
    label: str
    cmd: str
    out: str
    err: str
    code: int


def _run_local(cmd: str, timeout: int = 30) -> CmdResult:
    shell_cmd = cmd
    if os.name == "nt":
        # Windows 下用 cmd 执行，且把常见的 unix 命令替换成可用的等价形式
        shell_cmd = _win_rewrite(cmd)
    try:
        p = subprocess.run(
            shell_cmd if os.name != "nt" else shell_cmd,
            shell=True, capture_output=True, timeout=timeout,
            text=False,
        )
        out = (p.stdout or b"")[:MAX_OUT].decode("utf-8", errors="replace")
        err = (p.stderr or b"")[:4096].decode("utf-8", errors="replace")
        return CmdResult("", cmd, out, err, p.returncode)
    except subprocess.TimeoutExpired:
        return CmdResult("", cmd, "", "timeout", -1)
    except Exception as e:  # noqa: BLE001
        return CmdResult("", cmd, "", str(e), -1)


def _win_rewrite(cmd: str) -> str:
    """Windows 上只保留能跑的命令，其余返回空。"""
    if cmd.strip().startswith("php -v"):
        return "php -v"
    if cmd.strip().startswith("php --ini"):
        return "php --ini"
    if cmd.strip().startswith("php -r"):
        return "php -r \"echo PHP_SAPI;\""
    if cmd.strip().startswith("php -i"):
        return "php -i"
    if cmd.strip() == "command -v php || true":
        return "where php"
    return "echo"  # 其余在 Windows 上无意义


def collect_phpinfo_evidence(text: str, source_label: str) -> list[Evidence]:
    info = parse_phpinfo_text(text)
    evs: list[Evidence] = []
    if not info:
        return evs

    v = info.get("php version")
    if v:
        evs.append(Evidence("D3", "version", "php.version", v, Confidence.CONFIRMED,
                            "php -i 输出的 PHP Version（本机事实）",
                            "version_local", source_label))
    api = info.get("server api")
    if api:
        evs.append(Evidence("D3", "sapi", "php.sapi", normalize_sapi(api),
                            Confidence.CONFIRMED, f"php -i Server API = {api}",
                            "sapi", source_label))
    if info.get("build date"):
        evs.append(Evidence("D3", "version", "php.build_date", info["build date"],
                            Confidence.CONFIRMED, "php -i Build Date",
                            "version_local", source_label))
    if info.get("configure command"):
        evs.append(Evidence("D3", "version", "php.configure_command",
                            info["configure command"][:400], Confidence.HIGH,
                            "php -i Configure Command（判断是否发行版/自编译）",
                            "version_local", source_label))
    for k in ("memory_limit", "post_max_size", "max_file_uploads",
              "max_input_nesting_level", "session.upload_progress.enabled",
              "enable_post_data_reading", "fatal_error_backtraces",
              "expose_php", "open_basedir"):
        if k in info:
            evs.append(Evidence("D3", "ini", f"ini.{k}", info[k], Confidence.CONFIRMED,
                                f"php -i {k}", "ini", source_label))
    return evs


def run(ctx: DetectionContext, mode: str = "local",
        ssh_conf: dict | None = None) -> DetectionResult:
    res = DetectionResult(detector="D3")

    if mode == "ssh":
        return _run_ssh(ctx, ssh_conf or {}, res)
    return _run_local_mode(ctx, res)


def _run_local_mode(ctx: DetectionContext, res: DetectionResult) -> DetectionResult:
    php = shutil.which("php")
    if not php:
        res.err("本机未找到 php 命令（--local 模式需要本机安装 PHP）")
        res.notes.append("本机无 PHP，跳过主机核查；如需远程核查请使用 --host 提供 SSH 凭证")
        return res

    res.notes.append(f"本机 PHP 路径：{php}")
    ver = _run_local("php -v")
    m = re.search(r"PHP\s+([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+~]*)", ver.out)
    if m:
        res.add(Evidence("D3", "version", "php.version", m.group(1), Confidence.CONFIRMED,
                         "php -v（本机 CLI 二进制）", "version_local", "php -v"))
        res.notes.append(
            "注意：CLI 版本不等于 Web 实际运行的版本；若本机同时跑 Apache/FPM，需单独核对"
        )

    ini = _run_local("php -i")
    if ini.out:
        for ev in collect_phpinfo_evidence(ini.out, "php -i"):
            res.add(ev)

    # 包管理归属与 changelog
    for label, cmd in LOCAL_COMMANDS:
        if label not in ("pkg_owner", "changelog_rpm", "changelog_dpkg",
                         "changelog_apk", "service_state", "apache_modules",
                         "fpm_listen", "php_procs"):
            continue
        r = _run_local(cmd)
        if CVE_RE.search(r.out):
            pkg = ""
            mm = re.search(r"P2S_MATCH:(\S+)", r.out)
            if mm:
                pkg = mm.group(1)
            res.add(Evidence("D3", "changelog", "php.patch_status",
                             {"patched": True, "source": label, "package": pkg},
                             Confidence.CONFIRMED,
                             f"包 changelog 命中 CVE 编号（{label}）",
                             "changelog", _first_match_line(r.out)))
            res.notes.append(f"✓ 包 {pkg or label} 的 changelog 包含 CVE-2026-10961x，已回移补丁")
            break
        elif r.out.strip() and label.startswith("changelog"):
            res.add(Evidence("D3", "changelog", "php.patch_status",
                             {"patched": False, "source": label},
                             Confidence.HIGH,
                             f"包 changelog 未命中 CVE 编号（{label}）",
                             "changelog", r.out.strip()[:200]))

    # worker 启动时间（判断补丁是否生效）
    r = _run_local("ps -eo pid,lstart,cmd 2>/dev/null | grep -E 'php-fpm|apache2|httpd' | grep -v grep | head -3")
    if r.out.strip():
        res.add(Evidence("D3", "process", "php.workers", r.out.strip()[:600],
                         Confidence.MEDIUM, "进程启动时间快照",
                         "process", "ps -eo pid,lstart,cmd"))
        res.notes.append("已采集 worker 启动时间：补丁后若 worker 未重启，配置不生效")

    return res


def _first_match_line(text: str) -> str:
    for line in text.splitlines():
        if CVE_RE.search(line):
            return line.strip()[:300]
    return text.strip()[:200]


def _run_ssh(ctx: DetectionContext, conf: dict, res: DetectionResult) -> DetectionResult:
    try:
        import paramiko  # type: ignore
    except ImportError:
        res.err("SSH 模式需要 paramiko，当前环境未安装：pip install paramiko")
        res.notes.append("可先用 --local 模式验证逻辑，或安装 paramiko 后重试")
        return res

    host = conf.get("host") or ""
    user = conf.get("user") or "root"
    port = int(conf.get("port") or 22)
    password = conf.get("password")
    key_path = conf.get("key")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=user,
            password=password,
            key_filename=key_path,
            timeout=ctx.timeout, banner_timeout=ctx.timeout,
            auth_timeout=ctx.timeout, allow_agent=False, look_for_keys=False,
        )
    except Exception as e:  # noqa: BLE001
        res.err(f"SSH 连接失败：{type(e).__name__}: {e}")
        return res

    try:
        for label, cmd in LOCAL_COMMANDS:
            if label in ("container",):
                continue
            try:
                _stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                out = stdout.read()[:MAX_OUT].decode("utf-8", errors="replace")
                stdout.channel.recv_exit_status()
            except Exception as e:  # noqa: BLE001
                res.err(f"{label} 执行失败：{e}")
                continue

            if label == "php_version":
                m = re.search(r"PHP\s+([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+~]*)", out)
                if m:
                    res.add(Evidence("D3", "version", "php.version", m.group(1),
                                     Confidence.CONFIRMED,
                                     "远程 php -v", "version_local", f"{host}:php -v"))
            elif label in ("changelog_rpm", "changelog_dpkg", "changelog_apk"):
                if CVE_RE.search(out):
                    pkg = ""
                    mm = re.search(r"P2S_MATCH:(\S+)", out)
                    if mm:
                        pkg = mm.group(1)
                    res.add(Evidence("D3", "changelog", "php.patch_status",
                                     {"patched": True, "source": label, "package": pkg},
                                     Confidence.CONFIRMED,
                                     f"包 changelog 命中 CVE（{label}）",
                                     "changelog", _first_match_line(out)))
                elif out.strip():
                    res.add(Evidence("D3", "changelog", "php.patch_status",
                                     {"patched": False, "source": label},
                                     Confidence.HIGH,
                                     f"包 changelog 未命中 CVE（{label}）",
                                     "changelog", out.strip()[:200]))
            elif label == "apache_modules" and "php" in out.lower():
                res.add(Evidence("D3", "sapi", "php.sapi", "apache2handler",
                                 Confidence.CONFIRMED,
                                 "Apache 模块列表含 php_module（mod_php）",
                                 "sapi", f"{host}:apachectl -M"))
            elif label == "php_procs" and out.strip():
                res.add(Evidence("D3", "process", "php.workers", out.strip()[:600],
                                 Confidence.MEDIUM, "远程进程启动时间",
                                 "process", f"{host}:ps"))
            elif label == "os_release" and out.strip():
                res.add(Evidence("D3", "http_header", "host.os", out.strip()[:200],
                                 Confidence.HIGH, "目标 OS 版本",
                                 "process", f"{host}:/etc/os-release"))
    finally:
        client.close()

    # 采集完整 php -i
    try:
        _in, out, _err = client.exec_command("php -i 2>/dev/null", timeout=30)
        text = out.read()[:MAX_OUT].decode("utf-8", errors="replace")
        for ev in collect_phpinfo_evidence(text, f"{host}:php -i"):
            res.add(ev)
    except Exception:  # noqa: BLE001
        pass

    return res
