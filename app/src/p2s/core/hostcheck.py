"""本地取证（L3）——跨平台。

覆盖 Windows / Linux / macOS 的统一抽象：
  - PHP 安装点清点（PATH、注册表、常见目录、包管理器）
  - 生效配置核查（多来源合并求实际生效值）
  - 入侵痕迹（可疑文件、webshell、已知样本哈希、伪装进程、出站连接）

所有操作均为只读。
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import binforensics
from .ioc import IocLibrary, scan_webshell
from .versions import classify

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

#: 关键配置项的期望值与说明
KEY_SETTINGS: tuple[tuple[str, str, str], ...] = (
    ("session.upload_progress.enabled", "0",
     "上传进度功能：php2shell 主攻击链的生产者，必须关闭"),
    ("fatal_error_backtraces", "0",
     "PHP 8.5 致命错误回溯：已确认 RCE 链路的生产者，应关闭"),
    ("memory_limit", "-1",
     "OOM 攻击面：建议 -1（由 php_admin_value 保证不可被应用覆盖）"),
    ("post_max_size", "8M",
     "建议收紧：无需上传 8M，需要上传 32M"),
)

#: 值得留意的配置文件来源（实际生效值 = 这些文件里最"靠后"的决定者）
CONFIG_SOURCES = {
    "linux": (
        "/etc/php/{ver}/fpm/php.ini",
        "/etc/php/{ver}/fpm/pool.d/*.conf",
        "/etc/php/{ver}/cli/php.ini",
        "/etc/php.ini",
        "/usr/local/etc/php/php.ini",
    ),
    "windows": (
        "C:\\php\\php.ini",
        "C:\\xampp\\php\\php.ini",
        "C:\\php{ver}\\php.ini",
        "C:\\Program Files\\PHP\\php.ini",
    ),
    "macos": (
        "/opt/homebrew/etc/php/php.ini",
        "/usr/local/etc/php/php.ini",
        "/opt/local/etc/php/php.ini",
    ),
}


@dataclass
class PhpInstall:
    """一个 PHP 安装点。"""

    path: str
    version: Optional[str] = None
    sapi: Optional[str] = None
    configured_path: Optional[str] = None
    is_default: bool = False
    verdict_status: Optional[str] = None
    needs_action: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SettingCheck:
    """一个配置项的核查结果。"""

    name: str
    actual: Optional[str]
    expected: str
    ok: bool
    note: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SuspiciousArtifact:
    """一个可疑痕迹。"""

    kind: str
    path: str
    detail: str
    severity: str
    sha256: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostReport:
    """主机检测报告。"""

    hostname: str
    platform: str
    platform_release: str
    checked_at: str
    installs: list[PhpInstall] = field(default_factory=list)
    settings: list[SettingCheck] = field(default_factory=list)
    artifacts: list[SuspiciousArtifact] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if any(a.severity == "critical" for a in self.artifacts):
            return "critical"
        if any(i.needs_action for i in self.installs):
            return "high"
        if self.artifacts:
            return "medium"
        return "low"

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "platform": self.platform,
            "platform_release": self.platform_release,
            "checked_at": self.checked_at,
            "risk": self.risk,
            "installs": [i.to_dict() for i in self.installs],
            "settings": [s.to_dict() for s in self.settings],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "processes": self.processes,
            "connections": self.connections,
            "errors": self.errors,
        }


# --------------------------------------------------------------------------
# PHP 安装点清点
# --------------------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 12.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              errors="replace")
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return -1, f"{type(exc).__name__}: {exc}"


def _php_version(exe: str) -> Optional[str]:
    rc, out = _run([exe, "-r", "echo PHP_VERSION;"])
    if rc == 0:
        v = out.strip().splitlines()
        if v:
            return v[0].strip()
    rc, out = _run([exe, "-v"])
    m = re.search(r"PHP (\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def _php_sapi(exe: str) -> Optional[str]:
    rc, out = _run([exe, "-r", "echo PHP_SAPI;"])
    return out.strip() if rc == 0 and out.strip() else None


def _php_ini(exe: str) -> Optional[str]:
    rc, out = _run([exe, "-i"])
    m = re.search(r"Loaded Configuration File => (.+)", out)
    return m.group(1).strip() if m and m.group(1).strip() else None


def _candidate_php_paths() -> list[str]:
    """按平台枚举可能的 PHP 可执行文件位置。"""
    cands: list[str] = []

    # 1) PATH
    found = shutil.which("php")
    if found:
        cands.append(found)

    # 2) 平台常见目录
    if IS_WINDOWS:
        roots = [
            r"C:\php", r"C:\xampp\php", r"C:\laragon\bin\php", r"C:\wamp64\bin\php",
            r"C:\Program Files\PHP", r"C:\tools\php", r"C:\php8", r"C:\php7",
        ]
        for root in roots:
            p = Path(root)
            if p.is_dir():
                for exe in p.glob("php.exe"):
                    cands.append(str(exe))
        # 注册表
        for hive, key in (
            ("HKLM", r"SOFTWARE\PHP\PHP"),
            ("HKCU", r"SOFTWARE\PHP\PHP"),
        ):
            try:
                import winreg

                root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
                with winreg.OpenKey(root, key) as k:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(k, i)
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(k, sub) as sk:
                                val, _ = winreg.QueryValueEx(sk, "InstallPath")
                                if val:
                                    cands.append(str(Path(val) / "php.exe"))
                        except OSError:
                            pass
                        i += 1
            except Exception:  # noqa: BLE001
                pass
    else:
        for root in ("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin",
                     "/usr/sbin", "/opt/php/bin"):
            p = Path(root)
            if p.is_dir():
                for exe in p.glob("php*"):
                    if exe.is_file() and exe.name in {"php", "php-cli", "php8", "php8.2", "php8.3",
                                                      "php8.4", "php8.5", "php7"}:
                        cands.append(str(exe))
        # Debian/Ubuntu alternatives
        for alt in ("/etc/alternatives/php",):
            if Path(alt).exists():
                cands.append(alt)

    # 去重保序
    seen: set[str] = set()
    out = []
    for c in cands:
        key = c.lower() if IS_WINDOWS else c
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


#: 补丁标志：修复版 PHP 引入了这个 ini 指令；未打补丁的构建里它不存在
PATCH_FLAG_KEY = "memory_hard_limit_percent"


def probe_patch_flag(exe: str) -> Optional[bool]:
    """True=指令存在（补丁已在二进制里）；False=不存在；None=读不到。"""
    rc, out = _run([
        exe, "-r",
        f'var_dump(ini_get("{PATCH_FLAG_KEY}"));',
    ])
    if rc != 0:
        return None
    low = (out or "").strip().lower()
    if "bool(false)" in low:
        return False
    if low.startswith("string(") or "null" in low:
        # string(0) "" —— 指令存在但值为空，同样说明补丁已编入
        return True
    return None


def enumerate_php_installs() -> tuple[list[PhpInstall], list[str]]:
    """清点主机上的 PHP 安装点。"""
    installs: list[PhpInstall] = []
    errors: list[str] = []
    default = shutil.which("php")

    for path in _candidate_php_paths():
        ver = _php_version(path)
        if not ver:
            continue
        sapi = _php_sapi(path)
        v = classify(ver)
        # M5 二进制取证：构建时间是不可伪造的证据（版本号可以改，编译时间改不了）
        build = {}
        try:
            import os as _os
            real = _os.path.realpath(path)
            build = binforensics.probe_binary(real)
            if not build.get("build_time") and build.get("kind") == "pe":
                # Windows 的 php.exe 可能由包装器启动，再试同目录的 php.exe
                build = binforensics.probe_binary(path)
        except Exception:
            build = {}
        b_status, b_reason = binforensics.verdict(
            ver, build.get("build_time"), bool(getattr(v, "changelog_hit", False)), [])
        # 二进制证据比版本号更硬：它说"必然不含修复"时，采纳它
        if b_status == "vulnerable" and v.status != "vulnerable":
            v_status, v_reason = "vulnerable", b_reason
        else:
            v_status, v_reason = v.status, v.reason
        # 运行时补丁标志（借鉴开源实现）：比版本号更接近"二进制里到底有没有修复"
        patch_flag = probe_patch_flag(path)
        if patch_flag is True and v_status != "patched":
            v_status = "patched"
            v_reason = (f"运行时补丁标志 {PATCH_FLAG_KEY} 存在 → 判定补丁已编入二进制"
                        f"（原判定：{v_reason}）")
        elif patch_flag is False and v_status == "patched":
            v_status = "unknown"
            v_reason = (f"版本/changelog 显示已修复，但运行时补丁标志 {PATCH_FLAG_KEY} 不存在，"
                        f"两者矛盾 → 降级为无法确定，需人工核对")

        installs.append(
            PhpInstall(
                path=path,
                version=ver,
                sapi=sapi,
                configured_path=_php_ini(path),
                is_default=(default is not None and os.path.normcase(path) == os.path.normcase(default)),
                verdict_status=v_status,
                needs_action=(v_status == "vulnerable"),
                reason=v_reason + (f"｜二进制：{b_reason}" if build.get("kind") else ""),
            )
        )
        try:
            installs[-1].patch_flag = patch_flag
        except Exception:
            pass
        if build.get("build_id") or build.get("build_time"):
            try:
                installs[-1].build_id = build.get("build_id")
                installs[-1].build_time = build.get("build_time")
                installs[-1].toolchain = build.get("toolchain")
            except Exception:
                pass
    if not installs:
        errors.append("未在本机发现可用的 PHP 安装")
    return installs, errors


# --------------------------------------------------------------------------
# 配置核查
# --------------------------------------------------------------------------

def _ini_value(exe: str, key: str) -> Optional[str]:
    rc, out = _run([exe, "-r", f"echo ini_get('{key}');"])
    if rc == 0:
        return out.strip()
    return None


def check_settings(exe: str) -> list[SettingCheck]:
    """核查关键配置项的实际生效值。"""
    out: list[SettingCheck] = []
    for name, expected, note in KEY_SETTINGS:
        actual = _ini_value(exe, name)
        if actual is None:
            out.append(SettingCheck(name, None, expected, False, f"{note}（无法读取生效值）"))
            continue
        ok = actual.strip().lower() == expected.lower()
        if name == "post_max_size":
            # 允许 8M 或 32M
            ok = actual.strip().upper() in {"8M", "32M"}
        out.append(SettingCheck(name, actual, expected, ok, note))
    return out


# --------------------------------------------------------------------------
# 入侵痕迹
# --------------------------------------------------------------------------

#: 值得扫描的目录（可能包含攻击者落地文件）
#: 扫描目录数上限：目录越多耗时越长，必须有明确上界
_MAX_SCAN_DIRS = 24


def _scan_dirs() -> list[Path]:
    dirs: list[Path] = []
    tmp = [os.environ.get("TMPDIR"), os.environ.get("TMP"), os.environ.get("TEMP"), "/tmp", "/var/tmp"]
    for t in tmp:
        if t and Path(t).is_dir():
            dirs.append(Path(t))
    if IS_LINUX:
        for d in ("/var/lib/php/sessions", "/var/lib/php/session", "/tmp", "/var/tmp",
                  "/var/www", "/srv/http", "/opt", "/var/lib/php"):
            if Path(d).is_dir():
                dirs.append(Path(d))
    elif IS_WINDOWS:
        for d in (r"C:\Windows\Temp", r"C:\inetpub\wwwroot", r"C:\xampp\htdocs", r"C:\php"):
            if Path(d).is_dir():
                dirs.append(Path(d))
    elif IS_MAC:
        for d in ("/private/tmp", "/private/var/tmp", "/usr/local/var/www"):
            if Path(d).is_dir():
                dirs.append(Path(d))
    # 去重 + 数量上限
    out, seen = [], set()
    for d in dirs:
        k = str(d)
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
        if len(out) >= _MAX_SCAN_DIRS:
            break
    return out


def _iter_recent_files(dirs: Iterable[Path], since: datetime, max_files: int = 4000,
                       deadline: float | None = None):
    """遍历目录里 mtime >= since 的文件。

    deadline 是单调时钟的时间点（monotonic），用来给遍历本身封顶：
    os.walk 在大目录树上本身就可能耗时很久，光靠"每处理一个文件查一次时间"
    是来不及的 —— 一个巨型目录光 stat 就能耗掉几十秒。
    """
    for d in dirs:
        try:
            for root, _dirs, files in os.walk(d):
                # 每进入一个目录就查一次预算：大目录树的 walk 才是主要开销
                if deadline is not None and time.monotonic() > deadline:
                    return
                for fn in files:
                    if deadline is not None and time.monotonic() > deadline:
                        return
                    p = Path(root) / fn
                    try:
                        st = p.stat()
                    except OSError:
                        continue
                    if st.st_size > 8 * 1024 * 1024:
                        continue
                    try:
                        mt = datetime.fromtimestamp(st.st_mtime)
                    except (OSError, OverflowError, ValueError):
                        continue
                    if mt >= since:
                        yield p, mt
                        max_files -= 1
                        if max_files <= 0:
                            return
        except (PermissionError, OSError):
            continue


def _sha256(path: Path, limit: int = 32 * 1024 * 1024) -> Optional[str]:
    try:
        if path.stat().st_size > limit:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


#: 非脚本类文件也要参与哈希匹配时的体积上限（改名的小样本仍能命中）
_HASH_PROBE_MAX_BYTES = 1024 * 1024


def scan_artifacts(
    since: datetime | None = None, *, deep: bool = True, lib: IocLibrary | None = None,
    budget_seconds: float = 20.0,
) -> list[SuspiciousArtifact]:
    """扫描入侵痕迹。

    since 默认取 2026-10-20（漏洞披露窗口）之后的文件；deep=True 时做内容与哈希检查。
    budget_seconds 是总时间预算：磁盘遍历与哈希都会膨胀，必须有上界。
    预算耗尽时产出 scan_truncated 记录（如实说明结果不完整），绝不静默截断。
    """
    lib = lib or IocLibrary()
    since = since or datetime(2026, 10, 20)
    found: list[SuspiciousArtifact] = []
    deadline = time.monotonic() + budget_seconds
    truncated = False

    for path, mt in _iter_recent_files(_scan_dirs(), since, deadline=deadline):
        # 时间预算：超过就停。取证不能无限期占用。
        if time.monotonic() > deadline:
            truncated = True
            break
        try:
            suffix = path.suffix.lower()
        except OSError:
            continue

        # --- 先分流，别急着算哈希 ---
        # 只有两类文件值得付出 SHA-256 的代价：
        #   a) 脚本/可执行后缀 —— 本来就要报出来
        #   b) 体积小的文件 —— 改名成 .txt 的恶意样本仍然能被哈希命中
        # 其余（.log/.json/大文件等）跳过哈希：它们既不是脚本，
        # 命中 IOC 的概率也极低，算几千次 SHA-256 却不产出任何结论。
        interesting = suffix in {".php", ".phtml", ".phar", ".sh", ".bin", ".so"}
        if not interesting:
            try:
                interesting = path.stat().st_size <= _HASH_PROBE_MAX_BYTES
            except OSError:
                continue
        if not interesting:
            continue

        # 1) 已知样本哈希
        digest = _sha256(path)
        if digest:
            m = lib.match_hash(digest)
            if m:
                found.append(SuspiciousArtifact("known_malware", str(path), m.context, "critical", digest))
                continue

        # 2) 可执行/脚本后缀 + 在 PHP 相关目录
        if suffix in {".php", ".phtml", ".phar", ".sh", ".bin", ".so"}:
            found.append(SuspiciousArtifact(
                "recent_script", str(path),
                f"{suffix} 文件，修改时间 {mt.isoformat()}",
                "medium", digest))
            if deep:
                try:
                    content = path.read_text(errors="replace")[:200000]
                except OSError:
                    content = ""
                for label, evidence in scan_webshell(content):
                    found.append(SuspiciousArtifact("webshell", str(path),
                                                    f"{label} | {evidence}", "critical", digest))
                    break
                for m in lib.match_text(content[:20000], context=str(path)):
                    found.append(SuspiciousArtifact("ioc_in_file", str(path),
                                                    f"{m.ioc_type}: {m.value}", "critical", digest))

    # 生成器正常结束不代表没被截断 —— 遍历器自己也可能在预算耗尽时返回
    # （它在 os.walk 里检查 deadline 后直接 return，不会给上层发信号）。
    if not truncated and time.monotonic() > deadline:
        truncated = True

    if truncated:
        found.append(SuspiciousArtifact(
            "scan_truncated", "",
            f"扫描达到 {budget_seconds:.0f} 秒时间预算，已停止遍历；"
            f"本轮结果不完整，需提高预算后重跑",
            "info", None,
        ))
    return found

def list_processes() -> list[str]:
    """列出与 PHP 相关的进程，以及可疑伪装进程。"""
    out: list[str] = []
    try:
        import psutil  # type: ignore

        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                name = (p.info.get("name") or "").lower()
                exe = (p.info.get("exe") or "").lower()
                cmd = " ".join(p.info.get("cmdline") or [])
            except Exception:  # noqa: BLE001
                continue
            if "php" in name or "php" in exe or "php-fpm" in cmd:
                out.append(f"pid={p.info.get('pid')} {name} {cmd[:200]}")
            elif name in {"sysmon", "crong3-agent"}:
                out.append(f"[SUSPICIOUS] pid={p.info.get('pid')} {name} {cmd[:200]}")
        return out
    except ImportError:
        pass

    # 无 psutil 时的降级实现
    if IS_WINDOWS:
        rc, out_text = _run(["tasklist", "/fo", "csv", "/nh"])
    else:
        rc, out_text = _run(["ps", "-eo", "pid,comm,args"])
    for line in (out_text or "").splitlines():
        low = line.lower()
        if "php" in low or "sysmon" in low or "crong3-agent" in low:
            out.append(line.strip()[:250])
    return out


def list_connections() -> list[str]:
    """列出外部 TCP 连接，用于匹配 IOC C2。"""
    lines: list[str] = []
    if IS_WINDOWS:
        rc, text = _run(["netstat", "-ano"])
    else:
        rc, text = _run(["ss", "-tunp"]) or _run(["netstat", "-tunp"])
    for line in (text or "").splitlines():
        if "ESTABLISHED" in line.upper() or "ESTAB" in line.upper():
            lines.append(line.strip()[:250])
    return lines


def run_host_check(deep: bool = True, budget_seconds: float = 60.0) -> HostReport:
    """执行完整的本地取证。

    budget_seconds 是**总**时间预算：取证涉及磁盘遍历、哈希、进程/连接枚举，
    每一步都可能因为目标机器规模而膨胀。必须有总上界，
    否则在慢机器/CI runner 上这个任务会一直挂着。
    """
    rep = HostReport(
        hostname=platform.node(),
        platform=f"{platform.system()} {platform.machine()}",
        platform_release=platform.release(),
        checked_at=datetime.now().isoformat(timespec="seconds"),
    )
    deadline = time.monotonic() + budget_seconds

    def _left() -> float:
        """剩余预算（秒）。为负表示已经超时。"""
        return deadline - time.monotonic()

    def _skip(stage: str) -> None:
        rep.errors.append(
            f"{stage} 已跳过：本次取证已达 {budget_seconds:.0f} 秒总预算"
            f"（该步骤结果不完整）")

    installs, errors = enumerate_php_installs()

    # 容器 / K8s 里的 PHP 在宿主机上不可见，单独清点后并入安装点列表。
    # 任何异常都不能让主机检测整体失败 —— 宁可少报一类，也不能整份报告挂掉。
    #
    # 注意：这一段会调 docker / kubectl。runner 上装了 docker CLI 但 daemon 常没起，
    # docker 客户端会反复重连，单个命令就能耗掉好几秒。所以每一步之前都要看总预算。
    for _scanner, _label in (("scan_containers", "容器"), ("scan_kubernetes", "Kubernetes")):
        if _left() <= 0:
            _skip(f"{_label}清点")
            continue
        try:
            from . import containers as _c
            _fn = getattr(_c, _scanner, None)
            if _fn is None:
                continue
            # 把总截止时刻传下去：docker exec / kubectl 都是串行外部命令，
            # 容器多的时候会线性累加，必须让它们自己收敛。
            _items, _notes = _fn(deadline=deadline)
            errors.extend(_notes)
            for _it in _items:
                _d = _it.to_dict()
                # 容器也要给真实结论：版本判定 + 补丁标志（与主机侧同一套规则）
                _ver = _d.get("version") or "unknown"
                _status, _reason = "unknown", "版本未知，无法判定"
                if _ver != "unknown":
                    _v = classify(_ver)
                    _status, _reason = _v.status, _v.reason
                _flag = _d.get("patch_flag")
                if _flag is True and _status != "patched":
                    _status = "patched"
                    _reason = "容器内补齐丁标志 memory_hard_limit_percent 存在 → 补丁已编入"
                elif _flag is False and _status == "patched":
                    _status = "unknown"
                    _reason = "版本显示已修复，但容器内无补丁标志，两者矛盾 → 需人工核对"
                installs.append(PhpInstall(
                    path=_d["path"],
                    version=_ver,
                    sapi=_d.get("sapi") or "",
                    configured_path="",
                    is_default=False,
                    verdict_status=_status,
                    needs_action=_status in ("vulnerable", "eol_unpatchable", "eol_backport_available"),
                    reason=f"{_label} {_it.container}（镜像 {_it.image}）：{_reason}",
                ))
        except Exception as _e:
            errors.append(f"{_label}清点失败：{_e}")
    rep.installs = installs
    rep.errors.extend(errors)

    default_exe = next((i.path for i in installs if i.is_default), None) or (
        installs[0].path if installs else None
    )
    if default_exe:
        rep.settings = check_settings(default_exe)

    # 痕迹扫描是磁盘密集型的，拿剩余预算的绝大部分，
    # 但要给后面的进程/连接枚举留至少 5 秒余量。
    if _left() > 1.0:
        per_scan = max(2.0, _left() - 5.0)
        try:
            rep.artifacts = scan_artifacts(deep=deep, budget_seconds=per_scan)
        except Exception as exc:  # noqa: BLE001
            rep.errors.append(f"痕迹扫描失败: {exc}")
    else:
        _skip("痕迹扫描")

    if _left() > 0:
        try:
            rep.processes = list_processes()
        except Exception as exc:  # noqa: BLE001
            rep.errors.append(f"进程枚举失败: {exc}")
    else:
        _skip("进程枚举")

    if _left() > 0:
        try:
            rep.connections = list_connections()
        except Exception as exc:  # noqa: BLE001
            rep.errors.append(f"连接枚举失败: {exc}")
    else:
        _skip("连接枚举")

    return rep
