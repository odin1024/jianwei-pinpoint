"""Windows 加固包测试：语法 + 真实执行。

为什么必须真跑：生成的 PowerShell 只要有一处语法或逻辑错误，
在客户机器上就是"点了没反应"。语法用真实解析器校验，
行为则在本机对一份临时 php.ini 完整走一遍
（预检 → 备份 → 写入 → 校验 → 回执 → 回滚冲突）。
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

from p2s.core import harden_ps

WINDOWS = sys.platform == "win32"
PWSH = shutil.which("powershell") or shutil.which("pwsh")

pytestmark = pytest.mark.skipif(not WINDOWS or not PWSH,
                                reason="需要 Windows + PowerShell")

INI_TEMPLATE = """[Session]
; 加固前：暴露面更大
session.upload_progress.enabled = 1
session.use_strict_mode = 0
session.use_only_cookies = 0
session.cookie_httponly = 0

[Date]
date.timezone = Asia/Shanghai
"""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _make_target(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "phpconf"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "php.ini"
    p.write_text(INI_TEMPLATE, encoding="utf-8", newline="\n")
    return p


def _actions(target: pathlib.Path) -> list[dict]:
    return [
        {"key": "session.upload_progress.enabled", "from": "1", "value": "0",
         "level": "critical", "why": "关闭上传进度机制，消除会话注入面",
         "action": "php.ini.set", "target": str(target)},
        {"key": "session.use_strict_mode", "from": "0", "value": "1",
         "level": "high", "why": "拒绝未初始化的会话 ID",
         "action": "php.ini.set", "target": str(target)},
    ]


def _write_pack(tmp_path: pathlib.Path, target: pathlib.Path,
                ticket: str = "") -> pathlib.Path:
    text = target.read_text(encoding="utf-8")
    hr = {"ini_sha256": _sha(text), "php_bin": "php.exe"}
    pack = harden_ps.build_pack("test-host", hr, str(target), _actions(target),
                                ticket=ticket)
    for name, content in pack.items():
        enc = "utf-8-sig" if name.endswith(".ps1") else "utf-8"
        (tmp_path / name).write_text(content, encoding=enc, newline="\r\n")
    return tmp_path / "harden.ps1"


def _run(script: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PWSH, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )


# ---------------------------------------------------------------- 语法

def test_generated_scripts_parse(tmp_path) -> None:
    """交给真实 PowerShell 解析器，不接受"看起来对"。"""
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target)
    for name in ("harden.ps1", "rollback.ps1"):
        p = tmp_path / name
        cmd = ("$e=$null; $null=[System.Management.Automation.Language.Parser]"
               f"::ParseFile('{p}',[ref]$null,[ref]$e); "
               "if($e.Count){$e|%{$_.Message};exit 1}else{exit 0}")
        r = subprocess.run([PWSH, "-NoProfile", "-Command", cmd],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        assert r.returncode == 0, f"{name} 语法错误：{r.stdout}"


def test_pack_contains_all_parts(tmp_path) -> None:
    target = _make_target(tmp_path)
    text = target.read_text(encoding="utf-8")
    pack = harden_ps.build_pack("h", {"ini_sha256": _sha(text)}, str(target),
                                _actions(target))
    assert set(pack) == {"harden.ps1", "rollback.ps1", "diff.patch",
                         "manifest.json", "README.txt"}
    man = json.loads(pack["manifest.json"])
    assert man["platform"] == "windows"
    assert man["whitelist"] == ["php.ini.set", "file.backup", "service.reload"]
    assert man["runtime_verified"] is False


# ---------------------------------------------------------------- 执行

def test_harden_applies_and_receipts(tmp_path) -> None:
    """完整跑一遍：改值、留备份、出回执、退出码 0。"""
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target, ticket="tk-abc123")
    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 0, f"加固失败：{r.stdout}\n{r.stderr}"

    after = target.read_text(encoding="utf-8")
    assert "session.upload_progress.enabled = 0" in after
    assert "session.use_strict_mode = 1" in after
    # 未涉及的项必须原样保留
    assert "date.timezone = Asia/Shanghai" in after
    assert "; 加固前：暴露面更大" in after, "注释不能被吃掉"

    backups = list(tmp_path.glob("phpconf/php.ini.p2s.bak.*"))
    assert backups, "必须留下备份"
    assert backups[0].read_text(encoding="utf-8") == INI_TEMPLATE

    state = (tmp_path / "phpconf/php.ini.p2s.state").read_text(encoding="utf-8-sig")
    assert "after_sha=" in state and "backup=" in state, "state 需含加固后 sha 与备份路径"

    # 回执：必须包含主机、前后 sha、动作清单，且 runtime_verified 明确为 false
    assert "回执：" in r.stdout, f"未输出回执路径：{r.stdout}"
    receipt_path = pathlib.Path(r.stdout.split("回执：")[-1].strip().splitlines()[0])
    assert receipt_path.exists(), f"回执文件不存在：{receipt_path}"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8-sig"))
    assert receipt["host"] == "test-host"
    assert receipt["applied"], "回执必须记录已应用的动作"
    assert {a["key"] for a in receipt["applied"]} == {
        "session.upload_progress.enabled", "session.use_strict_mode"}
    assert receipt["runtime_verified"] is False, "存储态写入不等于运行时生效，必须标 false"

def test_harden_rejects_sha_mismatch(tmp_path) -> None:
    """文件与平台记录不一致时必须拒绝，绝不改文件。"""
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target)
    target.write_text(INI_TEMPLATE + "\n; 有人改过\n", encoding="utf-8", newline="\n")

    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 13, f"应返回 13，实际 {r.returncode}：{r.stdout}"
    assert "session.upload_progress.enabled = 1" in target.read_text(encoding="utf-8")


def test_harden_rejects_duplicate_directive(tmp_path) -> None:
    """重复指令不猜哪条生效，直接拒绝（退出码 18）。"""
    d = tmp_path / "dup"
    d.mkdir()
    target = d / "php.ini"
    target.write_text(INI_TEMPLATE + "session.use_strict_mode = 1\n",
                      encoding="utf-8", newline="\n")
    _write_pack(tmp_path, target)
    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 18, f"应返回 18，实际 {r.returncode}：{r.stdout}"


def test_harden_rejects_managed_by_config_tool(tmp_path) -> None:
    """配置管理工具托管的文件不要碰（退出码 14）。"""
    d = tmp_path / "mgd"
    d.mkdir()
    target = d / "php.ini"
    target.write_text("# Managed by Ansible - do not edit\n" + INI_TEMPLATE,
                      encoding="utf-8", newline="\n")
    _write_pack(tmp_path, target)
    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 14, f"应返回 14，实际 {r.returncode}：{r.stdout}"


def test_harden_rejects_continuation_line(tmp_path) -> None:
    """续行会让"一行一键值"的假设失效（退出码 19）。"""
    d = tmp_path / "cont"
    d.mkdir()
    target = d / "php.ini"
    target.write_text(INI_TEMPLATE + "session.cookie_domain = \\\n",
                      encoding="utf-8", newline="\n")
    _write_pack(tmp_path, target)
    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 19, f"应返回 19，实际 {r.returncode}：{r.stdout}"


def test_harden_rejects_tampered_pairs(tmp_path) -> None:
    """篡改包内动作清单（ActPairs）→ 计划指纹对不上，预检即拒（退出码 21）。"""
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target, ticket="tk-x")
    script = (tmp_path / "harden.ps1").read_text(encoding="utf-8-sig")
    tampered = script.replace(
        "$ActPairs    = 'session.upload_progress.enabled=0|session.use_strict_mode=1'",
        "$ActPairs    = 'session.use_strict_mode=1'")
    assert tampered != script, "未找到 ActPairs 行"
    (tmp_path / "harden.ps1").write_text(tampered, encoding="utf-8-sig", newline="\r\n")

    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 21, f"应返回 21，实际 {r.returncode}：{r.stdout}"
    # 预检拒绝 → 文件未被触碰
    assert target.read_text(encoding="utf-8") == INI_TEMPLATE


def test_harden_tampered_apply_is_caught_by_verify(tmp_path) -> None:
    """篡改实际写入值（但指纹仍匹配）→ 由校验拦截并自动回滚（退出码 30）。

    这是纵深防御：指纹只保证"清单没被改"，清单与脚本不一致时靠第 4 步兜住。
    """
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target, ticket="tk-x")
    script = (tmp_path / "harden.ps1").read_text(encoding="utf-8-sig")
    tampered = script.replace(
        "Apply-IniKV 'session.use_strict_mode' '1'",
        "Apply-IniKV 'session.use_strict_mode' '0'")
    assert tampered != script
    (tmp_path / "harden.ps1").write_text(tampered, encoding="utf-8-sig", newline="\r\n")

    r = _run(tmp_path / "harden.ps1")
    assert r.returncode == 30, f"应返回 30，实际 {r.returncode}：{r.stdout}"
    # 自动回滚 → 文件恢复原样
    assert target.read_text(encoding="utf-8") == INI_TEMPLATE


# ---------------------------------------------------------------- 回滚

def test_rollback_restores_file(tmp_path) -> None:
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target)
    assert _run(tmp_path / "harden.ps1").returncode == 0

    r = _run(tmp_path / "rollback.ps1")
    assert r.returncode == 0, f"回滚失败：{r.stdout}"
    assert target.read_text(encoding="utf-8") == INI_TEMPLATE


def test_rollback_detects_conflict(tmp_path) -> None:
    """加固后有人改过文件 → 回滚必须中止（31），避免抹掉别人的改动。"""
    target = _make_target(tmp_path)
    _write_pack(tmp_path, target)
    assert _run(tmp_path / "harden.ps1").returncode == 0

    target.write_text(target.read_text(encoding="utf-8") + "\n; 运维又改了一行\n",
                      encoding="utf-8", newline="\n")
    r = _run(tmp_path / "rollback.ps1")
    assert r.returncode == 31, f"应返回 31，实际 {r.returncode}：{r.stdout}"
    assert "运维又改了一行" in target.read_text(encoding="utf-8"), "冲突时不得覆盖"

    forced = _run(tmp_path / "rollback.ps1", "-Force")
    assert forced.returncode == 0
    assert target.read_text(encoding="utf-8") == INI_TEMPLATE
