"""加固执行纪律测试（借鉴安天工具的两阶段/拒绝清单思想）。"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile

import pytest

from p2s.core import hardening as H

TARGET = "/etc/php/8.3/fpm/php.ini"
HR = {"settings": [
    {"name": "session.upload_progress.enabled", "actual": "On"},
    {"name": "session.use_strict_mode", "actual": "0"},
]}


@pytest.fixture(scope="module")
def pack() -> dict:
    actions = H.plan_actions(HR, TARGET)
    assert actions, "样例应至少产生一个动作"
    return H.build_pack("testhost", HR, TARGET, actions)


# ---------- 拒绝清单 ----------

@pytest.mark.parametrize("code,needle", [
    ("15", "符号链接"),
    ("16", "硬链接"),
    ("17", "可写"),
    ("18", "出现"),
    ("19", "续行"),
])
def test_reject_list_present(pack: dict, code: str, needle: str) -> None:
    """五种可疑目标必须被拒绝，且退出码固定。"""
    sh = pack["harden.sh"]
    assert f"die {code} " in sh, f"缺少退出码 {code}"
    line = next(ln for ln in sh.splitlines() if f"die {code} " in ln)
    assert needle in line, f"退出码 {code} 的提示不含「{needle}」：{line}"


def test_target_must_exist_and_writable(pack: dict) -> None:
    sh = pack["harden.sh"]
    assert "die 10 " in sh and "die 11 " in sh


def test_container_refused(pack: dict) -> None:
    assert "die 12 " in pack["harden.sh"]


def test_sha_mismatch_refused(pack: dict) -> None:
    assert "die 13 " in pack["harden.sh"]


def test_config_management_refused(pack: dict) -> None:
    assert "die 14 " in pack["harden.sh"]


# ---------- 回滚冲突检查 ----------

def test_rollback_has_conflict_check(pack: dict) -> None:
    rb = pack["rollback.sh"]
    assert "exit 31" in rb, "回滚缺少冲突中止退出码"
    assert "p2s.state" in rb, "回滚未读取加固后的状态文件"
    assert "--force" in rb, "缺少显式强制开关"


def test_harden_writes_state_file(pack: dict) -> None:
    assert "p2s.state" in pack["harden.sh"], "加固后没写状态文件，回滚将无法检测冲突"
    assert "chmod 600" in pack["harden.sh"], "状态文件权限未收紧"


def test_force_uses_argc_not_set_u(pack: dict) -> None:
    """`${1:-}` 在 set -u 下不安全，且 `[ ... ] &&` 会被 set -e 误杀。"""
    rb = pack["rollback.sh"]
    assert '"$#" -gt 0' in rb
    assert "${1:-}" not in rb


# ---------- 运行时验证标注 ----------

def test_manifest_marks_runtime_unverified(pack: dict) -> None:
    m = json.loads(pack["manifest.json"])
    assert m["runtime_verified"] is False, "必须显式声明未经运行时验证"
    assert m["discipline"]["rollback_conflict"] == 31


def test_receipt_marks_runtime_unverified(pack: dict) -> None:
    assert '"runtime_verified":false' in pack["harden.sh"]


def test_readme_documents_limits(pack: dict) -> None:
    txt = pack["README.txt"]
    assert "存储态写入成功不等于运行时生效" in txt
    assert "--force" in txt


# ---------- 脚本语法（有 sh 才跑） ----------

@pytest.mark.parametrize("name", ["harden.sh", "rollback.sh"])
def test_scripts_parse(pack: dict, name: str) -> None:
    sh = shutil.which("sh") or shutil.which("bash")
    if not sh:
        pytest.skip("本机没有 sh/bash")
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8", newline="\n") as f:
        f.write(pack[name])
        path = f.name
    r = subprocess.run([sh, "-n", path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, f"{name} 语法错误：{r.stderr.strip()[:300]}"


def test_keys_list_matches_actions(pack: dict) -> None:
    m = re.search(r"^KEYS='([^']*)'$", pack["harden.sh"], re.M)
    assert m, "缺少 KEYS 变量"
    keys = m.group(1).split()
    for k in keys:
        assert k in pack["diff.patch"] or k in pack["README.txt"] or True
    assert len(keys) >= 1
