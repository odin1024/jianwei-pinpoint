"""采集脚本的防回归测试。

背景：模板是 Python f-string 包裹的 shell，改一处就可能：
  - 让 `\\r` / `\\n` 变成真回车换行，整段语法崩；
  - 多插/少插一段循环，留下悬空 `done`；
  - 误删 JSON 字段，服务端拿不到 ini 路径（加固会打到错误文件）。
这三次都真实发生过，且都靠人工真机 `sh -n` 才发现。这里把它们固化。
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

import pytest

from p2s.core import agentkit


@pytest.fixture(scope="module")
def script() -> str:
    return agentkit.render("linux", "http://console.local:18080", "token-abc")


def test_no_stray_control_chars(script: str) -> None:
    """模板里的 `\\r` / `\\n` 若没转义，会变成真实控制字符，shell 直接语法错误。"""
    assert "\r" not in script, "采集脚本里出现回车符（多半是 \\r 转义没写对）"


def test_shell_syntax(script: str) -> None:
    """用真实 shell 做语法检查——这是唯一可靠的门槛。

    找不到 sh/bash 时跳过（Windows 上没有），这是有意的：
    宁可跳过也不要写一个会误报的启发式（试过，误报很严重）。
    """
    sh = shutil.which("sh") or shutil.which("bash") or shutil.which("busybox")
    if not sh:
        pytest.skip("本机没有 sh/bash，跳过 shell 语法检查")
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8", newline="\n") as f:
        f.write(script)
        path = f.name
    r = subprocess.run([sh, "-n", path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, f"shell 语法错误：{r.stderr.strip()[:400]}"


@pytest.mark.parametrize("marker", ['INI_CANDS=""', 'INI_FILES=""'])
def test_block_appears_once(script: str, marker: str) -> None:
    """块重复插入过一次，导致悬空 done。"""
    assert script.count(marker) == 1, f"{marker} 出现了 {script.count(marker)} 次"


@pytest.mark.parametrize("field_name", [
    "ini_candidates_raw", "ini_files_raw", "ini_path", "ini_sha256",
    "php_bin", "installs", "settings", "artifacts",
])
def test_json_fields_present(script: str, field_name: str) -> None:
    """服务端依赖这些字段；删掉任何一个都会让加固目标回退到错误路径。"""
    assert f'"{field_name}"' in script, f"JSON 缺少字段 {field_name}"


def test_no_unresolved_placeholder(script: str) -> None:
    """f-string 占位符必须全部被替换。"""
    leftovers = re.findall(r"\{[a-z_][a-z0-9_]*\}", script)
    assert not leftovers, f"未替换的占位符：{leftovers[:5]}"


def test_single_quotes_even_per_logical_line(script: str) -> None:
    """单引号按「逻辑行」成对（续行会拼接），捕捉被吃掉的引号。"""
    bad, buf = [], ""
    for i, line in enumerate(script.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        buf += line
        if line.rstrip().endswith(("|", "\\", "&&", "||")):
            continue
        if buf.count("'") % 2:
            bad.append((i, buf[:80]))
        buf = ""
    assert not bad, f"单引号不成对：{bad[:3]}"


def test_windows_script_renders() -> None:
    ps = agentkit.render("windows", "http://console.local:18080", "token-abc")
    assert "Invoke-RestMethod" in ps or "ConvertTo-Json" in ps
