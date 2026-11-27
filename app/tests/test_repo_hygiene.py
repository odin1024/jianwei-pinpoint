"""仓库卫生门禁：编码、残留文件、体积上限。

真实事故（2026-11-27 公开前体检）
--------------------------------
1. `app/requirements.lock.txt` 的**头部中文注释全是乱码**：
   UTF-8 文本在某次 PowerShell `Set-Content` 写入时被按 GBK 解释，
   中文变成「渚濊禆閿佸畾鏂囦欢…」，而且**不可机械还原**（部分字符已丢失）。
   同时文件带 UTF-8 BOM。
2. `archive/scratch/upload_test.log` 是调试残留，混进了公开仓库。
3. `docs/03-情报/证据/nvd-php-oct2026.json` 单文件 2.6 MB，
   占整个仓库的 1/4，而它没有任何代码读取。

这三类问题共同的特征：**不会让测试失败，只会让仓库变脏**。
所以必须有专门的门禁盯着。

为什么不用 pre-commit / .gitattributes 解决
-----------------------------------------
`.gitattributes` 只能管换行符，管不住"内容是不是乱码"。
乱码必须在**内容层面**判断——这只能在 Python 里做。
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent
ROOT = APP.parent

#: 允许带 BOM 的文件类型 —— PowerShell 5.1 需要 BOM 才能正确识别
#: 脚本里的 UTF-8 中文，否则按 ANSI 解析会让注释乱码甚至解析失败。
BOM_ALLOWED_SUFFIX = {".ps1"}

#: 允许带 BOM 的其它后缀：
#:   .csv  —— Excel 双击打开时，没有 BOM 会把 UTF-8 中文显示成乱码。
#:             对"给人看的表格"来说，BOM 是必需的，不是脏。
BOM_ALLOWED_SUFFIX |= {".csv"}

#: 允许出现在仓库里的 .log 文件（用户可见的样例日志）
LOG_ALLOWLIST = {
    "samples/样例日志/access.log",
    "samples/样例日志/error.log",
    "samples/样例日志/php_error.log",
}

#: 单文件体积上限（KB）。超过就要问"这个文件有人读吗"。
MAX_FILE_KB = 1200


def _tracked() -> list[str]:
    r = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        pytest.skip("git 不可用")
    return [x for x in r.stdout.splitlines() if x.strip()]


def _read(rel: str) -> bytes | None:
    p = ROOT / rel
    return p.read_bytes() if p.is_file() else None


# ---------------------------------------------------------------- 锁文件
def test_lock_file_has_no_bom() -> None:
    """requirements.lock.txt 不应有 BOM。

    pip 能容忍 BOM，但 BOM 会让"第一行是不是注释"的判断在某些工具里失效，
    而且它是"用 PowerShell 写文件"时顺带引入的典型脏标记。
    """
    raw = _read("app/requirements.lock.txt")
    assert raw is not None, "锁文件不存在"
    assert not raw.startswith(b"\xef\xbb\xbf"), (
        "锁文件带 UTF-8 BOM —— 用 PowerShell 写文件时会顺带加进来，"
        "请用 Python 写文本或显式指定无 BOM 编码")


def _looks_like_mojibake(text: str) -> list[tuple[int, str]]:
    """找出疑似 mojibake 的行。

    判定思路
    --------
    mojibake 的本质是：**一段本是 UTF-8 的字节，被按 GBK/CP936 解读，
    再当作 UTF-8 存了下来**。

    但"行内出现生僻字"不足以判定 —— 真实中文技术文档里也会有
    「Mirai」「longjmp」「失陷」这类词。**实测误报率过高**，
    所以必须用更严的判据：

    ① 整行（去掉代码标记与 ASCII 后）的中文字符里，
       **GBK 生僻字占比 ≥ 50%** —— 正常中文句子这个比例接近 0；
    ② 或整行能按 GBK 编码回去、且解出来是合法 UTF-8 **且**含中文
       （这是"被 GBK 误解过"的数学特征）。

    两条都要求"整行"成立，避免长文档里混入一两个生僻字就误报。
    """
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = re.sub(r"[`*_\[\]()#>|\-\s:：，。、；：（）「」【】…—─]", "", line)
        cjk = [ch for ch in stripped if "一" <= ch <= "鿿"]
        if len(cjk) >= 4:
            rare = sum(1 for ch in cjk if _is_rare_cjk(ch))
            if rare / len(cjk) >= 0.5:
                hits.append((i, line))
                continue
        # ② 编码往返：整行 GBK→UTF-8 往返成立
        try:
            raw = line.encode("gbk")
        except UnicodeEncodeError:
            continue
        try:
            back = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"[一-鿿]{2,}", back) and back != line:
            hits.append((i, line))
    return hits


#: GBK 编码里存在、但现代中文技术文档几乎不用的生僻字。
#: 这批字来自真实的乱码样本（锁文件损坏时的原文）。
_RARE_CJK = set(
    "渚濊禤閿佸畾鏂囦欢锛堢敱宸查獙璇佺幆澧冨紩鍑猴級鐢ㄧ敤锛歺yproject"
    "瑁呭寲绾跨寲闃翠鍖栫幏鏈夌郴缁戠粺鍙浠閲嶆搴忓〃鍒嗘被鍔犺浇"
    "鏈夋湁鍙€绋嬪簭鎵撳墍闇€鏂囦欢鏈夋缁忕粺鏇存柊鏃舵満"
    "鍗忚搴忓繖涓粬涓€"
)


def _is_rare_cjk(ch: str) -> bool:
    """是否是"GBK 误解 UTF-8"场景下才会出现的生僻字。"""
    if ch in _RARE_CJK:
        return True
    try:
        ch.encode("gbk")
    except UnicodeEncodeError:
        return False
    code = ord(ch)
    # GBK 扩展区基本是生僻字
    return 0xF900 <= code <= 0xFAFF


def test_lock_file_is_valid_utf8_without_mojibake() -> None:
    """锁文件必须是合法 UTF-8，且不含 mojibake（乱码）。

    真实事故：锁文件头部中文曾变成「渚濊禤閿佸畾鏂囦欢锛堢敱宸查獙璇佺幆澧…」
    —— UTF-8 文本被按 GBK 解读后存回。这种损坏**不可机械还原**
    （部分字符已被替换成 `?`），只能按语义重写，所以必须挡住。
    """
    raw = _read("app/requirements.lock.txt")
    assert raw is not None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        pytest.fail(f"锁文件不是合法 UTF-8：{exc}")

    bad = _looks_like_mojibake(text)
    assert not bad, (
        "锁文件出现乱码（UTF-8 被按 GBK 写入的痕迹）：\n"
        + "\n".join(f"  行 {i}: {line[:80]}" for i, line in bad[:5])
        + "\n这类损坏无法机械还原，只能按语义重写。")


def test_lock_file_has_no_duplicate_packages() -> None:
    """锁文件里同一个包不能出现两次。"""
    text = (_read("app/requirements.lock.txt") or b"").decode("utf-8")
    names = [ln.split("==")[0].strip().lower() for ln in text.splitlines()
             if "==" in ln and not ln.strip().startswith("#")]
    dupes = {n for n in names if names.count(n) > 1}
    assert not dupes, f"锁文件有重复条目：{sorted(dupes)}"


def test_lock_file_contains_test_dependencies() -> None:
    """锁文件必须包含 pytest / ruff —— CI 只装锁文件，不装 dev extra。

    漏掉任何一个，CI 会直接失败（没有 pytest 就跑不了测试）。
    这条门禁守住的是"重新生成锁文件时别把测试依赖过滤掉了"。
    """
    text = (_read("app/requirements.lock.txt") or b"").decode("utf-8")
    for pkg in ("pytest", "ruff", "pytest-timeout"):
        assert f"{pkg}==" in text, (
            f"锁文件缺少 {pkg} —— CI 只执行 pip install -r requirements.lock.txt，"
            f"缺了它 CI 会失败")


# ---------------------------------------------------------------- 残留文件
def test_no_unexpected_log_files() -> None:
    """仓库里不该有调试残留的 .log。

    只有 `samples/样例日志/` 下的三份是给用户演示日志检测功能的样例，
    其余 .log 都是调试残留（曾经混入过 archive/scratch/upload_test.log）。
    """
    bad = [f for f in _tracked() if f.lower().endswith(".log") and f not in LOG_ALLOWLIST]
    assert not bad, (
        f"仓库里有未列入白名单的 .log（调试残留）：{bad}\n"
        f"确属样例请加进 test_repo_hygiene.LOG_ALLOWLIST 并说明用途")


def test_no_editor_backup_files() -> None:
    """不该有编辑器/工具的备份与临时文件。"""
    patterns = (".orig", ".rej", ".bak", ".swp", ".swo", "~")
    bad = [
        f for f in _tracked()
        if f.endswith(patterns) or f.endswith("~")
        or ".pytest_cache" in f or "__pycache__" in f
    ]
    assert not bad, f"仓库里有备份/临时文件：{bad}"


def test_no_zero_byte_tracked_files() -> None:
    """被跟踪的文件不该是 0 字节 —— 空文件通常是写错了路径。

    例外：Python 包的 `__init__.py` **本来就该是空的**（它是包标记，
    不是模块）。空着才是对的。
    """
    empty = []
    for f in _tracked():
        raw = _read(f)
        if raw is None or len(raw) != 0:
            continue
        if Path(f).name == "__init__.py":
            continue          # 包标记文件，空是对的
        empty.append(f)
    assert not empty, f"仓库里有 0 字节文件：{empty}"


# ---------------------------------------------------------------- 体积
def test_no_oversized_files() -> None:
    """单文件不得超过上限（默认 1.2 MB）。

    超过就要问：这个文件有人读吗？原始抓取类归档应当精简字段而不是整份保留。
    """
    big = []
    for f in _tracked():
        raw = _read(f)
        if raw is None:
            continue
        kb = len(raw) / 1024
        if kb > MAX_FILE_KB:
            big.append((f, round(kb)))
    assert not big, (
        f"以下文件超过 {MAX_FILE_KB} KB：{big}\n"
        f"原始抓取类归档请精简字段（如 NVD JSON 只保留需要的 CVE 与字段）")


def test_nvd_archive_keeps_target_cves() -> None:
    """精简 NVD 归档时，两个目标 CVE 必须完整保留。

    这是"精简体积"的护栏 —— 别为了省空间把真正的依据删了。
    """
    raw = _read("docs/03-情报/证据/nvd-php-oct2026.json")
    if raw is None:
        pytest.skip("NVD 归档不存在")
    data = json.loads(raw.decode("utf-8"))
    cves = data.get("cves", data) if isinstance(data, dict) else data
    by_id = {e.get("cve", {}).get("id"): e.get("cve", {}) for e in cves}
    for cid in ("CVE-2026-109618", "CVE-2026-109619"):
        assert cid in by_id, f"NVD 归档里没有 {cid} —— 精简时把它删掉了"
        c = by_id[cid]
        assert c.get("descriptions"), f"{cid} 缺少描述"
        assert c.get("references"), f"{cid} 缺少 references（应完整保留）"
        assert c.get("metrics"), f"{cid} 缺少 CVSS 指标"


# ---------------------------------------------------------------- 编码
def test_text_files_have_consistent_encoding() -> None:
    """仓库里的文本文件应当是合法 UTF-8（BOM 除外，见下）。

    检查范围排除二进制文件 —— 用内容嗅探判断，不靠扩展名。
    """
    text_suffixes = {".py", ".md", ".txt", ".yml", ".yaml", ".toml", ".json",
                     ".js", ".css", ".html", ".sql", ".sh", ".cfg", ".ini", ".ps1"}
    bad = []
    for f in _tracked():
        p = ROOT / f
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if not raw:
            continue
        if b"\x00" in raw[:8000]:
            continue                      # 二进制，跳过
        if p.suffix.lower() not in text_suffixes:
            continue
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            bad.append((f, str(exc)[:60]))
    assert not bad, f"以下文本文件不是合法 UTF-8：{bad}"


def test_bom_only_where_needed() -> None:
    """BOM 只允许出现在 PowerShell 脚本里。

    原因：Windows PowerShell 5.1 读取无 BOM 的 .ps1 时按 ANSI 解析，
    脚本里的中文注释会变成乱码（曾经真的踩过）。
    但 BOM 加在 .py / .md / .txt 上纯属脏 —— 那是"用 PowerShell 写文件"的副作用。
    """
    offenders = []
    for f in _tracked():
        raw = _read(f)
        if raw is None or not raw.startswith(b"\xef\xbb\xbf"):
            continue
        if Path(f).suffix.lower() in BOM_ALLOWED_SUFFIX:
            continue
        offenders.append(f)
    assert not offenders, (
        f"以下文件带 BOM，但不属于允许清单（.ps1）：{offenders}\n"
        f"用 PowerShell 写文本时会自动加 BOM —— 请改用 Python 或 "
        f"`Set-Content -Encoding utf8NoBOM`")
