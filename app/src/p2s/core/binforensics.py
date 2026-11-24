"""二进制取证（M5）：从 ELF / PE 里读出"这个二进制何时、用什么编译器构建的"。

为什么需要它：
    · 版本号可以被改成任意值（自编译、打包脚本篡改），只看版本号会**漏报**；
    · 发行版会把补丁回移进旧版本号，只看版本号会**误报**；
    · 构建时间是不可伪造的物理证据：**早于补丁发布日编译的二进制，不可能包含该补丁**。

这说明什么、不说明什么：
    ✅ 构建时间早于修复日 → 一定未修复（强证据）
    ⚠️ 构建时间晚于修复日 → 不能证明已修复（可能只是重新编译），仍需 changelog / 标记库
    ❌ 完全没有构建信息（strip 且无 note）→ 无法判定，如实返回 None

纯标准库实现，不引入依赖；只读前 4MB，避免大文件拖慢采集。
"""
from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

#: 本 CVE 的修复发布日（UTC）。早于此时间构建的工件必然不含修复。
FIX_RELEASE_DATE = datetime(2026, 10, 21, tzinfo=timezone.utc)

#: 读取上限：ELF 的 note/comment 段通常在文件前部
MAX_READ = 4 * 1024 * 1024


def _read_head(path: Path) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(MAX_READ)
    except OSError:
        return b""


def is_pe(data: bytes) -> bool:
    return data[:2] == b"MZ" and len(data) > 0x40


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def pe_build_time(data: bytes) -> Optional[datetime]:
    """PE 头里的 TimeDateStamp：链接器写入的编译时间（UTC）。"""
    if not is_pe(data):
        return None
    try:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[off:off + 4] != b"PE\0\0":
            return None
        ts = struct.unpack_from("<I", data, off + 8)[0]
        if ts <= 0:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except struct.error:
        return None


def elf_build_id(data: bytes) -> Optional[str]:
    """解析 ELF 的 .note.gnu.build-id（GNU build-id），用于跨主机同版本比对。"""
    if not is_elf(data):
        return None
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        if is64:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
        for i in range(min(e_shnum, 256)):
            base = e_shoff + i * e_shentsize
            name_off = struct.unpack_from(endian + "I", data, base)[0]
            sh_type = struct.unpack_from(endian + "I", data, base + 4)[0]
            sh_offset = struct.unpack_from(
                endian + ("Q" if is64 else "I"), data, base + (0x18 if is64 else 0x10))[0]
            sh_size = struct.unpack_from(
                endian + ("Q" if is64 else "I"), data, base + (0x20 if is64 else 0x14))[0]
            if sh_type != 7 or name_off == 0:      # SHT_NOTE
                continue
            blob = data[sh_offset:sh_offset + max(0, min(sh_size, 4096))]
            pos = 0
            while pos + 12 <= len(blob):
                namesz, descsz, ntype = struct.unpack_from(endian + "III", blob, pos)
                name = blob[pos + 12:pos + 12 + namesz].rstrip(b"\0")
                desc_off = pos + 12 + ((namesz + 3) & ~3)
                desc = blob[desc_off:desc_off + descsz]
                if name == b"GNU" and ntype == 3 and desc:
                    return desc.hex()
                pos = desc_off + ((descsz + 3) & ~3)
    except (struct.error, IndexError):
        pass
    # 回退 1：程序头里的 PT_NOTE；回退 2：原始字节扫描
    return _note_from_program_headers(data) or _note_by_raw_scan(data)


def elf_comment(data: bytes) -> Optional[str]:
    """从 .comment 段取编译器标识（GCC/clang 版本），strip 后通常仍保留。"""
    if not is_elf(data):
        return None
    idx = data.find(b"GCC: (")
    if idx < 0:
        idx = data.find(b"clang version ")
    if idx < 0:
        return None
    chunk = data[idx:idx + 120].split(b"\0")[0]
    try:
        return chunk.decode("utf-8", "replace")[:100]
    except Exception:
        return None


def probe_binary(path: str | Path) -> dict:
    """返回一个二进制的取证信息（全部可缺失，缺就是 None）。"""
    p = Path(path)
    data = _read_head(p)
    out: dict = {"path": str(p), "kind": None, "build_time": None,
                 "build_id": None, "toolchain": None, "size": None}
    if not data:
        return out
    try:
        out["size"] = p.stat().st_size
    except OSError:
        pass
    if is_pe(data):
        out["kind"] = "pe"
        bt = pe_build_time(data)
        out["build_time"] = bt.isoformat() if bt else None
    elif is_elf(data):
        out["kind"] = "elf"
        out["build_id"] = elf_build_id(data)
        out["toolchain"] = elf_comment(data)
    else:
        out["kind"] = "unknown"
    return out


def built_before_fix(build_time: Optional[str]) -> Optional[bool]:
    """构建时间早于修复发布日 → True（**一定未修复**）；晚于 → False；无信息 → None。"""
    if not build_time:
        return None
    try:
        bt = datetime.fromisoformat(build_time)
        if bt.tzinfo is None:
            bt = bt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return bt < FIX_RELEASE_DATE


# --------------------------------------------------------------------------
# 补丁标记库：拿到"补丁前后"一对样本后，把差异特征写进 markers.json，
# 之后即可对任意二进制做"是否含补丁"的判定。
# 结构：[{"id":"php-8.4.27-oom-fix","format":"hex|ascii","pattern":"...",
#          "meaning":"patched","note":"CVE-2026-109618 修复后新增/移除的特征"}]
# --------------------------------------------------------------------------
def load_markers(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return [m for m in data if isinstance(m, dict) and m.get("pattern")]
    except (json.JSONDecodeError, OSError):
        return []


def match_markers(data: bytes, markers: list[dict]) -> list[dict]:
    """在二进制里找标记，返回命中的条目（含 meaning）。"""
    hits: list[dict] = []
    if not data:
        return hits
    for m in markers:
        pat = m.get("pattern") or ""
        try:
            needle = bytes.fromhex(pat) if m.get("format") == "hex" else pat.encode()
        except ValueError:
            continue
        if needle and needle in data:
            hits.append({"id": m.get("id"), "meaning": m.get("meaning", "unknown"),
                         "note": m.get("note", "")})
    return hits


def verdict(version: Optional[str], build_time: Optional[str],
            changelog_hit: bool, marker_hits: list[dict]) -> tuple[str, str]:
    """把二进制证据与版本/changelog 合成结论（供 hostcheck 使用）。

    优先级：changelog（发行版回移）> 补丁标记 > 构建时间 > 版本号。
    """
    if changelog_hit:
        return "patched", "包 changelog 命中 CVE，判定已回移补丁"
    if any(h.get("meaning") == "patched" for h in marker_hits):
        return "patched", "二进制命中补丁标记"
    if any(h.get("meaning") == "vulnerable" for h in marker_hits):
        return "vulnerable", "二进制命中未修复标记"
    before = built_before_fix(build_time)
    if before is True:
        return "vulnerable", f"二进制构建于 {build_time}，早于修复发布日，必然不含修复"
    if before is False:
        return "unknown", "二进制构建晚于修复日，不能据此判定，需 changelog 或标记库"
    return "unknown", "无二进制构建信息，无法判定"


def _note_from_program_headers(data: bytes) -> str | None:
    """遍历 PT_NOTE 程序头取 build-id（section 被 strip 时的主路径）。"""
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        if is64:
            e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 0x36)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 0x2A)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x2C)[0]
        for i in range(min(e_phnum, 128)):
            base = e_phoff + i * e_phentsize
            p_type = struct.unpack_from(endian + "I", data, base)[0]
            if p_type != 4:                      # PT_NOTE
                continue
            if is64:
                off = struct.unpack_from(endian + "Q", data, base + 8)[0]
                size = struct.unpack_from(endian + "Q", data, base + 32)[0]
            else:
                off = struct.unpack_from(endian + "I", data, base + 4)[0]
                size = struct.unpack_from(endian + "I", data, base + 16)[0]
            got = _parse_notes(data[off:off + min(size, 8192)], endian)
            if got:
                return got
    except (struct.error, IndexError):
        return None
    return None


def _parse_notes(blob: bytes, endian: str) -> str | None:
    pos = 0
    while pos + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from(endian + "III", blob, pos)
        name = blob[pos + 12:pos + 12 + namesz].rstrip(b"\0")
        desc_off = pos + 12 + ((namesz + 3) & ~3)
        desc = blob[desc_off:desc_off + descsz]
        if name == b"GNU" and ntype == 3 and desc:
            return desc.hex()
        pos = desc_off + ((descsz + 3) & ~3)
    return None


def _note_by_raw_scan(data: bytes) -> str | None:
    """最后一层：直接在字节流里找 GNU note（对付完全 strip 的文件）。"""
    idx = 0
    while True:
        idx = data.find(b"GNU\0", idx)
        if idx < 0:
            return None
        start = idx - 12
        if start >= 0:
            try:
                namesz, descsz, ntype = struct.unpack_from("<III", data, start)
            except struct.error:
                return None
            if namesz == 4 and ntype == 3 and 1 <= descsz <= 64:
                desc = data[idx + 4:idx + 4 + descsz]
                if len(desc) == descsz:
                    return desc.hex()
        idx += 4
