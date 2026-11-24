"""二进制取证（M5）测试：用真实 PE 与合成 ELF 验证解析与判定优先级。"""
from __future__ import annotations

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from p2s.core import binforensics as bf


def test_pe_timestamp_on_real_binary():
    """用当前解释器自己（真实 PE）验证：能读出合理的构建时间。"""
    if not sys.executable.lower().endswith(".exe"):
        pytest.skip("非 Windows 环境")
    info = bf.probe_binary(sys.executable)
    assert info["kind"] == "pe"
    assert info["build_time"], "真实 PE 应能读出 TimeDateStamp"
    bt = datetime.fromisoformat(info["build_time"])
    assert 2000 < bt.year < 2100


def test_pe_synthetic_timestamp():
    """合成一个最小 PE：验证解析的是 PE 头里的 TimeDateStamp，而不是随机偏移。"""
    ts = int(datetime(2026, 10, 19, tzinfo=timezone.utc).timestamp())
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<I", buf, 0x88, ts)
    got = bf.pe_build_time(bytes(buf))
    assert got is not None
    assert got.year == 2026 and got.month == 10 and got.day == 19


def _elf_with_notes(build_id: bytes, comment: str) -> bytes:
    """构造一个带 .note.gnu.build-id 与 .comment 的最小 ELF64 可解析结构。"""
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" 
    note += build_id + b"\0" * ((4 - len(build_id) % 4) % 4)
    comment_bytes = b"GCC: (" + comment.encode() + b")\0"
    notes_off = 0x100
    comment_off = notes_off + len(note)
    shstrtab_off = comment_off + len(comment_bytes)
    shstrtab = b"\0.note.gnu.build-id\0.comment\0"
    shoff = 0x400

    buf = bytearray(shoff + 64 * 4)
    buf[0:4] = b"\x7fELF"
    buf[4] = 2      # ELFCLASS64
    buf[5] = 1      # little endian
    struct.pack_into("<Q", buf, 0x28, shoff)
    struct.pack_into("<H", buf, 0x3A, 64)
    struct.pack_into("<H", buf, 0x3C, 4)
    buf[notes_off:notes_off + len(note)] = note
    buf[comment_off:comment_off + len(comment_bytes)] = comment_bytes
    buf[shstrtab_off:shstrtab_off + len(shstrtab)] = shstrtab

    def section(i, name_off, stype, off, size):
        base = shoff + i * 64
        struct.pack_into("<I", buf, base, name_off)
        struct.pack_into("<I", buf, base + 4, stype)
        struct.pack_into("<Q", buf, base + 0x18, off)
        struct.pack_into("<Q", buf, base + 0x20, size)

    section(0, 0, 0, 0, 0)
    section(1, 1, 7, notes_off, len(note))                     # SHT_NOTE
    section(2, len(b"\0.note.gnu.build-id"), 1, comment_off, len(comment_bytes))
    section(3, len(b"\0.note.gnu.build-id\0.comment"), 3, shstrtab_off, len(shstrtab))
    return bytes(buf)


def test_elf_build_id_and_comment(tmp_path: Path):
    data = _elf_with_notes(bytes.fromhex("deadbeefcafe1234"), "Ubuntu 13.3.0")
    f = tmp_path / "php"
    f.write_bytes(data)
    info = bf.probe_binary(f)
    assert info["kind"] == "elf"
    assert info["build_id"] == "deadbeefcafe1234"
    assert info["toolchain"] and "Ubuntu 13.3.0" in info["toolchain"]


def test_built_before_fix_boundary():
    assert bf.built_before_fix("2026-10-19T15:16:58+00:00") is True    # 早于补丁日
    assert bf.built_before_fix("2026-10-25T00:00:00+00:00") is False   # 晚于
    assert bf.built_before_fix(None) is None


def test_verdict_priority():
    # 1) changelog 最高优先：版本旧也判已修复
    assert bf.verdict("8.3.6", "2026-10-19T00:00:00+00:00", True, [])[0] == "patched"
    # 2) 无 changelog，但构建早于修复日 → 一定未修复
    st, why = bf.verdict("8.4.20", "2026-10-19T00:00:00+00:00", False, [])
    assert st == "vulnerable" and "早于修复发布日" in why
    # 3) 构建晚于修复日 → 不能定论
    assert bf.verdict("8.4.20", "2026-10-25T00:00:00+00:00", False, [])[0] == "unknown"
    # 4) 补丁标记命中优先于构建时间
    hit = [{"id": "x", "meaning": "patched", "note": ""}]
    assert bf.verdict("8.4.20", "2026-10-19T00:00:00+00:00", False, hit)[0] == "patched"


def test_markers_roundtrip(tmp_path: Path):
    mf = tmp_path / "markers.json"
    mf.write_text('[{"id":"a","format":"ascii","pattern":"PHP_PATCH_MARK","meaning":"patched"}]',
                  encoding="utf-8")
    markers = bf.load_markers(mf)
    assert len(markers) == 1
    hits = bf.match_markers(b"...PHP_PATCH_MARK...", markers)
    assert hits and hits[0]["meaning"] == "patched"
    assert bf.match_markers(b"nothing", markers) == []


def test_missing_file_is_safe(tmp_path: Path):
    info = bf.probe_binary(tmp_path / "nope")
    assert info["kind"] is None and info["build_time"] is None
