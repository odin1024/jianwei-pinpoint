"""M5 回退路径测试：section 被 strip 后仍能取到 build-id。"""
from __future__ import annotations

import struct

from p2s.core import binforensics as bf


def _elf_only_program_note(build_id: bytes) -> bytes:
    """构造只含 PT_NOTE、没有 section header 的 ELF64（模拟 strip 后的发行版二进制）。"""
    note = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id
    note += b"\0" * ((4 - len(build_id) % 4) % 4)
    phoff = 0x40
    notes_off = 0x200
    buf = bytearray(notes_off + len(note))
    buf[0:4] = b"\x7fELF"
    buf[4] = 2          # ELFCLASS64
    buf[5] = 1          # little endian
    struct.pack_into("<Q", buf, 0x20, phoff)      # e_phoff
    struct.pack_into("<H", buf, 0x36, 56)         # e_phentsize
    struct.pack_into("<H", buf, 0x38, 1)          # e_phnum
    struct.pack_into("<H", buf, 0x3A, 0)          # e_shnum = 0（无 section header）
    struct.pack_into("<Q", buf, 0x28, 0)          # e_shoff = 0
    base = phoff
    struct.pack_into("<I", buf, base, 4)          # PT_NOTE
    struct.pack_into("<Q", buf, base + 8, notes_off)
    struct.pack_into("<Q", buf, base + 32, len(note))
    buf[notes_off:notes_off + len(note)] = note
    return bytes(buf)


def test_build_id_from_program_header_without_sections(tmp_path):
    data = _elf_only_program_note(bytes.fromhex("aabbccdd11223344"))
    f = tmp_path / "php-stripped"
    f.write_bytes(data)
    info = bf.probe_binary(f)
    assert info["kind"] == "elf"
    assert info["build_id"] == "aabbccdd11223344"


def test_build_id_raw_scan_fallback(tmp_path):
    """没有任何头结构、只有裸 note 字节时，靠原始扫描兜底。"""
    raw = b"\x00" * 64 + struct.pack("<III", 4, 8, 3) + b"GNU\0" + bytes.fromhex("0011223344556677")
    f = tmp_path / "weird.bin"
    f.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 58 + raw)
    info = bf.probe_binary(f)
    assert info["build_id"] == "0011223344556677"
