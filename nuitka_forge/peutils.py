"""
Nuitka 解包后的 PE 文件处理模块。

处理从 onefile 包中提取出的 PE 文件（如 mask.dll）：
- PE 资源目录枚举
- PE 资源数据提取
- Nuitka 常量资源 (RT_RCDATA/3) 的 CRC32 校验与修复
- Nuitka 常量资源 payload 深度解析（TLV 格式完整解析）
- 通用二进制内容搜索替换
"""

from __future__ import annotations

import binascii
import json
import struct
from typing import Any, NamedTuple

import pefile

from .constants import (
    BlobParseResult,
    CodeObjectData,
    build_blob,
    format_blob_summary,
    format_blob_tree,
    format_code_objects,
    parse_blob,
)


# ---------------------------------------------------------------------------
# PE 资源类型名称
# ---------------------------------------------------------------------------
RESOURCE_TYPE_NAMES: dict[int, str] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}

# 常见的 Nuitka 序列化标记（用于估算对象数量）
NUITKA_OBJECT_MARKERS = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
}

IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000


# ---------------------------------------------------------------------------
# PE 资源条目
# ---------------------------------------------------------------------------

class PEResourceEntry(NamedTuple):
    """PE 资源目录中的一个条目。"""

    type_id: int
    type_name: str
    name_id: int | str
    lang_id: int
    size: int
    data_rva: int
    data_offset: int  # 相对 PE 文件起始的文件偏移


# ---------------------------------------------------------------------------
# PE 资源枚举与提取
# ---------------------------------------------------------------------------

def list_pe_resources(pe_data: bytes) -> list[PEResourceEntry]:
    """列出 PE 文件（EXE / DLL）中的所有资源条目。"""
    pe = pefile.PE(data=pe_data)
    resources: list[PEResourceEntry] = []

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = entry.id
        type_name = RESOURCE_TYPE_NAMES.get(type_id, f"RT_{type_id}")

        if not hasattr(entry, "directory"):
            continue

        for name_entry in entry.directory.entries:
            name_id: int | str = name_entry.id
            if hasattr(name_entry, "name") and name_entry.name:
                name_id = name_entry.name.decode("utf-8", errors="replace")

            if not hasattr(name_entry, "directory"):
                continue

            for lang_entry in name_entry.directory.entries:
                lang_id = lang_entry.id
                info = lang_entry.data.struct

                resources.append(
                    PEResourceEntry(
                        type_id=type_id,
                        type_name=type_name,
                        name_id=name_id,
                        lang_id=lang_id,
                        size=info.Size,
                        data_rva=info.OffsetToData,
                        data_offset=pe.get_offset_from_rva(info.OffsetToData),
                    )
                )

    pe.close()
    return resources


def get_pe_resource_data(
    pe_data: bytes,
    resource_type: int,
    resource_id: int,
) -> bytes:
    """从 PE 文件中提取指定类型和 ID 的原始资源数据。"""
    pe = pefile.PE(data=pe_data)
    image = pe.get_memory_mapped_image()

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != resource_type:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != resource_id:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            pe.close()
            return bytes(image[info.OffsetToData : info.OffsetToData + info.Size])

    pe.close()
    raise ValueError(f"PE 资源 type={resource_type} id={resource_id} 未找到")


def replace_pe_resource_data(
    pe_data: bytes,
    resource_type: int,
    resource_id: int,
    new_resource_data: bytes,
    *,
    allow_expand: bool = True,
) -> bytes:
    """Replace a PE resource, expanding the image when it no longer fits.

    If the new data fits in the original resource slot, it is written in place.
    If it grows and ``allow_expand`` is true, the data is appended to the last
    section and the resource data entry is repointed to the new RVA.
    """
    pe = pefile.PE(data=pe_data)
    try:
        lang_entry = _find_resource_lang_entry(pe, resource_type, resource_id)
        info = lang_entry.data.struct
        old_rva = info.OffsetToData
        old_size = info.Size
        old_offset = pe.get_offset_from_rva(old_rva)
        info_offset = info.get_file_offset()

        if len(new_resource_data) <= old_size:
            patched = bytearray(pe_data)
            patched[old_offset:old_offset + len(new_resource_data)] = new_resource_data
            if len(new_resource_data) < old_size:
                patched[old_offset + len(new_resource_data):old_offset + old_size] = (
                    b"\x00" * (old_size - len(new_resource_data))
                )
            struct.pack_into("<I", patched, info_offset + 4, len(new_resource_data))
            return _refresh_pe_checksum(bytes(patched))

        if not allow_expand:
            raise ValueError(
                "新 PE 资源超出原始槽位: "
                f"new_size={len(new_resource_data):,} bytes, "
                f"original_size={old_size:,} bytes, "
                f"expanded=+{len(new_resource_data) - old_size:,} bytes"
            )

        return _append_expanded_resource(
            pe,
            pe_data,
            info_offset,
            new_resource_data,
        )
    finally:
        pe.close()


def _find_resource_lang_entry(
    pe: pefile.PE,
    resource_type: int,
    resource_id: int,
):
    """Find the first language entry for a numeric PE resource."""
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != resource_type:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != resource_id:
                continue
            return name_entry.directory.entries[0]
    raise ValueError(f"PE 资源 type={resource_type} id={resource_id} 未找到")


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def _append_expanded_resource(
    pe: pefile.PE,
    pe_data: bytes,
    resource_info_offset: int,
    new_resource_data: bytes,
) -> bytes:
    """Append resource data to the last section and repoint the resource entry."""
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    last_section = max(
        pe.sections,
        key=lambda section: section.PointerToRawData + section.SizeOfRawData,
    )

    patched = bytearray(pe_data)
    append_offset = _align(len(patched), file_alignment)
    if append_offset > len(patched):
        patched.extend(b"\x00" * (append_offset - len(patched)))

    new_rva = (
        last_section.VirtualAddress
        + (append_offset - last_section.PointerToRawData)
    )
    patched.extend(new_resource_data)

    new_raw_end = append_offset + len(new_resource_data)
    new_raw_size = _align(
        new_raw_end - last_section.PointerToRawData,
        file_alignment,
    )
    padded_end = last_section.PointerToRawData + new_raw_size
    if padded_end > len(patched):
        patched.extend(b"\x00" * (padded_end - len(patched)))

    new_virtual_size = max(
        last_section.Misc_VirtualSize,
        (new_rva - last_section.VirtualAddress) + len(new_resource_data),
    )
    new_size_of_image = _align(
        last_section.VirtualAddress + new_virtual_size,
        section_alignment,
    )

    # IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (RVA), Size, CodePage, Reserved.
    struct.pack_into("<II", patched, resource_info_offset, new_rva, len(new_resource_data))

    section_offset = last_section.get_file_offset()
    struct.pack_into("<I", patched, section_offset + 8, new_virtual_size)
    struct.pack_into("<I", patched, section_offset + 16, new_raw_size)
    struct.pack_into(
        "<I",
        patched,
        section_offset + 36,
        last_section.Characteristics
        | IMAGE_SCN_CNT_INITIALIZED_DATA
        | IMAGE_SCN_MEM_READ,
    )
    struct.pack_into(
        "<I",
        patched,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
        new_size_of_image,
    )

    return _refresh_pe_checksum(bytes(patched))


def _refresh_pe_checksum(pe_data: bytes) -> bytes:
    """Recalculate the PE checksum when pefile supports it."""
    try:
        pe = pefile.PE(data=pe_data)
        checksum = pe.generate_checksum()
        checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
        pe.close()
    except Exception:
        return pe_data

    patched = bytearray(pe_data)
    struct.pack_into("<I", patched, checksum_offset, checksum)
    return bytes(patched)


# ---------------------------------------------------------------------------
# CRC32 校验 / 修复
# ---------------------------------------------------------------------------

def verify_pe_resource_crc32(
    pe_data: bytes,
    resource_type: int,
    resource_id: int,
) -> tuple[bool, int, int]:
    """验证 PE 文件中指定资源的 CRC32 校验。

    资源头部格式::

        uint32  stored_crc
        uint32  payload_size
        bytes   payload[payload_size]

    返回 (match, stored_crc, calc_crc)。
    """
    pe = pefile.PE(data=pe_data)
    image = pe.get_memory_mapped_image()

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != resource_type:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != resource_id:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            resource_rva = info.OffsetToData
            resource_size = info.Size

            resource = image[resource_rva : resource_rva + resource_size]
            stored_crc, payload_size = struct.unpack_from("<II", resource, 0)
            calc_crc = binascii.crc32(resource[8 : 8 + payload_size]) & 0xFFFFFFFF
            pe.close()
            return (stored_crc == calc_crc, stored_crc, calc_crc)

    pe.close()
    raise ValueError(f"资源 RT_RCDATA/{resource_id} 未找到")


def fix_pe_resource_crc32(
    pe_data: bytes,
    resource_type: int,
    resource_id: int,
) -> bytes:
    """重新计算并修复 PE 文件中指定资源的 CRC32 校验，返回修复后的 PE 字节数据。"""
    pe = pefile.PE(data=pe_data)
    image = pe.get_memory_mapped_image()

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != resource_type:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != resource_id:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            resource_rva = info.OffsetToData
            resource_size = info.Size
            resource_offset = pe.get_offset_from_rva(resource_rva)

            resource = image[resource_rva : resource_rva + resource_size]
            _stored_crc, payload_size = struct.unpack_from("<II", resource, 0)
            calc_crc = binascii.crc32(
                resource[8 : 8 + payload_size]
            ) & 0xFFFFFFFF

            patched = bytearray(pe_data)
            struct.pack_into("<I", patched, resource_offset, calc_crc)
            pe.close()
            return bytes(patched)

    pe.close()
    raise ValueError(f"资源 RT_RCDATA/{resource_id} 未找到")


# ---------------------------------------------------------------------------
# Nuitka 常量资源分析（基础 — 保持向后兼容）
# ---------------------------------------------------------------------------

def inspect_nuitka_constants_resource(resource_data: bytes) -> dict:
    """解析 Nuitka 常量资源 (RT_RCDATA/3) 的头部信息。

    自动检测旧版（CRC32 头部）和新版格式。

    返回::

        {
            "version": "legacy" | "new",
            "stored_crc": "0x..." | None,
            "payload_size": int,
            "calc_crc": "0x..." | None,
            "match": bool | None,
            "payload_preview": "0x...",
        }
    """
    if len(resource_data) < 4:
        return {
            "version": "unknown",
            "stored_crc": None,
            "payload_size": len(resource_data),
            "calc_crc": None,
            "match": None,
            "payload_preview": resource_data[:16].hex(" ").upper(),
        }

    # 尝试旧版格式
    if len(resource_data) >= 8:
        stored_crc, payload_size = struct.unpack_from("<II", resource_data, 0)
        if payload_size == len(resource_data) - 8:
            payload = resource_data[8 : 8 + payload_size]
            calc_crc = binascii.crc32(payload) & 0xFFFFFFFF
            if stored_crc == calc_crc:
                return {
                    "version": "legacy",
                    "stored_crc": f"0x{stored_crc:08x}",
                    "payload_size": payload_size,
                    "calc_crc": f"0x{calc_crc:08x}",
                    "match": True,
                    "payload_preview": payload[:16].hex(" ").upper(),
                }
            # CRC 不匹配但 size 匹配 — 可能是被修改过的旧版
            return {
                "version": "legacy (modified)",
                "stored_crc": f"0x{stored_crc:08x}",
                "payload_size": payload_size,
                "calc_crc": f"0x{calc_crc:08x}",
                "match": False,
                "payload_preview": payload[:16].hex(" ").upper(),
            }

    # 新版格式：直接是 section 数据
    return {
        "version": "new",
        "stored_crc": None,
        "payload_size": len(resource_data),
        "calc_crc": None,
        "match": None,
        "payload_preview": resource_data[:16].hex(" ").upper(),
    }


def dump_constants_payload(payload: bytes, max_preview: int = 128) -> dict:
    """深度分析 Nuitka 常量资源 payload，使用 TLV 解析器。

    返回::

        {
            "version": "legacy" | "new",
            "payload_size": int,
            "hex_preview": str,
            "section_count": int,
            "constant_count": int,
            "sections": [{"name": str, "count": int, ...}, ...],
            "strings": [str, ...],
            "code_objects": int,
        }
    """
    result_parse = parse_blob(payload)

    # 提取可读字符串
    strings: list[str] = []
    current = []
    for byte in payload:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= 4:
                s = "".join(current)
                if s not in strings:
                    strings.append(s)
            current = []
    if len(current) >= 4:
        s = "".join(current)
        if s not in strings:
            strings.append(s)

    # 收集代码对象信息
    code_objects = format_code_objects(result_parse)

    section_info = []
    for section in result_parse.sections:
        code_count = sum(
            1 for c in section.constants
            if isinstance(c, CodeObjectData)
        )
        section_info.append({
            "name": section.name if section.name else "(global)",
            "count": len(section.constants),
            "data_size": section.data_size,
            "code_objects": code_count,
        })

    return {
        "version": result_parse.version,
        "payload_size": result_parse.total_size,
        "hex_preview": payload[:max_preview].hex(" ").upper(),
        "section_count": len(result_parse.sections),
        "constant_count": result_parse.constant_count,
        "sections": section_info,
        "strings": strings[:50],
        "code_objects": len(code_objects),
    }


# ---------------------------------------------------------------------------
# Nuitka 常量资源替换（自动修复 CRC）
# ---------------------------------------------------------------------------

def replace_nuitka_constants_payload(
    pe_data: bytes,
    new_payload: bytes,
) -> bytes:
    """替换 PE 中 Nuitka 常量资源 (RT_RCDATA/3) 的 payload，自动修复 CRC32。

    自动检测旧版/新版格式：
    - 旧版：新 payload 会被加上 CRC32 + data_size 头部
    - 新版：新 payload 直接写入

    参数:
        pe_data: PE 文件字节数据
        new_payload: 新的常量 payload（不含旧版头部的纯 section 数据）

    返回:
        修复后的 PE 文件字节数据

    变长 payload 会自动迁移到 PE 最后一个 section 的末尾，并更新资源 RVA/Size。
    """
    pe = pefile.PE(data=pe_data)
    image = pe.get_memory_mapped_image()

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != 10:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != 3:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            resource_rva = info.OffsetToData
            resource_size = info.Size

            resource = image[resource_rva : resource_rva + resource_size]

            # 检测当前资源格式
            is_legacy = False
            if len(resource) >= 8:
                stored_crc, payload_size = struct.unpack_from("<II", resource, 0)
                if payload_size == len(resource) - 8:
                    actual_crc = binascii.crc32(resource[8:]) & 0xFFFFFFFF
                    if actual_crc == stored_crc:
                        is_legacy = True

            # 构建新的资源数据
            if is_legacy:
                # 旧版格式：CRC32 + data_size + payload
                crc = binascii.crc32(new_payload) & 0xFFFFFFFF
                new_resource_data = struct.pack("<II", crc, len(new_payload)) + new_payload
            else:
                # 新版格式：直接是 payload
                new_resource_data = new_payload

            new_total = len(new_resource_data)
            version_str = "legacy" if is_legacy else "new"

            pe.close()
            patched = replace_pe_resource_data(pe_data, 10, 3, new_resource_data)

            if new_total > resource_size:
                print(
                    f"    +-- Nuitka 常量资源已迁移扩容 ({version_str} 格式, "
                    f"new_size={new_total:,} bytes, was {resource_size:,} bytes, "
                    f"expanded=+{new_total - resource_size:,} bytes)"
                )
            else:
                print(
                    f"    +-- Nuitka 常量资源已替换 ({version_str} 格式, "
                    f"new_size={new_total:,} bytes, was {resource_size:,} bytes)"
                )
            return patched

    pe.close()
    raise ValueError("Nuitka 常量资源 (RT_RCDATA/3) 未找到")


# ---------------------------------------------------------------------------
# Nuitka 常量资源 TLV 解析（高级 API）
# ---------------------------------------------------------------------------

def parse_nuitka_constants_resource(pe_data: bytes) -> BlobParseResult:
    """从 PE 文件中提取并完整解析 Nuitka 常量资源 (RT_RCDATA/3)。

    返回 BlobParseResult，包含所有 section 和常量的解析结果。
    """
    resource_raw = get_pe_resource_data(pe_data, 10, 3)
    return parse_blob(resource_raw)


def format_nuitka_constants_resource(pe_data: bytes, max_items: int = 50) -> str:
    """从 PE 文件中提取并格式化显示 Nuitka 常量资源。"""
    resource_raw = get_pe_resource_data(pe_data, 10, 3)
    result = parse_blob(resource_raw)

    lines = []
    lines.append(f"资源原始大小: {len(resource_raw):,} bytes")
    lines.append("")
    lines.append(format_blob_summary(result))
    lines.append("─── Sections ───")
    lines.append(format_blob_tree(result, max_items=max_items))
    return "\n".join(lines)


def rebuild_nuitka_constants_resource(
    pe_data: bytes,
    sections: list[tuple[str, list[Any]]],
) -> bytes:
    """重建 Nuitka 常量资源并替换到 PE 中。

    自动检测原始资源格式（旧版/新版），构建对应格式的新数据。

    Args:
        pe_data: PE 文件字节数据
        sections: list of (section_name, constants_list)

    Returns:
        修改后的 PE 文件字节数据
    """
    # 检测原始格式
    resource_raw = get_pe_resource_data(pe_data, 10, 3)
    info = inspect_nuitka_constants_resource(resource_raw)
    is_legacy = info["version"].startswith("legacy")

    # 构建新 blob
    new_blob = build_blob(sections, legacy=is_legacy)

    # 替换资源
    return replace_nuitka_constants_payload(pe_data, new_blob)


# ---------------------------------------------------------------------------
# 通用二进制搜索替换
# ---------------------------------------------------------------------------

def find_all_occurrences(data: bytes, pattern: bytes) -> list[tuple[int, int]]:
    """在二进制数据中查找 pattern 的所有出现位置，返回 [(start, end), ...]。"""
    positions: list[tuple[int, int]] = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        positions.append((idx, idx + len(pattern)))
        start = idx + 1
    return positions
