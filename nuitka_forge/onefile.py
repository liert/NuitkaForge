"""
Nuitka onefile 打包文件处理模块。

处理 Nuitka 编译的单个 EXE 中的 onefile 资源包：
- 从 EXE 中提取 onefile 资源 (RT_RCDATA 10/27)
- KAY + zstd 格式的解压与压缩
- Nuitka 自定义 archive 格式的遍历与重建
- 将资源写回 EXE
"""

from __future__ import annotations

import ctypes
import io
import struct
from ctypes import wintypes
from pathlib import Path
from typing import Iterator, NamedTuple

import pefile
import zstandard as zstd


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
MAGIC_KAY = b"KAY"
RESOURCE_TYPE_RCDATA = 10
RESOURCE_ID_ONEFILE = 27
ZSTD_CHUNK_SIZE = 1024 * 1024  # 1 MB


class ArchiveEntry(NamedTuple):
    """Onefile archive 中单个条目的信息。"""

    name: str
    name_offset: int
    size_offset: int
    size: int
    data_offset: int
    data_end: int


# ---------------------------------------------------------------------------
# 资源提取
# ---------------------------------------------------------------------------

def extract_onefile_resource(exe_path: Path | str) -> bytes:
    """从 EXE 中提取 RT_RCDATA 10/27 资源原始字节。"""
    pe = pefile.PE(str(exe_path))
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != RESOURCE_TYPE_RCDATA:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != RESOURCE_ID_ONEFILE:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            return bytes(
                pe.get_memory_mapped_image()[
                    info.OffsetToData : info.OffsetToData + info.Size
                ]
            )
    raise ValueError(f"资源 RT_RCDATA/{RESOURCE_ID_ONEFILE} 未找到: {exe_path}")


# ---------------------------------------------------------------------------
# 解压 / 压缩
# ---------------------------------------------------------------------------

def decompress_onefile_payload(payload: bytes) -> bytes:
    """解压 KAY + zstd 格式的 onefile payload。

    zstd 流后可能有 Nuitka 附加数据，遇到 Unknown frame descriptor 时
    只要已有输出即可认为第一帧完整。
    """
    if not payload.startswith(MAGIC_KAY):
        raise ValueError("unexpected onefile payload header (missing KAY)")

    out = bytearray()
    try:
        with zstd.ZstdDecompressor().stream_reader(
            io.BytesIO(payload[len(MAGIC_KAY) :]),
            read_across_frames=False,
        ) as reader:
            while True:
                chunk = reader.read(ZSTD_CHUNK_SIZE)
                if not chunk:
                    break
                out.extend(chunk)
    except zstd.ZstdError:
        if not out:
            raise

    return bytes(out)


def compress_onefile_archive(archive: bytes, level: int = 6) -> bytes:
    """将 archive 重新压缩为 KAY + zstd 格式。"""
    return MAGIC_KAY + zstd.ZstdCompressor(level=level).compress(archive)


# ---------------------------------------------------------------------------
# archive 遍历
# ---------------------------------------------------------------------------

def iter_archive_entries(archive: bytes) -> Iterator[ArchiveEntry]:
    """遍历 Nuitka onefile archive 中的每个条目。

    条目格式::

        utf16le_filename + uint16_zero + uint64le_file_size + file_bytes

    末尾有一个空 UTF-16 名称 (00 00) 作为结束标记。
    """
    pos = 0
    while pos < len(archive):
        # 查找 UTF-16LE NUL 终止符 (00 00)
        end = None
        q = pos
        while q + 1 < len(archive):
            if archive[q : q + 2] == b"\x00\x00":
                end = q
                break
            q += 2

        if end is None:
            raise ValueError(f"unterminated UTF-16 file name at 0x{pos:x}")

        name_bytes = archive[pos:end]
        if not name_bytes:
            return

        name = name_bytes.decode("utf-16le")
        size_offset = end + 2
        size = struct.unpack_from("<Q", archive, size_offset)[0]
        data_offset = size_offset + 8
        data_end = data_offset + size

        if data_end > len(archive):
            raise ValueError(f"archive entry {name!r} exceeds archive size")

        yield ArchiveEntry(name, pos, size_offset, size, data_offset, data_end)
        pos = data_end


def list_archive(archive: bytes) -> list[ArchiveEntry]:
    """列出 archive 中所有条目，返回列表。"""
    return list(iter_archive_entries(archive))


# ---------------------------------------------------------------------------
# 解压到目录
# ---------------------------------------------------------------------------

def extract_archive_to_dir(archive: bytes, out_dir: Path | str) -> None:
    """将 archive 中所有文件释放到指定目录。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for entry in iter_archive_entries(archive):
        out_path = out_dir / entry.name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(archive[entry.data_offset : entry.data_end])


# ---------------------------------------------------------------------------
# 重建 archive
# ---------------------------------------------------------------------------

def rebuild_archive(entries: list[tuple[str, bytes]]) -> bytes:
    """从 (name, data) 列表重建 Nuitka onefile archive。

    保持传入顺序，末尾自动添加空名称结束标记。
    """
    parts: list[bytes] = []
    for name, data in entries:
        name_encoded = name.encode("utf-16le")
        parts.append(name_encoded)
        parts.append(b"\x00\x00")
        parts.append(struct.pack("<Q", len(data)))
        parts.append(data)
    parts.append(b"\x00\x00")
    return b"".join(parts)


def rebuild_archive_from_dir(
    src_dir: Path | str,
    original_entries: list[ArchiveEntry],
) -> bytes:
    """从目录中的文件按原始条目顺序重建 archive。"""
    src_dir = Path(src_dir)
    entries: list[tuple[str, bytes]] = []
    for entry in original_entries:
        file_path = src_dir / entry.name
        if not file_path.exists():
            raise FileNotFoundError(f"missing file for entry: {entry.name}")
        entries.append((entry.name, file_path.read_bytes()))
    return rebuild_archive(entries)


# ---------------------------------------------------------------------------
# 替换条目
# ---------------------------------------------------------------------------

def replace_archive_entry(
    archive: bytes,
    target_name: str,
    new_data: bytes,
) -> bytes:
    """替换 archive 中指定名称的条目（支持不同长度，自动重建 archive）。"""
    entries: list[tuple[str, bytes]] = []
    replaced = False
    for entry in iter_archive_entries(archive):
        if entry.name == target_name:
            entries.append((entry.name, new_data))
            replaced = True
        else:
            entries.append(
                (entry.name, archive[entry.data_offset : entry.data_end])
            )
    if not replaced:
        raise ValueError(f"entry not found: {target_name}")
    return rebuild_archive(entries)


# ---------------------------------------------------------------------------
# Windows 资源写回
# ---------------------------------------------------------------------------

def _make_int_resource(value: int):
    return ctypes.cast(ctypes.c_void_p(value), ctypes.c_wchar_p)


def update_exe_resource(
    exe_path: Path | str,
    resource_data: bytes,
    resource_type: int = RESOURCE_TYPE_RCDATA,
    resource_id: int = RESOURCE_ID_ONEFILE,
    lang_id: int = 0,
) -> None:
    """将资源数据写入 EXE 的 PE 资源段。"""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    BeginUpdateResourceW = kernel32.BeginUpdateResourceW
    BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    BeginUpdateResourceW.restype = wintypes.HANDLE

    UpdateResourceW = kernel32.UpdateResourceW
    UpdateResourceW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.WORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    UpdateResourceW.restype = wintypes.BOOL

    EndUpdateResourceW = kernel32.EndUpdateResourceW
    EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    EndUpdateResourceW.restype = wintypes.BOOL

    handle = BeginUpdateResourceW(str(exe_path), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    buf = ctypes.create_string_buffer(resource_data)
    ok = UpdateResourceW(
        handle,
        _make_int_resource(resource_type),
        _make_int_resource(resource_id),
        lang_id,
        buf,
        len(resource_data),
    )
    if not ok:
        err = ctypes.get_last_error()
        EndUpdateResourceW(handle, True)
        raise ctypes.WinError(err)

    if not EndUpdateResourceW(handle, False):
        raise ctypes.WinError(ctypes.get_last_error())


# ---------------------------------------------------------------------------
# 一站式工具函数
# ---------------------------------------------------------------------------

def get_archive_from_exe(exe_path: Path | str) -> bytes:
    """从 EXE 中提取并解压 onefile archive。"""
    payload = extract_onefile_resource(exe_path)
    return decompress_onefile_payload(payload)


def pack_and_write_exe(
    exe_path: Path | str,
    out_path: Path | str,
    archive: bytes,
    level: int = 6,
) -> None:
    """将 archive 压缩后写回 EXE 副本。"""
    import shutil

    src = Path(exe_path)
    dst = Path(out_path)
    if src.resolve() != dst.resolve():
        shutil.copy2(src, dst)

    payload = compress_onefile_archive(archive, level=level)
    update_exe_resource(dst, payload)
