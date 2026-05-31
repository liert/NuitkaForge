"""
Nuitka Forge 核心调度模块。

提供所有功能的统一导入入口和公共工具函数。

子模块说明：
- onefile.py  — Nuitka 打包 EXE（onefile）处理：资源提取、zstd、archive 遍历/重建/替换、写回
- peutils.py  — 解包后的 PE 文件处理：PE 资源枚举、CRC 校验/修复、常量资源深度分析
- constants.py — Nuitka 常量 Blob (RT_RCDATA/3) TLV 格式解析与序列化
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# 公共工具函数
# ---------------------------------------------------------------------------

def get_file_magic(data: bytes) -> str:
    """获取数据前 4 字节的十六进制表示，用于判断文件类型。"""
    return data[:4].hex(" ").upper() if len(data) >= 4 else data.hex(" ").upper()


# ---------------------------------------------------------------------------
# 从 onefile 模块 re-export
# ---------------------------------------------------------------------------

from .onefile import (  # noqa: E402, F401
    MAGIC_KAY,
    RESOURCE_TYPE_RCDATA,
    RESOURCE_ID_ONEFILE,
    ZSTD_CHUNK_SIZE,
    ArchiveEntry,
    extract_onefile_resource,
    decompress_onefile_payload,
    compress_onefile_archive,
    iter_archive_entries,
    list_archive,
    extract_archive_to_dir,
    rebuild_archive,
    rebuild_archive_from_dir,
    replace_archive_entry,
    update_exe_resource,
    get_archive_from_exe,
    pack_and_write_exe,
)


# ---------------------------------------------------------------------------
# 从 peutils 模块 re-export
# ---------------------------------------------------------------------------

from .peutils import (  # noqa: E402, F401
    RESOURCE_TYPE_NAMES,
    NUITKA_OBJECT_MARKERS,
    PEResourceEntry,
    list_pe_resources,
    get_pe_resource_data,
    verify_pe_resource_crc32,
    fix_pe_resource_crc32,
    inspect_nuitka_constants_resource,
    dump_constants_payload,
    replace_nuitka_constants_payload,
    find_all_occurrences,
    parse_nuitka_constants_resource,
    format_nuitka_constants_resource,
    rebuild_nuitka_constants_resource,
)


# ---------------------------------------------------------------------------
# 从 constants 模块 re-export
# ---------------------------------------------------------------------------

from .constants import (  # noqa: E402, F401
    BlobParseResult,
    BlobSection,
    CodeObjectData,
    SearchMatch,
    parse_blob,
    parse_constant,
    parse_varint,
    encode_constant,
    build_section,
    build_blob,
    build_constants_resource,
    replace_sections_in_blob,
    format_blob_summary,
    format_blob_tree,
    format_code_objects,
    search_constants,
)


# ---------------------------------------------------------------------------
# 从 config 模块 re-export
# ---------------------------------------------------------------------------

from .config import (  # noqa: E402, F401
    CONFIG_PATH,
    FilterConfig,
    NuitkaForgeConfig,
    load_config,
    save_config,
    filter_sections,
)
