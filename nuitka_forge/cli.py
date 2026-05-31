"""
Nuitka Forge — Nuitka onefile 资源包处理工具的 CLI 入口。

子命令::

    extract          将 onefile 包解压到目录
    pack             从目录重建 onefile 包并写回 EXE
    replace          替换 archive 中的指定条目
    verify           验证 onefile 包结构
    info             显示 EXE 的 onefile 资源概要信息
    inspect-dll      检查 DLL/EXE 的 PE 资源目录（含 Nuitka 常量 CRC 校验）
    parse-constants  解析并显示 Nuitka 常量资源 (RT_RCDATA/3) 的完整 TLV 结构
    replace-constants  重建并替换 Nuitka 常量资源 (RT_RCDATA/3)
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from .core import get_file_magic
from .onefile import (
    compress_onefile_archive,
    decompress_onefile_payload,
    extract_archive_to_dir,
    extract_onefile_resource,
    iter_archive_entries,
    rebuild_archive,
    rebuild_archive_from_dir,
    replace_archive_entry,
    update_exe_resource,
)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("exe", help="Nuitka onefile EXE 路径")


def _load_archive(exe: str) -> tuple[bytes, bytes, bytes]:
    """返回 (payload, archive, exe_path_bytes)。"""
    exe_path = Path(exe)
    payload = extract_onefile_resource(exe_path)
    archive = decompress_onefile_payload(payload)
    return payload, archive, exe_path


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------

def cmd_extract(args: argparse.Namespace) -> None:
    """将 onefile 包解压到目录。"""
    _, archive, _ = _load_archive(args.exe)

    # 未指定 --out 时，默认输出目录为 "程序名_extracted"
    out_dir = Path(args.out) if args.out else Path(Path(args.exe).stem + "_extracted")

    extract_archive_to_dir(archive, out_dir)

    count = len(list(iter_archive_entries(archive)))
    print(f"已将 {count} 个文件解压到: {out_dir.resolve()}")


def setup_extract_parser(subparsers) -> None:
    p = subparsers.add_parser("extract", help="将 onefile 包解压到目录")
    _add_common_args(p)
    p.add_argument("--out", "-o", default=None, help="输出目录路径（默认: 程序名_extracted）")
    p.set_defaults(func=cmd_extract)


# ---------------------------------------------------------------------------
# pack
# ---------------------------------------------------------------------------

def cmd_pack(args: argparse.Namespace) -> None:
    """从目录重建 onefile 包并写回 EXE。"""
    payload, archive, exe_path = _load_archive(args.exe)
    src_dir = Path(args.src_dir)

    if not src_dir.is_dir():
        print(f"错误: 目录不存在: {src_dir}", file=sys.stderr)
        sys.exit(1)

    # 获取原始条目顺序
    original_entries = list(iter_archive_entries(archive))

    # 重建
    new_archive = rebuild_archive_from_dir(src_dir, original_entries)

    # 未指定 --out 时，默认输出为 "程序名.patch.exe"
    out_path = Path(args.out) if args.out else Path(Path(args.exe).stem + ".patch.exe")

    # 压缩并写回
    level = args.level
    new_payload = compress_onefile_archive(new_archive, level=level)

    shutil.copy2(exe_path, out_path)
    update_exe_resource(out_path, new_payload)

    print(f"原始大小:     {len(payload):>12,} bytes")
    print(f"新资源大小:   {len(new_payload):>12,} bytes")
    print(f"压缩等级:     {level}")
    print(f"输出:         {out_path.resolve()}")


def setup_pack_parser(subparsers) -> None:
    p = subparsers.add_parser("pack", help="从目录重建 onefile 包并写回 EXE")
    _add_common_args(p)
    p.add_argument("--src-dir", required=True, help="包含原始条目文件的目录")
    p.add_argument("--out", "-o", default=None, help="输出 EXE 路径（默认: 程序名.patch.exe）")
    p.add_argument(
        "--level", type=int, default=6, choices=range(1, 23),
        help="zstd 压缩等级 (1-22, 默认 6)",
    )
    p.set_defaults(func=cmd_pack)


# ---------------------------------------------------------------------------
# replace
# ---------------------------------------------------------------------------

def cmd_replace(args: argparse.Namespace) -> None:
    """替换 archive 中的指定条目。"""
    payload, archive, exe_path = _load_archive(args.exe)
    new_data = Path(args.file).read_bytes()

    new_archive = replace_archive_entry(archive, args.name, new_data)
    out_path = Path(args.out)

    new_payload = compress_onefile_archive(new_archive, level=args.level)

    shutil.copy2(exe_path, out_path)
    update_exe_resource(out_path, new_payload)

    print(f"已替换条目:   {args.name}")
    print(f"原始大小:     {len(payload):>12,} bytes")
    print(f"新资源大小:   {len(new_payload):>12,} bytes")
    print(f"输出:         {out_path.resolve()}")


def setup_replace_parser(subparsers) -> None:
    p = subparsers.add_parser("replace", help="替换 archive 中的指定条目")
    _add_common_args(p)
    p.add_argument("--name", required=True, help="要替换的条目名称 (如 mask.dll)")
    p.add_argument("--file", required=True, help="替换用文件路径")
    p.add_argument("--out", required=True, help="输出 EXE 路径")
    p.add_argument(
        "--level", type=int, default=6, choices=range(1, 23),
        help="zstd 压缩等级 (1-22, 默认 6)",
    )
    p.set_defaults(func=cmd_replace)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> None:
    """验证 onefile 包结构完整性。"""
    payload, archive, _ = _load_archive(args.exe)

    errors: list[str] = []

    # 1. 检查 KAY 头
    if not payload.startswith(b"KAY"):
        errors.append("PAYLOAD: 缺少 KAY 头")

    # 2. 检查条目完整性
    entries = list(iter_archive_entries(archive))

    # 检查末尾结束标记
    if not entries or entries[-1].name != "":
        # 验证空名称结束标记
        last_entry = entries[-1]
        after_last = last_entry.data_end
        remaining = archive[after_last:]
        if remaining != b"\x00\x00":
            errors.append(
                f"ARCHIVE: 末尾缺少空名称结束标记 "
                f"(剩余 {len(remaining)} bytes: {remaining[:8].hex()})"
            )

    # 3. 检查条目总数
    print(f"资源头:       {'KAY + zstd' if payload.startswith(b'KAY') else '未知'}")
    print(f"资源大小:     {len(payload):>12,} bytes")
    print(f"解压后大小:   {len(archive):>12,} bytes")
    print(f"条目总数:     {len(entries)}")
    print(f"条目检查:     {'通过' if not errors else '失败'}")

    if errors:
        print("\n发现错误:")
        for err in errors:
            print(f"  [X] {err}")
        sys.exit(1)
    else:
        print("\n[OK] 验证通过 -- onefile 包结构完整")


def setup_verify_parser(subparsers) -> None:
    p = subparsers.add_parser("verify", help="验证 onefile 包结构完整性")
    _add_common_args(p)
    p.set_defaults(func=cmd_verify)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def cmd_info(args: argparse.Namespace) -> None:
    """显示 EXE 的 onefile 资源概要信息。"""
    from pefile import PE

    pe = PE(str(args.exe))

    print(f"EXE 路径:     {args.exe}")
    print(f"PE 类型:      {'PE32+' if pe.OPTIONAL_HEADER.Magic == 0x20B else 'PE32'}")
    print(f"入口点:       0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")

    # 检查 onefile 资源
    found = False
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != 10:
            continue
        for name_entry in entry.directory.entries:
            if name_entry.id != 27:
                continue
            lang_entry = name_entry.directory.entries[0]
            info = lang_entry.data.struct
            found = True
            print(f"\nonefile 资源:")
            print(f"  RT_RCDATA:  type=10, id=27, lang={lang_entry.id}")
            print(f"  资源大小:   {info.Size:,} bytes")
            print(f"  数据 RVA:   0x{info.OffsetToData:08X}")

    if not found:
        print("\n[!] 未找到 onefile 资源 (RT_RCDATA 10/27)")
        print("   该 EXE 可能不是 Nuitka onefile 程序。")

    # 检查可用资源类型统计
    print(f"\n资源目录统计:")
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        names = [str(e.id) for e in entry.directory.entries]
        print(f"  type={entry.id}: ids=[{', '.join(names[:5])}{'...' if len(names) > 5 else ''}]")


def setup_info_parser(subparsers) -> None:
    p = subparsers.add_parser("info", help="显示 EXE 的 onefile 资源概要信息")
    _add_common_args(p)
    p.set_defaults(func=cmd_info)


# ---------------------------------------------------------------------------
# inspect-dll
# ---------------------------------------------------------------------------

RT_RCDATA = 10
NUITKA_CONSTANTS_ID = 3


def cmd_inspect_dll(args: argparse.Namespace) -> None:
    """检查任意 DLL/EXE 的 PE 资源目录（含 Nuitka 常量 CRC 校验）。"""
    pe_path = Path(args.pe)
    if not pe_path.is_file():
        print(f"错误: 文件不存在: {pe_path}", file=sys.stderr)
        sys.exit(1)

    dll_data = pe_path.read_bytes()

    print(f"正在检查: {pe_path}")
    print(f"文件大小:  {len(dll_data):>12,} bytes")
    print(f"文件 Magic: {get_file_magic(dll_data):>12s}")
    print()

    if not dll_data[:2] == b"MZ":
        print("[!] 该文件不是有效的 PE 文件（缺少 MZ 头）")
        sys.exit(1)

    from .peutils import (
        dump_constants_payload,
        format_nuitka_constants_resource,
        get_pe_resource_data,
        inspect_nuitka_constants_resource,
        list_pe_resources,
    )

    resources = list_pe_resources(dll_data)

    if not resources:
        print("该文件没有 PE 资源目录。")
        return

    print(f"共发现 {len(resources)} 个 PE 资源:\n")

    print(f"{'类型':<20s} {'ID':<12s} {'语言':<6s} {'大小':>12s}  {'偏移'}")
    print("-" * 80)

    for res in resources:
        type_str = f"{res.type_name} ({res.type_id})"
        name_str = str(res.name_id)
        lang_str = str(res.lang_id)
        print(
            f"  {type_str:<20s} {name_str:<12s} {lang_str:<6s} "
            f"{res.size:>12,} bytes  @0x{res.data_offset:x}"
        )

        # 如果是 Nuitka 常量资源，显示 CRC 校验详情
        if res.type_id == RT_RCDATA and res.name_id == NUITKA_CONSTANTS_ID:
            try:
                resource_raw = get_pe_resource_data(
                    dll_data, RT_RCDATA, NUITKA_CONSTANTS_ID
                )
                info = inspect_nuitka_constants_resource(resource_raw)
                version_str = info["version"]
                print(
                    f"    +-- Nuitka 常量资源 ({version_str}):"
                )
                if info.get("stored_crc"):
                    status = "OK" if info["match"] else "MISMATCH"
                    print(
                        f"       stored_crc={info['stored_crc']}"
                        f" calc_crc={info['calc_crc']}"
                        f" payload_size={info['payload_size']:,} bytes"
                        f" [{status}]"
                    )
                else:
                    print(f"       size={info['payload_size']:,} bytes (无 CRC 头)")

                # 如果指定了 --constants，使用 TLV 解析器深度分析
                if args.constants:
                    print()
                    print(format_nuitka_constants_resource(dll_data, max_items=100))

            except Exception as e:
                print(f"    +-- CRC 检查失败: {e}")


def setup_inspect_dll_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "inspect-dll",
        help="检查 DLL/EXE 的 PE 资源目录（含 Nuitka 常量 CRC 校验）",
    )
    p.add_argument("pe", help="DLL/EXE 文件路径（提取后的 PE 文件）")
    p.add_argument(
        "--constants", "-c",
        action="store_true",
        help="深度分析 Nuitka 常量资源 payload（TLV 完整解析）",
    )
    p.set_defaults(func=cmd_inspect_dll)


# ---------------------------------------------------------------------------
# parse-constants
# ---------------------------------------------------------------------------

def cmd_parse_constants(args: argparse.Namespace) -> None:
    """解析并显示 Nuitka 常量资源 (RT_RCDATA/3) 的完整 TLV 结构。"""
    pe_path = Path(args.pe)
    if not pe_path.is_file():
        print(f"错误: 文件不存在: {pe_path}", file=sys.stderr)
        sys.exit(1)

    pe_data = pe_path.read_bytes()
    if not pe_data[:2] == b"MZ":
        print("[!] 该文件不是有效的 PE 文件（缺少 MZ 头）", file=sys.stderr)
        sys.exit(1)

    from .peutils import (
        get_pe_resource_data,
        inspect_nuitka_constants_resource,
        parse_nuitka_constants_resource,
    )
    from .constants import (
        BlobParseResult,
        CodeObjectData,
        format_blob_summary,
        format_blob_tree,
        format_code_objects,
        parse_blob,
    )
    from .config import load_config, filter_sections

    cfg = load_config()
    show_all = getattr(args, "all_sections", False)

    try:
        resource_raw = get_pe_resource_data(pe_data, 10, 3)
    except ValueError:
        print("[!] 未找到 Nuitka 常量资源 (RT_RCDATA/3)", file=sys.stderr)
        sys.exit(1)

    info = inspect_nuitka_constants_resource(resource_raw)

    if args.format == "info":
        # 仅显示概要
        print(f"文件:     {pe_path}")
        print(f"版本:     {info['version']}")
        if info.get("stored_crc"):
            status = "OK" if info["match"] else "MISMATCH"
            print(f"CRC32:    stored={info['stored_crc']} calc={info['calc_crc']} [{status}]")
        print(f"大小:     {info['payload_size']:,} bytes")
        return

    # 构建跳过集合：--all 时不跳过任何 section
    skip_names = None
    skip_prefixes = None
    if not show_all:
        fc = cfg.section_filter
        if fc.hide_names:
            skip_names = set(fc.hide_names)
        if fc.hide_prefixes:
            skip_prefixes = tuple(fc.hide_prefixes)

    result = parse_blob(resource_raw, skip_names=skip_names, skip_prefixes=skip_prefixes)

    if args.format == "json":
        # JSON 输出
        json_data = {
            "file": str(pe_path),
            "version": result.version,
            "crc32": result.crc32,
            "total_size": result.total_size,
            "section_count": len(result.sections),
            "constant_count": result.constant_count,
            "sections": [],
        }
        for section in result.sections:
            section_data = {
                "name": section.name if section.name else "(global)",
                "data_size": section.data_size,
                "constants_count": len(section.constants),
                "constants": [_value_to_json(c) for c in section.constants],
            }
            json_data["sections"].append(section_data)
        print(json.dumps(json_data, ensure_ascii=False, indent=2))
        return

    if args.format == "tree":
        # 树形结构（支持过滤）
        visible, hidden = filter_sections(result.sections, cfg.section_filter, show_all)

        # 临时替换 sections 用于显示
        from dataclasses import replace
        filtered_result = replace(result, sections=visible)

        print(f"文件:     {pe_path}")
        print(f"资源大小: {len(resource_raw):,} bytes")
        print()
        print(format_blob_summary(filtered_result))
        print("─── Sections ───")
        print(format_blob_tree(filtered_result, max_items=args.max_items, hidden_sections=hidden))
        return

    if args.format == "code":
        # 仅显示代码对象
        code_objects = format_code_objects(result)
        print(f"文件:     {pe_path}")

        if code_objects:
            print(f"代码对象: {len(code_objects)} 个 (TAG_CODE_OBJECT)\n")
            for i, co in enumerate(code_objects):
                kind = f" [{co.kind}]" if co.kind else ""
                print(f"  [{i}] {co.qualname}{kind}")
                print(f"      文件行:   {co.line_number}")
                print(f"      参数数:   {co.arg_count}")
                print(f"      变量:     {co.var_names}")
                if co.flag_list:
                    print(f"      标志:     {', '.join(co.flag_list)}")
                print()
        else:
            print("未找到 TAG_CODE_OBJECT 代码对象。")

        # 显示 .bytecode section 信息
        bytecode_section = None
        for section in result.sections:
            if section.name == ".bytecode":
                bytecode_section = section
                break

        if bytecode_section:
            blob_count = sum(
                1 for c in bytecode_section.constants if isinstance(c, bytes)
            )
            total_bytes = sum(
                len(c) for c in bytecode_section.constants if isinstance(c, bytes)
            )
            print(f"\n.bytecode 段:")
            print(f"  条目数:   {blob_count}")
            print(f"  总大小:   {total_bytes:,} bytes")
            print(f"  (代码对象以原始字节码 blob 形式存储)")
        return


def _value_to_json(val) -> any:
    """将解析后的值转换为 JSON 可序列化格式。"""
    if val is None:
        return None
    if val is True or val is False:
        return val
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        return val
    if isinstance(val, bytes):
        return {"__type__": "bytes", "hex": val.hex(), "length": len(val)}
    if isinstance(val, bytearray):
        return {"__type__": "bytearray", "hex": bytes(val).hex(), "length": len(val)}
    if isinstance(val, complex):
        return {"__type__": "complex", "real": val.real, "imag": val.imag}
    # CodeObjectData has flags, name, qualname attributes
    if hasattr(val, "flags") and hasattr(val, "qualname") and hasattr(val, "var_names"):
        return {
            "__type__": "code_object",
            "name": val.name,
            "qualname": val.qualname,
            "line_number": val.line_number,
            "arg_count": val.arg_count,
            "var_names": list(val.var_names),
            "kw_only_count": val.kw_only_count,
            "pos_only_count": val.pos_only_count,
            "flags": val.flags,
            "flag_names": val.flag_list,
            "kind": val.kind,
        }
    if isinstance(val, tuple):
        return {"__type__": "tuple", "items": [_value_to_json(v) for v in val]}
    if isinstance(val, list):
        return [_value_to_json(v) for v in val]
    if isinstance(val, dict):
        return {str(k): _value_to_json(v) for k, v in val.items()}
    if isinstance(val, (set, frozenset)):
        return {"__type__": type(val).__name__, "items": [_value_to_json(v) for v in val]}
    if isinstance(val, slice):
        return {
            "__type__": "slice",
            "start": _value_to_json(val.start),
            "stop": _value_to_json(val.stop),
            "step": _value_to_json(val.step),
        }
    if isinstance(val, range):
        return {
            "__type__": "range",
            "start": val.start,
            "stop": val.stop,
            "step": val.step,
        }
    return str(val)


def setup_parse_constants_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "parse-constants",
        help="解析并显示 Nuitka 常量资源 (RT_RCDATA/3) 的完整 TLV 结构",
    )
    p.add_argument("pe", help="PE 文件路径 (DLL/EXE)")
    p.add_argument(
        "--format", "-f",
        choices=["tree", "json", "code", "info"],
        default="tree",
        help="输出格式: tree=树形结构, json=JSON, code=仅代码对象, info=概要 (默认: tree)",
    )
    p.add_argument(
        "--max-items",
        type=int,
        default=50,
        help="每个 section 最多显示的常量数量 (默认: 50)",
    )
    p.add_argument(
        "--all", "-a",
        dest="all_sections",
        action="store_true",
        help="显示所有 section（忽略配置文件中的过滤规则）",
    )
    p.set_defaults(func=cmd_parse_constants)


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

def cmd_search(args: argparse.Namespace) -> None:
    """在常量资源中搜索字符串，递归搜索容器内部。"""
    pe_path = Path(args.pe)
    if not pe_path.is_file():
        print(f"错误: 文件不存在: {pe_path}", file=sys.stderr)
        sys.exit(1)

    pe_data = pe_path.read_bytes()
    if not pe_data[:2] == b"MZ":
        print("[!] 该文件不是有效的 PE 文件（缺少 MZ 头）", file=sys.stderr)
        sys.exit(1)

    from .peutils import get_pe_resource_data, inspect_nuitka_constants_resource
    from .constants import parse_blob, search_constants
    from .config import load_config

    cfg = load_config()
    show_all = getattr(args, "all_sections", False)

    try:
        resource_raw = get_pe_resource_data(pe_data, 10, 3)
    except ValueError:
        print("[!] 未找到 Nuitka 常量资源 (RT_RCDATA/3)", file=sys.stderr)
        sys.exit(1)

    info = inspect_nuitka_constants_resource(resource_raw)

    # 构建跳过集合
    skip_names = None
    skip_prefixes = None
    if not show_all:
        fc = cfg.section_filter
        if fc.hide_names:
            skip_names = set(fc.hide_names)
        if fc.hide_prefixes:
            skip_prefixes = tuple(fc.hide_prefixes)

    result = parse_blob(resource_raw, skip_names=skip_names, skip_prefixes=skip_prefixes)

    query = args.query
    matches = search_constants(
        result,
        query,
        ignore_case=args.ignore_case,
        use_regex=args.regex,
        max_results=args.max_results,
    )

    # 统计
    skipped_count = sum(1 for s in result.sections if not s.constants and s.data_size > 0)
    parsed_count = len(result.sections) - skipped_count
    print(f"搜索: {query!r}  (sections: {parsed_count} parsed, {skipped_count} skipped)")
    print(f"结果: {len(matches)} 匹配" + (f" (上限 {args.max_results})" if len(matches) >= args.max_results else ""))
    print()

    if not matches:
        print("未找到匹配项。")
        if not show_all and skipped_count > 0:
            print("提示: 使用 --all 搜索所有 section（包括被配置过滤的）")
        return

    # 按 section 分组显示
    current_section = None
    for m in matches:
        if m.section_name != current_section:
            current_section = m.section_name
            print(f"[{current_section}]")
        display = m.value if len(str(m.value)) <= 80 else str(m.value)[:77] + "..."
        print(f"  {m.path}")
        print(f"    = {display!r}")


def setup_search_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "search",
        help="在常量资源中搜索字符串（递归搜索容器内部）",
    )
    p.add_argument("pe", help="PE 文件路径 (DLL/EXE)")
    p.add_argument("query", help="搜索文本")
    p.add_argument("-i", "--ignore-case", action="store_true", help="忽略大小写")
    p.add_argument("-r", "--regex", action="store_true", help="使用正则表达式")
    p.add_argument("-n", "--max-results", type=int, default=200, help="最大结果数 (默认: 200)")
    p.add_argument(
        "--all", "-a",
        dest="all_sections",
        action="store_true",
        help="搜索所有 section（忽略配置文件中的过滤规则）",
    )
    p.set_defaults(func=cmd_search)


# ---------------------------------------------------------------------------
# replace-constants
# ---------------------------------------------------------------------------

def cmd_replace_constants(args: argparse.Namespace) -> None:
    """重建并替换 Nuitka 常量资源 (RT_RCDATA/3)。"""
    pe_path = Path(args.pe)
    if not pe_path.is_file():
        print(f"错误: 文件不存在: {pe_path}", file=sys.stderr)
        sys.exit(1)

    pe_data = pe_path.read_bytes()
    if not pe_data[:2] == b"MZ":
        print("[!] 该文件不是有效的 PE 文件（缺少 MZ 头）", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out) if args.out else Path(pe_path.stem + ".patch" + pe_path.suffix)

    from .peutils import (
        get_pe_resource_data,
        inspect_nuitka_constants_resource,
        replace_nuitka_constants_payload,
    )
    from .constants import parse_blob, build_blob, build_section

    try:
        resource_raw = get_pe_resource_data(pe_data, 10, 3)
    except ValueError:
        print("[!] 未找到 Nuitka 常量资源 (RT_RCDATA/3)", file=sys.stderr)
        sys.exit(1)

    info = inspect_nuitka_constants_resource(resource_raw)
    is_legacy = info["version"].startswith("legacy")

    print(f"原始资源: {info['version']} 格式, {info['payload_size']:,} bytes")

    # ── 单 section 导出 ──────────────────────────────────────
    if args.dump_section:
        target_name = args.dump_section
        result = parse_blob(resource_raw)
        found = None
        for s in result.sections:
            if s.name == target_name:
                found = s
                break
        if found is None:
            print(f"[!] 未找到 section: {target_name}", file=sys.stderr)
            sys.exit(1)

        dump_path = Path(args.output) if args.output else Path(f"{target_name}.json")
        section_json = {
            "name": found.name if found.name else "(global)",
            "data_size": found.data_size,
            "constants_count": len(found.constants),
            "constants": [_value_to_json(c) for c in found.constants],
        }
        with open(dump_path, "w", encoding="utf-8") as f:
            json.dump(section_json, f, ensure_ascii=False, indent=2)

        print(f"已导出 section [{target_name}]:")
        print(f"  常量数: {len(found.constants)}")
        print(f"  原大小: {found.data_size:,} bytes")
        print(f"  输出:   {dump_path.resolve()}")
        suggest_out = Path(pe_path.stem + ".patch" + pe_path.suffix)
        print(f"\n修改后使用以下命令重建:")
        print(f"  nuitka-forge replace-constants {pe_path} --replace-section {dump_path} -o {suggest_out}")
        print(f"  (支持多个: --replace-section a.json b.json c.json)")
        return

    # ── section 替换（支持多个，原地替换不重编码其他 section） ──
    if args.replace_section:
        from .constants import replace_sections_in_blob
        from .peutils import replace_pe_resource_data

        # 加载所有要替换的 section
        replacements: dict[str, list] = {}
        for json_path_str in args.replace_section:
            json_path = Path(json_path_str)
            if not json_path.is_file():
                print(f"错误: JSON 文件不存在: {json_path}", file=sys.stderr)
                sys.exit(1)
            with open(json_path, "r", encoding="utf-8") as f:
                section_json = json.load(f)
            target_name = section_json["name"]
            if target_name == "(global)":
                target_name = ""
            replacements[target_name] = [_json_to_value(c) for c in section_json["constants"]]

        # 原地替换：只修改目标 section 的字节，其他 section 原样保留
        new_resource = replace_sections_in_blob(resource_raw, replacements)

        # 显示替换信息
        size_changed = len(new_resource) != len(resource_raw)
        for name in replacements:
            print(f"  section [{name}]: {len(replacements[name])} constants")
        if size_changed:
            print(f"  大小变化: {len(resource_raw):,} -> {len(new_resource):,} bytes")
        else:
            print(f"  大小不变: {len(resource_raw):,} bytes")

        # 写入 PE 资源
        import shutil as _shutil
        if pe_path.resolve() != out_path.resolve():
            _shutil.copy2(pe_path, out_path)

        out_data = out_path.read_bytes()
        patched = replace_pe_resource_data(out_data, 10, 3, new_resource)
        out_path.write_bytes(patched)

        print(f"  输出:   {out_path.resolve()}")
        return

    # ── 全量 JSON 导出 ───────────────────────────────────────
    if args.dump_json:
        result = parse_blob(resource_raw)
        print(f"段数量:   {len(result.sections)}")
        print(f"常量总数: {result.constant_count:,}")

        dump_path = Path(args.dump_json)
        json_data = {
            "version": result.version,
            "crc32": result.crc32,
            "total_size": result.total_size,
            "sections": [],
        }
        for section in result.sections:
            section_data = {
                "name": section.name if section.name else "(global)",
                "data_size": section.data_size,
                "constants": [_value_to_json(c) for c in section.constants],
            }
            json_data["sections"].append(section_data)

        with open(dump_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)

        print(f"已导出常量资源到: {dump_path.resolve()}")
        print(f"\n修改后使用以下命令重建:")
        print(f"  nuitka-forge replace-constants {pe_path} --json {dump_path} -o {out_path}")
        return

    # ── 全量 JSON 重建 ───────────────────────────────────────
    if args.json:
        json_path = Path(args.json)
        if not json_path.is_file():
            print(f"错误: JSON 文件不存在: {json_path}", file=sys.stderr)
            sys.exit(1)

        with open(json_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        sections = []
        for section_data in json_data.get("sections", []):
            name = section_data["name"]
            if name == "(global)":
                name = ""
            constants = [_json_to_value(c) for c in section_data["constants"]]
            sections.append((name, constants))

        new_blob = build_blob(sections, legacy=False)

        import shutil as _shutil
        if pe_path.resolve() != out_path.resolve():
            _shutil.copy2(pe_path, out_path)
        new_pe = replace_nuitka_constants_payload(out_path.read_bytes(), new_blob)
        out_path.write_bytes(new_pe)

        print(f"\n已重建常量资源:")
        print(f"  新大小: {len(new_blob):,} bytes")
        print(f"  输出:   {out_path.resolve()}")
        return

    print("错误: 请指定操作 (--dump-json, --json, --dump-section, --replace-section)", file=sys.stderr)
    sys.exit(1)


def _json_to_value(data) -> any:
    """将 JSON 数据还原为 Python 值。"""
    if data is None or isinstance(data, (bool, int, float, str)):
        return data
    if isinstance(data, list):
        return [_json_to_value(v) for v in data]
    if isinstance(data, dict):
        type_name = data.get("__type__")
        if type_name == "bytes":
            return bytes.fromhex(data["hex"])
        if type_name == "bytearray":
            return bytearray.fromhex(data["hex"])
        if type_name == "complex":
            return complex(data["real"], data["imag"])
        if type_name == "tuple":
            return tuple(_json_to_value(v) for v in data["items"])
        if type_name == "set":
            return {_json_to_value(v) for v in data["items"]}
        if type_name == "frozenset":
            return frozenset(_json_to_value(v) for v in data["items"])
        if type_name == "slice":
            return slice(
                _json_to_value(data["start"]),
                _json_to_value(data["stop"]),
                _json_to_value(data["step"]),
            )
        if type_name == "range":
            return range(data["start"], data["stop"], data["step"])
        # 普通 dict
        return {k: _json_to_value(v) for k, v in data.items()}
    return data


def setup_replace_constants_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "replace-constants",
        help="重建并替换 Nuitka 常量资源 (RT_RCDATA/3)",
    )
    p.add_argument("pe", help="PE 文件路径 (DLL/EXE)")
    p.add_argument("--out", "-o", default=None, help="输出文件路径 (默认: 程序名.patch.ext)")
    p.add_argument("--dump-json", default=None, metavar="FILE",
                   help="导出全部常量资源为 JSON 文件")
    p.add_argument("--json", default=None, metavar="FILE",
                   help="从全量 JSON 文件重建常量资源并替换")
    p.add_argument("--dump-section", default=None, metavar="NAME",
                   help="导出指定 section 为 JSON 文件（配合 --output 指定路径）")
    p.add_argument("--replace-section", nargs="+", default=None, metavar="FILE",
                   help="从 section JSON 文件重建，支持多个文件（一次替换多个 section）")
    p.add_argument("--output", default=None, metavar="FILE",
                   help="dump-section 的输出文件路径 (默认: NAME.json)")
    p.set_defaults(func=cmd_replace_constants)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def cmd_config(args: argparse.Namespace) -> None:
    """管理 Nuitka Forge 配置。"""
    from .config import CONFIG_PATH, load_config, save_config

    action = args.config_action

    if action == "show":
        cfg = load_config()
        exists = CONFIG_PATH.exists()
        print(f"配置文件: {CONFIG_PATH}")
        print(f"文件存在: {'是' if exists else '否 (不过滤任何 section)'}")
        print()
        print("[section_filter]")
        print(f"  hide_prefixes: {len(cfg.section_filter.hide_prefixes)} 个")
        print(f"  hide_names:    {len(cfg.section_filter.hide_names)} 个")
        if cfg.section_filter.hide_prefixes:
            print()
            print("  hide_prefixes:")
            for p in cfg.section_filter.hide_prefixes:
                print(f"    - {p}")
        if cfg.section_filter.hide_names:
            print()
            print("  hide_names:")
            for n in cfg.section_filter.hide_names:
                print(f"    - {n}")
        return

    if action == "edit":
        import subprocess
        editor = (
            _env_editor()
            or ("notepad" if sys.platform == "win32" else "vi")
        )
        print(f"正在打开: {CONFIG_PATH}")
        subprocess.run([editor, str(CONFIG_PATH)])
        return

    if action == "add":
        cfg = load_config()
        target = args.target
        value = args.value

        if target == "prefix":
            if value in cfg.section_filter.hide_prefixes:
                print(f"前缀 '{value}' 已在列表中。")
                return
            cfg.section_filter.hide_prefixes.append(value)
            save_config(cfg)
            print(f"已添加隐藏前缀: {value}")
        elif target == "name":
            if value in cfg.section_filter.hide_names:
                print(f"名称 '{value}' 已在列表中。")
                return
            cfg.section_filter.hide_names.append(value)
            save_config(cfg)
            print(f"已添加隐藏名称: {value}")
        return

    if action == "remove":
        cfg = load_config()
        target = args.target
        value = args.value

        if target == "prefix":
            if value not in cfg.section_filter.hide_prefixes:
                print(f"前缀 '{value}' 不在列表中。")
                return
            cfg.section_filter.hide_prefixes.remove(value)
            save_config(cfg)
            print(f"已移除隐藏前缀: {value}")
        elif target == "name":
            if value not in cfg.section_filter.hide_names:
                print(f"名称 '{value}' 不在列表中。")
                return
            cfg.section_filter.hide_names.remove(value)
            save_config(cfg)
            print(f"已移除隐藏名称: {value}")
        return


def _env_editor() -> str | None:
    """从环境变量获取编辑器。"""
    import os
    for var in ("EDITOR", "VISUAL"):
        editor = os.environ.get(var)
        if editor:
            return editor
    return None


def setup_config_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "config",
        help="管理 Nuitka Forge 配置（section 过滤规则等）",
    )
    sub = p.add_subparsers(dest="config_action", metavar="<action>", required=True)

    sub.add_parser("show", help="显示当前配置")
    sub.add_parser("edit", help="用编辑器打开配置文件")

    p_add = sub.add_parser("add", help="添加过滤规则")
    p_add.add_argument("target", choices=["prefix", "name"],
                       help="prefix=隐藏前缀, name=精确名称")
    p_add.add_argument("value", help="要添加的值")

    p_rm = sub.add_parser("remove", help="移除过滤规则")
    p_rm.add_argument("target", choices=["prefix", "name"],
                      help="prefix=隐藏前缀, name=精确名称")
    p_rm.add_argument("value", help="要移除的值")

    p.set_defaults(func=cmd_config)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nuitka-forge",
        description="Nuitka onefile 资源包处理工具 — 列出、解压、修改、重封",
        epilog="更多信息: https://github.com/liert/NuitkaForge",
    )
    parser.add_argument(
        "--version", action="version",
        version="nuitka-forge 0.1.0",
    )

    subparsers = parser.add_subparsers(
        title="子命令",
        metavar="<command>",
        required=True,
    )

    setup_extract_parser(subparsers)
    setup_pack_parser(subparsers)
    setup_replace_parser(subparsers)
    setup_verify_parser(subparsers)
    setup_info_parser(subparsers)
    setup_inspect_dll_parser(subparsers)
    setup_parse_constants_parser(subparsers)
    setup_search_parser(subparsers)
    setup_replace_constants_parser(subparsers)
    setup_config_parser(subparsers)

    return parser


def main() -> None:
    # 确保输出使用 UTF-8 编码（Windows GBK 环境需要）
    import io
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )

    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
