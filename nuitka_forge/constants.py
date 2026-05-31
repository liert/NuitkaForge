"""
Nuitka 常量 Blob (RT_RCDATA/3) 解析与序列化模块。

支持旧版（含 CRC32 头部）和新版格式，完整解析所有 TLV tag 类型。
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Tag 值定义
# ---------------------------------------------------------------------------

# 基础类型
TAG_PREVIOUS = 0x70  # 'p' 复用前一个对象
TAG_NONE = 0x6E  # 'n'
TAG_TRUE = 0x74  # 't'
TAG_FALSE = 0x46  # 'F'
TAG_END = 0x2E  # '.' 段结束

# 容器类型
TAG_TUPLE = 0x54  # 'T'
TAG_LIST = 0x4C  # 'L'
TAG_DICT = 0x44  # 'D'
TAG_SET = 0x53  # 'S'
TAG_FROZENSET = 0x50  # 'P'

# 数值类型
TAG_INT_POSITIVE = 0x69  # 'i'
TAG_INT_NEGATIVE = 0x49  # 'I'
TAG_LONG_POSITIVE_SMALL = 0x6C  # 'l'
TAG_LONG_NEGATIVE_SMALL = 0x71  # 'q'
TAG_LONG_POSITIVE_LARGE = 0x67  # 'g'
TAG_LONG_NEGATIVE_LARGE = 0x47  # 'G'
TAG_FLOAT = 0x66  # 'f'
TAG_FLOAT_SPECIAL = 0x5A  # 'Z'
TAG_COMPLEX = 0x6A  # 'j'
TAG_COMPLEX_SPECIAL = 0x4A  # 'J'

# 字符串和字节类型
TAG_TEXT_EMPTY = 0x73  # 's'
TAG_TEXT_SINGLE = 0x77  # 'w'
TAG_TEXT_UTF8_LENGTH_PREFIXED = 0x76  # 'v'
TAG_TEXT_UTF8_ZERO_TERMINATED = 0x75  # 'u'
TAG_ATTRIBUTE_NAME = 0x61  # 'a'
TAG_BYTES_SINGLE = 0x64  # 'd'
TAG_BYTES_LENGTH_PREFIXED = 0x62  # 'b'
TAG_BYTES_ZERO_TERMINATED = 0x63  # 'c'
TAG_BYTEARRAY = 0x42  # 'B'

# 特殊类型
TAG_SLICE = 0x3A  # ':'
TAG_RANGE = 0x3B  # ';'
TAG_CODE_OBJECT = 0x43  # 'C'
TAG_BUILTIN_ANON = 0x4D  # 'M'
TAG_BUILTIN_SPECIAL = 0x51  # 'Q'
TAG_BUILTIN_NAMED = 0x4F  # 'O'
TAG_BUILTIN_EXCEPTION = 0x45  # 'E'
TAG_GENERIC_ALIAS = 0x41  # 'A'
TAG_UNION_TYPE = 0x48  # 'H'
TAG_BLOB_DATA = 0x58  # 'X'

TAG_NAMES: dict[int, str] = {
    TAG_PREVIOUS: "PREVIOUS",
    TAG_NONE: "NONE",
    TAG_TRUE: "TRUE",
    TAG_FALSE: "FALSE",
    TAG_END: "END",
    TAG_TUPLE: "TUPLE",
    TAG_LIST: "LIST",
    TAG_DICT: "DICT",
    TAG_SET: "SET",
    TAG_FROZENSET: "FROZENSET",
    TAG_INT_POSITIVE: "INT_POSITIVE",
    TAG_INT_NEGATIVE: "INT_NEGATIVE",
    TAG_LONG_POSITIVE_SMALL: "LONG_POS_SMALL",
    TAG_LONG_NEGATIVE_SMALL: "LONG_NEG_SMALL",
    TAG_LONG_POSITIVE_LARGE: "LONG_POS_LARGE",
    TAG_LONG_NEGATIVE_LARGE: "LONG_NEG_LARGE",
    TAG_FLOAT: "FLOAT",
    TAG_FLOAT_SPECIAL: "FLOAT_SPECIAL",
    TAG_COMPLEX: "COMPLEX",
    TAG_COMPLEX_SPECIAL: "COMPLEX_SPECIAL",
    TAG_TEXT_EMPTY: "TEXT_EMPTY",
    TAG_TEXT_SINGLE: "TEXT_SINGLE",
    TAG_TEXT_UTF8_LENGTH_PREFIXED: "TEXT_UTF8_LEN",
    TAG_TEXT_UTF8_ZERO_TERMINATED: "TEXT_UTF8_Z",
    TAG_ATTRIBUTE_NAME: "ATTR_NAME",
    TAG_BYTES_SINGLE: "BYTES_SINGLE",
    TAG_BYTES_LENGTH_PREFIXED: "BYTES_LEN",
    TAG_BYTES_ZERO_TERMINATED: "BYTES_Z",
    TAG_BYTEARRAY: "BYTEARRAY",
    TAG_SLICE: "SLICE",
    TAG_RANGE: "RANGE",
    TAG_CODE_OBJECT: "CODE_OBJECT",
    TAG_BUILTIN_ANON: "BUILTIN_ANON",
    TAG_BUILTIN_SPECIAL: "BUILTIN_SPECIAL",
    TAG_BUILTIN_NAMED: "BUILTIN_NAMED",
    TAG_BUILTIN_EXCEPTION: "BUILTIN_EXCEPTION",
    TAG_GENERIC_ALIAS: "GENERIC_ALIAS",
    TAG_UNION_TYPE: "UNION_TYPE",
    TAG_BLOB_DATA: "BLOB_DATA",
}

# Float 特殊子类型
FLOAT_SPECIAL_NAMES: dict[int, str] = {
    0x00: "+0.0",
    0x01: "-0.0",
    0x02: "+NaN",
    0x03: "-NaN",
    0x04: "+Inf",
    0x05: "-Inf",
}

# Code Object 标志位
FLAG_QUALNAME = 0x0001
FLAG_FREE_VARS = 0x0002
FLAG_KW_ONLY = 0x0004
FLAG_POS_ONLY = 0x0008
KIND_GENERATOR = 0x0010
KIND_COROUTINE = 0x0020
KIND_ASYNCGEN = 0x0030
FLAG_OPTIMIZED = 0x0040
FLAG_NEWLOCALS = 0x0080
FLAG_VARARGS = 0x0100
FLAG_VARKEYWORDS = 0x0200
FLAG_FUTURE_DIVISION = 0x0400
FLAG_FUTURE_UNICODE_LITERALS = 0x0800
FLAG_FUTURE_PRINT_FUNCTION = 0x1000
FLAG_FUTURE_ABSOLUTE_IMPORT = 0x2000
FLAG_FUTURE_GENERATOR_STOP = 0x4000
FLAG_FUTURE_ANNOTATIONS = 0x8000
FLAG_FUTURE_BARRY_AS_BDFL = 0x10000
FLAG_NOFREE = 0x20000

KIND_MASK = 0x0030

CODE_FLAG_NAMES: dict[int, str] = {
    FLAG_QUALNAME: "QUALNAME",
    FLAG_FREE_VARS: "FREE_VARS",
    FLAG_KW_ONLY: "KW_ONLY",
    FLAG_POS_ONLY: "POS_ONLY",
    FLAG_OPTIMIZED: "OPTIMIZED",
    FLAG_NEWLOCALS: "NEWLOCALS",
    FLAG_VARARGS: "VARARGS",
    FLAG_VARKEYWORDS: "VARKEYWORDS",
    FLAG_FUTURE_DIVISION: "FUTURE_DIVISION",
    FLAG_FUTURE_UNICODE_LITERALS: "FUTURE_UNICODE_LITERALS",
    FLAG_FUTURE_PRINT_FUNCTION: "FUTURE_PRINT_FUNCTION",
    FLAG_FUTURE_ABSOLUTE_IMPORT: "FUTURE_ABSOLUTE_IMPORT",
    FLAG_FUTURE_GENERATOR_STOP: "FUTURE_GENERATOR_STOP",
    FLAG_FUTURE_ANNOTATIONS: "FUTURE_ANNOTATIONS",
    FLAG_FUTURE_BARRY_AS_BDFL: "FUTURE_BARRY_AS_BDFL",
    FLAG_NOFREE: "NOFREE",
}

KIND_NAMES: dict[int, str] = {
    0x0000: "",
    KIND_GENERATOR: "generator",
    KIND_COROUTINE: "coroutine",
    KIND_ASYNCGEN: "async_generator",
}

# 内置匿名对象索引
BUILTIN_ANON_NAMES: dict[int, str] = {
    0: "Ellipsis",
    1: "NotImplemented",
}


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------

@dataclass
class BlobSection:
    """解析后的常量段。"""
    name: str
    data_size: int
    constants: list[Any]


@dataclass
class CodeObjectData:
    """解析后的代码对象。"""
    flags: int
    name: str
    qualname: str
    line_number: int
    var_names: tuple
    arg_count: int
    kw_only_count: int = 0
    pos_only_count: int = 0

    @property
    def kind(self) -> str:
        return KIND_NAMES.get(self.flags & KIND_MASK, "")

    @property
    def flag_list(self) -> list[str]:
        result = []
        for bit, name in CODE_FLAG_NAMES.items():
            if self.flags & bit:
                result.append(name)
        return result


@dataclass
class BlobParseResult:
    """完整解析结果。"""
    version: str  # "legacy" 或 "new"
    crc32: int | None
    total_size: int
    sections: list[BlobSection]
    raw_data: bytes = field(repr=False)

    @property
    def constant_count(self) -> int:
        return sum(len(s.constants) for s in self.sections)


# ---------------------------------------------------------------------------
# 低级解码
# ---------------------------------------------------------------------------

def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """解码 protobuf 风格 varint，返回 (value, new_offset)。"""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
    raise ValueError(f"truncated varint at offset {offset}")


def _encode_varint(value: int) -> bytes:
    """编码 protobuf 风格 varint。"""
    result = bytearray()
    while value >= 128:
        result.append((value & 0xFF) | 0x80)
        value >>= 7
    result.append(value & 0xFF)
    return bytes(result)


def _is_attribute_name(value: str) -> bool:
    """判断字符串是否为 Python 属性名格式 [a-zA-Z_][a-zA-Z0-9_]*。"""
    if not value:
        return False
    first = value[0]
    if not (first.isalpha() or first == "_"):
        return False
    for ch in value[1:]:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True


def _section_constants_equal(a: list[Any], b: list[Any]) -> bool:
    """比较两个常量列表是否语义相同（处理 float NaN 等特殊情况）。"""
    if len(a) != len(b):
        return False
    for va, vb in zip(a, b):
        if not _values_equal(va, vb):
            return False
    return True


def _values_equal(a: Any, b: Any) -> bool:
    """递归比较两个值是否语义相同。"""
    if type(a) != type(b):
        return False
    if isinstance(a, float):
        import math
        if math.isnan(a) and math.isnan(b):
            return True
        return a == b
    if isinstance(a, tuple):
        return len(a) == len(b) and all(_values_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, list):
        return len(a) == len(b) and all(_values_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        if len(a) != len(b):
            return False
        for (ka, va), (kb, vb) in zip(a.items(), b.items()):
            if not _values_equal(ka, kb) or not _values_equal(va, vb):
                return False
        return True
    if isinstance(a, (set, frozenset)):
        return a == b
    if isinstance(a, CodeObjectData):
        return (
            a.flags == b.flags and a.name == b.name and a.qualname == b.qualname
            and a.line_number == b.line_number and a.var_names == b.var_names
            and a.arg_count == b.arg_count and a.kw_only_count == b.kw_only_count
            and a.pos_only_count == b.pos_only_count
        )
    return a == b


def _read_null_terminated_utf8(data: bytes, offset: int) -> tuple[str, int]:
    """读取 null-terminated UTF-8 字符串。"""
    end = data.index(0x00, offset)
    return data[offset:end].decode("utf-8"), end + 1


# ---------------------------------------------------------------------------
# TLV 解码器
# ---------------------------------------------------------------------------

class _Decoder:
    """内部解码器，维护 TAG_PREVIOUS 状态。"""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self._previous: Any = None

    def at_end(self) -> bool:
        return self.offset >= len(self.data)

    def peek(self) -> int:
        return self.data[self.offset]

    def decode_constant(self) -> Any:
        """解码一个常量值。"""
        tag = self.data[self.offset]
        self.offset += 1

        # 基础类型
        if tag == TAG_NONE:
            return None
        if tag == TAG_TRUE:
            return True
        if tag == TAG_FALSE:
            return False
        if tag == TAG_PREVIOUS:
            return self._previous

        # 容器类型
        if tag == TAG_TUPLE:
            return self._decode_tuple()
        if tag == TAG_LIST:
            return self._decode_list()
        if tag == TAG_DICT:
            return self._decode_dict()
        if tag == TAG_SET:
            return self._decode_set()
        if tag == TAG_FROZENSET:
            return self._decode_frozenset()

        # 数值类型
        if tag == TAG_INT_POSITIVE:
            val, self.offset = _decode_varint(self.data, self.offset)
            self._previous = val
            return val
        if tag == TAG_INT_NEGATIVE:
            val, self.offset = _decode_varint(self.data, self.offset)
            val = -val
            self._previous = val
            return val
        if tag == TAG_LONG_POSITIVE_SMALL:
            val, self.offset = _decode_varint(self.data, self.offset)
            self._previous = val
            return val
        if tag == TAG_LONG_NEGATIVE_SMALL:
            val, self.offset = _decode_varint(self.data, self.offset)
            val = -val
            self._previous = val
            return val
        if tag == TAG_LONG_POSITIVE_LARGE:
            return self._decode_large_int(negative=False)
        if tag == TAG_LONG_NEGATIVE_LARGE:
            return self._decode_large_int(negative=True)
        if tag == TAG_FLOAT:
            val = struct.unpack_from("<d", self.data, self.offset)[0]
            self.offset += 8
            self._previous = val
            return val
        if tag == TAG_FLOAT_SPECIAL:
            return self._decode_float_special()
        if tag == TAG_COMPLEX:
            return self._decode_complex()
        if tag == TAG_COMPLEX_SPECIAL:
            return self._decode_complex_special()

        # 字符串类型
        if tag == TAG_TEXT_EMPTY:
            val = ""
            self._previous = val
            return val
        if tag == TAG_TEXT_SINGLE:
            val = chr(self.data[self.offset])
            self.offset += 1
            self._previous = val
            return val
        if tag == TAG_TEXT_UTF8_LENGTH_PREFIXED:
            length, self.offset = _decode_varint(self.data, self.offset)
            val = self.data[self.offset : self.offset + length].decode("utf-8")
            self.offset += length
            self._previous = val
            return val
        if tag == TAG_TEXT_UTF8_ZERO_TERMINATED:
            val, self.offset = _read_null_terminated_utf8(self.data, self.offset)
            self._previous = val
            return val
        if tag == TAG_ATTRIBUTE_NAME:
            val, self.offset = _read_null_terminated_utf8(self.data, self.offset)
            self._previous = val
            return val

        # 字节类型
        if tag == TAG_BYTES_SINGLE:
            val = bytes([self.data[self.offset]])
            self.offset += 1
            self._previous = val
            return val
        if tag == TAG_BYTES_LENGTH_PREFIXED:
            length, self.offset = _decode_varint(self.data, self.offset)
            val = bytes(self.data[self.offset : self.offset + length])
            self.offset += length
            self._previous = val
            return val
        if tag == TAG_BYTES_ZERO_TERMINATED:
            end = self.data.index(0x00, self.offset)
            val = bytes(self.data[self.offset:end])
            self.offset = end + 1
            self._previous = val
            return val
        if tag == TAG_BYTEARRAY:
            length, self.offset = _decode_varint(self.data, self.offset)
            val = bytearray(self.data[self.offset : self.offset + length])
            self.offset += length
            self._previous = val
            return val

        # 特殊类型
        if tag == TAG_SLICE:
            start = self.decode_constant()
            stop = self.decode_constant()
            step = self.decode_constant()
            return slice(start, stop, step)
        if tag == TAG_RANGE:
            start = self.decode_constant()
            stop = self.decode_constant()
            step = self.decode_constant()
            return range(start, stop, step)
        if tag == TAG_CODE_OBJECT:
            return self._decode_code_object()
        if tag == TAG_BUILTIN_ANON:
            idx = self.data[self.offset]
            self.offset += 1
            return BUILTIN_ANON_NAMES.get(idx, f"builtin_anon[{idx}]")
        if tag == TAG_BUILTIN_SPECIAL:
            idx = self.data[self.offset]
            self.offset += 1
            return f"builtin_special[{idx}]"
        if tag == TAG_BUILTIN_NAMED:
            val, self.offset = _read_null_terminated_utf8(self.data, self.offset)
            return f"builtin:{val}"
        if tag == TAG_BUILTIN_EXCEPTION:
            val, self.offset = _read_null_terminated_utf8(self.data, self.offset)
            return f"exception:{val}"
        if tag == TAG_GENERIC_ALIAS:
            origin = self.decode_constant()
            args = self.decode_constant()
            return f"GenericAlias({origin}, {args})"
        if tag == TAG_UNION_TYPE:
            args = self.decode_constant()
            return f"UnionType({args})"
        if tag == TAG_BLOB_DATA:
            length, self.offset = _decode_varint(self.data, self.offset)
            val = bytes(self.data[self.offset : self.offset + length])
            self.offset += length
            return val

        raise ValueError(
            f"unknown tag 0x{tag:02X} ({chr(tag) if 0x20 <= tag < 0x7F else '?'})"
            f" at offset 0x{self.offset - 1:X}"
        )

    def _decode_tuple(self) -> tuple:
        size, self.offset = _decode_varint(self.data, self.offset)
        items = [self.decode_constant() for _ in range(size)]
        val = tuple(items)
        self._previous = val
        return val

    def _decode_list(self) -> list:
        size, self.offset = _decode_varint(self.data, self.offset)
        val = [self.decode_constant() for _ in range(size)]
        self._previous = val
        return val

    def _decode_dict(self) -> dict:
        size, self.offset = _decode_varint(self.data, self.offset)
        keys = [self.decode_constant() for _ in range(size)]
        values = [self.decode_constant() for _ in range(size)]
        return dict(zip(keys, values))

    def _decode_set(self) -> set:
        size, self.offset = _decode_varint(self.data, self.offset)
        items = {self.decode_constant() for _ in range(size)}
        return items

    def _decode_frozenset(self) -> frozenset:
        size, self.offset = _decode_varint(self.data, self.offset)
        items = frozenset(self.decode_constant() for _ in range(size))
        return items

    def _decode_large_int(self, negative: bool) -> int:
        count, self.offset = _decode_varint(self.data, self.offset)
        val = 0
        for _ in range(count):
            part, self.offset = _decode_varint(self.data, self.offset)
            val = (val << 31) | part
        if negative:
            val = -val
        self._previous = val
        return val

    def _decode_float_special(self) -> float:
        sub = self.data[self.offset]
        self.offset += 1
        mapping = {
            0x00: 0.0,
            0x01: -0.0,
        }
        if sub in mapping:
            return mapping[sub]
        if sub == 0x02:
            return float("nan")
        if sub == 0x03:
            return float("-nan")
        if sub == 0x04:
            return float("inf")
        if sub == 0x05:
            return float("-inf")
        raise ValueError(f"unknown float special subtype 0x{sub:02X}")

    def _decode_complex(self) -> complex:
        real = struct.unpack_from("<d", self.data, self.offset)[0]
        imag = struct.unpack_from("<d", self.data, self.offset + 8)[0]
        self.offset += 16
        return complex(real, imag)

    def _decode_complex_special(self) -> complex:
        real = self.decode_constant()
        imag = self.decode_constant()
        return complex(real, imag)

    def _decode_code_object(self) -> CodeObjectData:
        flags, self.offset = _decode_varint(self.data, self.offset)
        name = self.decode_constant()
        line_number, self.offset = _decode_varint(self.data, self.offset)
        line_number += 1
        var_names = self.decode_constant()
        arg_count, self.offset = _decode_varint(self.data, self.offset)

        qualname = name
        kw_only = 0
        pos_only = 0

        if flags & FLAG_QUALNAME:
            prefix = self.decode_constant()
            if prefix:
                qualname = f"{prefix}.{name}"
            else:
                qualname = name

        free_vars = ()
        if flags & FLAG_FREE_VARS:
            free_vars = self.decode_constant()

        if flags & FLAG_KW_ONLY:
            kw_only, self.offset = _decode_varint(self.data, self.offset)
            kw_only += 1

        if flags & FLAG_POS_ONLY:
            pos_only, self.offset = _decode_varint(self.data, self.offset)
            pos_only += 1

        return CodeObjectData(
            flags=flags,
            name=name,
            qualname=qualname,
            line_number=line_number,
            var_names=var_names,
            arg_count=arg_count,
            kw_only_count=kw_only,
            pos_only_count=pos_only,
        )


# ---------------------------------------------------------------------------
# 核心解析 API
# ---------------------------------------------------------------------------

def parse_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """公共 API：解码 varint。"""
    return _decode_varint(data, offset)


def parse_constant(data: bytes, offset: int, decoder: _Decoder | None = None) -> tuple[Any, int]:
    """公共 API：解码一个常量。"""
    if decoder is None:
        decoder = _Decoder(data)
        decoder.offset = offset
    val = decoder.decode_constant()
    return val, decoder.offset


def parse_section(data: bytes, offset: int) -> tuple[BlobSection, int]:
    """解析一个 section：name + size + count + constants + TAG_END。"""
    name, offset = _read_null_terminated_utf8(data, offset)
    part_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    section_end = offset + part_size

    count = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    decoder = _Decoder(data)
    decoder.offset = offset
    constants: list[Any] = []
    for _ in range(count):
        val = decoder.decode_constant()
        constants.append(val)
    offset = decoder.offset

    # TAG_END
    if offset < len(data) and data[offset] == TAG_END:
        offset += 1

    return BlobSection(name=name, data_size=part_size, constants=constants), offset


def _skip_section(data: bytes, offset: int) -> tuple[str, int, int]:
    """仅读取 section 头部（name + data_size），然后跳过整个 body。

    返回 (name, data_size, new_offset)。
    """
    name, offset = _read_null_terminated_utf8(data, offset)
    part_size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    return name, part_size, offset + part_size


def parse_blob(
    data: bytes,
    skip_names: set[str] | None = None,
    skip_prefixes: tuple[str, ...] | None = None,
) -> BlobParseResult:
    """解析完整的 Nuitka 常量 blob，自动检测旧版/新版格式。

    旧版格式：前 8 字节为 uint32 CRC32 + uint32 data_size
    新版格式：直接是 section 数据

    Args:
        data: 原始资源字节
        skip_names: 要跳过解析的 section 名称精确匹配集合。
        skip_prefixes: 要跳过解析的 section 名称前缀。
                       匹配的 section 只读取头部，不解析常量内容。
    """
    crc32_val: int | None = None
    start_offset = 0
    version = "new"

    # 尝试检测旧版格式
    if len(data) >= 8:
        potential_crc, potential_size = struct.unpack_from("<II", data, 0)
        if potential_size == len(data) - 8:
            actual_crc = binascii.crc32(data[8:]) & 0xFFFFFFFF
            if actual_crc == potential_crc:
                version = "legacy"
                crc32_val = potential_crc
                start_offset = 8

    need_skip = bool(skip_names or skip_prefixes)
    sections: list[BlobSection] = []
    offset = start_offset
    while offset < len(data):
        try:
            if need_skip:
                # 先偷看 section name
                peek_end = data.index(0x00, offset)
                name = data[offset:peek_end].decode("utf-8")
                should_skip = False
                if skip_names and name in skip_names:
                    should_skip = True
                elif skip_prefixes:
                    for prefix in skip_prefixes:
                        if name.startswith(prefix):
                            should_skip = True
                            break
                if should_skip:
                    name, part_size, offset = _skip_section(data, offset)
                    sections.append(BlobSection(name=name, data_size=part_size, constants=[]))
                    continue

            section, offset = parse_section(data, offset)
            sections.append(section)
        except (ValueError, struct.error, IndexError):
            break

    return BlobParseResult(
        version=version,
        crc32=crc32_val,
        total_size=len(data),
        sections=sections,
        raw_data=data,
    )


# ---------------------------------------------------------------------------
# 可视化 / 格式化输出
# ---------------------------------------------------------------------------

def _format_value(val: Any, depth: int = 0, max_str: int = 60) -> str:
    """将解析后的值格式化为可读字符串。"""
    if val is None:
        return "None"
    if val is True:
        return "True"
    if val is False:
        return "False"
    if isinstance(val, str):
        if len(val) <= max_str:
            return repr(val)
        return repr(val[:max_str - 5] + "...")
    if isinstance(val, bytes):
        if len(val) <= 20:
            return f"bytes({val.hex(' ')})"
        return f"bytes({len(val)} bytes, {val[:16].hex(' ')}...)"
    if isinstance(val, bytearray):
        return f"bytearray({len(val)} bytes)"
    if isinstance(val, int):
        if abs(val) < 1_000_000:
            return str(val)
        return f"{val:,}"
    if isinstance(val, float):
        return str(val)
    if isinstance(val, complex):
        return str(val)
    if isinstance(val, CodeObjectData):
        kind = f" [{val.kind}]" if val.kind else ""
        flags_str = ", ".join(val.flag_list) if val.flag_list else ""
        return (
            f"code:{val.qualname}{kind} "
            f"(line {val.line_number}, args={val.arg_count}, "
            f"vars={len(val.var_names)}, flags=[{flags_str}])"
        )
    if isinstance(val, slice):
        return f"slice({_format_value(val.start)}, {_format_value(val.stop)}, {_format_value(val.step)})"
    if isinstance(val, range):
        return f"range({_format_value(val.start)}, {_format_value(val.stop)}, {_format_value(val.step)})"
    if isinstance(val, tuple):
        if depth >= 3:
            return f"tuple({len(val)} items)"
        items = [_format_value(v, depth + 1) for v in val]
        inner = ", ".join(items)
        if len(inner) > 120:
            inner = inner[:117] + "..."
        return f"({inner},)" if len(val) == 1 else f"({inner})"
    if isinstance(val, list):
        if depth >= 3:
            return f"list({len(val)} items)"
        items = [_format_value(v, depth + 1) for v in val[:10]]
        suffix = f", ... ({len(val)} total)" if len(val) > 10 else ""
        return f"[{', '.join(items)}{suffix}]"
    if isinstance(val, dict):
        if depth >= 3:
            return f"dict({len(val)} items)"
        pairs = []
        for k, v in list(val.items())[:5]:
            pairs.append(f"{_format_value(k, depth + 1)}: {_format_value(v, depth + 1)}")
        suffix = f", ... ({len(val)} total)" if len(val) > 5 else ""
        return "{" + ", ".join(pairs) + suffix + "}"
    if isinstance(val, (set, frozenset)):
        type_name = type(val).__name__
        if depth >= 3:
            return f"{type_name}({len(val)} items)"
        items = [_format_value(v, depth + 1) for v in list(val)[:5]]
        suffix = f", ... ({len(val)} total)" if len(val) > 5 else ""
        return f"{type_name}({{{', '.join(items)}{suffix}}})"
    return str(val)


def format_blob_summary(result: BlobParseResult) -> str:
    """格式化解析结果的概要信息。"""
    lines = [
        f"版本:     {result.version}",
    ]
    if result.crc32 is not None:
        lines.append(f"CRC32:    0x{result.crc32:08X}")
    lines.append(f"总大小:   {result.total_size:,} bytes")
    lines.append(f"段数量:   {len(result.sections)}")
    lines.append(f"常量总数: {result.constant_count:,}")
    lines.append("")
    return "\n".join(lines)


def format_blob_tree(
    result: BlobParseResult,
    max_items: int = 50,
    hidden_sections: list | None = None,
) -> str:
    """将解析结果格式化为树形结构。

    Args:
        result: 解析结果
        max_items: 每个 section 最多显示的常量数量
        hidden_sections: 被过滤隐藏的 section 列表（如有则在末尾显示汇总）
    """
    lines = []
    for section in result.sections:
        section_display = section.name if section.name else "(global)"
        lines.append(f"  [{section_display}] ({len(section.constants)} constants, {section.data_size} bytes)")
        for i, val in enumerate(section.constants[:max_items]):
            if isinstance(val, CodeObjectData):
                lines.append(f"    {i}: {_format_value(val)}")
                lines.append(f"        varnames = {val.var_names}")
            else:
                lines.append(f"    {i}: {_format_value(val)}")
        if len(section.constants) > max_items:
            lines.append(f"    ... ({len(section.constants) - max_items} more)")

    if hidden_sections:
        total_bytes = sum(s.data_size for s in hidden_sections)
        lines.append("")
        lines.append(f"  ... ({len(hidden_sections)} sections skipped by config, "
                      f"{total_bytes:,} bytes)")
        lines.append(f"      使用 --all 显示全部, 或通过配置文件管理过滤列表")

    return "\n".join(lines)


def format_code_objects(result: BlobParseResult) -> list[CodeObjectData]:
    """从解析结果中提取所有代码对象。"""
    code_objects = []
    for section in result.sections:
        for val in section.constants:
            if isinstance(val, CodeObjectData):
                code_objects.append(val)
            elif isinstance(val, (tuple, list)):
                _collect_code_objects(val, code_objects)
    return code_objects


# ---------------------------------------------------------------------------
# 搜索
# ---------------------------------------------------------------------------

@dataclass
class SearchMatch:
    """搜索匹配结果。"""
    section_name: str
    constant_index: int
    path: str        # 如 "constant[5] > tuple[2]"
    value: Any       # 匹配到的实际值
    context: str = "" # 周围上下文的简短描述


def search_constants(
    result: BlobParseResult,
    query: str,
    *,
    ignore_case: bool = False,
    use_regex: bool = False,
    max_results: int = 200,
) -> list[SearchMatch]:
    """在所有 section 的常量中搜索字符串，递归搜索容器内部。

    Args:
        result: parse_blob 的结果
        query: 搜索文本
        ignore_case: 是否忽略大小写
        use_regex: 是否使用正则表达式
        max_results: 最大结果数

    Returns:
        SearchMatch 列表
    """
    import re as _re

    if use_regex:
        flags = _re.IGNORECASE if ignore_case else 0
        pattern = _re.compile(query, flags)
        def _match(s: str) -> bool:
            return bool(pattern.search(s))
    elif ignore_case:
        query_lower = query.lower()
        def _match(s: str) -> bool:
            return query_lower in s.lower()
    else:
        def _match(s: str) -> bool:
            return query in s

    matches: list[SearchMatch] = []

    for section in result.sections:
        if len(matches) >= max_results:
            break
        section_name = section.name if section.name else "(global)"
        for i, val in enumerate(section.constants):
            if len(matches) >= max_results:
                break
            _search_value(val, _match, matches, section_name, f"constant[{i}]", max_results)

    return matches


def _search_value(
    val: Any,
    _match,
    matches: list[SearchMatch],
    section_name: str,
    path: str,
    max_results: int,
) -> None:
    """递归搜索单个值。"""
    if len(matches) >= max_results:
        return

    if isinstance(val, str):
        if _match(val):
            ctx = val if len(val) <= 80 else val[:77] + "..."
            matches.append(SearchMatch(section_name, -1, path, val, ctx))
        return

    if isinstance(val, CodeObjectData):
        # 搜索代码对象中的字符串字段
        if isinstance(val.name, str) and _match(val.name):
            matches.append(SearchMatch(section_name, -1, f"{path}.name", val.name, val.name))
        if isinstance(val.qualname, str) and _match(val.qualname):
            matches.append(SearchMatch(section_name, -1, f"{path}.qualname", val.qualname, val.qualname))
        if isinstance(val.var_names, tuple):
            for vi, vn in enumerate(val.var_names):
                if isinstance(vn, str) and _match(vn):
                    matches.append(SearchMatch(section_name, -1, f"{path}.varnames[{vi}]", vn, vn))
        return

    if isinstance(val, tuple):
        for i, item in enumerate(val):
            if len(matches) >= max_results:
                return
            _search_value(item, _match, matches, section_name, f"{path} > tuple[{i}]", max_results)
        return

    if isinstance(val, list):
        for i, item in enumerate(val):
            if len(matches) >= max_results:
                return
            _search_value(item, _match, matches, section_name, f"{path} > list[{i}]", max_results)
        return

    if isinstance(val, dict):
        for k, v in val.items():
            if len(matches) >= max_results:
                return
            _search_value(k, _match, matches, section_name, f"{path} > dict_key({repr(k)[:30]})", max_results)
            _search_value(v, _match, matches, section_name, f"{path} > dict_val({repr(k)[:30]})", max_results)
        return

    if isinstance(val, (set, frozenset)):
        for item in val:
            if len(matches) >= max_results:
                return
            _search_value(item, _match, matches, section_name, f"{path} > set_item", max_results)
        return


def _collect_code_objects(container, result: list) -> None:
    """递归收集嵌套容器中的代码对象。"""
    for item in container:
        if isinstance(item, CodeObjectData):
            result.append(item)
        elif isinstance(item, (tuple, list)):
            _collect_code_objects(item, result)


# ---------------------------------------------------------------------------
# 序列化：构建 blob
# ---------------------------------------------------------------------------

class _Encoder:
    """将 Python 值编码为 Nuitka TLV 二进制格式。"""

    def __init__(self):
        self.buf = bytearray()
        self._previous: Any = None

    def _write_tag(self, tag: int) -> None:
        self.buf.append(tag)

    def encode(self, value: Any) -> None:
        """编码一个常量值。"""
        # 去重：与前一个完全相同
        if value is not None and value == self._previous and not isinstance(value, (float, complex)):
            self._write_tag(TAG_PREVIOUS)
            return

        if value is None:
            self._write_tag(TAG_NONE)
        elif value is True:
            self._write_tag(TAG_TRUE)
        elif value is False:
            self._write_tag(TAG_FALSE)
        elif isinstance(value, int):
            self._encode_int(value)
        elif isinstance(value, float):
            self._encode_float(value)
        elif isinstance(value, complex):
            self._encode_complex(value)
        elif isinstance(value, str):
            self._encode_str(value)
        elif isinstance(value, bytearray):
            self._write_tag(TAG_BYTEARRAY)
            self.buf.extend(_encode_varint(len(value)))
            self.buf.extend(value)
        elif isinstance(value, bytes):
            self._encode_bytes(value)
        elif isinstance(value, tuple):
            self._encode_container(TAG_TUPLE, value)
        elif isinstance(value, list):
            self._encode_container(TAG_LIST, value)
        elif isinstance(value, dict):
            self._encode_dict(value)
        elif isinstance(value, set):
            self._encode_container(TAG_SET, value)
        elif isinstance(value, frozenset):
            self._encode_container(TAG_FROZENSET, value)
        elif isinstance(value, slice):
            self._write_tag(TAG_SLICE)
            self.encode(value.start)
            self.encode(value.stop)
            self.encode(value.step)
        elif isinstance(value, range):
            self._write_tag(TAG_RANGE)
            self.encode(value.start)
            self.encode(value.stop)
            self.encode(value.step)
        else:
            raise TypeError(f"unsupported type: {type(value)}")

        self._previous = value

    def _encode_int(self, value: int) -> None:
        if value >= 0:
            if value < 2**31:
                self._write_tag(TAG_LONG_POSITIVE_SMALL)
                self.buf.extend(_encode_varint(value))
            else:
                self._write_tag(TAG_LONG_POSITIVE_LARGE)
                parts = []
                v = value
                while v > 0:
                    parts.append(v & 0x7FFFFFFF)
                    v >>= 31
                parts.reverse()
                self.buf.extend(_encode_varint(len(parts)))
                for part in parts:
                    self.buf.extend(_encode_varint(part))
        else:
            abs_val = -value
            if abs_val < 2**31:
                self._write_tag(TAG_LONG_NEGATIVE_SMALL)
                self.buf.extend(_encode_varint(abs_val))
            else:
                self._write_tag(TAG_LONG_NEGATIVE_LARGE)
                parts = []
                v = abs_val
                while v > 0:
                    parts.append(v & 0x7FFFFFFF)
                    v >>= 31
                parts.reverse()
                self.buf.extend(_encode_varint(len(parts)))
                for part in parts:
                    self.buf.extend(_encode_varint(part))

    def _encode_float(self, value: float) -> None:
        import math
        if math.isnan(value):
            self._write_tag(TAG_FLOAT_SPECIAL)
            self.buf.append(0x02 if not math.copysign(1, value) < 0 else 0x03)
        elif math.isinf(value):
            self._write_tag(TAG_FLOAT_SPECIAL)
            self.buf.append(0x04 if value > 0 else 0x05)
        elif value == 0.0:
            self._write_tag(TAG_FLOAT_SPECIAL)
            self.buf.append(0x00 if not math.copysign(1, value) < 0 else 0x01)
        else:
            self._write_tag(TAG_FLOAT)
            self.buf.extend(struct.pack("<d", value))

    def _encode_complex(self, value: complex) -> None:
        import math
        needs_special = (
            math.isnan(value.real) or math.isnan(value.imag)
            or math.isinf(value.real) or math.isinf(value.imag)
            or (value.real == 0.0 and value.imag == 0.0)
        )
        if needs_special:
            self._write_tag(TAG_COMPLEX_SPECIAL)
            self._encode_float(value.real)
            self._encode_float(value.imag)
        else:
            self._write_tag(TAG_COMPLEX)
            self.buf.extend(struct.pack("<dd", value.real, value.imag))

    def _encode_str(self, value: str) -> None:
        if not value:
            self._write_tag(TAG_TEXT_EMPTY)
        elif len(value) == 1 and ord(value) < 256:
            self._write_tag(TAG_TEXT_SINGLE)
            self.buf.append(ord(value))
        elif "\0" not in value:
            # 属性名模式 [a-zA-Z_][a-zA-Z0-9_]* 使用 TAG_ATTRIBUTE_NAME (intern 缓存)
            if _is_attribute_name(value):
                self._write_tag(TAG_ATTRIBUTE_NAME)
            else:
                self._write_tag(TAG_TEXT_UTF8_ZERO_TERMINATED)
            self.buf.extend(value.encode("utf-8"))
            self.buf.append(0)
        else:
            encoded = value.encode("utf-8")
            self._write_tag(TAG_TEXT_UTF8_LENGTH_PREFIXED)
            self.buf.extend(_encode_varint(len(encoded)))
            self.buf.extend(encoded)

    def _encode_bytes(self, value: bytes) -> None:
        if len(value) == 1:
            self._write_tag(TAG_BYTES_SINGLE)
            self.buf.extend(value)
        elif b"\0" not in value:
            self._write_tag(TAG_BYTES_ZERO_TERMINATED)
            self.buf.extend(value)
            self.buf.append(0)
        else:
            self._write_tag(TAG_BYTES_LENGTH_PREFIXED)
            self.buf.extend(_encode_varint(len(value)))
            self.buf.extend(value)

    def _encode_container(self, tag: int, value) -> None:
        self._write_tag(tag)
        self.buf.extend(_encode_varint(len(value)))
        for item in value:
            self.encode(item)

    def _encode_dict(self, value: dict) -> None:
        self._write_tag(TAG_DICT)
        self.buf.extend(_encode_varint(len(value)))
        for key in value:
            self.encode(key)
        for val in value.values():
            self.encode(val)


def encode_constant(value: Any) -> bytes:
    """将单个 Python 值编码为 Nuitka TLV 二进制数据。"""
    enc = _Encoder()
    enc.encode(value)
    return bytes(enc.buf)


def build_section(name: str, constants: list[Any]) -> bytes:
    """构建一个完整的 section（name + size + count + constants + TAG_END）。"""
    enc = _Encoder()
    for c in constants:
        enc.encode(c)
    enc._write_tag(TAG_END)
    body = bytes(enc.buf)

    name_bytes = name.encode("utf-8") + b"\x00"
    header = struct.pack("<I", len(body))
    count = struct.pack("<H", len(constants))
    return name_bytes + header + count + body


def build_blob(
    sections: list[tuple[str, list[Any]]],
    legacy: bool = False,
) -> bytes:
    """构建完整的 Nuitka 常量 blob。

    Args:
        sections: list of (section_name, constants_list)
        legacy: 是否使用旧版格式（含 CRC32 头部）
    """
    parts = []
    for name, constants in sections:
        parts.append(build_section(name, constants))
    body = b"".join(parts)

    if legacy:
        crc = binascii.crc32(body) & 0xFFFFFFFF
        return struct.pack("<II", crc, len(body)) + body
    return body


# ---------------------------------------------------------------------------
# 重建资源数据（含头部）
# ---------------------------------------------------------------------------

def build_constants_resource(
    sections: list[tuple[str, list[Any]]],
    legacy: bool = True,
) -> bytes:
    """构建可直接写入 PE 资源的常量数据。

    Args:
        sections: list of (section_name, constants_list)
        legacy: 旧版格式含 CRC32 头部；新版无头部

    Returns:
        可直接写入 RT_RCDATA/3 资源的字节数据
    """
    return build_blob(sections, legacy=legacy)


# ---------------------------------------------------------------------------
# 原地替换（只修改目标 section 的原始字节）
# ---------------------------------------------------------------------------

def replace_sections_in_blob(
    data: bytes,
    replacements: dict[str, list[Any]],
) -> bytes:
    """原地替换 blob 中指定 section 的内容，其他 section 保持原始字节不变。

    Args:
        data: 原始资源字节（含或不含 CRC 头部均可）
        replacements: {section_name: new_constants_list}

    Returns:
        替换后的新资源字节（保留原格式，自动重算 CRC）
    """
    # 检测是否有 CRC 头部
    header_offset = 0
    if len(data) >= 8:
        potential_crc, potential_size = struct.unpack_from("<II", data, 0)
        if potential_size == len(data) - 8:
            import binascii
            actual_crc = binascii.crc32(data[8:]) & 0xFFFFFFFF
            if actual_crc == potential_crc:
                header_offset = 8

    body = data[header_offset:]

    # 扫描 section 边界，收集每个 section 的原始字节范围
    # 每个 entry: (name, raw_bytes)
    sections_raw: list[tuple[str, bytes]] = []
    offset = 0
    while offset < len(body):
        # 读取 name
        name_end = body.index(0x00, offset)
        name = body[offset:name_end].decode("utf-8")
        name_bytes = body[offset:name_end + 1]  # 含 \0
        offset = name_end + 1

        # 读取 data_size
        part_size = struct.unpack_from("<I", body, offset)[0]
        size_bytes = body[offset:offset + 4]
        offset += 4

        # 整个 section 的原始字节 = name_bytes + size_bytes + body
        section_body = body[offset:offset + part_size]
        section_raw = name_bytes + size_bytes + section_body
        sections_raw.append((name, section_raw))
        offset += part_size

    # 替换目标 section
    new_parts: list[bytes] = []
    for name, raw in sections_raw:
        if name in replacements:
            new_constants = replacements[name]
            # 解析原始 section 的常量，与新常量进行语义比较
            original_body = raw[len(name.encode("utf-8")) + 1 + 4:]
            original_constants = _parse_section_body(original_body)
            if _section_constants_equal(original_constants, new_constants):
                # 常量值完全相同，保留原始字节
                new_parts.append(raw)
            else:
                # 优先保留原始 TLV 编码，只替换等长字符串/bytes payload。
                # Nuitka 对同一个语义值可能有多种合法编码；重新编码会改变
                # section 尺寸，也可能影响运行时对常量流的读取。
                patched_body = _patch_section_body_preserving_encoding(
                    original_body,
                    original_constants,
                    new_constants,
                )
                if patched_body is not None:
                    new_body = patched_body
                else:
                    new_body = _encode_section_body(new_constants)
                name_part = name.encode("utf-8") + b"\x00"
                new_size = struct.pack("<I", len(new_body))
                new_parts.append(name_part + new_size + new_body)
        else:
            new_parts.append(raw)

    new_body = b"".join(new_parts)

    # 重新组装
    if header_offset > 0:
        import binascii
        new_crc = binascii.crc32(new_body) & 0xFFFFFFFF
        return struct.pack("<II", new_crc, len(new_body)) + new_body
    else:
        return new_body


def _encode_section_body(constants: list[Any]) -> bytes:
    """编码 section body = count(2) + constants + TAG_END。"""
    enc = _Encoder()
    for c in constants:
        enc.encode(c)
    enc._write_tag(TAG_END)
    body = bytes(enc.buf)
    count = struct.pack("<H", len(constants))
    return count + body


def _patch_section_body_preserving_encoding(
    original_body: bytes,
    original_constants: list[Any],
    new_constants: list[Any],
) -> bytes | None:
    """Patch scalar changes while preserving existing TLV wrappers.

    Returns None when the change is structural or not supported.
    """
    if len(original_constants) != len(new_constants):
        return None

    try:
        spans = _constant_spans_in_section_body(original_body)
    except (ValueError, struct.error, IndexError):
        return None

    if len(spans) != len(original_constants):
        return None

    patched = bytearray(original_body)
    for index, (old_value, new_value) in enumerate(zip(original_constants, new_constants)):
        if _values_equal(old_value, new_value):
            continue

        start, end = spans[index]

        replacement_constant = _encode_constant_like_original(
            original_body[start:end],
            old_value,
            new_value,
        )
        if replacement_constant is not None:
            patched[start:end] = replacement_constant
        else:
            chunk = _patch_nested_scalars_preserving_encoding(
                original_body[start:end],
                old_value,
                new_value,
            )
            if chunk is None:
                return None
            patched[start:end] = chunk

    try:
        if not _section_constants_equal(_parse_section_body(bytes(patched)), new_constants):
            return None
    except (ValueError, struct.error, IndexError):
        return None

    return bytes(patched)


def _patch_nested_scalars_preserving_encoding(
    original_raw: bytes,
    old_value: Any,
    new_value: Any,
) -> bytes | None:
    """Patch changed scalar leaves inside a container without re-encoding it."""
    changes = _collect_scalar_value_changes(old_value, new_value)
    if changes is None:
        return None

    patched = bytearray(original_raw)
    cursor = 0
    for old_scalar, new_scalar in changes:
        replacement = _replace_one_scalar_preserving_tag(
            bytes(patched),
            old_scalar,
            new_scalar,
            cursor,
        )
        if replacement is None:
            return None
        start, end, new_raw = replacement
        patched[start:end] = new_raw
        cursor = start + len(new_raw)

    return bytes(patched)


def _collect_scalar_value_changes(
    old_value: Any,
    new_value: Any,
) -> list[tuple[Any, Any]] | None:
    """Collect changed str/bytes leaves when the container shape is unchanged."""
    if type(old_value) != type(new_value):
        return None

    if isinstance(old_value, (str, bytes, bytearray)):
        if old_value == new_value:
            return []
        return [(old_value, new_value)]

    if isinstance(old_value, tuple):
        if len(old_value) != len(new_value):
            return None
        return _collect_nested_scalar_changes(zip(old_value, new_value))

    if isinstance(old_value, list):
        if len(old_value) != len(new_value):
            return None
        return _collect_nested_scalar_changes(zip(old_value, new_value))

    if isinstance(old_value, dict):
        if len(old_value) != len(new_value):
            return None
        changes: list[tuple[Any, Any]] = []
        for (old_key, old_item), (new_key, new_item) in zip(old_value.items(), new_value.items()):
            key_changes = _collect_scalar_value_changes(old_key, new_key)
            item_changes = _collect_scalar_value_changes(old_item, new_item)
            if key_changes is None or item_changes is None:
                return None
            changes.extend(key_changes)
            changes.extend(item_changes)
        return changes

    if isinstance(old_value, (set, frozenset, CodeObjectData)):
        return [] if _values_equal(old_value, new_value) else None

    return [] if _values_equal(old_value, new_value) else None


def _collect_nested_scalar_changes(
    pairs,
) -> list[tuple[Any, Any]] | None:
    changes: list[tuple[Any, Any]] = []
    for old_item, new_item in pairs:
        nested = _collect_scalar_value_changes(old_item, new_item)
        if nested is None:
            return None
        changes.extend(nested)
    return changes


def _replace_one_scalar_preserving_tag(
    raw: bytes,
    old_value: Any,
    new_value: Any,
    start_at: int,
) -> tuple[int, int, bytes] | None:
    for old_raw, new_raw in _scalar_encoding_candidates(old_value, new_value):
        pos = raw.find(old_raw, start_at)
        if pos >= 0:
            return pos, pos + len(old_raw), new_raw
    return None


def _scalar_encoding_candidates(
    old_value: Any,
    new_value: Any,
) -> list[tuple[bytes, bytes]]:
    if type(old_value) != type(new_value):
        return []

    if isinstance(old_value, str):
        old_bytes = old_value.encode("utf-8")
        new_bytes = new_value.encode("utf-8")
        candidates: list[tuple[bytes, bytes]] = []
        if old_value == "" and new_value == "":
            candidates.append((bytes([TAG_TEXT_EMPTY]), bytes([TAG_TEXT_EMPTY])))
        if len(old_value) == 1 and ord(old_value) < 256 and len(new_value) == 1 and ord(new_value) < 256:
            candidates.append((
                bytes([TAG_TEXT_SINGLE, ord(old_value)]),
                bytes([TAG_TEXT_SINGLE, ord(new_value)]),
            ))
        candidates.append((
            bytes([TAG_TEXT_UTF8_LENGTH_PREFIXED]) + _encode_varint(len(old_bytes)) + old_bytes,
            bytes([TAG_TEXT_UTF8_LENGTH_PREFIXED]) + _encode_varint(len(new_bytes)) + new_bytes,
        ))
        if "\0" not in old_value and "\0" not in new_value:
            candidates.append((
                bytes([TAG_TEXT_UTF8_ZERO_TERMINATED]) + old_bytes + b"\x00",
                bytes([TAG_TEXT_UTF8_ZERO_TERMINATED]) + new_bytes + b"\x00",
            ))
            candidates.append((
                bytes([TAG_ATTRIBUTE_NAME]) + old_bytes + b"\x00",
                bytes([TAG_ATTRIBUTE_NAME]) + new_bytes + b"\x00",
            ))
        return candidates

    if isinstance(old_value, bytes):
        candidates = []
        if len(old_value) == 1 and len(new_value) == 1:
            candidates.append((bytes([TAG_BYTES_SINGLE]) + old_value, bytes([TAG_BYTES_SINGLE]) + new_value))
        candidates.append((
            bytes([TAG_BYTES_LENGTH_PREFIXED]) + _encode_varint(len(old_value)) + old_value,
            bytes([TAG_BYTES_LENGTH_PREFIXED]) + _encode_varint(len(new_value)) + new_value,
        ))
        if b"\x00" not in old_value and b"\x00" not in new_value:
            candidates.append((
                bytes([TAG_BYTES_ZERO_TERMINATED]) + old_value + b"\x00",
                bytes([TAG_BYTES_ZERO_TERMINATED]) + new_value + b"\x00",
            ))
        return candidates

    if isinstance(old_value, bytearray):
        old_bytes = bytes(old_value)
        new_bytes = bytes(new_value)
        return [(
            bytes([TAG_BYTEARRAY]) + _encode_varint(len(old_bytes)) + old_bytes,
            bytes([TAG_BYTEARRAY]) + _encode_varint(len(new_bytes)) + new_bytes,
        )]

    return []


def _encode_constant_like_original(
    original_raw: bytes,
    old_value: Any,
    new_value: Any,
) -> bytes | None:
    """Encode a changed top-level scalar using its original TLV tag style."""
    if type(old_value) != type(new_value) or not original_raw:
        return None

    tag = original_raw[0]

    if isinstance(old_value, str):
        encoded = new_value.encode("utf-8")
        if tag == TAG_TEXT_EMPTY:
            if new_value == "":
                return bytes([tag])
            return None
        if tag == TAG_TEXT_SINGLE:
            if len(new_value) == 1 and ord(new_value) < 256:
                return bytes([tag, ord(new_value)])
            return None
        if tag == TAG_TEXT_UTF8_LENGTH_PREFIXED:
            return bytes([tag]) + _encode_varint(len(encoded)) + encoded
        if tag in (TAG_TEXT_UTF8_ZERO_TERMINATED, TAG_ATTRIBUTE_NAME):
            if "\0" in new_value:
                return None
            return bytes([tag]) + encoded + b"\x00"
        return None

    if isinstance(old_value, bytes):
        if tag == TAG_BYTES_SINGLE:
            if len(new_value) == 1:
                return bytes([tag]) + new_value
            return None
        if tag == TAG_BYTES_LENGTH_PREFIXED:
            return bytes([tag]) + _encode_varint(len(new_value)) + new_value
        if tag == TAG_BYTES_ZERO_TERMINATED:
            if b"\x00" in new_value:
                return None
            return bytes([tag]) + new_value + b"\x00"
        return None

    if isinstance(old_value, bytearray):
        new_bytes = bytes(new_value)
        if tag == TAG_BYTEARRAY:
            return bytes([tag]) + _encode_varint(len(new_bytes)) + new_bytes
        return None

    return None


def _constant_spans_in_section_body(body: bytes) -> list[tuple[int, int]]:
    """Return raw byte spans for top-level constants in a section body."""
    count = struct.unpack_from("<H", body, 0)[0]
    decoder = _Decoder(body)
    decoder.offset = 2
    spans: list[tuple[int, int]] = []
    for _ in range(count):
        start = decoder.offset
        decoder.decode_constant()
        spans.append((start, decoder.offset))
    return spans


def _collect_same_length_scalar_replacements(
    old_value: Any,
    new_value: Any,
) -> list[tuple[bytes, bytes]] | None:
    """Collect changed str/bytes leaves when the container shape is unchanged."""
    if type(old_value) != type(new_value):
        return None

    if isinstance(old_value, str):
        if old_value == new_value:
            return []
        old_bytes = old_value.encode("utf-8")
        new_bytes = new_value.encode("utf-8")
        if len(old_bytes) != len(new_bytes):
            return None
        return [(old_bytes, new_bytes)]

    if isinstance(old_value, bytes):
        if old_value == new_value:
            return []
        if len(old_value) != len(new_value):
            return None
        return [(old_value, new_value)]

    if isinstance(old_value, bytearray):
        if old_value == new_value:
            return []
        if len(old_value) != len(new_value):
            return None
        return [(bytes(old_value), bytes(new_value))]

    if isinstance(old_value, tuple):
        if len(old_value) != len(new_value):
            return None
        return _collect_nested_replacements(zip(old_value, new_value))

    if isinstance(old_value, list):
        if len(old_value) != len(new_value):
            return None
        return _collect_nested_replacements(zip(old_value, new_value))

    if isinstance(old_value, dict):
        if len(old_value) != len(new_value):
            return None
        replacements: list[tuple[bytes, bytes]] = []
        for (old_key, old_item), (new_key, new_item) in zip(old_value.items(), new_value.items()):
            key_replacements = _collect_same_length_scalar_replacements(old_key, new_key)
            item_replacements = _collect_same_length_scalar_replacements(old_item, new_item)
            if key_replacements is None or item_replacements is None:
                return None
            replacements.extend(key_replacements)
            replacements.extend(item_replacements)
        return replacements

    if isinstance(old_value, (set, frozenset, CodeObjectData)):
        return [] if _values_equal(old_value, new_value) else None

    return [] if _values_equal(old_value, new_value) else None


def _collect_nested_replacements(
    pairs,
) -> list[tuple[bytes, bytes]] | None:
    replacements: list[tuple[bytes, bytes]] = []
    for old_item, new_item in pairs:
        nested = _collect_same_length_scalar_replacements(old_item, new_item)
        if nested is None:
            return None
        replacements.extend(nested)
    return replacements


def _parse_section_body(body: bytes) -> list[Any]:
    """解析 section body（count + constants + TAG_END），不包含 name/size 头部。"""
    count = struct.unpack_from("<H", body, 0)[0]
    decoder = _Decoder(body)
    decoder.offset = 2
    constants: list[Any] = []
    for _ in range(count):
        val = decoder.decode_constant()
        constants.append(val)
    return constants
