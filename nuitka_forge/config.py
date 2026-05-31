"""
Nuitka Forge 配置管理模块。

配置文件位于项目根目录的 config.toml，随项目分发。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 配置文件路径：项目根目录下的 config.toml
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.toml"

# ---------------------------------------------------------------------------
# 配置数据类
# ---------------------------------------------------------------------------


@dataclass
class FilterConfig:
    """section 过滤配置。"""
    hide_prefixes: list[str] = field(default_factory=list)
    hide_names: list[str] = field(default_factory=list)

    def should_hide(self, section_name: str) -> bool:
        """判断一个 section 是否应该被隐藏。"""
        if not section_name:
            return False

        if section_name in self.hide_names:
            return True

        for prefix in self.hide_prefixes:
            if section_name.startswith(prefix):
                return True

        return False


@dataclass
class NuitkaForgeConfig:
    """Nuitka Forge 全局配置。"""
    section_filter: FilterConfig = field(default_factory=FilterConfig)


# ---------------------------------------------------------------------------
# 配置读写
# ---------------------------------------------------------------------------


def _parse_toml_simple(text: str) -> dict:
    """简易 TOML 解析器，仅支持本项目的配置结构。

    支持:
      [section]
      key = ["str1", "str2"]
      key = "value"
    支持多行数组和行内注释。
    """
    result: dict = {}
    current_section: str | None = None
    in_array = False
    array_key = ""
    array_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # 去掉行尾注释（但不破坏引号内的 #）
        stripped = _strip_inline_comment(stripped)

        # 正在收集多行数组
        if in_array:
            array_lines.append(stripped)
            if "]" in stripped:
                in_array = False
                inner = " ".join(array_lines)
                inner = inner[inner.index("[") + 1:]
                inner = inner[:inner.rindex("]")]
                if current_section is not None:
                    result[current_section][array_key] = _parse_toml_array_values(inner)
            continue

        # section header
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1].strip()
            if current_section not in result:
                result[current_section] = {}
            continue

        # key = value
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()

            if current_section is None:
                continue

            # 解析数组（可能跨多行）
            if value.startswith("["):
                if value.endswith("]"):
                    inner = value[1:-1].strip()
                    if not inner:
                        result[current_section][key] = []
                    else:
                        result[current_section][key] = _parse_toml_array_values(inner)
                else:
                    in_array = True
                    array_key = key
                    array_lines = [value]
            elif value.startswith('"') and value.endswith('"'):
                result[current_section][key] = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                result[current_section][key] = value[1:-1]
            else:
                result[current_section][key] = value

    return result


def _strip_inline_comment(line: str) -> str:
    """去掉行尾注释，但不影响引号内的内容。"""
    in_quote = False
    quote_char = ""
    for i, ch in enumerate(line):
        if in_quote:
            if ch == quote_char:
                in_quote = False
        elif ch in ('"', "'"):
            in_quote = True
            quote_char = ch
        elif ch == "#" and not in_quote:
            return line[:i].rstrip()
    return line


def _parse_toml_array_values(inner: str) -> list[str]:
    """解析 TOML 数组的内部值列表。"""
    if not inner.strip():
        return []
    items = []
    for item in _split_toml_array(inner):
        item = item.strip()
        if not item:
            continue
        if item.startswith('"') and item.endswith('"'):
            item = item[1:-1]
        elif item.startswith("'") and item.endswith("'"):
            item = item[1:-1]
        items.append(item)
    return items


def _split_toml_array(inner: str) -> list[str]:
    """分割 TOML 数组元素，正确处理带引号的字符串中的逗号。"""
    items: list[str] = []
    current = ""
    in_quote = False
    quote_char = ""

    for ch in inner:
        if in_quote:
            current += ch
            if ch == quote_char:
                in_quote = False
        elif ch in ('"', "'"):
            in_quote = True
            quote_char = ch
            current += ch
        elif ch == ",":
            items.append(current)
            current = ""
        else:
            current += ch

    if current.strip():
        items.append(current)
    return items


def load_config() -> NuitkaForgeConfig:
    """加载配置文件，不存在则返回空配置（不过滤任何 section）。"""
    if not CONFIG_PATH.exists():
        return NuitkaForgeConfig()

    text = CONFIG_PATH.read_text(encoding="utf-8")
    data = _parse_toml_simple(text)

    config = NuitkaForgeConfig()

    if "section_filter" in data:
        sf = data["section_filter"]
        if "hide_prefixes" in sf:
            config.section_filter.hide_prefixes = sf["hide_prefixes"]
        if "hide_names" in sf:
            config.section_filter.hide_names = sf["hide_names"]

    return config


def save_config(config: NuitkaForgeConfig) -> Path:
    """保存配置文件，返回文件路径。"""
    lines = [
        "# Nuitka Forge 配置文件",
        "# 直接编辑本文件，或使用 nuitka-forge config 命令管理",
        "",
        "[section_filter]",
        "",
        "# 隐藏匹配前缀的 section",
        "# 删除不需要的条目，或添加自己的前缀",
        "hide_prefixes = [",
    ]
    for prefix in config.section_filter.hide_prefixes:
        lines.append(f'    "{prefix}",')
    lines.append("]")
    lines.append("")
    lines.append("# 隐藏精确匹配的 section 名称")
    lines.append("hide_names = [")
    for name in config.section_filter.hide_names:
        lines.append(f'    "{name}",')
    lines.append("]")
    lines.append("")

    CONFIG_PATH.write_text("\n".join(lines), encoding="utf-8")
    return CONFIG_PATH


# ---------------------------------------------------------------------------
# 便捷函数
# ---------------------------------------------------------------------------


def filter_sections(
    sections: list,
    filter_config: FilterConfig,
    show_all: bool = False,
) -> tuple[list, list]:
    """将 sections 分为可见和隐藏两组。

    返回 (visible_sections, hidden_sections)。
    """
    if show_all:
        return list(sections), []

    visible = []
    hidden = []
    for section in sections:
        if filter_config.should_hide(section.name):
            hidden.append(section)
        else:
            visible.append(section)
    return visible, hidden


def build_skip_names(filter_config: FilterConfig) -> set[str]:
    """从过滤配置构建需要跳过解析的 section 名称集合。

    包含 hide_names 中的精确名称，以及 hide_prefixes 中的前缀。
    返回的集合传递给 parse_blob 的 skip_names 参数。
    """
    # hide_names 直接加入
    skip: set[str] = set(filter_config.hide_names)
    return skip
