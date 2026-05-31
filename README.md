# NuitkaForge

**Nuitka onefile 资源包处理工具** — 用于列出、解压、修改、重封 Nuitka onefile 程序生成的资源包。

## 功能

```
extract      将 onefile 包解压到目录
pack         从目录重建 onefile 包并写回 EXE
replace      替换 archive 中的指定条目
verify       验证 onefile 包结构完整性
info         显示 EXE 的 onefile 资源概要信息
inspect-dll  检查 onefile 包内 DLL 的 PE 资源目录（含 Nuitka 常量 CRC 校验）
parse-constants
             解析并导出 Nuitka 常量资源 (RT_RCDATA/3)
search       在常量资源中递归搜索字符串
replace-constants
             修改 Nuitka 常量 section，自动修复 CRC 和处理 PE 资源扩容
config       管理 section 过滤规则
```

## 安装

```bash
pip install -r requirements.txt
```

依赖：
- `pefile` — PE 文件解析
- `zstandard` — zstd 压缩/解压
- `rsa` — RSA 密钥处理（仅 `test_mask.py` 需要）

## 使用

### 解压到目录

```bash
python -m nuitka_forge extract app.exe --out ./extracted
```

### 从目录重建

```bash
python -m nuitka_forge pack app.exe --src-dir ./extracted --out app.patched.exe
```

### 替换指定条目

```bash
python -m nuitka_forge replace app.exe --name mask.dll --file ./new_mask.dll --out app.patched.exe
```

### 验证包结构

```bash
python -m nuitka_forge verify app.exe
```

### 查看 EXE 信息

```bash
python -m nuitka_forge info app.exe
```

### 检查 DLL/EXE 内层资源（含 Nuitka 常量 CRC 校验）

```bash
# 检查提取出的 mask.dll
python -m nuitka_forge inspect-dll app_extracted/mask.dll

# 深度分析常量资源 payload（提取字符串、PEM 公钥等）
python -m nuitka_forge inspect-dll mask.dll --constants
```

### 解析和搜索常量资源

```bash
# 显示 TLV 结构
python -m nuitka_forge parse-constants mask.dll

# 在所有常量 section 中递归搜索字符串
python -m nuitka_forge search mask.dll "BEGIN RSA PUBLIC KEY"

# 导出单个 section
python -m nuitka_forge replace-constants mask.dll --dump-section "__main__" -o __main__.json
python -m nuitka_forge replace-constants mask.dll --dump-section "__parents_main__" -o __parents_main__.json
```

### 修改常量 section

修改导出的 JSON 后，可以一次替换一个或多个 section：

```bash
python -m nuitka_forge replace-constants mask.dll \
  --replace-section __main__.json __parents_main__.json \
  -o mask.patch.dll
```

替换时会保留未修改 section 的原始字节。对于字符串、`bytes` 和
`bytearray`，工具会尽量沿用原始 TLV tag，只更新发生变化的 payload 和长度，
避免因为整段重编码导致资源大小异常变化。

如果新资源超过原 PE 资源槽位，工具会将资源迁移到可映射 section 的末尾，
同步更新资源 RVA、资源大小、section 大小、`SizeOfImage` 和 PE checksum。
因此支持不同长度的字符串或公钥修改。修改后仍需确保内容本身符合目标程序的
业务格式要求。

## 高级用法：替换 mask.dll 中的 RSA 公钥

先导出包含公钥的 section，修改 JSON 中的 PEM 字符串，再写回 `mask.dll`：

```bash
python -m nuitka_forge replace-constants mask.dll --dump-section "__main__" -o __main__.json
python -m nuitka_forge replace-constants mask.dll --dump-section "__parents_main__" -o __parents_main__.json
python -m nuitka_forge replace-constants mask.dll \
  --replace-section __main__.json __parents_main__.json \
  -o mask.patch.dll
```

如果同一个公钥同时存在于多个 section 中，应保持这些副本一致。

## 项目结构

```
nuitka_forge/
├── __init__.py          # 包版本信息
├── __main__.py          # python -m 入口
├── core.py              # 调度入口 + 公共工具（re-export 两个子模块）
├── onefile.py           # ★ Nuitka 打包 EXE 处理：资源提取、zstd、archive 遍历/重建/替换、写回
├── constants.py         # ★ Nuitka 常量 TLV 解析、搜索、保留编码替换
├── peutils.py           # ★ 解包后 PE 文件处理：PE 资源枚举、CRC 校验/修复、常量资源替换与深度分析
├── config.py            # section 过滤配置
└── cli.py               # CLI 子命令

.gitignore
requirements.txt
README.md
```

## 技术原理

1. Nuitka onefile 资源存储在 PE 的 `RT_RCDATA` 段（type=10, id=27）
2. 资源格式为 `KAY` 头 + zstd 压缩流
3. 解压后的 archive 是自定义文件表：`utf16le_filename + NUL + uint64le_size + file_bytes`
4. mask.dll 内部还有一个 Nuitka 常量资源 (RT_RCDATA/3)，带 CRC32 校验
5. 修改任何字节后必须同步更新 CRC32，否则程序启动会报 `"Error, corrupted constants object"` 并退出
6. 常量 section 中的字符串可能嵌套在 tuple、list 或 dict 中，修改时需要保留原始 TLV 编码结构
7. 常量资源变长并超过原槽位时，需要迁移资源并修正 PE 映射信息，不能直接覆盖后续资源
