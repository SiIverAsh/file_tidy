# 使用说明

工具提供 Rust core、平台只读适配层和 clap CLI。扫描选定目录或本地卷，显示文件元数据、类型分类、空间占用、陈旧文件、重复组与跳过原因。

## 构建与运行

在工程根目录执行：

```sh
cargo build --locked -p file-tidy-cli
cargo run --locked -p file-tidy-cli -- --help
cargo run --locked -p file-tidy-cli -- scan --help
```

首次构建需要从 crates.io 下载锁定的开发依赖。发布程序运行期间不请求网络。

先对当前目录执行仅元数据扫描：

```sh
cargo run --locked -p file-tidy-cli -- scan . --metadata-only
```

扫描指定目录并输出 JSON；将占位路径换成实际本地目录：

```sh
cargo run --locked -p file-tidy-cli -- scan /absolute/local/directory --format json --quiet
```

同时扫描多个根目录：

```sh
cargo run --locked -p file-tidy-cli -- scan /absolute/first /absolute/second --threads 4
```

Windows 可直接传入原生目录，例如 `scan "D:\Data" --metadata-only`。路径含空格时使用当前 shell 的引号规则；以连字符开头的相对路径放在 `--` 之后。

全盘模式按本地卷分别扫描，每个扫描任务不进入嵌套挂载点：

```sh
cargo run --locked -p file-tidy-cli -- scan --all --metadata-only
```

`--all` 和指定 ROOT 互斥。普通账户权限不足的项目会出现在跳过报告中，扫描继续；程序不会提权。

## 读取范围与隐私

报告输出至 stdout，进度输出至 stderr，扫描结果保存在内存中。需要保存报告时可使用 shell 重定向。

默认扫描普通本地文件的元数据与有限魔数前缀，并按大小、前段 BLAKE3、全量 BLAKE3 查重。敏感区域 B 始终只采集元数据，不进入魔数识别或查重。使用 `--metadata-only` 将这个限制扩展到所有扫描条目；`--no-duplicates` 只关闭查重，仍允许普通文件的魔数识别。

扫描先完成元数据阶段，再将已知敏感文件身份传播到本次清单中的硬链接别名，最后读取允许的文件内容。敏感识别依据常见目录、名称及本次清单中的已知身份；全局零内容读取使用 `--metadata-only`。

显式指定 `--rules` 时需要读取该 TOML 配置。配置读取同样检查普通本地文件、无链接跟随和敏感区限制；其内容不写入错误日志。规则不能解除敏感区域、系统保护区域或节点过滤。

隐藏文件和点文件可出现在只读清单中；后续整理计划仍将默认排除它们。项目、依赖目录和 `.app` 等整体会被标记，扫描期间仅采集和分析信息。链接、Windows reparse point、特殊节点、虚拟文件系统、非本地卷和不确定的内容读取会被阻止或记录为跳过。

JSON 的路径结构包含展示文本、平台编码和原始整数单元，支持非 UTF-8 文件名。展示文本用于阅读，不能反向构造执行路径。大小等可能超过 JavaScript 安全整数范围的量使用十进制字符串；例如 `summary.content_bytes_read` 为 `"0"` 时表示没有读取扫描内容。

## 参数与资源上限

| 参数 | 默认或范围 | 行为 |
| --- | --- | --- |
| `--metadata-only` | 关闭 | 扫描条目只读取元数据，关闭魔数和查重 |
| `--no-duplicates` | 关闭 | 关闭重复检测，仍可做类型识别 |
| `--format text\|json` | text | 人类可读文本或结构化 JSON |
| `--top N` | 20，正整数 | 显示占用最大的 N 项 |
| `--stale-days N` | 365 | 按修改时间标记陈旧，不是最后访问或使用时间 |
| `--threads N` | 可用并行度，最多默认 8 | 允许 1 到 64 个 worker |
| `--max-entries N` | 250000 | 允许 1 到 1000000；达到预算后停止并返回不完整报告 |
| `--rules TOML` | 内置规则 | 使用自定义分类规则，文件最大 1 MiB |
| `--quiet` / `-q` | 关闭 | 不显示进度，不影响 stdout 报告 |
| `--progress` | 终端自动显示 | 强制向非终端 stderr 输出无路径进度，与 quiet 互斥 |

遍历完成前显示发现数、处理数、读取字节和阶段，不估算精确完成百分比。按 Ctrl-C 会请求取消；正在处理的读取块结束后退出，并尽可能输出带取消标记的不完整报告。

扫描清单保存在内存中，上限为 1000000 条目；较大目录可分根扫描。达到上限后报告带不完整标记。目录发现和枚举按检查后的队列进行，元数据策略判断、魔数和哈希由有界 worker 并行处理。

空间报告分别展示逐路径逻辑总量、按文件身份去重的逻辑总量及可取得的分配字节。重复组排除同一身份的硬链接。稀疏、压缩、clone/reflink 文件的物理占用由文件系统决定；重复组用于人工审阅。

## 自定义分类规则

仓库中的 `config/default-rules.toml` 是可直接审阅的完整默认规则：

```sh
cargo run --locked -p file-tidy-cli -- scan . --rules config/default-rules.toml
```

自定义文件替换默认分类映射，不影响安全策略。最小示例：

```toml
schema_version = 1

[[rules]]
category = "document"
extensions = ["txt", "pdf"]
mime_types = ["application/pdf"]

[[rules]]
category = "image"
extensions = ["png", "jpg"]
mime_prefixes = ["image/"]
```

分类名为 document、image、video、audio、archive、code、installer、other。未知字段、重复或非法匹配、路径与脚本字段均拒绝。魔数与扩展名冲突会保留冲突证据；年/月按 UTC 修改时间分类。

## 退出码与自动化读取

| 退出码 | 意义 |
| --- | --- |
| 0 | 扫描完成并写出报告 |
| 2 | 参数、配置、初始化或报告输出失败 |
| 3 | 已输出不完整报告，例如条目预算达到上限或部分路径无法处理 |
| 130 | 收到取消请求，已输出取消后的部分报告 |

自动化调用应同时检查退出码和 `summary.complete`、`summary.cancelled`、`summary.limit_reached`。跳过和失败原因保存在报告中，未扫描项标记为未知。进度只显示聚合计数。

## 验证与平台状态

工程检查命令：

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

CLI 集成测试使用独立夹具验证 JSON、仅元数据读取统计、文件保持不变、条目预算、敏感规则拒绝、控制字符展示、非 UTF-8 名称及 Unix SIGINT 取消。`FILE_TIDY_TEST_ROOT` 可指定独立测试根；默认使用构建目录中的新建夹具。

本机 APFS 拒绝创建含非法 UTF-8 字节的原生文件名，相应用例标记为 ignored。在支持该名称的文件系统上，可显式运行：

```sh
cargo test -p file-tidy-cli --test scan_cli non_utf8 -- --ignored
```

各测试组结果见[测试说明](testing.md)。Windows/Linux 原生运行、平台权限、挂载和打包 GUI 场景按[安全验收矩阵](security-test-matrix.md)执行。
