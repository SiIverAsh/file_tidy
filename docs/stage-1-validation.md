# 阶段 1 验证记录

日期：2026-11-12。本阶段完成只读扫描、分类、查重与 CLI 报告。

## 实现内容

Cargo workspace 包含 `file-tidy-core`、`file-tidy-platform`、`file-tidy-cli`。core 与 CLI 均使用 `forbid(unsafe_code)`；挂载表与 Windows API FFI 位于 platform，每处 unsafe 均有安全不变量说明。

功能包括多根或逐本地卷扫描、有界并行元数据/类型识别/哈希、取消与聚合进度、八类 TOML 分类、UTC 修改年月、项目整体标记、大小 Top N、目录聚合、陈旧与重复报告、逐项跳过原因和 JSON 无损路径编码。报告输出到 stdout，进度输出到 stderr。

内容读取策略：

- 敏感项仅采集元数据；元数据阶段结束后，将已知敏感文件身份传播到本次清单中的硬链接别名。
- 敏感目录按路径及目录身份识别，覆盖 macOS Data 卷别名；内容读取前重新核验。
- 先检查本地性、挂载、卷身份和节点类型，再通过逐级 no-follow 目录句柄枚举，检查范围包括文件和目录 bind mount。
- 内容读取前核对原生文件身份、类型、大小和修改时间，读取后复核文件句柄及路径。FIFO、socket、设备、链接、reparse、云占位和非本地文件系统均跳过内容读取。
- 普通文件按大小、64 KiB 首段和完整 BLAKE3 分组；硬链接按身份去重，变化的候选记录原因并排除。
- 配置文件读取经过本地性、无链接、敏感区及 1 MiB 大小检查。

## 构建与检查结果

环境：macOS / Darwin arm64，rustc 1.99.0、cargo 1.99.0。

以下检查通过：

```sh
cargo check --workspace --offline
cargo build --locked --offline -p file-tidy-cli
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
```

提交前复查 `cargo test --locked --workspace`：**50 passed，0 failed，3 ignored**。

| 测试组 | 通过 | 跳过 |
| --- | --- | --- |
| CLI 单元 | 4 | 0 |
| CLI 进程集成 | 7 | 1 |
| core 单元 | 13 | 0 |
| core 只读集成 | 15 | 1 |
| platform 单元 | 3 | 0 |
| platform 集成 | 8 | 1 |

3 项跳过用例需要创建含非法 UTF-8 字节的原生文件名，本机 APFS 返回 EPERM。这些用例可在支持该名称的文件系统上显式运行。非 UTF-8 路径编码、敏感后缀和分类单元测试均通过。

功能测试覆盖敏感内容零读取、全局 metadata-only 零读取、敏感硬链接别名、首段相同末尾不同、空文件、类型冲突、陈旧时间、路径与目录汇总、修改中候选排除、源文件保持不变、链接与断链、FIFO 替换、socket 跳过、原生身份变化、受限目录枚举、取消、终端转义及配置拒绝。Linux mountinfo 解析与 bind 边界使用纯数据夹具。

## CLI 验证

对仓库的 config、docs 目录使用默认 TOML 输出 JSON 报告：退出码 0，扫描完成。复查命令：

```sh
cargo run --locked -p file-tidy-cli -- scan config docs \
  --rules config/default-rules.toml --format json --quiet
```

对本地卷执行 `--metadata-only --max-entries 32`：退出码 3，`limit_reached = true`、`complete = false`，扫描内容打开次数及读取字节数均为 0。

参数与退出码见[阶段 1 使用说明](stage-1-usage.md)。

## 平台与后续验证

| 项目 | 当前记录与安排 |
| --- | --- |
| macOS | 已验证常规文件、目录、链接、硬链接、FIFO、socket、挂载枚举和 Data 卷敏感目录身份；云占位、TCC、外接卷及其他文件系统场景按矩阵补测 |
| Windows 10/11 | 已编写平台分支和条件测试；原生构建、junction/reparse、长路径、文件 ID 与共享模式安排在阶段 5 |
| Linux | 已运行 mountinfo 解析与 bind 边界数据测试；原生构建、真实挂载与特殊文件系统场景安排在阶段 5 |
| 资源规模 | 默认 250000 条目，上限 1000000；达到上限输出不完整报告，百万条目性能与内存压测待执行 |
| 内容策略 | 扫描已确认的本地文件系统，敏感识别覆盖常见名字、目录和本次清单内的已知身份；`--metadata-only` 适用于全局零内容读取 |
| 授权与文件操作 | 阶段 2 实现授权及计划，阶段 3 实现执行、journal、恢复与撤销 |
| GUI 与依赖审计 | GUI 在阶段 4 实现，三平台 CI、打包、漏洞与许可证检查在阶段 5 执行 |
