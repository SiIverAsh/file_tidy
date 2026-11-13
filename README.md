# File Tidy

Rust 编写的本地文件整理工具，支持空间分析、文件分类、查重、操作计划与授权移动。

## 功能

- 扫描单个目录、多个目录，或按本地卷分别扫描。
- 按扩展名和文件类型识别文档、图片、视频、音频、压缩包、代码、安装包及其他文件，支持 TOML 自定义分类规则。
- 展示占用最大的文件、目录汇总、逻辑大小和可取得的实际分配大小。
- 按修改时间标记陈旧文件，默认阈值为 365 天。
- 通过文件大小、首段哈希和完整 BLAKE3 查找重复文件，并按文件身份排除硬链接重复计数。
- 支持仅元数据扫描；敏感目录和密钥类文件默认只采集元数据。
- 标记项目、依赖目录和应用包，记录链接、特殊节点、权限不足等跳过原因。
- 输出文本或 JSON 报告，JSON 路径保留平台原生编码。
- 支持并行处理、进度显示、条目数量限制和 Ctrl-C 取消，取消或达到上限时输出部分报告。
- 管理会话与持久目录授权，记录目录身份，支持授权查看和撤销。
- 生成复制、移动、重命名、隔离及永久删除的操作计划，展示完整清单、隐藏项、敏感项和冲突改名。
- 支持逐项选择、数量确认与敏感项许可，将确认后的计划快照保存到私有状态存储。
- 交互确认后执行同卷移动与重命名，支持文件、完整目录和符号链接，并采用无覆盖发布。
- 保存批次与逐步操作日志，查询执行历史，核对中断操作的源、目标和完整目录清单。

## 构建

需要 Rust 1.99 或更新版本。

```sh
cargo build --locked -p file-tidy-cli
```

## 使用

扫描当前目录：

```sh
cargo run --locked -p file-tidy-cli -- scan .
```

只采集元数据：

```sh
cargo run --locked -p file-tidy-cli -- scan . --metadata-only
```

输出 JSON 报告：

```sh
cargo run --locked -p file-tidy-cli -- scan . --format json --quiet
```

按本地卷扫描：

```sh
cargo run --locked -p file-tidy-cli -- scan --all --metadata-only
```

报告输出到 stdout，进度输出到 stderr。更多参数见[使用说明](docs/usage.md)，分类规则见[默认配置](config/default-rules.toml)。

## CI 与发布

GitHub Actions 在 Linux、Windows 和 macOS 上运行构建与测试，并定期检查依赖安全与许可证。在 Actions 中手动运行 Release 并填写已推送的版本标签，检查通过后发布 CLI 下载包；配置与操作见 [CI 与发布说明](docs/ci-cd.md)。
