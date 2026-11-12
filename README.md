# File Tidy 本地文件整理工具

面向 Windows 10/11、macOS、Linux 的 Rust 文件整理工具。全盘扫描只读，文件修改必须经过区域授权、计划预览和明确确认。

当前版本提供**只读扫描、分类、查重与 CLI 报告**。授权、操作计划、文件修改和 GUI 按下方路线图推进。

```sh
cargo build --locked -p file-tidy-cli
cargo run --locked -p file-tidy-cli -- scan . --metadata-only
cargo run --locked -p file-tidy-cli -- scan . --format json --quiet
```

扫描结果输出 stdout，进度输出 stderr，不自动创建缓存、journal 或文件日志。默认最多扫描 250000 个条目，可调整至 1000000；达到预算会明确输出不完整报告。敏感文件仅采集元数据，普通文件可按大小、首段及完整 BLAKE3 检测重复，结果不自动触发修改。

- [阶段 1 使用与验证方法](docs/stage-1-usage.md)
- [阶段 1 验证记录](docs/stage-1-validation.md)：macOS arm64 上构建、fmt、clippy 及 50 项测试通过，3 项原生非 UTF-8 用例因 APFS 文件名限制跳过。

- [威胁模型与架构](docs/architecture.md)：区域规则、授权入口、路径安全、计划、执行、撤销、GUI 与阶段边界。
- [依赖选型](docs/dependencies.md)：2026-11-12 核实到的稳定版本、用途和官方来源。
- [Journal 表结构设计](docs/journal-v1.sql)：操作记录、确认审计与隔离区的数据模型。
- [安全验收矩阵](docs/security-test-matrix.md)：后续各阶段必须实现的测试及平台验证方法。
- [阶段 0 验证记录](docs/stage-0-validation.md)：SQLite 表结构与约束检查。

阶段顺序：0 设计 → 1 只读扫描、分类与报告 → 2 授权与计划 → 3a 移动、重命名、复制、journal 与撤销 → 3b 隔离区 → 3c 永久删除专项评审 → 4 GUI → 5 三平台 CI、打包与文档。

目录遍历先检查节点和挂载，再通过无跟随目录句柄枚举。三平台验证安排见[安全验收矩阵](docs/security-test-matrix.md)。
