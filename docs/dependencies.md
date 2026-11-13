# 依赖选型与来源

记录日期：2026-11-13。表中版本来自各项目的 docs.rs 文档，当前构建使用的版本由 Cargo.toml 与 Cargo.lock 确定。

目录扫描使用 platform 的无跟随目录句柄枚举替代 walkdir，以便在枚举前检查节点和挂载。tracing、dunce、unicode-normalization 保留为后续候选。time 0.3.55 用于 UTC 修改月份，macOS libc 0.2.191 用于线程安全的挂载表查询。

后续引入依赖时检查版本、MSRV、功能开关、许可证和安全公告，更新锁文件并运行对应平台检查。CI 使用 `--locked`。

## 依赖与引入安排

| crate | 核实版本 | 用途与选择理由 | 使用情况 |
| --- | --- | --- | --- |
| [walkdir](https://docs.rs/walkdir/latest/walkdir/) | 2.5.0 | 遍历候选；当前使用 platform 无跟随目录句柄枚举 | 不引入 |
| [rayon](https://docs.rs/rayon/latest/rayon/) | 1.12.0 | 有界线程池用于元数据和内容处理；另设 I/O 队列与每卷限制 | 已使用 |
| [blake3](https://docs.rs/blake3/latest/blake3/) | 1.8.7 | 分段/全量流式哈希及计划摘要；默认不用 mmap | 已使用 |
| [infer](https://docs.rs/infer/latest/infer/) | 0.22.0 | 对已经获许可的有限字节缓冲区识别魔数；不是直接按路径读取 | 已使用 |
| [directories](https://docs.rs/directories/latest/directories/) | 6.0.0 | 系统目录机制及 UserDirs；只建议位置，不自动授权 | 已使用 |
| [dunce](https://docs.rs/dunce/latest/dunce/) | 1.0.5 | Windows 路径兼容辅助；授权使用规范化、身份与句柄检查 | 后续候选 |
| [unicode-normalization](https://docs.rs/unicode-normalization/latest/unicode_normalization/) | 0.1.26 | NFC/NFD 搜索和碰撞提示，保留操作用的原始名称 | 后续候选 |
| [serde](https://docs.rs/serde/latest/serde/) | 1.0.229 | 类型化配置和报告 DTO；不用普通字符串保存原生路径 | 已使用 |
| [serde_json](https://docs.rs/serde_json/latest/serde_json/) | 1.0.154 | stdout 报告、版本化计划快照与 IPC 数据；路径另作无损编码 | 已使用 |
| [toml](https://docs.rs/toml/latest/toml/) | 1.2.1+spec-1.1.0 | 分类规则解析；Cargo 版本约束采用 1.2.1，构建元数据由解析结果确定 | 已使用 |
| [thiserror](https://docs.rs/thiserror/latest/thiserror/) | 2.0.21 | core 的明确错误类型及 I/O 错误链 | 已使用 |
| [anyhow](https://docs.rs/anyhow/latest/anyhow/) | 1.0.104 | CLI/GUI 边界上下文，core 不用它替代结构化错误 | 已使用 |
| [tracing](https://docs.rs/tracing/latest/tracing/) | 0.1.44 | 结构化事件输出 | 后续候选 |
| [clap](https://docs.rs/clap/latest/clap/) | 4.6.7 | CLI 参数、PathBuf 与清晰帮助信息 | 已使用 |
| [ctrlc](https://docs.rs/ctrlc/latest/ctrlc/) | 3.5.2 | CLI 取消信号转为核心取消标记；不在信号回调做文件操作 | 已使用 |
| [tempfile](https://docs.rs/tempfile/latest/tempfile/) | 3.27.0 | 测试夹具；生产暂存必须创建于已授权目标目录并登记 journal，不能只依赖 Drop | 测试依赖 |
| [cap-std](https://docs.rs/cap-std/latest/cap_std/) | 4.0.3 | 目录句柄相对的能力式访问，叠加业务策略与平台安全原语 | 已用于私有状态目录 |
| [rustix](https://docs.rs/rustix/latest/rustix/) | 1.1.6 | Unix 安全 fd 包装、文件系统身份/空间与原子操作，按平台和 feature 引入 | 已用于平台读取 |
| [windows-sys](https://docs.rs/windows-sys/latest/windows_sys/) | 0.61.2 | Windows 常量与必要句柄 API；FFI 只在 platform crate，按需启用 Win32 模块 | 已用于平台读取 |
| [getrandom](https://docs.rs/getrandom/latest/getrandom/) | 0.4.3 | 计划/操作随机 ID、确认挑战和临时对象随机名；失败则拒绝生成能力 | 已用于授权、计划与确认 ID |
| [rusqlite](https://docs.rs/rusqlite/latest/rusqlite/) | 0.42.0 | SQLite journal；拟使用 bundled 统一 SQLite，最终 feature 与底层版本须实际构建核实 | 已用于授权与确认快照 |
| [tauri](https://docs.rs/tauri/latest/tauri/) | 2.12.5 | 本地 IPC GUI，不需要产品运行时 HTTP 服务 | GUI 候选 |
| [tauri-build](https://docs.rs/tauri-build/latest/tauri_build/) | 2.7.4 | GUI 构建及应用命令权限清单；与 tauri 的实际组合待构建 | GUI 候选 |

## 核实但暂不采用

| 候选 | 核实版本 | 决定 |
| --- | --- | --- |
| [trash](https://docs.rs/trash/latest/trash/) | 5.3.0 | 暂不引入。默认工具隔离区可完整控制落点和恢复；系统回收站落点可能越过授权边界，恢复能力也不统一。其文档另提示 Linux/FreeBSD 挂载查询的线程安全限制，需要单独验证 |
| [assert_fs](https://docs.rs/assert_fs/latest/assert_fs/) | 1.1.4 | 当前使用 tempfile 加标准库断言；按后续 CLI 夹具需求评估 |
| ignore | 未作版本选型 | 当前使用 platform 遍历，空间报告包含被 ignore 规则匹配的文件 |
| dirs | 未作版本选型 | directories 已覆盖需求，不重复引入 |
| axum / ratatui | 未作版本选型 | 采用用户指定 Tauri 2，不引入额外 Web 服务或替换为 TUI |

TypeScript、前端构建工具、Tauri JavaScript API、对话框库、打包器及审计工具在 GUI 与打包功能引入时选型并锁定版本。

## 工具链与构建政策

当前工具链为 `rustc 1.99.0`、`cargo 1.99.0`，平台 Darwin arm64。Workspace 使用 Rust 2024 edition，`rust-version` 设为 1.99。跨平台最小支持版本通过 CI 矩阵验证。

CI 计划引入 cargo-audit 检查 workspace 锁文件及 GUI 依赖，并评估用 cargo-deny 检查许可证与来源策略。审计结果随 CI 记录保存。
