# CI 与发布

## 自动检查

| 配置 | 触发条件 | 检查内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | PR、推送 main、手动运行、发布流程调用 | 格式、工作流语法、dist 发布规划；Ubuntu / Windows / macOS 上的 Rust 与 GUI 前端检查、测试和构建 |
| `.github/workflows/security.yml` | 依赖或自身配置变更的 PR / main 推送、每天北京时间 10:23、手动运行、发布流程调用 | RustSec 漏洞审计；依赖许可证、来源与版本规则；保存 14 天审计 JSON |
| `.github/workflows/release.yml` | 在 Actions 中手动运行，填写已存在的版本标签 | 解析标签对应的提交，重新执行 CI 和安全检查，构建 CLI 四目标下载包与 GUI 四目标安装包，全部成功后统一创建 GitHub Release |
| `.github/dependabot.yml` | 每周一北京时间 10:00 | 为 Cargo 依赖及 Actions 提交更新 PR，将兼容的 Cargo 更新分组 |

Rust 固定为 1.99.0，见 `rust-toolchain.toml`。工作流使用 `--locked`；dist 和 Tauri 构建同样使用锁文件。GUI 前端使用 Node.js 22 和 `npm ci`。三平台测试包含 platform crate，Linux 会运行 macOS 上因 APFS 限制而跳过的非 UTF-8 文件名测试。文件操作测试通过 `FILE_TIDY_TEST_ROOT` 使用工作区旁的独立夹具目录；Windows 串行运行相关测试，避免共享祖先目录的元数据变化互相干扰。

日常检查仅使用读取仓库的权限；安全检查直接调用 cargo-audit，支持外部 fork PR，不需要创建 Check 或 Issue 的写权限。只有最后创建 Release 的任务具有 `contents: write`。首次接入无需新增仓库 Secret。

## 发布 CLI

`dist-workspace.toml` 定义以下目标：

- `x86_64-unknown-linux-gnu`：Linux x86_64，以 Ubuntu 22.04 构建，要求 glibc 2.35 或更新版本。
- `x86_64-pc-windows-msvc`：Windows x86_64。
- `aarch64-apple-darwin`：Apple Silicon macOS。
- `x86_64-apple-darwin`：Intel macOS，由 macOS ARM runner 交叉编译。

Release 中以 `file-tidy-cli-` 开头的附件提供 `.tar.xz` / `.zip` 压缩包及 shell / PowerShell 安装脚本，另有源码包和 SHA-256 校验文件。压缩包内的命令为 `file-tidy`（Windows 为 `file-tidy.exe`）。安装脚本由用户按需运行；程序本身不增加自动更新或网络行为。

## 发布 GUI

Tauri 构建与 CLI 打包使用标签解析出的同一个固定提交。GUI 安装包矩阵如下，每个安装包都有同名的 `.sha256` 校验文件：

| 目标 | 安装包格式 | 附件文件名 |
| --- | --- | --- |
| `aarch64-apple-darwin` | macOS DMG | `file-tidy-gui-<version>-aarch64-apple-darwin.dmg` |
| `x86_64-apple-darwin` | macOS DMG | `file-tidy-gui-<version>-x86_64-apple-darwin.dmg` |
| `x86_64-pc-windows-msvc` | Windows NSIS 安装程序 | `file-tidy-gui-<version>-x86_64-pc-windows-msvc-setup.exe` |
| `x86_64-unknown-linux-gnu` | Debian 安装包 | `file-tidy-gui-<version>-x86_64-unknown-linux-gnu.deb` |

Linux GUI 以 Ubuntu 22.04 构建，运行时需要发行版提供的 WebKitGTK 等系统依赖，安装 `.deb` 时由包管理器解析。GUI 构建产物先保存在工作流附件中，只有 CLI、GUI、CI 和安全检查全部成功，最后的发布任务才将它们上传到同一个 GitHub Release。

macOS GUI 暂使用临时签名（ad-hoc），不需要新增仓库 Secret，但不具备 Apple Developer ID 身份和公证。确认软件来源可信后，用户仍需在“系统设置 → 隐私与安全性”中选择“仍要打开”。后续如需通过默认的 macOS 下载安全校验，应另行配置 Developer ID 签名证书和 Apple 公证凭据。

## 创建版本发布

发布步骤：

1. 更新根 `Cargo.toml` 中的 `workspace.package.version` 和两个内部 path 依赖的版本约束，同步 GUI 的 `src-tauri/tauri.conf.json`、`package.json` 与 `package-lock.json` 中的版本，必要时更新 `Cargo.lock`；补充该版本说明并提交。该提交必须包含 GUI 源码及新的发布配置。
2. 将提交推送到 main，确认检查通过。
3. 为该提交创建与版本相符的新标签并推送。例如准备发布 0.2.0：

   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. 进入仓库的 **Actions → Release → Run workflow**，运行分支选择 main，在 `tag` 中填写新标签（例如 `v0.2.0`），再点击 **Run workflow**。首次使用前，工作流配置需已推送到默认分支。

推送标签不会自动发布。手动填写的标签必须已存在于远程，且版本必须与该标签对应的 Cargo 和 GUI 版本相符。所有检查和打包使用标签解析出的同一个固定提交，避免运行分支与发布代码不一致。若发布预发布版，版本和标签应包含相同后缀，例如 `0.2.0-rc.1` / `v0.2.0-rc.1`；工作流会标记 GitHub prerelease。任一检查或构建失败均不执行发布任务。已经存在同名 Release 时，创建步骤会失败，不覆盖现有版本。

已有的 `v0.1.0` Release 仅包含 CLI。更新或推送发布工作流不会自动替换旧附件，也不会让旧标签获得新提交中的 GUI；请使用包含这些改动的新版本标签。

## 维护与本地验证

工作流由仓库维护，dist 负责 CLI 规划和打包，锁定在 GUI `package-lock.json` 中的 Tauri CLI 负责应用打包。配置中的 `allow-dirty = ["ci"]` 用于禁止 dist 在构建检查时要求其默认生成模板，不应使用 `dist generate` 覆盖本仓库的发布门禁。

第三方 Actions 固定到提交 SHA，由 Dependabot 更新。dist 当前固定为 0.33.0，CI / Release 共用 `.github/actions/setup-dist`，直接下载官方 GitHub Release 中的预编译归档并核对固定的 SHA-256，不依赖 crates.io 上的 cargo-dist 版本。升级时同步更新 `dist-workspace.toml` 与该本地 action 的版本、各平台归档校验值。cargo-audit 与 actionlint 也固定版本；actionlint 的下载归档按 SHA-256 校验，升级时需同步更新版本和校验值。

`deny.toml` 对所有平台依赖检查许可证与来源，默认仅允许 crates.io，拒绝未知 Git 来源。`option-ext` 的 MPL-2.0 使用 crate 级例外；新增许可证应审阅后单独修改规则，不通过忽略漏洞绕过安全检查。

安装 actionlint 1.7.12、cargo-deny、cargo-audit 0.22.2 与 dist 0.33.0 后，可执行：

```sh
actionlint
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p file-tidy-cli
cargo audit --file Cargo.lock
cargo deny --locked check bans licenses sources
dist plan
dist build --artifacts=local --target aarch64-apple-darwin
```

最后一条需换为本机目标。测试夹具需要创建 Unix socket / FIFO，受限沙箱可能阻止这些操作；应在允许这些操作的本地环境或原生 runner 验证，不在 CI 静默跳过。
