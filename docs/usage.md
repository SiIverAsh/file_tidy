# 使用说明

工具提供 Rust core、平台适配层和 clap CLI。扫描选定目录或本地卷，显示文件元数据、类型分类、空间占用、陈旧文件、重复组与跳过原因。

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

同一目录经不同大小写或命名空间再次出现时，按原生目录身份识别已枚举别名；单链接文件也按身份避免重复计数。跳过记录中的 `path_alias` 表示相同对象已经由另一个路径发现，不是读取失败。真正的硬链接目录项仍可分别显示，空间另有按文件身份去重的统计。Windows 全盘任务优先使用卷 GUID 根，因此报告路径可能是 `\\?\Volume{...}\...`。

魔数与后缀的一致性按具体格式判断；例如 PNG 内容使用 `.jpg` 后缀会显示 Conflict。通用 ZIP 签名只能证明容器格式，APK、Office 等具体类别可依据已配置后缀保留，但证据只标 Extension，不表示验证过完整应用格式。

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

## 目录授权

选择一个已有的本地数据目录初始化状态存储：

```sh
cargo run --locked -p file-tidy-cli -- state init /absolute/local/workspace
```

命令先展示位置和用途，交互确认后在所选目录内创建 `.file-tidy`，保存持久授权与计划快照。该目录采用当前用户私有权限，并通过单写者锁协调授权变更和确认记录。

查看授权、添加目录或按 ID 撤销：

```sh
cargo run --locked -p file-tidy-cli -- grant list --state /absolute/local/workspace
cargo run --locked -p file-tidy-cli -- grant add /absolute/other/data --state /absolute/local/workspace
cargo run --locked -p file-tidy-cli -- grant revoke GRANT_ID --state /absolute/local/workspace
```

授权绑定目录的原生身份。目录被删除重建、卷发生变化或授权被撤销后，需要重新审阅相关操作计划。会话授权通过计划命令的 `--grant ROOT` 传入，进程结束时失效。

系统建议目录可通过 `grant suggest` 查看。Linux 的 `grant suggest --read-user-dirs` 会读取系统用户目录配置，此选项明确允许该配置读取。

## 操作计划

预览移动计划：

```sh
cargo run --locked -p file-tidy-cli -- plan move /absolute/local/workspace/source \
  --to /absolute/local/workspace/destination --state /absolute/local/workspace
```

使用会话授权预览复制计划并输出 JSON：

```sh
cargo run --locked -p file-tidy-cli -- plan copy /absolute/source/file \
  --to /absolute/local/data/copy --grant /absolute/local/data --format json
```

操作类型支持 `copy`、`move`、`rename`、`quarantine`、`permanent-delete`。单个源的 `--to` 表示完整目标路径；多个源时表示目标目录。`--select 1,3` 按从 1 开始的序号保留指定操作，`--include-hidden` 显式包含隐藏项，`--max-entries` 设置完整清单的条目预算。

文本预览列出每个源与目标、完整目录清单、需要创建的目录、冲突改名、隐藏项与敏感项。默认确认阈值为 100 个文件/链接或 10 GiB；空目录作为独立确认项计数。永久删除的额外阈值为 10 项或 1 GiB。

添加 `--approve` 后，命令在交互终端依次核对计划摘要、所需数量、逐项敏感许可和永久删除确认词，再保存确认快照。确认有效期为 15 分钟。确认时会重新检查授权、文件与目录身份、清单和目标冲突。

预览只读取文件系统；`--approve` 保存审阅快照。

## 移动与重命名

使用 `--execute` 在同一次交互中审阅、确认并执行：

```sh
cargo run --locked -p file-tidy-cli -- plan move /absolute/local/workspace/source \
  --to /absolute/local/workspace/destination --state /absolute/local/workspace --execute
```

执行入口支持目标父目录已存在的同卷 `move` 和 `rename`，包括普通文件、完整目录及符号链接。目录按已审阅的完整清单检查，符号链接移动链接本身。目标在执行前被占用时，该项停止并保留现存目标。数据库及虚拟机对象需先建立一致快照。

在名称大小写不敏感的文件系统上，仅修改名称拼写时，预览会展示同目录内的中间位置。两步重命名分别记录日志，中途停止时，执行报告与恢复诊断会列出保留的临时路径。

每次文件操作先保存意图，完成后核验原生身份与清单并记录结果。批内某项失败、日志不可写或收到 Ctrl-C 时停止后续项，报告保留已完成、未开始和待恢复的操作。执行成功返回 0，部分完成或失败返回 2，取消返回 130。`--execute` 与仅保存快照的 `--approve` 分别使用。

## 校验复制

```sh
cargo run --locked -p file-tidy-cli -- plan copy /absolute/source/file \
  --to /absolute/local/workspace/copy --state /absolute/local/workspace --execute
```

`copy --execute` 支持普通文件和完整目录，逐文件复制主数据流，目标父目录须已存在并在当前授权内。源可以位于授权目录之外；敏感源按清单逐项确认内容读取许可。副本保留修改时间，使用当前用户私有权限；ACL、扩展属性、资源叉及附加数据流不在该主数据流复制策略的范围内。

预览列出目标旁的暂存位置。执行时检查目标卷可用空间与预留量，流式计算源 BLAKE3，写入并同步暂存文件，再完整复读暂存副本核对哈希和长度，最后无覆盖发布。源变化、校验不一致、目标被占用或取消会停止发布。保留的暂存对象及其身份记录可通过 `recover` 查看。

目录复制先在私有暂存目录中构建整棵树，逐文件验证内容，保留空目录、隐藏项及修改时间，按原始目标文本重建符号链接。确认包含隐藏项使用 `--include-hidden`。所有子项验证完成后，目标目录整体发布；目录中出现新增、替换或无法核验的子项时停止发布。目标路径下的敏感子项分别确认写入范围，读取敏感源文件时分别确认内容许可。

## 隔离与恢复

审阅并将对象移入来源授权根内的隔离区：

```sh
cargo run --locked -p file-tidy-cli -- plan quarantine /absolute/local/workspace/source \
  --state /absolute/local/workspace --retain-days 30 --execute
```

隔离支持普通文件、完整目录和符号链接。计划展示 `<授权根>/.file-tidy/quarantine/<批次>/<操作>/payload`、需要创建的私有目录、完整清单与保留天数。确认后使用同卷重命名，保留原对象身份、权限、扩展属性和链接关系。隐藏项使用 `--include-hidden`，敏感项逐项确认写入范围。

查看隔离项及到期提醒：

```sh
cargo run --locked -p file-tidy-cli -- quarantine list --state /absolute/local/workspace
cargo run --locked -p file-tidy-cli -- quarantine list --state /absolute/local/workspace --due
```

保留期默认为 30 天，`--retain-days` 可设为 1 至 36500 天。到期项列入提醒，载荷继续保留供恢复。列表包含隔离项 ID、所属批次、原位置、隔离位置和状态。

按列表中的 ID 预览并恢复：

```sh
cargo run --locked -p file-tidy-cli -- quarantine restore ITEM_ID \
  --state /absolute/local/workspace --execute
```

可同时传入多个 ID；使用 `quarantine restore --batch BATCH_ID` 恢复该批次中仍保留的全部隔离项，`quarantine list --batch BATCH_ID` 按批次查看。默认恢复到原位置，同名目标存在时预览 `name (1).ext`；`--to PATH` 指定单项的完整目标路径，多项时指定目标目录。恢复目标父目录须已存在、位于同卷当前授权内。恢复重新检查隔离目录身份、完整清单、敏感项许可和授权；撤销原授权后可重新授权同一目录，再生成恢复计划。`--include-hidden` 显式包含原对象中的隐藏项。

恢复完成会追加独立批次，并记录与原隔离操作的关联。`recover` 可核对隔离或恢复中断后的实际位置与未完成日志。

## 永久删除与隔离区清理

预览并永久删除授权目录内的对象：

```sh
cargo run --locked -p file-tidy-cli -- plan permanent-delete /absolute/local/workspace/source \
  --state /absolute/local/workspace --include-hidden --permanent --execute
```

计划列出完整清单、总量、需要创建的私有目录和删除前的暂存位置。确认时输入 `PERMANENT <数量> <挑战码>`；超过 10 个文件/链接或 1 GiB 时另行核对数量，敏感项逐项确认写入范围。`--permanent` 与永久删除操作配合使用。

执行先在同卷私有位置捕获原对象，再逐项移除文件、链接及空目录，每项分别保存意图与结果。链接处理链接本身。执行历史保留不可撤销的已删除项，`recover` 列出已确认移除数量、待核对的删除意图和当前尚存清单。

清理已登记的隔离项：

```sh
cargo run --locked -p file-tidy-cli -- quarantine purge ITEM_ID \
  --state /absolute/local/workspace --permanent --execute
cargo run --locked -p file-tidy-cli -- quarantine purge --batch BATCH_ID \
  --state /absolute/local/workspace --include-hidden --permanent --execute
```

清理重新审阅当前载荷、授权和确认词。中断后可对尚存清单生成新的清理计划，或显式恢复尚存内容：

```sh
cargo run --locked -p file-tidy-cli -- quarantine restore ITEM_ID \
  --state /absolute/local/workspace --remaining --include-hidden --execute
```

`--remaining` 展示并恢复当前保留的清单；原操作中已删除的项继续保留在删除记录中。完整恢复使用普通 `quarantine restore`，按批次恢复尚存内容可加 `--batch BATCH_ID`。

## 撤销操作

预览并撤销已完成的批次：

```sh
cargo run --locked -p file-tidy-cli -- undo BATCH_ID \
  --state /absolute/local/workspace --execute
```

使用 `--operation OPERATION_ID` 选择单条操作，可重复传入。批次按原操作的逆序生成新计划，已完成撤销的项会从整批计划中排除。每次重新核对当前授权、对象身份和完整清单，并展示目标冲突的新名称。原批次保持原有记录，撤销批次通过操作 ID 关联原操作。

移动与重命名撤销会把原对象移回审阅的位置。隔离撤销会生成恢复计划，恢复撤销会把对象重新移入隔离区。复制撤销核对本工具创建的副本身份、目录清单和逐文件 BLAKE3，再将副本移入其授权根的隔离区；这一步可以在原复制源已移走后执行。`--retain-days` 设置撤销副本的保留期，默认 30 天。

包含隐藏项时使用 `--include-hidden`。复制撤销涉及的敏感文件重新确认内容校验许可。后续操作仍依赖该对象时，先撤销后续操作，再生成较早操作的撤销计划。

## 执行历史与恢复诊断

```sh
cargo run --locked -p file-tidy-cli -- history --state /absolute/local/workspace
cargo run --locked -p file-tidy-cli -- history --state /absolute/local/workspace --batch BATCH_ID
cargo run --locked -p file-tidy-cli -- recover --state /absolute/local/workspace
```

历史按批次展示操作、确认快照、步骤意图与结果。恢复诊断只读核验未完成记录，区分尚未提交、已观察到移动结果、复制半成品、已校验待发布副本、已发布待记账副本、需检查的对象变化，以及授权或介质不可用。已取消批次中仍有未完成意图的操作也会列出。诊断结果以 JSON 输出，`--batch` 指定批次，`--limit` 设置批次数量上限。
