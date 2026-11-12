# 阶段 0 验证记录

日期：2026-11-12。本阶段完成架构设计、安全测试规格、依赖选型及 journal 表结构设计。

## 验证环境

- 平台：Darwin arm64。
- 工具链：Rust 1.99.0、Cargo 1.99.0、Python 3.14.8。
- 数据库：SQLite 3.53.4，使用 Python 标准库 sqlite3 的内存数据库。
- 依赖来源见[依赖选型](dependencies.md)。

## SQLite 表结构与约束

加载 [journal-v1.sql](journal-v1.sql) 后，检查结果如下：

- 7 个 STRICT 表创建成功，schema `user_version = 1`。
- 合法的 copy 与 permanent_delete 记录可插入；永久删除记录要求显式标记 irreversible。
- 17 个非法变更被拒绝：错误 ID 长度、copy 缺少目的地、永久删除未标不可逆、永久删除带目的地、失效外键、未知路径编码、以 TEXT 代替原生路径 BLOB、批内序号重复、负总大小、改写已封存快照、改写操作源路径、替换授权根、更新事件、删除事件、无效确认到期时间、敏感确认缺少子项 ID、隔离保留期倒置。
- 包含 `0xff` 字节的 Unix 路径 BLOB 无损往返。
- SAVEPOINT/ROLLBACK 恢复数据库操作状态成功。
- `PRAGMA foreign_key_check` 无错误，`PRAGMA integrity_check` 为 `ok`。

在工程根目录复查基本 DDL：

```sh
sqlite3 :memory: ".read docs/journal-v1.sql" \
  "PRAGMA foreign_key_check;" \
  "PRAGMA integrity_check;" \
  "PRAGMA user_version;"
```

预期 integrity 输出 `ok`，schema 版本输出 `1`；外键检查无违规行。

## 后续验证安排

Rust 工程构建、扫描和报告验证见[阶段 1 记录](stage-1-validation.md)。授权、文件操作、崩溃恢复与平台场景按[安全验收矩阵](security-test-matrix.md)执行。
