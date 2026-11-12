-- Journal v1 表结构设计：授权、操作状态、确认审计与隔离区记录。
-- 应用打开已授权、私有、本地状态目录后再设置并读取验证：
-- foreign_keys=ON; journal_mode=DELETE; synchronous=EXTRA;
-- macOS 按支持情况启用 fullfsync；所有状态写入单写者串行化。
-- DDL 使用内存数据库检查；持久化参数在状态库初始化时检查。
PRAGMA foreign_keys = ON;

CREATE TABLE store_metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 16),
    path_encoding TEXT NOT NULL CHECK (path_encoding IN ('unix_bytes', 'windows_wide_le')),
    root_path BLOB NOT NULL CHECK (length(root_path) > 0),
    volume_identity BLOB NOT NULL CHECK (length(volume_identity) > 0),
    directory_identity BLOB NOT NULL CHECK (length(directory_identity) > 0),
    persistent INTEGER NOT NULL CHECK (persistent IN (0, 1)),
    epoch INTEGER NOT NULL CHECK (epoch >= 0),
    created_at_s INTEGER NOT NULL,
    revoked_at_s INTEGER
) STRICT;

CREATE TABLE batches (
    batch_id BLOB PRIMARY KEY CHECK (length(batch_id) = 16),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    snapshot BLOB NOT NULL CHECK (length(snapshot) > 0),
    grant_epoch INTEGER NOT NULL CHECK (grant_epoch >= 0),
    item_count INTEGER NOT NULL CHECK (item_count >= 0),
    total_bytes INTEGER NOT NULL CHECK (total_bytes >= 0),
    state TEXT NOT NULL CHECK (state IN (
        'sealed', 'confirmed', 'running', 'completed', 'partial',
        'cancelled', 'rejected', 'needs_recovery'
    )),
    created_at_s INTEGER NOT NULL,
    completed_at_s INTEGER
) STRICT;

CREATE TABLE operations (
    op_id BLOB PRIMARY KEY CHECK (length(op_id) = 16),
    batch_id BLOB NOT NULL REFERENCES batches(batch_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    kind TEXT NOT NULL CHECK (kind IN (
        'move', 'rename', 'copy', 'quarantine', 'restore',
        'permanent_delete', 'undo_copy'
    )),
    inverse_of BLOB REFERENCES operations(op_id),
    path_encoding TEXT NOT NULL CHECK (path_encoding IN ('unix_bytes', 'windows_wide_le')),
    source_path BLOB NOT NULL CHECK (length(source_path) > 0),
    destination_path BLOB,
    before_fingerprint BLOB NOT NULL CHECK (length(before_fingerprint) > 0),
    after_fingerprint BLOB,
    manifest BLOB,
    source_grant_id BLOB REFERENCES grants(grant_id),
    destination_grant_id BLOB REFERENCES grants(grant_id),
    irreversible INTEGER NOT NULL CHECK (irreversible IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN (
        'planned', 'prepared', 'staged', 'verified', 'published',
        'source_remove_intent', 'done', 'skipped', 'failed', 'needs_recovery'
    )),
    reason_code TEXT,
    CHECK (
        (kind = 'permanent_delete' AND irreversible = 1 AND destination_path IS NULL)
        OR
        (kind <> 'permanent_delete' AND irreversible = 0
            AND destination_path IS NOT NULL AND length(destination_path) > 0)
    ),
    UNIQUE (batch_id, ordinal)
) STRICT;

-- 恢复/撤销所需的必要原生路径和指纹仅在本地私有状态库中存储。
-- payload 是 core 校验的版本化步骤记录，禁止写入原文件内容或原始确认秘密。
CREATE TABLE operation_events (
    event_id INTEGER PRIMARY KEY,
    op_id BLOB NOT NULL REFERENCES operations(op_id),
    step TEXT NOT NULL CHECK (length(step) > 0),
    phase TEXT NOT NULL CHECK (phase IN ('intent', 'result', 'reconciliation')),
    payload BLOB NOT NULL CHECK (length(payload) > 0),
    created_at_s INTEGER NOT NULL
) STRICT;

-- 此表仅作确认审计，不可从数据库记录重新构造运行期写能力。
CREATE TABLE approval_audit (
    approval_id BLOB PRIMARY KEY CHECK (length(approval_id) = 16),
    batch_id BLOB NOT NULL REFERENCES batches(batch_id),
    plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
    subject_op_id BLOB REFERENCES operations(op_id),
    subject_entry_id BLOB CHECK (subject_entry_id IS NULL OR length(subject_entry_id) = 16),
    scope TEXT NOT NULL CHECK (scope IN (
        'ordinary', 'large_plan', 'sensitive_write', 'sensitive_content',
        'permanent', 'large_permanent'
    )),
    grant_epoch INTEGER NOT NULL CHECK (grant_epoch >= 0),
    nonce_digest BLOB NOT NULL CHECK (length(nonce_digest) = 32),
    issued_at_s INTEGER NOT NULL,
    expires_at_s INTEGER NOT NULL,
    consumed_at_s INTEGER,
    CHECK (expires_at_s > issued_at_s),
    CHECK (consumed_at_s IS NULL OR
        (consumed_at_s >= issued_at_s AND consumed_at_s <= expires_at_s)),
    CHECK (scope NOT IN ('sensitive_write', 'sensitive_content') OR
        (subject_op_id IS NOT NULL AND subject_entry_id IS NOT NULL))
) STRICT;

CREATE TABLE quarantine_items (
    item_id BLOB PRIMARY KEY CHECK (length(item_id) = 16),
    op_id BLOB NOT NULL REFERENCES operations(op_id),
    grant_id BLOB NOT NULL REFERENCES grants(grant_id),
    path_encoding TEXT NOT NULL CHECK (path_encoding IN ('unix_bytes', 'windows_wide_le')),
    original_path BLOB NOT NULL CHECK (length(original_path) > 0),
    storage_path BLOB NOT NULL UNIQUE CHECK (length(storage_path) > 0),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    retained_at_s INTEGER NOT NULL,
    expires_at_s INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('stored', 'restored', 'purged', 'needs_recovery')),
    CHECK (expires_at_s >= retained_at_s)
) STRICT;

CREATE INDEX operations_by_batch ON operations(batch_id, ordinal);
CREATE INDEX events_by_operation ON operation_events(op_id, event_id);
CREATE INDEX quarantine_expiry ON quarantine_items(state, expires_at_s);

CREATE TRIGGER immutable_batch_plan
BEFORE UPDATE OF schema_version, plan_digest, policy_digest, snapshot,
    grant_epoch, item_count, total_bytes, created_at_s ON batches
BEGIN
    SELECT RAISE(ABORT, 'sealed plan is immutable');
END;

CREATE TRIGGER immutable_grant_root
BEFORE UPDATE OF path_encoding, root_path, volume_identity, directory_identity ON grants
BEGIN
    SELECT RAISE(ABORT, 'grant root replacement requires a new grant');
END;

CREATE TRIGGER immutable_operation_plan
BEFORE UPDATE OF batch_id, ordinal, kind, inverse_of, path_encoding, source_path,
    destination_path, before_fingerprint, manifest, source_grant_id,
    destination_grant_id, irreversible ON operations
BEGIN
    SELECT RAISE(ABORT, 'operation plan is immutable');
END;

CREATE TRIGGER events_no_update BEFORE UPDATE ON operation_events
BEGIN
    SELECT RAISE(ABORT, 'operation events are append only');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON operation_events
BEGIN
    SELECT RAISE(ABORT, 'operation events are append only');
END;

-- core 负责区域检查、状态转换、跨表一致性和当前对象身份核验。
-- approval_audit 的操作归属与 digest 一致性由 core 校验。
-- raw 路径 BLOB 不一定是 UTF-8；不能 CAST 成执行用 TEXT。
-- SQL INTEGER 只能容纳有符号 64 位；总量超限时拒绝计划，不能截断/溢出。
PRAGMA user_version = 1;
