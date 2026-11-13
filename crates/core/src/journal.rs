//! Durable execution intents and read-only history of reviewed batches.
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::approval::ApprovedPlan;
use crate::authorization::{Grant, Id, NativePath, PlanningError as E, Result, Session};
use crate::plan::{OperationKind, now};
use crate::storage::StateStore;

const MAX_SNAPSHOT: usize = 64 * 1024 * 1024;
const MAX_EVENT: usize = MAX_SNAPSHOT;
type StoredGrantRoot = (String, Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Planned,
    Prepared,
    Staged,
    Verified,
    Published,
    SourceRemoveIntent,
    Done,
    Skipped,
    Failed,
    NeedsRecovery,
}
impl OperationState {
    fn name(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Prepared => "prepared",
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Published => "published",
            Self::SourceRemoveIntent => "source_remove_intent",
            Self::Done => "done",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::NeedsRecovery => "needs_recovery",
        }
    }
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Done | Self::Skipped | Self::Failed | Self::NeedsRecovery
        )
    }
    fn accepts(self, next: Self) -> bool {
        if self.terminal() || next == Self::Planned {
            return false;
        }
        if matches!(next, Self::Failed | Self::NeedsRecovery) {
            return true;
        }
        match self {
            Self::Planned => matches!(next, Self::Prepared | Self::Skipped),
            Self::Prepared => matches!(
                next,
                Self::Prepared | Self::Staged | Self::Published | Self::Done
            ),
            Self::Staged => matches!(next, Self::Staged | Self::Verified | Self::Done),
            Self::Verified => matches!(next, Self::Verified | Self::Published),
            Self::Published => matches!(
                next,
                Self::Published | Self::SourceRemoveIntent | Self::Done
            ),
            Self::SourceRemoveIntent => matches!(next, Self::SourceRemoveIntent | Self::Done),
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchState {
    Running,
    Completed,
    Partial,
    Cancelled,
    NeedsRecovery,
}
impl BatchState {
    fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::NeedsRecovery => "needs_recovery",
        }
    }
}

/// History is audit data. It does not grant permission to repeat an operation.
#[derive(Debug, Serialize)]
pub struct BatchHistory {
    pub id: String,
    pub digest: String,
    pub state: BatchState,
    pub item_count: u64,
    pub total_bytes: String,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct OperationHistory {
    pub id: String,
    pub ordinal: u64,
    pub kind: String,
    pub source: NativePath,
    pub destination: Option<NativePath>,
    pub state: OperationState,
    pub reason: Option<String>,
    pub source_grant: Option<String>,
    pub destination_grant: Option<String>,
    pub before_fingerprint: serde_json::Value,
    pub after_fingerprint: Option<serde_json::Value>,
    pub manifest: serde_json::Value,
}
#[derive(Debug, Serialize)]
pub struct JournalEvent {
    pub id: u64,
    pub operation_id: String,
    pub step: String,
    pub phase: String,
    pub payload: serde_json::Value,
    pub created_at: u64,
}
#[derive(Debug, Serialize)]
pub struct BatchHistoryDetail {
    pub batch: BatchHistory,
    pub snapshot: serde_json::Value,
    pub operations: Vec<OperationHistory>,
    pub events: Vec<JournalEvent>,
    pub events_truncated: bool,
}

impl Session {
    pub fn history(&self, limit: usize) -> Result<Vec<BatchHistory>> {
        if !(1..=1000).contains(&limit) {
            return Err(E::InvalidRequest);
        }
        self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|connection| {
            let mut query = connection.prepare("SELECT hex(batch_id), hex(plan_digest), state, item_count, total_bytes, created_at_s, completed_at_s FROM batches ORDER BY created_at_s DESC, rowid DESC LIMIT ?1")?;
            let mut rows = query.query([limit as i64])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                result.push(read_batch(row)?);
            }
            Ok(result)
        })
    }

    pub(crate) fn pending_execution_batches(&self, limit: usize) -> Result<Vec<String>> {
        if !(1..=1000).contains(&limit) {
            return Err(E::InvalidRequest);
        }
        self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|connection| {
            let mut query = connection.prepare("SELECT DISTINCT hex(batch_id) FROM operations WHERE state NOT IN ('done','skipped','failed') ORDER BY batch_id LIMIT ?1")?;
            let result = query.query_map([(limit+1) as i64], |row| row.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if result.len()>limit { return Err(E::Overflow); }
            Ok(result.into_iter().map(|id|id.to_ascii_lowercase()).collect())
        })
    }

    pub fn batch_history(&self, batch: &Id) -> Result<BatchHistoryDetail> {
        let id = id_bytes(batch)?;
        self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|connection| {
            let mut query = connection.prepare("SELECT hex(batch_id), hex(plan_digest), state, item_count, total_bytes, created_at_s, completed_at_s FROM batches WHERE batch_id=?1")?;
            let mut rows = query.query([&id])?;
            let batch = read_batch(rows.next()?.ok_or(E::InvalidRequest)?)?;
            let snapshot = connection.query_row("SELECT snapshot FROM batches WHERE batch_id=?1 AND length(snapshot)<=?2", params![id, MAX_SNAPSHOT as i64], |row| row.get::<_,Vec<u8>>(0))?;
            if blake3::hash(&snapshot).to_hex().as_str() != batch.digest {
                return Err(E::StorageUnavailable);
            }
            let snapshot: serde_json::Value = serde_json::from_slice(&snapshot)?;
            let mut query = connection.prepare("SELECT hex(op_id), ordinal, kind, path_encoding, source_path, destination_path, state, reason_code, before_fingerprint, after_fingerprint, manifest, CASE WHEN source_grant_id IS NULL THEN NULL ELSE hex(source_grant_id) END, CASE WHEN destination_grant_id IS NULL THEN NULL ELSE hex(destination_grant_id) END FROM operations WHERE batch_id=?1 ORDER BY ordinal LIMIT 10001")?;
            let mut rows = query.query([&id])?;
            let mut operations = Vec::new();
            while let Some(row) = rows.next()? {
                let encoding: String = row.get(3)?;
                let source: Vec<u8> = row.get(4)?;
                let destination: Option<Vec<u8>> = row.get(5)?;
                let before: Vec<u8> = row.get(8)?;
                let after: Option<Vec<u8>> = row.get(9)?;
                let manifest: Vec<u8> = row.get(10)?;
                if before.len() > MAX_EVENT || after.as_ref().is_some_and(|b| b.len()>MAX_EVENT) || manifest.len() > MAX_SNAPSHOT {
                    return Err(E::StorageUnavailable);
                }
                operations.push(OperationHistory {
                    id: row.get::<_,String>(0)?.to_ascii_lowercase(),
                    ordinal: nonnegative(row.get(1)?)?,
                    kind: row.get(2)?,
                    source: native_path(&encoding, &source)?,
                    destination: destination.map(|p| native_path(&encoding,&p)).transpose()?,
                    state: parse_state(&row.get::<_,String>(6)?)?,
                    reason: row.get(7)?,
                    source_grant: row.get::<_,Option<String>>(11)?.map(|v|v.to_ascii_lowercase()),
                    destination_grant: row.get::<_,Option<String>>(12)?.map(|v|v.to_ascii_lowercase()),
                    before_fingerprint: serde_json::from_slice(&before)?,
                    after_fingerprint: after.map(|b| serde_json::from_slice(&b)).transpose()?,
                    manifest: serde_json::from_slice(&manifest)?,
                });
            }
            if operations.len()>10000 { return Err(E::StorageUnavailable); }
            validate_operation_records(&snapshot, &operations)?;
            let mut query = connection.prepare("SELECT event_id, hex(e.op_id), step, phase, payload, created_at_s FROM operation_events e JOIN operations o ON e.op_id=o.op_id WHERE o.batch_id=?1 ORDER BY event_id LIMIT 10001")?;
            let mut rows = query.query([&id])?;
            let mut events = Vec::new();
            let mut event_bytes = 0usize;
            let mut events_truncated = false;
            while let Some(row) = rows.next()? {
                let payload: Vec<u8> = row.get(4)?;
                if payload.len()>MAX_EVENT { return Err(E::StorageUnavailable); }
                event_bytes = event_bytes.checked_add(payload.len()).ok_or(E::Overflow)?;
                if event_bytes>MAX_SNAPSHOT { events_truncated = true; break; }
                events.push(JournalEvent { id: nonnegative(row.get(0)?)?, operation_id: row.get::<_,String>(1)?.to_ascii_lowercase(), step: row.get(2)?, phase: row.get(3)?, payload: serde_json::from_slice(&payload)?, created_at: nonnegative(row.get(5)?)? });
            }
            events_truncated |= events.len()>10000;
            events.truncate(10000);
            Ok(BatchHistoryDetail { batch, snapshot, operations, events, events_truncated })
        })
    }
}

impl StateStore {
    /// Save the complete batch and confirmation before the first filesystem mutation.
    pub(crate) fn start_execution(
        &mut self,
        approved: &ApprovedPlan,
        grants: &BTreeMap<Id, Grant>,
    ) -> Result<()> {
        let preview = approved.preview();
        let snapshot = serde_json::to_vec(preview)?;
        if snapshot.len() > MAX_SNAPSHOT
            || blake3::hash(&snapshot).to_hex().as_str() != approved.digest()
            || now()? >= preview.expires_at
        {
            return Err(E::InvalidPlan);
        }
        let digest = hex_bytes::<32>(approved.digest())?;
        let policy_digest = hex_bytes::<32>(&preview.policy_digest)?;
        let batch = id_bytes(&preview.id)?;
        let epoch = integer(preview.authorization_epoch)?;
        let created = integer(now()?)?;
        let total: i64 = preview.total_bytes.parse().map_err(|_| E::Overflow)?;
        if total < 0 || preview.operations.is_empty() || preview.operations.len() > 10000 {
            return Err(E::InvalidPlan);
        }
        self.journal_write(|transaction| {
            let audit: Option<(String,Vec<u8>,i64)> = transaction.query_row("SELECT digest,snapshot,confirmed_at FROM confirmation_snapshots WHERE receipt=?1 AND length(snapshot)<=?2", params![approved.receipt_id().as_str(),MAX_SNAPSHOT as i64], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let (audit_digest,audit_snapshot,confirmed_at) = audit.ok_or(E::ConfirmationRequired)?;
            if audit_digest!=approved.digest() || audit_snapshot!=snapshot || confirmed_at<integer(preview.created_at)? || confirmed_at>=integer(preview.expires_at)? { return Err(E::ConfirmationRequired); }
            let mut referenced = BTreeSet::new();
            for operation in &preview.operations {
                referenced.extend(operation.source_grant.iter());
                referenced.extend(operation.destination_grant.iter());
            }
            for id in referenced {
                let grant = grants.get(id).ok_or(E::OutsideGrant)?;
                if grant.revoked { return Err(E::OutsideGrant); }
                let grant_id = id_bytes(id)?;
                let (encoding,path) = path_bytes(&grant.root)?;
                let old: Option<StoredGrantRoot> = transaction.query_row("SELECT path_encoding,root_path,volume_identity,directory_identity FROM grants WHERE grant_id=?1", [&grant_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
                if let Some((old_encoding,old_path,volume,file)) = old
                    && (old_encoding!=encoding || old_path!=path || volume!=grant.identity.volume.as_bytes() || file!=grant.identity.file.as_bytes())
                { return Err(E::StorageUnavailable); }
                transaction.execute("INSERT INTO grants(grant_id,path_encoding,root_path,volume_identity,directory_identity,persistent,epoch,created_at_s) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(grant_id) DO UPDATE SET persistent=excluded.persistent,epoch=excluded.epoch", params![grant_id,encoding,path,grant.identity.volume.as_bytes(),grant.identity.file.as_bytes(),grant.persistent,epoch,created])?;
            }
            transaction.execute("INSERT INTO batches(batch_id,schema_version,plan_digest,policy_digest,snapshot,grant_epoch,item_count,total_bytes,state,created_at_s) VALUES(?1,1,?2,?3,?4,?5,?6,?7,'running',?8)", params![batch,digest,policy_digest,snapshot,epoch,integer(preview.confirmation_count)?,total,integer(preview.created_at)?])?;
            for (ordinal,operation) in preview.operations.iter().enumerate() {
                let kind = match operation.kind { OperationKind::Move=>"move",OperationKind::Rename=>"rename",OperationKind::Copy=>"copy",OperationKind::Quarantine=>"quarantine",OperationKind::PermanentDelete=>"permanent_delete" };
                let (encoding,source) = path_bytes(&operation.source)?;
                let destination = operation.destination.as_ref().map(|d| path_bytes(&d.path).map(|(_,b)|b)).transpose()?;
                let root = operation.manifest.iter().find(|e| e.path==operation.source).ok_or(E::InvalidPlan)?;
                transaction.execute("INSERT INTO operations(op_id,batch_id,ordinal,kind,path_encoding,source_path,destination_path,before_fingerprint,manifest,source_grant_id,destination_grant_id,irreversible,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'planned')",params![id_bytes(&operation.id)?,batch,ordinal as i64,kind,encoding,source,destination,serde_json::to_vec(&root.stamp)?,serde_json::to_vec(&operation.manifest)?,operation.source_grant.as_ref().map(id_bytes).transpose()?,operation.destination_grant.as_ref().map(id_bytes).transpose()?,operation.kind==OperationKind::PermanentDelete])?;
            }
            let nonce = blake3::hash(approved.receipt_id().as_str().as_bytes());
            transaction.execute("INSERT INTO approval_audit(approval_id,batch_id,plan_digest,scope,grant_epoch,nonce_digest,issued_at_s,expires_at_s,consumed_at_s) VALUES(?1,?2,?3,'ordinary',?4,?5,?6,?7,?8)",params![id_bytes(approved.receipt_id())?,batch,digest,epoch,nonce.as_bytes(),confirmed_at,integer(preview.expires_at)?,created])?;
            let mut scopes = Vec::new();
            if preview.requires_count_confirmation {
                scopes.push((if preview.permanent_challenge.is_some() { "large_permanent" } else { "large_plan" }, None, None));
            }
            if preview.permanent_challenge.is_some() { scopes.push(("permanent", None, None)); }
            for acknowledgement in &preview.sensitive_acknowledgements {
                let mut parts = acknowledgement.split(':');
                let operation = hex_bytes::<16>(parts.next().ok_or(E::InvalidPlan)?)?;
                let subject = parts.next().ok_or(E::InvalidPlan)?;
                let scope = match parts.next() { Some("content") => "sensitive_content", Some("write") => "sensitive_write", _ => return Err(E::InvalidPlan) };
                if parts.next().is_some() || !preview.operations.iter().any(|op|id_bytes(&op.id).is_ok_and(|id|id==operation)) { return Err(E::InvalidPlan); }
                let entry: [u8;16] = blake3::hash(subject.as_bytes()).as_bytes()[..16].try_into().map_err(|_|E::InvalidPlan)?;
                scopes.push((scope, Some(operation), Some(entry)));
            }
            for (scope, operation, entry) in scopes {
                transaction.execute("INSERT INTO approval_audit(approval_id,batch_id,plan_digest,subject_op_id,subject_entry_id,scope,grant_epoch,nonce_digest,issued_at_s,expires_at_s,consumed_at_s) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![id_bytes(&Id::new()?)?,batch,digest,operation,entry,scope,epoch,nonce.as_bytes(),confirmed_at,integer(preview.expires_at)?,created])?;
            }
            Ok(())
        })
    }

    /// An intent is committed before the corresponding native operation is attempted.
    pub(crate) fn record_intent(
        &mut self,
        operation: &Id,
        step: &str,
        payload: &impl Serialize,
    ) -> Result<()> {
        self.record_event(operation, step, "intent", payload, None)
    }

    /// Results follow native durability checks; uncertain outcomes retain recovery status.
    pub(crate) fn record_result(
        &mut self,
        operation: &Id,
        step: &str,
        payload: &impl Serialize,
        state: OperationState,
    ) -> Result<()> {
        self.record_event(operation, step, "result", payload, Some(state))
    }

    fn record_event(
        &mut self,
        operation: &Id,
        step: &str,
        phase: &str,
        payload: &impl Serialize,
        state: Option<OperationState>,
    ) -> Result<()> {
        if step.is_empty()
            || step.len() > 64
            || !step.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(E::InvalidRequest);
        }
        let payload = serde_json::to_vec(payload)?;
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        let reason = value
            .get("reason")
            .or_else(|| value.get("error"))
            .and_then(serde_json::Value::as_str)
            .filter(|s| s.len() <= 4096);
        if payload.len() > MAX_EVENT {
            return Err(E::Overflow);
        }
        let operation = id_bytes(operation)?;
        self.journal_write(|transaction| {
            let previous: String = transaction.query_row("SELECT o.state FROM operations o JOIN batches b ON o.batch_id=b.batch_id WHERE o.op_id=?1 AND b.state='running'",[&operation],|row|row.get(0))?;
            let previous = parse_state(&previous)?;
            let last: Option<(String,String)> = transaction.query_row("SELECT step,phase FROM operation_events WHERE op_id=?1 ORDER BY event_id DESC LIMIT 1",[&operation],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
            let next = state.unwrap_or(if previous==OperationState::Planned { OperationState::Prepared } else { previous });
            if !previous.accepts(next) || (phase=="intent" && last.as_ref().is_some_and(|(_,p)| p=="intent")) { return Err(E::InvalidPlan); }
            if phase=="result" {
                let paired = last.as_ref().is_some_and(|(s,p)| s==step && p=="intent");
                if !paired && !matches!(next,OperationState::Failed | OperationState::Skipped | OperationState::NeedsRecovery) { return Err(E::InvalidPlan); }
                if last.as_ref().is_some_and(|(s,p)|p=="intent" && s!=step) { return Err(E::InvalidPlan); }
            }
            transaction.execute("INSERT INTO operation_events(op_id,step,phase,payload,created_at_s) VALUES(?1,?2,?3,?4,?5)",params![operation,step,phase,payload,integer(now()?)?])?;
            let after = matches!(next, OperationState::Done | OperationState::Published).then_some(&payload);
            transaction.execute("UPDATE operations SET state=?2, after_fingerprint=COALESCE(?3,after_fingerprint),reason_code=COALESCE(?4,reason_code) WHERE op_id=?1",params![operation,next.name(),after,reason])?;
            Ok(())
        })
    }

    pub(crate) fn finish_execution(&mut self, batch: &Id, state: BatchState) -> Result<()> {
        if state == BatchState::Running {
            return Err(E::InvalidRequest);
        }
        let batch = id_bytes(batch)?;
        self.journal_write(|transaction| {
            let mut query = transaction.prepare("SELECT state FROM operations WHERE batch_id=?1")?;
            let mut rows = query.query([&batch])?;
            let mut states=Vec::new();
            while let Some(row)=rows.next()? { states.push(parse_state(&row.get::<_,String>(0)?)?); }
            let valid = !states.is_empty() && match state {
                BatchState::Completed => states.iter().all(|s| *s == OperationState::Done),
                BatchState::Cancelled => states.iter().all(|s| matches!(s,
                    OperationState::Planned | OperationState::Prepared | OperationState::Done | OperationState::Skipped)),
                BatchState::Partial => states.iter().all(|s| matches!(s,
                    OperationState::Planned | OperationState::Prepared | OperationState::Done | OperationState::Skipped | OperationState::Failed)),
                BatchState::NeedsRecovery => true,
                BatchState::Running => false,
            };
            if !valid { return Err(E::InvalidPlan); }
            let changed=transaction.execute("UPDATE batches SET state=?2,completed_at_s=?3 WHERE batch_id=?1 AND state='running'",params![batch,state.name(),integer(now()?)?])?;
            if changed!=1 { return Err(E::InvalidPlan); }
            Ok(())
        })
    }
}

fn validate_operation_records(
    snapshot: &serde_json::Value,
    records: &[OperationHistory],
) -> Result<()> {
    let operations = snapshot
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .ok_or(E::StorageUnavailable)?;
    if operations.len() != records.len() {
        return Err(E::StorageUnavailable);
    }
    for (index, (operation, record)) in operations.iter().zip(records).enumerate() {
        let source: NativePath = serde_json::from_value(
            operation
                .get("source")
                .ok_or(E::StorageUnavailable)?
                .clone(),
        )?;
        let destination: Option<NativePath> = operation
            .get("destination")
            .and_then(|d| d.get("path"))
            .map(|p| serde_json::from_value(p.clone()))
            .transpose()?;
        let manifest = operation.get("manifest").ok_or(E::StorageUnavailable)?;
        let before = manifest
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.get("path") == operation.get("source"))
            })
            .and_then(|entry| entry.get("stamp"))
            .ok_or(E::StorageUnavailable)?;
        if record.ordinal != index as u64
            || operation.get("id").and_then(serde_json::Value::as_str) != Some(record.id.as_str())
            || operation.get("kind").and_then(serde_json::Value::as_str)
                != Some(record.kind.as_str())
            || source.to_path()? != record.source.to_path()?
            || destination.map(|p| p.to_path()).transpose()?
                != record
                    .destination
                    .as_ref()
                    .map(NativePath::to_path)
                    .transpose()?
            || *manifest != record.manifest
            || *before != record.before_fingerprint
            || operation
                .get("source_grant")
                .and_then(serde_json::Value::as_str)
                != record.source_grant.as_deref()
            || operation
                .get("destination_grant")
                .and_then(serde_json::Value::as_str)
                != record.destination_grant.as_deref()
        {
            return Err(E::StorageUnavailable);
        }
    }
    Ok(())
}

fn parse_state(s: &str) -> Result<OperationState> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| E::StorageUnavailable)
}
fn read_batch(row: &rusqlite::Row<'_>) -> Result<BatchHistory> {
    let state: String = row.get(2)?;
    Ok(BatchHistory {
        id: row.get::<_, String>(0)?.to_ascii_lowercase(),
        digest: row.get::<_, String>(1)?.to_ascii_lowercase(),
        state: serde_json::from_value(serde_json::Value::String(state))
            .map_err(|_| E::StorageUnavailable)?,
        item_count: nonnegative(row.get(3)?)?,
        total_bytes: nonnegative(row.get(4)?)?.to_string(),
        created_at: nonnegative(row.get(5)?)?,
        completed_at: row.get::<_, Option<i64>>(6)?.map(nonnegative).transpose()?,
    })
}
fn integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| E::Overflow)
}
fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| E::StorageUnavailable)
}
fn id_bytes(id: &Id) -> Result<[u8; 16]> {
    hex_bytes(id.as_str())
}
fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(E::InvalidPlan);
    }
    let mut result = [0; N];
    for (i, value) in result.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| E::InvalidPlan)?;
    }
    Ok(result)
}
fn path_bytes(path: &NativePath) -> Result<(&'static str, Vec<u8>)> {
    let path = path.to_path()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(("unix_bytes", path.as_os_str().as_bytes().to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        Ok((
            "windows_wide_le",
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        ))
    }
}
fn native_path(encoding: &str, bytes: &[u8]) -> Result<NativePath> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        if encoding != "unix_bytes" || bytes.is_empty() || bytes.contains(&0) {
            return Err(E::StorageUnavailable);
        }
        Ok(NativePath::new(&std::path::PathBuf::from(
            std::ffi::OsString::from_vec(bytes.to_vec()),
        )))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if encoding != "windows_wide_le" || bytes.is_empty() || bytes.len() % 2 != 0 {
            return Err(E::StorageUnavailable);
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        if units.contains(&0) {
            return Err(E::StorageUnavailable);
        }
        Ok(NativePath::new(&std::path::PathBuf::from(
            std::ffi::OsString::from_wide(&units),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Confirmation;
    use crate::plan::{OperationRequest, PlanOptions};
    use serde_json::json;
    use std::path::PathBuf;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn initialized()
    -> std::result::Result<(tempfile::TempDir, Session, ApprovedPlan), Box<dyn std::error::Error>>
    {
        let fixture = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
            Some(root) => tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?,
            None => tempfile::tempdir()?,
        };
        let mut session = Session::new()?;
        let grant = session.grant(fixture.path(), false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        let source = fixture.path().join("original.txt");
        std::fs::write(&source, b"actual contents do not belong in the journal")?;
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Rename,
                source,
                destination: Some(fixture.path().join("renamed.txt")),
            }],
            PlanOptions::default(),
        )?;
        let confirmation = Confirmation {
            digest: plan.digest().to_owned(),
            ..Confirmation::default()
        };
        let approved = session.confirm(plan, confirmation)?;
        Ok((fixture, session, approved))
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn intent_result_history_and_reopen_preserve_exact_snapshot() -> TestResult {
        let (fixture, mut session, approved) = initialized()?;
        let batch = approved.preview().id.clone();
        let op = approved.preview().operations[0].id.clone();
        let store = session.store.as_mut().ok_or("missing store")?;
        store.start_execution(&approved, &session.grants)?;
        assert!(store.start_execution(&approved, &session.grants).is_err());
        assert!(
            store
                .finish_execution(&batch, BatchState::Completed)
                .is_err()
        );
        store.record_intent(
            &op,
            "rename",
            &json!({"expected": approved.preview().operations[0].manifest}),
        )?;
        assert!(store.record_intent(&op, "rename", &json!({})).is_err());
        assert!(
            store
                .record_result(&op, "other", &json!({}), OperationState::Done)
                .is_err()
        );
        let observed = json!({"observed_manifest": approved.preview().operations[0].manifest});
        store.record_result(&op, "rename", &observed, OperationState::Done)?;
        assert!(store.record_intent(&op, "rename", &json!({})).is_err());
        store.finish_execution(&batch, BatchState::Completed)?;
        assert!(store.finish_execution(&batch, BatchState::Partial).is_err());
        let history = session.batch_history(&batch)?;
        assert_eq!(history.batch.state, BatchState::Completed);
        assert_eq!(history.events.len(), 2);
        assert_eq!(history.events[0].phase, "intent");
        assert_eq!(history.operations[0].after_fingerprint, Some(observed));
        assert_eq!(history.snapshot, serde_json::to_value(approved.preview())?);
        assert!(session.pending_execution_batches(10)?.is_empty());
        assert!(fixture.path().join("original.txt").is_file());
        let path = fixture.path().to_owned();
        drop(session);
        let mut read_only = Session::open(&path)?;
        assert_eq!(read_only.history(10)?.len(), 1);
        assert_eq!(
            read_only.batch_history(&batch)?.operations[0].state,
            OperationState::Done
        );
        assert!(
            read_only
                .store
                .as_mut()
                .ok_or("missing store")?
                .record_intent(&op, "rename", &json!({}))
                .is_err()
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn journal_transactions_rollback_and_pending_operations_survive_batch_status() -> TestResult {
        let (_fixture, mut session, approved) = initialized()?;
        let batch = approved.preview().id.clone();
        let op = approved.preview().operations[0].id.clone();
        let store = session.store.as_mut().ok_or("missing store")?;
        store.start_execution(&approved, &session.grants)?;
        store.journal_write(|tx| {
            tx.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON operation_events BEGIN SELECT RAISE(ABORT,'injected journal failure'); END;")?;
            Ok(())
        })?;
        assert!(store.record_intent(&op, "rename", &json!({})).is_err());
        store.journal_write(|tx| {
            tx.execute_batch("DROP TRIGGER reject_event;")?;
            Ok(())
        })?;
        let history = session.batch_history(&batch)?;
        assert_eq!(history.operations[0].state, OperationState::Planned);
        assert!(history.events.is_empty());
        let store = session.store.as_mut().ok_or("missing store")?;
        store.record_intent(&op, "rename", &json!({}))?;
        store.finish_execution(&batch, BatchState::NeedsRecovery)?;
        assert_eq!(
            session.pending_execution_batches(10)?,
            vec![batch.to_string()]
        );
        assert_eq!(
            session.batch_history(&batch)?.operations[0].state,
            OperationState::Prepared
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn unaudited_approval_and_record_tampering_are_rejected() -> TestResult {
        let (_fixture, mut session, mut approved) = initialized()?;
        let receipt = approved.receipt.clone();
        approved.receipt = Id::new()?;
        let store = session.store.as_mut().ok_or("missing store")?;
        assert!(matches!(
            store.start_execution(&approved, &session.grants),
            Err(E::ConfirmationRequired)
        ));
        approved.receipt = receipt;
        store.start_execution(&approved, &session.grants)?;
        // Even a database whose write-protection trigger was removed is not imported as a plan.
        store.journal_write(|tx| {
            tx.execute_batch("DROP TRIGGER immutable_operation_plan; UPDATE operations SET source_path=x'2f756e6578706563746564';")?;
            Ok(())
        })?;
        assert!(matches!(
            session.batch_history(&approved.preview().id),
            Err(E::StorageUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn native_path_encoding_and_ids_reject_malformed_input() -> TestResult {
        assert!(hex_bytes::<16>("not an id").is_err());
        assert!(hex_bytes::<16>(&"é".repeat(16)).is_err());
        #[cfg(unix)]
        {
            let original = native_path("unix_bytes", b"/name-\xff")?;
            assert_eq!(
                path_bytes(&original)?,
                ("unix_bytes", b"/name-\xff".to_vec())
            );
            assert!(native_path("unix_bytes", b"/bad\0name").is_err());
        }
        #[cfg(windows)]
        {
            assert!(native_path("windows_wide_le", &[1]).is_err());
            assert!(native_path("windows_wide_le", &[0, 0]).is_err());
        }
        Ok(())
    }
}
