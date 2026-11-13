//! Reviewed permanent removal with per-entry intents and retained capture locations.
use crate::CancellationToken;
use crate::approval::ApprovedPlan;
use crate::authorization::{
    Id, NativePath, PlanningError as E, Result, Session, checked_existing, planning_policy,
};
use crate::copy::{CopyFailure, checkpoint, update_parent};
use crate::journal::{OperationState, id_bytes};
use crate::plan::{
    OperationKind as K, OperationRequest, Plan, PlanOptions, PlannedOperation, Stamp,
};
use crate::quarantine::{QuarantineScope, register_retained};
use file_tidy_platform as platform;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PermanentScope {
    pub(crate) storage: QuarantineScope,
    pub(crate) item: Option<Id>,
    pub(crate) original: NativePath,
}

impl Session {
    pub fn build_purge_plan(&self, items: &[Id], options: PlanOptions) -> Result<Plan> {
        crate::plan::validate_options(&options)?;
        if items.is_empty() || items.len() > 1000 || BTreeSet::from_iter(items).len() != items.len()
        {
            return Err(E::InvalidRequest);
        }
        let policy = planning_policy()?;
        let mut operations = Vec::new();
        let mut requests = Vec::new();
        let mut budget = options.max_entries;
        for item in items {
            let (storage, original) = self.load_retained_item(item)?;
            if !options.include_hidden && original.manifest.iter().any(|e| e.hidden) {
                return Err(E::HiddenEntry);
            }
            let source = storage.payload.to_path()?;
            let mut manifest = self.payload_manifest(&storage, &options)?;
            budget = budget
                .checked_sub(manifest.len())
                .ok_or(E::IncompleteManifest)?;
            crate::quarantine::retain_sensitivity(&original, &mut manifest, &source)?;
            requests.push(OperationRequest {
                kind: K::PermanentDelete,
                source: source.clone(),
                destination: None,
            });
            operations.push(PlannedOperation {
                id: Id::new()?,
                kind: K::PermanentDelete,
                source: NativePath::new(&source),
                destination: None,
                source_grant: Some(self.grant_for(&source, &policy)?.id().clone()),
                destination_grant: None,
                manifest,
                inverse: None,
                managed: None,
                permanent: Some(PermanentScope {
                    storage,
                    item: Some(item.clone()),
                    original: original.source,
                }),
                source_parent_stamp: Stamp::capture(&platform::inspect(
                    source.parent().ok_or(E::InvalidPath)?,
                )?)?,
            });
        }
        self.seal_plan(operations, requests, options, Id::new()?)
    }
    pub fn build_batch_purge_plan(&self, batch: &Id, options: PlanOptions) -> Result<Plan> {
        let items=self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db|{
            let mut query=db.prepare("SELECT hex(q.item_id) FROM quarantine_items q JOIN operations o ON q.op_id=o.op_id WHERE o.batch_id=?1 AND q.state IN ('stored','needs_recovery') ORDER BY o.ordinal LIMIT 1001")?;
            let ids=query.query_map([id_bytes(batch)?],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if ids.len()>1000 {return Err(E::Overflow);}
            ids.iter().map(|v|v.parse()).collect::<Result<Vec<Id>>>()
        })?;
        self.build_purge_plan(&items, options)
    }
    pub(crate) fn select_purges(&self, plan: &Plan, wanted: &BTreeSet<&Id>) -> Result<Plan> {
        let items = plan
            .preview
            .operations
            .iter()
            .filter(|op| wanted.contains(&op.id))
            .map(|op| {
                op.permanent
                    .as_ref()
                    .and_then(|p| p.item.clone())
                    .ok_or(E::InvalidPlan)
            })
            .collect::<Result<Vec<_>>>()?;
        self.build_purge_plan(&items, plan.preview.options.clone())
    }
    pub(crate) fn validate_permanent_operation(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        parents: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<()> {
        self.validate_plan_context(plan)?;
        if op.kind != K::PermanentDelete
            || op.destination.is_some()
            || op.managed.is_some()
            || op.inverse.is_some()
        {
            return Err(E::InvalidPlan);
        }
        let scope = op.permanent.as_ref().ok_or(E::InvalidPlan)?;
        let policy = planning_policy()?;
        self.validate_scope(&scope.storage, parents)?;
        let source = op.source.to_path()?;
        let actual = if let Some(item) = &scope.item {
            let (current, original) = self.load_retained_item(item)?;
            if current.payload != scope.storage.payload
                || source != current.payload.to_path()?
                || scope.original != original.source
            {
                return Err(E::StorageUnavailable);
            }
            self.payload_manifest(&scope.storage, &plan.preview.options)?
        } else {
            if scope.original != op.source {
                return Err(E::InvalidPlan);
            }
            self.check_source(&checked_existing(&source, true)?, op.kind, &policy)?;
            let mut budget = plan.preview.options.max_entries;
            self.manifest(
                &source,
                op.kind,
                &plan.preview.options,
                &policy,
                &mut budget,
            )?
        };
        if self.grant_for(&source, &policy)?.id()
            != op.source_grant.as_ref().ok_or(E::OutsideGrant)?
        {
            return Err(E::OutsideGrant);
        }
        let parent = source.parent().ok_or(E::InvalidPath)?;
        if Stamp::capture(&platform::inspect(parent)?)?
            != *parents.get(parent).unwrap_or(&op.source_parent_stamp)
        {
            return Err(E::ChangedSincePlan);
        }
        if actual.len() != op.manifest.len()
            || actual.iter().zip(&op.manifest).any(|(a, b)| {
                a.path != b.path
                    || a.stamp != b.stamp
                    || a.link_target != b.link_target
                    || a.symlink_directory != b.symlink_directory
                    || (a.sensitive && !b.sensitive)
            })
        {
            return Err(E::ChangedSincePlan);
        }
        if scope.item.is_none() {
            match std::fs::symlink_metadata(scope.storage.payload.to_path()?) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(E::DestinationConflict),
            }
        }
        Ok(())
    }

    pub(crate) fn execute_permanent(
        &mut self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        let plan = &approved.plan;
        let mut created = false;
        let mut journal = false;
        let mut step = "permanent_capture";
        let mut run = || -> Result<()> {
            let spec = op.permanent.as_ref().ok_or(E::InvalidPlan)?;
            let mut storage = spec.storage.clone();
            let item = spec.item.as_ref().unwrap_or(&op.id);
            if spec.item.is_none() {
                let (prepared, made) = self
                    .prepare_quarantine_directories(plan, op, &storage, parents, cancel)
                    .map_err(|f| {
                        created |= f.created;
                        journal |= f.journal;
                        step = f.step;
                        f.error
                    })?;
                created |= made;
                storage = prepared;
                step = "permanent_capture";
                checkpoint(cancel)?;
                self.validate_permanent_operation(plan, op, parents)?;
                let source = op.source.to_path()?;
                let payload = storage.payload.to_path()?;
                let from = source.parent().ok_or(E::InvalidPath)?;
                let to = payload.parent().ok_or(E::InvalidPath)?;
                let before = platform::inspect(&source)?;
                let from_before = platform::inspect(from)?;
                let to_before = platform::inspect(to)?;
                self.store.as_mut().ok_or(E::StorageRequired)?.record_intent(&op.id,step,&json!({"source":op.source,"storage":storage,"manifest_digest":blake3::hash(&serde_json::to_vec(&op.manifest)?).to_hex().to_string()})).inspect_err(|_|journal=true)?;
                self.validate_permanent_operation(plan, op, parents)?;
                checkpoint(cancel)?;
                let _pins = self.validate_scope(&storage, parents)?;
                platform::rename_noreplace(&source, &before, &payload, &from_before, &to_before)
                    .map_err(|e| {
                        created |= e.may_have_moved;
                        E::from(e.error)
                    })?;
                created = true;
                let actual = self.payload_manifest(
                    &storage,
                    &PlanOptions {
                        include_hidden: true,
                        max_entries: op.manifest.len(),
                        ..Default::default()
                    },
                )?;
                crate::quarantine::compare_relocated(&source, &op.manifest, &payload, &actual)?;
                update_parent(from, &from_before, parents)?;
                update_parent(to, &to_before, parents)?;
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_managed_result(
                        &op.id,
                        step,
                        &json!({"storage":storage,"observed_manifest":actual}),
                        OperationState::Prepared,
                        |tx| register_retained(tx, op, &storage),
                    )
                    .inspect_err(|_| journal = true)?;
            }
            #[cfg(test)]
            tests::after_capture();
            let root = storage.payload.to_path()?;
            self.validate_plan_context(plan)?;
            self.validate_scope(&storage, parents)?;
            let root_parent = root.parent().ok_or(E::InvalidPath)?;
            parents
                .entry(root_parent.to_owned())
                .or_insert(Stamp::capture(&platform::inspect(root_parent)?)?);
            let options = PlanOptions {
                include_hidden: true,
                max_entries: op.manifest.len(),
                ..Default::default()
            };
            let actual = self.payload_manifest(&storage, &options)?;
            crate::quarantine::compare_relocated(
                &op.source.to_path()?,
                &op.manifest,
                &root,
                &actual,
            )?;
            let mut remaining = actual
                .into_iter()
                .map(|entry| Ok((entry.path.to_path()?, entry)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            let mut order = remaining.keys().cloned().collect::<Vec<_>>();
            order.sort_by(|a, b| {
                b.components()
                    .count()
                    .cmp(&a.components().count())
                    .then_with(|| a.cmp(b))
            });
            for path in order {
                step = "permanent_remove";
                checkpoint(cancel)?;
                self.validate_plan_context(plan)?;
                let _pins = self.validate_scope(&storage, parents)?;
                self.grant_for(&path, &planning_policy()?)?;
                let entry = remaining.get(&path).ok_or(E::StorageUnavailable)?;
                let before = platform::inspect(&checked_existing(&path, true)?)?;
                if Stamp::capture(&before)? != entry.stamp {
                    return Err(E::ChangedSincePlan);
                }
                let parent = path.parent().ok_or(E::InvalidPath)?;
                let parent_before = platform::inspect(parent)?;
                let expected_parent = remaining
                    .get(parent)
                    .map(|e| &e.stamp)
                    .or_else(|| parents.get(parent))
                    .ok_or(E::StorageUnavailable)?;
                if Stamp::capture(&parent_before)? != *expected_parent {
                    return Err(E::ChangedSincePlan);
                }
                if entry.kind == "Directory" {
                    let listing = platform::read_directory_verified(&path, &before, 0)?;
                    if listing.truncated || !listing.names.is_empty() {
                        return Err(E::ChangedSincePlan);
                    }
                }
                let payload = json!({"path":NativePath::new(&path),"stamp":entry.stamp,"irreversible":true,"item":item});
                self.store.as_mut().ok_or(E::StorageRequired)?.record_managed_intent(&op.id,step,&payload,|tx|{
                    if tx.execute("UPDATE quarantine_items SET state='needs_recovery' WHERE item_id=?1 AND state IN ('stored','needs_recovery')",[id_bytes(item)?])?!=1 {return Err(E::StorageUnavailable);}
                    Ok(())
                }).inspect_err(|_|journal=true)?;
                checkpoint(cancel)?;
                self.validate_plan_context(plan)?;
                self.validate_scope(&storage, parents)?;
                platform::remove_verified(&path, &before, &parent_before).map_err(|e| {
                    created |= e.may_have_removed;
                    E::from(e.error)
                })?;
                created = true;
                update_parent(parent, &parent_before, parents)?;
                remaining.remove(&path);
                if let Some(entry) = remaining.get_mut(parent) {
                    entry.stamp = Stamp::capture(&platform::inspect(parent)?)?;
                }
                let payload = json!({"path":NativePath::new(&path),"removed":true,"irreversible":true,"item":item});
                let state = if path == root {
                    "purged"
                } else {
                    "needs_recovery"
                };
                self.store.as_mut().ok_or(E::StorageRequired)?.record_managed_result(&op.id,step,&payload,OperationState::Prepared,|tx|{
                    if tx.execute("UPDATE quarantine_items SET state=?2 WHERE item_id=?1 AND state IN ('stored','needs_recovery')",rusqlite::params![id_bytes(item)?,state])?!=1 {return Err(E::StorageUnavailable);}
                    Ok(())
                }).inspect_err(|_|journal=true)?;
            }
            step = "permanent_complete";
            let complete = json!({"item":item,"irreversible":true,"removed_entries":op.manifest.len(),"storage":storage.payload});
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&op.id, step, &complete)
                .inspect_err(|_| journal = true)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&op.id, step, &complete, OperationState::Done)
                .inspect_err(|_| journal = true)?;
            Ok(())
        };
        run().map_err(|error| CopyFailure {
            error,
            created,
            journal,
            step,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct PermanentProgress {
    pub disposition: crate::recovery::RecoveryDisposition,
    pub reason: String,
    pub storage: NativePath,
    pub confirmed_removed_entries: u64,
    pub unconfirmed_entry: Option<NativePath>,
    pub remaining: Vec<crate::plan::ManifestEntry>,
    pub irreversible: bool,
    pub restoration_destination: Option<NativePath>,
}
impl Session {
    pub fn permanent_progress(&self, batch: &Id, operation: &Id) -> Result<PermanentProgress> {
        let history = self.batch_history(batch)?;
        let preview: crate::plan::PlanPreview = serde_json::from_value(history.snapshot.clone())?;
        let op = preview
            .operations
            .iter()
            .find(|op| &op.id == operation)
            .ok_or(E::InvalidRequest)?;
        self.inspect_permanent_progress(op, &history)
    }
    pub(crate) fn inspect_permanent_progress(
        &self,
        op: &PlannedOperation,
        history: &crate::journal::BatchHistoryDetail,
    ) -> Result<PermanentProgress> {
        use crate::recovery::RecoveryDisposition as D;
        let spec = op
            .permanent
            .as_ref()
            .filter(|_| op.kind == K::PermanentDelete)
            .ok_or(E::InvalidRequest)?;
        let (captured,count,last_intent,last_success)=self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db|{
            use rusqlite::OptionalExtension;
            let captured:Option<Vec<u8>>=db.query_row("SELECT payload FROM operation_events WHERE op_id=?1 AND step='permanent_capture' AND phase='intent' ORDER BY event_id LIMIT 1",[id_bytes(&op.id)?],|r|r.get(0)).optional()?;
            let (count,last_success):(i64,Option<i64>)=db.query_row("SELECT count(*),max(event_id) FROM operation_events WHERE op_id=?1 AND step='permanent_remove' AND phase='result' AND json_extract(CAST(payload AS TEXT),'$.removed')=1",[id_bytes(&op.id)?],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let last:Option<(i64,Vec<u8>)>=db.query_row("SELECT event_id,payload FROM operation_events WHERE op_id=?1 AND step='permanent_remove' AND phase='intent' ORDER BY event_id DESC LIMIT 1",[id_bytes(&op.id)?],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            Ok((captured,count,last,last_success))
        })?;
        let count = u64::try_from(count).map_err(|_| E::StorageUnavailable)?;
        if count > op.manifest.len() as u64 {
            return Err(E::StorageUnavailable);
        }
        let mut storage = spec.storage.clone();
        if let Some(captured) = &captured {
            if captured.len() > 64 * 1024 * 1024 {
                return Err(E::Overflow);
            }
            let value: serde_json::Value = serde_json::from_slice(captured)?;
            if value.get("source") != Some(&json!(op.source))
                || value.get("manifest_digest").and_then(|v| v.as_str())
                    != Some(
                        blake3::hash(&serde_json::to_vec(&op.manifest)?)
                            .to_hex()
                            .as_str(),
                    )
            {
                return Err(E::StorageUnavailable);
            }
            storage =
                serde_json::from_value(value.get("storage").ok_or(E::StorageUnavailable)?.clone())?;
            if storage.payload != spec.storage.payload
                || storage.root != spec.storage.root
                || storage.identity != spec.storage.identity
            {
                return Err(E::StorageUnavailable);
            }
        }
        let root = storage.payload.to_path()?;
        let item = spec.item.as_ref().unwrap_or(&op.id);
        let restoration_destination=self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db|{
            use rusqlite::OptionalExtension;
            let row:Option<(String,Vec<u8>)>=db.query_row("SELECT o.path_encoding,o.destination_path FROM operations o JOIN quarantine_items q ON q.item_id=o.inverse_of WHERE q.item_id=?1 AND q.state='restored' AND o.kind='restore' AND o.state='done' ORDER BY o.rowid DESC LIMIT 1",[id_bytes(item)?],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            row.map(|(encoding,path)|crate::journal::native_path(&encoding,&path)).transpose()
        })?;
        let mut unconfirmed = None;
        if let Some((id, payload)) = last_intent
            && last_success.is_none_or(|last| last < id)
        {
            let value: serde_json::Value = serde_json::from_slice(&payload)?;
            let path: NativePath =
                serde_json::from_value(value.get("path").ok_or(E::StorageUnavailable)?.clone())?;
            if !path.to_path()?.starts_with(&root)
                || path
                    .to_path()?
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(E::StorageUnavailable);
            }
            unconfirmed = Some(path);
        }
        if captured.is_none() && spec.item.is_none() {
            let source = checked_existing(&op.source.to_path()?, true)?;
            self.check_source(&source, K::PermanentDelete, &planning_policy()?)?;
            let options = PlanOptions {
                include_hidden: true,
                max_entries: op.manifest.len(),
                ..Default::default()
            };
            let mut budget = op.manifest.len();
            let current = self.manifest(
                &source,
                K::PermanentDelete,
                &options,
                &planning_policy()?,
                &mut budget,
            )?;
            crate::quarantine::compare_relocated(&source, &op.manifest, &source, &current)?;
            return Ok(PermanentProgress {
                disposition: D::NotCommitted,
                reason: "source_retained_before_permanent_capture".into(),
                storage: storage.payload,
                confirmed_removed_entries: count,
                unconfirmed_entry: unconfirmed,
                remaining: current,
                irreversible: true,
                restoration_destination,
            });
        }
        self.validate_scope(&storage, &BTreeMap::new())?;
        let remaining = match std::fs::symlink_metadata(&root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
            Ok(_) => {
                let before = op
                    .manifest
                    .iter()
                    .find(|e| e.path == op.source)
                    .ok_or(E::StorageUnavailable)?;
                if !before
                    .stamp
                    .same_identity(&platform::inspect(&checked_existing(&root, true)?)?)
                {
                    return Err(E::ChangedSincePlan);
                }
                self.payload_manifest(
                    &storage,
                    &PlanOptions {
                        include_hidden: true,
                        max_entries: serde_json::from_value::<crate::plan::PlanPreview>(
                            history.snapshot.clone(),
                        )?
                        .options
                        .max_entries,
                        ..Default::default()
                    },
                )?
            }
        };
        let (disposition, reason) = if restoration_destination.is_some() {
            (
                D::PermanentProgressObserved,
                "remaining_payload_restored_by_reviewed_plan",
            )
        } else if unconfirmed.is_some() {
            (
                D::NeedsAttention,
                "irreversible_removal_result_requires_reconciliation",
            )
        } else {
            (
                D::PermanentProgressObserved,
                "confirmed_removals_and_current_remaining_manifest",
            )
        };
        Ok(PermanentProgress {
            disposition,
            reason: reason.into(),
            storage: storage.payload,
            confirmed_removed_entries: count,
            unconfirmed_entry: unconfirmed,
            remaining,
            irreversible: true,
            restoration_destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    thread_local! {static AFTER_CAPTURE:RefCell<Option<Box<dyn FnOnce()>>>=RefCell::new(None);}
    pub(super) fn after_capture() {
        if let Some(hook) = AFTER_CAPTURE.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn cancellation_after_capture_keeps_the_complete_object_restorable()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let base = std::env::var_os("FILE_TIDY_TEST_ROOT").ok_or("FILE_TIDY_TEST_ROOT required")?;
        let directory = tempfile::tempdir_in(base)?;
        let root = directory.path();
        let mut session = Session::new()?;
        let grant = session.grant(root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        std::fs::write(root.join("file"), b"data")?;
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: K::PermanentDelete,
                source: root.join("file"),
                destination: None,
            }],
            PlanOptions::default(),
        )?;
        let confirmation = crate::approval::Confirmation {
            digest: plan.digest().into(),
            permanent_phrase: plan
                .preview()
                .permanent_challenge
                .as_ref()
                .map(|challenge| format!("PERMANENT 1 {challenge}")),
            ..Default::default()
        };
        let approved = session.confirm(plan, confirmation)?;
        let token = CancellationToken::new();
        let cancel = token.clone();
        AFTER_CAPTURE.with(|hook| *hook.borrow_mut() = Some(Box::new(move || cancel.cancel())));
        let report = session.execute_approved(approved, &token)?;
        assert_eq!(
            report.operations[0].status,
            crate::execution::ExecutionStatus::NeedsRecovery,
            "{report:?}"
        );
        let item = session.quarantine_items(10, false)?.remove(0);
        assert_eq!(std::fs::read(item.storage_path.to_path()?)?, b"data");
        let plan = session.build_restore_plan(&[item.id], None, PlanOptions::default())?;
        let confirmation = crate::approval::Confirmation {
            digest: plan.digest().into(),
            ..Default::default()
        };
        let approved = session.confirm(plan, confirmation)?;
        assert!(
            session
                .execute_approved(approved, &CancellationToken::new())?
                .completed()
        );
        assert_eq!(std::fs::read(root.join("file"))?, b"data");
        Ok(())
    }
}
