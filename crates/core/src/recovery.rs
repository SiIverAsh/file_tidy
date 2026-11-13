//! Read-only reconciliation of interrupted operations against current filesystem state.
use std::path::Path;

use serde::Serialize;

use crate::authorization::{
    Id, NativePath, PlanningError as E, Result, Session, checked_existing, managed_component,
    planning_policy,
};
use crate::journal::{BatchHistoryDetail, OperationState};
use crate::plan::{OperationKind, PlanPreview, PlannedOperation, policy_digest};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDisposition {
    /// The reviewed source is present and the destination is absent.
    NotCommitted,
    /// The first rename reached the reviewed intermediate name; completion needs review.
    TemporaryObserved,
    /// A durable rename intent matches the relocated object; journal completion is pending.
    RenameObserved,
    /// An identified partial copy remains at its reviewed staging name.
    StagedCopyObserved,
    /// A previously verified copy is present; content verification needs a new permit.
    VerifiedCopyObserved,
    /// Publication intent and recorded identity match the destination.
    CopyPublishedObserved,
    /// The objects or intent do not establish one unambiguous outcome.
    NeedsAttention,
    /// Current authorization, policy, or media availability prevents inspection.
    Unavailable,
}

#[derive(Debug, Serialize)]
pub struct RecoveryItem {
    pub batch_id: String,
    pub operation_id: String,
    pub source: NativePath,
    pub destination: Option<NativePath>,
    pub temporary: Option<NativePath>,
    pub journal_state: OperationState,
    pub policy_changed: bool,
    pub disposition: RecoveryDisposition,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryReport {
    pub items: Vec<RecoveryItem>,
}

impl Session {
    /// Inspect pending operations without modifying the journal or user files.
    /// `limit` bounds batches; exceeding it returns an error rather than omitting records.
    pub fn recovery_report(&self, batch: Option<&Id>, limit: usize) -> Result<RecoveryReport> {
        if !(1..=1000).contains(&limit) {
            return Err(E::InvalidRequest);
        }
        let batches = match batch {
            Some(id) => vec![id.clone()],
            None => self
                .pending_execution_batches(limit)?
                .into_iter()
                .map(|id| serde_json::from_value(serde_json::Value::String(id)).map_err(E::from))
                .collect::<Result<Vec<Id>>>()?,
        };
        let mut items = Vec::new();
        for batch in batches {
            let history = self.batch_history(&batch)?;
            let preview = checked_snapshot(&history)?;
            for (operation, recorded) in preview.operations.iter().zip(&history.operations) {
                if matches!(
                    recorded.state,
                    OperationState::Done | OperationState::Skipped | OperationState::Failed
                ) {
                    continue;
                }
                // Diagnosis grants no execution capability. Recheck current
                // policy below, including for records from an older binary.
                let policy_changed = preview.policy_digest != policy_digest();
                let (disposition, reason) = if history.events_truncated {
                    (
                        RecoveryDisposition::NeedsAttention,
                        "event_history_incomplete".to_owned(),
                    )
                } else if operation.kind == OperationKind::Copy {
                    self.inspect_interrupted_copy(operation, &history)
                } else if operation.managed.is_some() {
                    match self.inspect_interrupted_managed(operation, &history) {
                        Ok(observation) => observation,
                        Err(error) => (RecoveryDisposition::Unavailable, error.to_string()),
                    }
                } else if !matches!(operation.kind, OperationKind::Move | OperationKind::Rename) {
                    (
                        RecoveryDisposition::NeedsAttention,
                        "operation_protocol_requires_review".to_owned(),
                    )
                } else {
                    let intents = matching_rename_intents(&history, operation)?;
                    self.inspect_interrupted_rename(operation, intents, preview.options.max_entries)
                };
                items.push(RecoveryItem {
                    batch_id: history.batch.id.clone(),
                    operation_id: recorded.id.clone(),
                    source: operation.source.clone(),
                    destination: operation.destination.as_ref().map(|d| d.path.clone()),
                    temporary: operation.destination.as_ref().and_then(|d| {
                        d.spelling_temporary
                            .clone()
                            .or_else(|| d.copy_temporary.clone())
                    }),
                    journal_state: recorded.state,
                    policy_changed,
                    disposition,
                    reason,
                });
            }
        }
        Ok(RecoveryReport { items })
    }

    fn inspect_interrupted_rename(
        &self,
        operation: &PlannedOperation,
        intents: RenameIntents,
        max_entries: usize,
    ) -> (RecoveryDisposition, String) {
        use RecoveryDisposition::{NeedsAttention, NotCommitted, RenameObserved, Unavailable};
        let inspect = || -> Result<(RecoveryDisposition, &'static str)> {
            let source = operation.source.to_path()?;
            let destination = operation
                .destination
                .as_ref()
                .ok_or(E::StorageUnavailable)?;
            if !destination.create_directories.is_empty() {
                return Ok((NeedsAttention, "directory_creation_requires_review"));
            }
            let target = destination.path.to_path()?;
            let policy = planning_policy()?;
            // Both parents must be reachable under current grants. Historical grant
            // records never authorize reads of an absent or replaced volume.
            let source_parent = checked_existing(source.parent().ok_or(E::InvalidPath)?, false)?;
            let target_parent = checked_existing(target.parent().ok_or(E::InvalidPath)?, false)?;
            for (parent, leaf) in [(&source_parent, &source), (&target_parent, &target)] {
                self.grant_for(parent, &policy)?;
                if policy.labels(parent).protected
                    || leaf
                        .components()
                        .any(|part| managed_component(part.as_os_str()))
                {
                    return Err(E::ProtectedZone);
                }
            }
            if !operation
                .source_parent_stamp
                .same_identity(&file_tidy_platform::inspect(&source_parent)?)
                || !destination
                    .parent_stamp
                    .same_identity(&file_tidy_platform::inspect(&target_parent)?)
            {
                return Ok((NeedsAttention, "parent_identity_changed"));
            }
            if let Some(temporary) = &destination.spelling_temporary {
                return self.inspect_spelling_rename(
                    operation,
                    &temporary.to_path()?,
                    intents,
                    max_entries,
                );
            }
            let source_exists = entry_exists(&source)?;
            let target_exists = entry_exists(&target)?;
            match (source_exists, target_exists) {
                (true, false) => match self.verify_renamed(operation, &source) {
                    Ok(_) => Ok((NotCommitted, "source_matches_destination_absent")),
                    Err(
                        E::ChangedSincePlan
                        | E::IncompleteManifest
                        | E::UnsupportedNode
                        | E::ProtectedRoot,
                    ) => Ok((NeedsAttention, "source_manifest_changed")),
                    Err(error) => Err(error),
                },
                (false, true) if intents.direct => match self.verify_renamed(operation, &target) {
                    Ok(_) => Ok((RenameObserved, "rename_observed_completion_pending")),
                    Err(
                        E::ChangedSincePlan
                        | E::IncompleteManifest
                        | E::UnsupportedNode
                        | E::ProtectedRoot,
                    ) => Ok((NeedsAttention, "destination_manifest_changed")),
                    Err(error) => Err(error),
                },
                (false, true) => Ok((NeedsAttention, "destination_present_without_rename_intent")),
                (true, true) => Ok((NeedsAttention, "source_and_destination_present")),
                (false, false) => Ok((NeedsAttention, "source_and_destination_absent")),
            }
        };
        match inspect() {
            Ok((disposition, reason)) => (disposition, reason.to_owned()),
            Err(error) => (Unavailable, error.to_string()),
        }
    }

    fn inspect_spelling_rename(
        &self,
        operation: &PlannedOperation,
        temporary: &Path,
        intents: RenameIntents,
        max_entries: usize,
    ) -> Result<(RecoveryDisposition, &'static str)> {
        use RecoveryDisposition::{
            NeedsAttention, NotCommitted, RenameObserved, TemporaryObserved,
        };
        let source = operation.source.to_path()?;
        let target = operation
            .destination
            .as_ref()
            .ok_or(E::StorageUnavailable)?
            .path
            .to_path()?;
        let parent = source.parent().ok_or(E::InvalidPath)?;
        let before = file_tidy_platform::inspect(parent)?;
        let listing = file_tidy_platform::read_directory_verified(parent, &before, max_entries)?;
        if listing.truncated {
            return Ok((NeedsAttention, "parent_listing_incomplete"));
        }
        let exact = |path: &Path| -> Result<bool> {
            let name = path.file_name().ok_or(E::InvalidPath)?;
            Ok(listing.names.iter().any(|entry| entry == name))
        };
        let source_exact = exact(&source)?;
        let target_exact = exact(&target)?;
        let temporary_exact = exact(temporary)?;
        let temporary_exists = entry_exists(temporary)?;
        let outcome = if temporary_exists {
            if !temporary_exact {
                (NeedsAttention, "temporary_name_changed")
            } else if entry_exists(&source)? || entry_exists(&target)? {
                (NeedsAttention, "temporary_present_name_conflict")
            } else if !intents.to_temporary {
                (NeedsAttention, "temporary_present_without_rename_intent")
            } else {
                self.inspect_manifest_at(
                    operation,
                    temporary,
                    TemporaryObserved,
                    "temporary_observed_completion_pending",
                )?
            }
        } else if source_exact && !target_exact {
            // On insensitive volumes the target lookup is an alias of the source.
            if !same_if_present(&source, &target)? {
                (NeedsAttention, "source_and_destination_conflict")
            } else {
                self.inspect_manifest_at(
                    operation,
                    &source,
                    NotCommitted,
                    "source_spelling_unchanged",
                )?
            }
        } else if target_exact && !source_exact {
            if !intents.from_temporary {
                (NeedsAttention, "destination_present_without_final_intent")
            } else if !same_if_present(&target, &source)? {
                (NeedsAttention, "source_and_destination_conflict")
            } else {
                self.inspect_manifest_at(
                    operation,
                    &target,
                    RenameObserved,
                    "rename_observed_completion_pending",
                )?
            }
        } else {
            (NeedsAttention, "source_spelling_ambiguous_or_absent")
        };
        if !before.matches(&file_tidy_platform::inspect(parent)?) {
            return Ok((NeedsAttention, "parent_changed_during_reconciliation"));
        }
        Ok(outcome)
    }

    fn inspect_manifest_at(
        &self,
        operation: &PlannedOperation,
        path: &Path,
        matched: RecoveryDisposition,
        reason: &'static str,
    ) -> Result<(RecoveryDisposition, &'static str)> {
        match self.verify_renamed(operation, path) {
            Ok(_) => Ok((matched, reason)),
            Err(
                E::ChangedSincePlan | E::IncompleteManifest | E::UnsupportedNode | E::ProtectedRoot,
            ) => Ok((
                RecoveryDisposition::NeedsAttention,
                "relocated_manifest_changed",
            )),
            Err(error) => Err(error),
        }
    }
}

fn checked_snapshot(history: &BatchHistoryDetail) -> Result<PlanPreview> {
    // batch_history verifies the digest of the exact persisted bytes before JSON parsing.
    let preview: PlanPreview = serde_json::from_value(history.snapshot.clone())?;
    if preview.id.as_str() != history.batch.id
        || preview.operations.len() != history.operations.len()
        || preview.operations.is_empty()
        || preview.operations.len() > 10_000
        || !(1..=1_000_000).contains(&preview.options.max_entries)
        || preview.confirmation_count != history.batch.item_count
        || preview.total_bytes != history.batch.total_bytes
    {
        return Err(E::StorageUnavailable);
    }
    let mut entries = 0usize;
    for (index, (operation, recorded)) in preview
        .operations
        .iter()
        .zip(&history.operations)
        .enumerate()
    {
        entries = entries
            .checked_add(operation.manifest.len())
            .ok_or(E::Overflow)?;
        let source = operation.source.to_path()?;
        if operation.id.as_str() != recorded.id
            || recorded.ordinal != index as u64
            || operation.source != recorded.source
            || operation.destination.as_ref().map(|d| &d.path) != recorded.destination.as_ref()
            || serde_json::to_value(operation.kind)? != recorded.kind
            || serde_json::to_value(&operation.manifest)? != recorded.manifest
            || !source.is_absolute()
            || source.parent().is_none()
            || source
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || operation.manifest.is_empty()
            || entries > preview.options.max_entries
        {
            return Err(E::StorageUnavailable);
        }
        let root = operation
            .manifest
            .iter()
            .find(|entry| entry.path == operation.source)
            .ok_or(E::StorageUnavailable)?;
        if serde_json::to_value(&root.stamp)? != recorded.before_fingerprint {
            return Err(E::StorageUnavailable);
        }
        if let Some(destination) = &operation.destination {
            let target = destination.path.to_path()?;
            if !target.is_absolute()
                || target.parent().is_none()
                || target
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || source.starts_with(&target)
                || target.starts_with(&source)
                || destination.existing_parent.to_path()?
                    != target.parent().ok_or(E::InvalidPath)?
                    && destination.create_directories.is_empty()
            {
                return Err(E::StorageUnavailable);
            }
            if let Some(temporary) = &destination.spelling_temporary {
                let temporary = temporary.to_path()?;
                if operation.kind != OperationKind::Rename
                    || source.parent() != target.parent()
                    || temporary.parent() != source.parent()
                    || temporary == source
                    || temporary == target
                    || temporary
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                    || temporary
                        .components()
                        .any(|part| managed_component(part.as_os_str()))
                    || !destination.create_directories.is_empty()
                {
                    return Err(E::StorageUnavailable);
                }
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for entry in &operation.manifest {
            let path = entry.path.to_path()?;
            if !path.starts_with(&source)
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || !names.insert(path)
            {
                return Err(E::StorageUnavailable);
            }
        }
    }
    Ok(preview)
}

#[derive(Clone, Copy, Default)]
struct RenameIntents {
    direct: bool,
    to_temporary: bool,
    from_temporary: bool,
}

fn matching_rename_intents(
    history: &BatchHistoryDetail,
    operation: &PlannedOperation,
) -> Result<RenameIntents> {
    let base = serde_json::json!({
        "source": operation.source,
        "destination": operation.destination,
        "manifest": operation.manifest,
    });
    let temporary = operation
        .destination
        .as_ref()
        .and_then(|d| d.spelling_temporary.as_ref());
    let mut found = RenameIntents::default();
    for event in history
        .events
        .iter()
        .filter(|event| event.operation_id == operation.id.as_str())
    {
        let mut expected = base.clone();
        let already_found = match (event.step.as_str(), temporary) {
            ("rename", None) => &mut found.direct,
            ("rename_to_temporary", Some(temporary)) => {
                expected["step_source"] = serde_json::to_value(&operation.source)?;
                expected["step_destination"] = serde_json::to_value(temporary)?;
                &mut found.to_temporary
            }
            ("rename_from_temporary", Some(temporary)) => {
                if !found.to_temporary {
                    return Err(E::StorageUnavailable);
                }
                expected["step_source"] = serde_json::to_value(temporary)?;
                expected["step_destination"] =
                    serde_json::to_value(operation.destination.as_ref().map(|d| &d.path))?;
                &mut found.from_temporary
            }
            _ => return Err(E::StorageUnavailable),
        };
        if event.phase == "intent" {
            if event.payload != expected || *already_found {
                return Err(E::StorageUnavailable);
            }
            *already_found = true;
        } else if event.phase != "result" {
            return Err(E::StorageUnavailable);
        }
    }
    Ok(found)
}

fn same_if_present(existing: &Path, alias: &Path) -> Result<bool> {
    let expected = file_tidy_platform::inspect(existing)?;
    match file_tidy_platform::inspect(alias) {
        Ok(actual) => Ok(expected.matches(&actual)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn entry_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovedPlan, Confirmation};
    use crate::plan::{OperationRequest, PlanOptions};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn fixture() -> std::result::Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        Ok(match std::env::var_os("FILE_TIDY_TEST_ROOT") {
            Some(root) => tempfile::tempdir_in(std::path::PathBuf::from(root).canonicalize()?)?,
            None => tempfile::tempdir()?,
        })
    }

    fn prepared(
        root: &Path,
        directory: bool,
    ) -> std::result::Result<(Session, ApprovedPlan), Box<dyn std::error::Error>> {
        let mut session = Session::new()?;
        let grant = session.grant(root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        if directory {
            std::fs::create_dir(root.join("source"))?;
            std::fs::write(root.join("source/child"), b"payload")?;
            std::fs::create_dir(root.join("source/empty"))?;
        } else {
            std::fs::write(root.join("source"), b"payload")?;
        }
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Move,
                source: root.join("source"),
                destination: Some(root.join("destination")),
            }],
            PlanOptions::default(),
        )?;
        let confirmation = Confirmation {
            digest: plan.digest().to_owned(),
            sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
            ..Default::default()
        };
        let approved = session.confirm(plan, confirmation)?;
        session
            .store
            .as_mut()
            .ok_or("missing store")?
            .start_execution(&approved, &session.grants)?;
        Ok((session, approved))
    }

    fn intent(session: &mut Session, approved: &ApprovedPlan) -> Result<()> {
        let operation = &approved.preview().operations[0];
        session
            .store
            .as_mut()
            .ok_or(E::StorageRequired)?
            .record_intent(
                &operation.id,
                "rename",
                &serde_json::json!({
                    "source": operation.source,
                    "destination": operation.destination,
                    "manifest": operation.manifest,
                }),
            )
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn pending_intent_is_found_in_cancelled_batch_without_writes() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared(dir.path(), false)?;
        intent(&mut session, &approved)?;
        // Reproduce an interrupted batch whose outer status was already updated.
        session
            .store
            .as_mut()
            .ok_or("missing store")?
            .journal_write(|transaction| {
                transaction.execute("UPDATE batches SET state='cancelled'", [])?;
                Ok(())
            })?;
        drop(session);
        let before = std::fs::read(dir.path().join(".file-tidy/state.db"))?;
        let session = Session::open(dir.path())?;
        let report = session.recovery_report(None, 100)?;
        assert_eq!(report.items.len(), 1);
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::NotCommitted
        );
        assert_eq!(report.items[0].journal_state, OperationState::Prepared);
        assert_eq!(
            before,
            std::fs::read(dir.path().join(".file-tidy/state.db"))?
        );
        assert_eq!(std::fs::read(dir.path().join("source"))?, b"payload");
        assert!(!dir.path().join("destination").exists());
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn relocated_directory_is_observed_without_repeating_rename() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared(dir.path(), true)?;
        intent(&mut session, &approved)?;
        std::fs::rename(dir.path().join("source"), dir.path().join("destination"))?;
        drop(session);
        let session = Session::open(dir.path())?;
        let report = session.recovery_report(Some(&approved.preview().id), 1)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::RenameObserved
        );
        assert_eq!(
            std::fs::read(dir.path().join("destination/child"))?,
            b"payload"
        );
        assert!(dir.path().join("destination/empty").is_dir());
        assert!(!dir.path().join("source").exists());
        assert_eq!(
            session.batch_history(&approved.preview().id)?.operations[0].state,
            OperationState::Prepared
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn changed_or_ambiguous_objects_require_attention() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared(dir.path(), true)?;
        intent(&mut session, &approved)?;
        std::fs::rename(dir.path().join("source"), dir.path().join("destination"))?;
        std::fs::write(dir.path().join("destination/new"), b"unreviewed")?;
        drop(session);
        let session = Session::open(dir.path())?;
        assert_eq!(
            session.recovery_report(None, 10)?.items[0].disposition,
            RecoveryDisposition::NeedsAttention
        );
        std::fs::create_dir(dir.path().join("source"))?;
        let report = session.recovery_report(None, 10)?;
        assert_eq!(report.items[0].reason, "source_and_destination_present");
        assert_eq!(
            std::fs::read(dir.path().join("destination/new"))?,
            b"unreviewed"
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn relocated_object_without_intent_is_not_attributed_to_execution() -> TestResult {
        let dir = fixture()?;
        let (session, _approved) = prepared(dir.path(), false)?;
        std::fs::rename(dir.path().join("source"), dir.path().join("destination"))?;
        drop(session);
        let report = Session::open(dir.path())?.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::NeedsAttention
        );
        assert_eq!(
            report.items[0].reason,
            "destination_present_without_rename_intent"
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn revoked_authorization_makes_objects_unavailable() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared(dir.path(), false)?;
        intent(&mut session, &approved)?;
        let grant = session.grants().next().ok_or("missing grant")?.id().clone();
        session.revoke(&grant)?;
        drop(session);
        let report = Session::open(dir.path())?.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::Unavailable
        );
        assert_eq!(std::fs::read(dir.path().join("source"))?, b"payload");
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn altered_snapshot_is_rejected_before_filesystem_reconciliation() -> TestResult {
        let dir = fixture()?;
        let (mut session, _approved) = prepared(dir.path(), false)?;
        session.store.as_mut().ok_or("missing store")?.journal_write(|transaction| {
            transaction.execute_batch("DROP TRIGGER immutable_batch_plan; UPDATE batches SET snapshot=CAST('{}' AS BLOB);")?;
            Ok(())
        })?;
        assert!(matches!(
            session.recovery_report(None, 10),
            Err(E::StorageUnavailable)
        ));
        assert_eq!(std::fs::read(dir.path().join("source"))?, b"payload");
        Ok(())
    }

    fn prepared_spelling(
        root: &Path,
    ) -> std::result::Result<(Session, ApprovedPlan), Box<dyn std::error::Error>> {
        let mut session = Session::new()?;
        let grant = session.grant(root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        std::fs::write(root.join("Example"), b"payload")?;
        let mut plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Rename,
                source: root.join("Example"),
                destination: Some(root.join("EXAMPLE")),
            }],
            PlanOptions::default(),
        )?;
        let destination = plan.preview.operations[0]
            .destination
            .as_mut()
            .ok_or("missing destination")?;
        if destination.spelling_temporary.is_none() {
            // Exercise the two-step recovery protocol on case-sensitive fixtures too.
            // Only this private test module constructs a recorded intermediate name.
            destination.spelling_temporary =
                Some(NativePath::new(&root.join(".file-tidy-test.rename")));
            plan.digest = blake3::hash(&serde_json::to_vec(&plan.preview)?)
                .to_hex()
                .to_string();
        }
        let receipt = Id::new()?;
        let audit = crate::approval::ApprovalAudit {
            id: receipt.clone(),
            confirmed_at: crate::plan::now()?,
            digest: plan.digest.clone(),
            plan: plan.preview.clone(),
        };
        session.store.as_mut().ok_or("missing store")?.save(
            &session.grants,
            session.epoch,
            Some(&audit),
        )?;
        let approved = ApprovedPlan { plan, receipt };
        session
            .store
            .as_mut()
            .ok_or("missing store")?
            .start_execution(&approved, &session.grants)?;
        Ok((session, approved))
    }

    fn spelling_intent(
        session: &mut Session,
        approved: &ApprovedPlan,
        final_step: bool,
    ) -> Result<()> {
        let operation = &approved.preview().operations[0];
        let destination = operation.destination.as_ref().ok_or(E::InvalidPlan)?;
        let temporary = destination
            .spelling_temporary
            .as_ref()
            .ok_or(E::InvalidPlan)?;
        let (step, source, target) = if final_step {
            ("rename_from_temporary", temporary, &destination.path)
        } else {
            ("rename_to_temporary", &operation.source, temporary)
        };
        session.store.as_mut().ok_or(E::StorageRequired)?.record_intent(&operation.id, step, &serde_json::json!({
            "source": operation.source, "destination": operation.destination,
            "manifest": operation.manifest, "step_source": source, "step_destination": target,
        }))
    }

    fn native_rename(source: &Path, destination: &Path) -> TestResult {
        file_tidy_platform::rename_noreplace(
            source,
            &file_tidy_platform::inspect(source)?,
            destination,
            &file_tidy_platform::inspect(source.parent().ok_or("missing parent")?)?,
            &file_tidy_platform::inspect(destination.parent().ok_or("missing parent")?)?,
        )?;
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn spelling_source_is_uncommitted_even_when_target_lookup_aliases_it() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared_spelling(dir.path())?;
        spelling_intent(&mut session, &approved, false)?;
        drop(session);
        let report = Session::open(dir.path())?.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::NotCommitted
        );
        assert_eq!(report.items[0].reason, "source_spelling_unchanged");
        assert_eq!(std::fs::read(dir.path().join("Example"))?, b"payload");
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn spelling_temporary_is_observed_and_conflict_keeps_its_location() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared_spelling(dir.path())?;
        let temporary = approved.preview().operations[0]
            .destination
            .as_ref()
            .and_then(|d| d.spelling_temporary.as_ref())
            .ok_or("missing temporary")?
            .to_path()?;
        spelling_intent(&mut session, &approved, false)?;
        native_rename(&dir.path().join("Example"), &temporary)?;
        drop(session);
        let session = Session::open(dir.path())?;
        let report = session.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::TemporaryObserved
        );
        assert_eq!(
            report.items[0]
                .temporary
                .as_ref()
                .ok_or("missing temporary")?
                .to_path()?,
            temporary
        );
        std::fs::write(dir.path().join("EXAMPLE"), b"other")?;
        let report = session.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::NeedsAttention
        );
        assert_eq!(report.items[0].reason, "temporary_present_name_conflict");
        assert_eq!(std::fs::read(&temporary)?, b"payload");
        assert_eq!(std::fs::read(dir.path().join("EXAMPLE"))?, b"other");
        Ok(())
    }

    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn spelling_final_name_requires_second_intent_before_completion_observation() -> TestResult {
        let dir = fixture()?;
        let (mut session, approved) = prepared_spelling(dir.path())?;
        let operation = &approved.preview().operations[0];
        let destination = operation
            .destination
            .as_ref()
            .ok_or("missing destination")?;
        let temporary = destination
            .spelling_temporary
            .as_ref()
            .ok_or("missing temporary")?
            .to_path()?;
        spelling_intent(&mut session, &approved, false)?;
        native_rename(&dir.path().join("Example"), &temporary)?;
        let manifest = session.verify_renamed(operation, &temporary)?;
        session.store.as_mut().ok_or("missing store")?.record_result(&operation.id, "rename_to_temporary", &serde_json::json!({
            "source": operation.source, "destination": NativePath::new(&temporary), "observed_manifest": manifest,
        }), OperationState::Staged)?;
        native_rename(&temporary, &dir.path().join("EXAMPLE"))?;
        assert_eq!(
            session.recovery_report(None, 10)?.items[0].disposition,
            RecoveryDisposition::NeedsAttention
        );
        // The durable second intent is a prerequisite for attributing this state.
        native_rename(&dir.path().join("EXAMPLE"), &temporary)?;
        spelling_intent(&mut session, &approved, true)?;
        native_rename(&temporary, &dir.path().join("EXAMPLE"))?;
        drop(session);
        let session = Session::open(dir.path())?;
        let report = session.recovery_report(None, 10)?;
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::RenameObserved
        );
        assert!(!temporary.exists());
        assert_eq!(std::fs::read(dir.path().join("EXAMPLE"))?, b"payload");
        assert_eq!(
            session.batch_history(&approved.preview().id)?.operations[0].state,
            OperationState::Staged
        );
        Ok(())
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn historical_policy_digest_does_not_recreate_permission_or_block_read_only_diagnosis()
    -> TestResult {
        let directory = fixture()?;
        let (mut session, approved) = prepared(directory.path(), false)?;
        let mut snapshot = serde_json::to_value(approved.preview())?;
        snapshot["policy_digest"] = serde_json::json!("00".repeat(32));
        let bytes = serde_json::to_vec(&snapshot)?;
        let digest = blake3::hash(&bytes);
        session
            .store
            .as_mut()
            .ok_or("missing storage")?
            .journal_write(|db| {
                db.execute_batch("DROP TRIGGER immutable_batch_plan;")?;
                db.execute(
                    "UPDATE batches SET snapshot=?1,plan_digest=?2,policy_digest=?3",
                    rusqlite::params![bytes, digest.as_bytes(), [0u8; 32]],
                )?;
                Ok(())
            })?;
        let report = session.recovery_report(None, 10)?;
        assert_eq!(report.items.len(), 1);
        assert!(report.items[0].policy_changed);
        assert_eq!(
            report.items[0].disposition,
            RecoveryDisposition::NotCommitted
        );
        let grant = session.grants().next().ok_or("missing grant")?.id().clone();
        session.revoke(&grant)?;
        drop(session);
        let session = Session::open(directory.path())?;
        assert_eq!(
            session.recovery_report(None, 10)?.items[0].disposition,
            RecoveryDisposition::Unavailable
        );
        Ok(())
    }
}
