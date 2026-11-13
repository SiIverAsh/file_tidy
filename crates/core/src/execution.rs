//! Execution consumes a live confirmation and journals each filesystem step.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use file_tidy_platform as platform;
use serde::Serialize;

use crate::CancellationToken;
use crate::approval::ApprovedPlan;
use crate::authorization::{Id, NativePath, PlanningError as E, Result, Session, planning_policy};
use crate::journal::{BatchState, OperationState};
use crate::plan::{ManifestEntry, OperationKind, Plan, PlannedOperation, Stamp};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Done,
    Failed,
    NeedsRecovery,
    NotStarted,
    Cancelled,
}

#[cfg(test)]
mod spelling_tests {
    use std::cell::RefCell;
    use std::io;
    type Hook = RefCell<Option<Box<dyn FnOnce() -> io::Result<()>>>>;
    thread_local! { static AFTER_STAGE: Hook = RefCell::new(None); }
    pub(super) fn after_stage() -> io::Result<()> {
        match AFTER_STAGE.with(|hook| hook.borrow_mut().take()) {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }

    #[cfg(any(target_os = "macos", windows))]
    mod native {
        use super::*;
        use crate::CancellationToken;
        use crate::approval::Confirmation;
        use crate::authorization::Session;
        use crate::execution::ExecutionStatus;
        use crate::plan::{OperationKind, OperationRequest, PlanOptions};

        fn run_interrupted(cancel: bool) -> Result<(), Box<dyn std::error::Error>> {
            let fixture_root =
                std::env::var_os("FILE_TIDY_TEST_ROOT").ok_or("FILE_TIDY_TEST_ROOT is required")?;
            let directory = tempfile::tempdir_in(fixture_root)?;
            let root = directory.path();
            let mut session = Session::new()?;
            let grant = session.grant(root, false)?;
            let storage = session.storage_plan(&grant)?;
            let digest = storage.digest().to_owned();
            session.initialize_storage(storage, &digest)?;
            let source = root.join("Example");
            let target = root.join("EXAMPLE");
            std::fs::write(&source, b"original")?;
            let plan = session.build_plan(
                vec![OperationRequest {
                    kind: OperationKind::Rename,
                    source: source.clone(),
                    destination: Some(target.clone()),
                }],
                PlanOptions::default(),
            )?;
            let temporary = plan.preview().operations[0]
                .destination
                .as_ref()
                .and_then(|d| d.spelling_temporary.as_ref())
                .ok_or("case-insensitive fixture filesystem required")?
                .to_path()?;
            let confirmation = Confirmation {
                digest: plan.digest().to_owned(),
                ..Default::default()
            };
            let approved = session.confirm(plan, confirmation)?;
            let cancellation = CancellationToken::new();
            let token = cancellation.clone();
            let occupied = target.clone();
            AFTER_STAGE.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if cancel {
                        token.cancel();
                        Ok(())
                    } else {
                        std::fs::write(occupied, b"racing entry")
                    }
                }))
            });
            let report = session.execute_approved(approved, &cancellation)?;
            assert_eq!(
                report.operations[0].status,
                ExecutionStatus::NeedsRecovery,
                "{report:?}"
            );
            assert!(report.journal_error.is_none(), "{report:?}");
            assert_eq!(std::fs::read(&temporary)?, b"original");
            if cancel {
                assert!(!target.try_exists()?);
            } else {
                assert_eq!(std::fs::read(&target)?, b"racing entry");
            }
            let history = session.batch_history(&report.batch_id)?;
            assert_eq!(history.events[0].step, "rename_to_temporary");
            assert_eq!(history.events[1].step, "rename_to_temporary");
            assert_eq!(
                history.events.last().ok_or("missing result event")?.step,
                "rename_from_temporary"
            );
            Ok(())
        }

        #[test]
        #[ignore = "requires FILE_TIDY_TEST_ROOT on a case-insensitive filesystem"]
        fn occupied_final_name_preserves_the_reviewed_temporary()
        -> Result<(), Box<dyn std::error::Error>> {
            run_interrupted(false)
        }

        #[test]
        #[ignore = "requires FILE_TIDY_TEST_ROOT on a case-insensitive filesystem"]
        fn cancellation_between_steps_preserves_the_reviewed_temporary()
        -> Result<(), Box<dyn std::error::Error>> {
            run_interrupted(true)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OperationResult {
    pub id: Id,
    pub source: NativePath,
    pub destination: Option<NativePath>,
    pub temporary: Option<NativePath>,
    pub status: ExecutionStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecutionReport {
    pub batch_id: Id,
    pub operations: Vec<OperationResult>,
    pub journal_error: Option<String>,
}
impl ExecutionReport {
    pub fn completed(&self) -> bool {
        self.journal_error.is_none()
            && self
                .operations
                .iter()
                .all(|op| op.status == ExecutionStatus::Done)
    }
}

struct SpellingFailure {
    error: E,
    moved: bool,
    journal: bool,
    cancelled: bool,
    step: &'static str,
}

impl Session {
    /// Check that every selected operation has an available execution protocol.
    /// The check is read-only and can run before prompting for confirmation.
    pub fn validate_executable(&self, plan: &Plan) -> Result<()> {
        self.validate_plan(plan)?;
        for operation in &plan.preview.operations {
            for entry in &operation.manifest {
                let path = entry.path.to_path()?;
                let name = path.file_name().ok_or(E::InvalidPath)?.as_encoded_bytes();
                let lower: Vec<_> = name.iter().map(u8::to_ascii_lowercase).collect();
                if entry.kind != "Symlink"
                    && [
                        b".db".as_slice(),
                        b".sqlite",
                        b".sqlite3",
                        b"-wal",
                        b"-shm",
                        b"-journal",
                        b".vmdk",
                        b".vdi",
                        b".qcow",
                        b".qcow2",
                        b".vhd",
                        b".vhdx",
                        b".vmwarevm",
                        b".pvm",
                        b".vbox",
                        b".vmx",
                    ]
                    .iter()
                    .any(|suffix| lower.ends_with(suffix))
                {
                    return Err(E::ConsistencyRequired);
                }
            }
            if !matches!(
                operation.kind,
                OperationKind::Move | OperationKind::Rename | OperationKind::Copy
            ) || (operation.kind == OperationKind::Copy
                && (operation.manifest.len() != 1 || operation.manifest[0].kind != "Regular"))
                || operation
                    .destination
                    .as_ref()
                    .is_none_or(|d| !d.create_directories.is_empty())
            {
                return Err(E::UnsupportedSafetyGuarantee);
            }
        }
        let mut volumes: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        for operation in plan
            .preview
            .operations
            .iter()
            .filter(|op| op.kind == OperationKind::Copy)
        {
            let destination = operation.destination.as_ref().ok_or(E::InvalidPlan)?;
            let parent = destination.existing_parent.to_path()?;
            let info = platform::inspect(&parent)?;
            let pinned = platform::open_directory_pinned(&parent, &info)?;
            let available = platform::available_bytes(&pinned)?;
            let volume = info.identity.ok_or(E::UnsupportedSafetyGuarantee)?.volume;
            let entry = volumes.entry(volume).or_insert((0, available));
            entry.0 = entry
                .0
                .checked_add(
                    operation.manifest[0]
                        .size_bytes
                        .parse::<u64>()
                        .map_err(|_| E::Overflow)?,
                )
                .ok_or(E::Overflow)?;
            entry.1 = entry.1.min(available);
        }
        for (bytes, available) in volumes.values() {
            let required = bytes
                .checked_add((64 * 1024 * 1024).max(bytes.div_ceil(20)))
                .ok_or(E::Overflow)?;
            if required > *available {
                return Err(E::InsufficientSpace);
            }
        }
        Ok(())
    }

    pub fn execute_approved(
        &mut self,
        approved: ApprovedPlan,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionReport> {
        self.validate_executable(&approved.plan)?;
        self.store
            .as_mut()
            .ok_or(E::StorageRequired)?
            .start_execution(&approved, &self.grants)?;
        let plan = &approved.plan;
        let mut report = ExecutionReport {
            batch_id: plan.preview.id.clone(),
            operations: plan
                .preview
                .operations
                .iter()
                .map(|op| OperationResult {
                    id: op.id.clone(),
                    source: op.source.clone(),
                    destination: op.destination.as_ref().map(|d| d.path.clone()),
                    temporary: op.destination.as_ref().and_then(|d| {
                        d.spelling_temporary
                            .clone()
                            .or_else(|| d.copy_temporary.clone())
                    }),
                    status: ExecutionStatus::NotStarted,
                    reason: None,
                })
                .collect(),
            journal_error: None,
        };
        let mut changed_parents = BTreeMap::new();
        for (index, operation) in plan.preview.operations.iter().enumerate() {
            if cancellation.is_cancelled() {
                report.operations[index].status = ExecutionStatus::Cancelled;
                break;
            }
            if let Err(error) = self.validate_operation(plan, operation, &changed_parents) {
                self.fail_operation(&mut report, index, operation, error, false);
                break;
            }
            if operation.kind == OperationKind::Copy {
                match self.copy_operation(&approved, operation, &mut changed_parents, cancellation)
                {
                    Ok(()) => report.operations[index].status = ExecutionStatus::Done,
                    Err(failure) => {
                        let result = &mut report.operations[index];
                        result.status = if failure.created {
                            ExecutionStatus::NeedsRecovery
                        } else if cancellation.is_cancelled() {
                            ExecutionStatus::Cancelled
                        } else {
                            ExecutionStatus::Failed
                        };
                        result.reason = Some(failure.error.to_string());
                        if failure.journal {
                            report.journal_error = Some(failure.error.to_string());
                        } else {
                            let state = if failure.created {
                                OperationState::NeedsRecovery
                            } else {
                                OperationState::Failed
                            };
                            if let Err(error) = self
                                .store
                                .as_mut()
                                .ok_or(E::StorageRequired)?
                                .record_result(&operation.id, failure.step, result, state)
                            {
                                report.journal_error = Some(error.to_string());
                            }
                        }
                        break;
                    }
                }
                continue;
            }
            if operation
                .destination
                .as_ref()
                .is_some_and(|d| d.spelling_temporary.is_some())
            {
                match self.rename_spelling(plan, operation, &mut changed_parents, cancellation) {
                    Ok(()) => report.operations[index].status = ExecutionStatus::Done,
                    Err(failure) => {
                        let result = &mut report.operations[index];
                        result.status = if failure.moved {
                            ExecutionStatus::NeedsRecovery
                        } else if failure.cancelled {
                            ExecutionStatus::Cancelled
                        } else if failure.journal {
                            ExecutionStatus::NotStarted
                        } else {
                            ExecutionStatus::Failed
                        };
                        result.reason = Some(failure.error.to_string());
                        if failure.journal {
                            report.journal_error = Some(failure.error.to_string());
                        } else if !failure.cancelled || failure.moved {
                            let state = if failure.moved {
                                OperationState::NeedsRecovery
                            } else {
                                OperationState::Failed
                            };
                            if let Err(error) = self
                                .store
                                .as_mut()
                                .ok_or(E::StorageRequired)?
                                .record_result(&operation.id, failure.step, result, state)
                            {
                                report.journal_error = Some(error.to_string());
                            }
                        }
                        break;
                    }
                }
                continue;
            }
            let intent = serde_json::json!({
                "source": operation.source,
                "destination": operation.destination,
                "manifest": operation.manifest,
            });
            if let Err(error) = self
                .store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&operation.id, "rename", &intent)
            {
                report.journal_error = Some(error.to_string());
                break;
            }
            // The durable intent can take time; repeat policy and manifest checks.
            if let Err(error) = self.validate_operation(plan, operation, &changed_parents) {
                self.fail_operation(&mut report, index, operation, error, false);
                break;
            }
            if cancellation.is_cancelled() {
                report.operations[index].status = ExecutionStatus::Cancelled;
                break;
            }
            match self.rename_operation(operation, &mut changed_parents) {
                Ok(manifest) => {
                    report.operations[index].status = ExecutionStatus::Done;
                    let result = serde_json::json!({
                        "source": operation.source,
                        "destination": operation.destination.as_ref().map(|d| &d.path),
                        "observed_manifest": manifest,
                    });
                    if let Err(error) = self
                        .store
                        .as_mut()
                        .ok_or(E::StorageRequired)?
                        .record_result(&operation.id, "rename", &result, OperationState::Done)
                    {
                        report.operations[index].status = ExecutionStatus::NeedsRecovery;
                        report.journal_error = Some(error.to_string());
                        break;
                    }
                }
                Err((error, may_have_moved)) => {
                    self.fail_operation(&mut report, index, operation, error, may_have_moved);
                    break;
                }
            }
        }
        if report.journal_error.is_none() {
            let state = if report.completed() {
                BatchState::Completed
            } else if report
                .operations
                .iter()
                .any(|op| op.status == ExecutionStatus::NeedsRecovery)
            {
                BatchState::NeedsRecovery
            } else if report
                .operations
                .iter()
                .any(|op| op.status == ExecutionStatus::Cancelled)
            {
                BatchState::Cancelled
            } else {
                BatchState::Partial
            };
            if let Err(error) = self
                .store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .finish_execution(&report.batch_id, state)
            {
                report.journal_error = Some(error.to_string());
            }
        }
        Ok(report)
    }

    fn fail_operation(
        &mut self,
        report: &mut ExecutionReport,
        index: usize,
        operation: &PlannedOperation,
        error: E,
        may_have_moved: bool,
    ) {
        let result = &mut report.operations[index];
        result.status = if may_have_moved {
            ExecutionStatus::NeedsRecovery
        } else {
            ExecutionStatus::Failed
        };
        result.reason = Some(error.to_string());
        let journal_state = if may_have_moved {
            OperationState::NeedsRecovery
        } else {
            OperationState::Failed
        };
        let write = self
            .store
            .as_mut()
            .ok_or(E::StorageRequired)
            .and_then(|store| store.record_result(&operation.id, "rename", result, journal_state));
        if let Err(error) = write {
            report.journal_error = Some(error.to_string());
        }
    }

    fn rename_operation(
        &self,
        operation: &PlannedOperation,
        changed_parents: &mut BTreeMap<PathBuf, Stamp>,
    ) -> std::result::Result<Vec<ManifestEntry>, (E, bool)> {
        let prepare = || -> Result<_> {
            let source = operation.source.to_path()?;
            let destination = operation
                .destination
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .path
                .to_path()?;
            let source_parent = source.parent().ok_or(E::InvalidPath)?.to_owned();
            let destination_parent = destination.parent().ok_or(E::InvalidPath)?.to_owned();
            let source_info = platform::inspect(&source)?;
            let root = operation
                .manifest
                .iter()
                .find(|entry| entry.path == operation.source)
                .ok_or(E::InvalidPlan)?;
            if Stamp::capture(&source_info)? != root.stamp {
                return Err(E::ChangedSincePlan);
            }
            let source_parent_info = platform::inspect(&source_parent)?;
            let destination_parent_info = platform::inspect(&destination_parent)?;
            if Stamp::capture(&source_parent_info)?
                != *changed_parents
                    .get(&source_parent)
                    .unwrap_or(&operation.source_parent_stamp)
                || Stamp::capture(&destination_parent_info)?
                    != *changed_parents.get(&destination_parent).unwrap_or(
                        &operation
                            .destination
                            .as_ref()
                            .ok_or(E::InvalidPlan)?
                            .parent_stamp,
                    )
            {
                return Err(E::ChangedSincePlan);
            }
            Ok((
                source,
                destination,
                source_parent,
                destination_parent,
                source_info,
                source_parent_info,
                destination_parent_info,
            ))
        };
        let (
            source,
            destination,
            source_parent,
            destination_parent,
            source_info,
            source_parent_info,
            destination_parent_info,
        ) = prepare().map_err(|e| (e, false))?;
        platform::rename_noreplace(
            &source,
            &source_info,
            &destination,
            &source_parent_info,
            &destination_parent_info,
        )
        .map_err(|error| (E::Io(error.error), error.may_have_moved))?;
        let verify = || -> Result<Vec<ManifestEntry>> {
            let manifest = self.verify_renamed(operation, &destination)?;
            for (path, before) in [
                (&source_parent, &source_parent_info),
                (&destination_parent, &destination_parent_info),
            ] {
                let after = platform::inspect(path)?;
                if after.identity != before.identity || after.kind != before.kind {
                    return Err(E::ChangedSincePlan);
                }
            }
            match std::fs::symlink_metadata(&source) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(E::ChangedSincePlan),
            }
            Ok(manifest)
        };
        let manifest = verify().map_err(|e| (e, true))?;
        for (path, before) in [
            (source_parent, source_parent_info),
            (destination_parent, destination_parent_info),
        ] {
            let node = platform::inspect(&path).map_err(|e| (E::from(e), true))?;
            let expected = Stamp::capture(&before).map_err(|e| (e, true))?;
            if !expected.same_identity(&node) {
                return Err((E::ChangedSincePlan, true));
            }
            let stamp = Stamp::capture(&node).map_err(|e| (e, true))?;
            changed_parents.insert(path, stamp);
        }
        Ok(manifest)
    }

    fn rename_spelling(
        &mut self,
        plan: &Plan,
        operation: &PlannedOperation,
        changed_parents: &mut BTreeMap<PathBuf, Stamp>,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), SpellingFailure> {
        let failure = |error, moved, journal, cancelled, step| SpellingFailure {
            error,
            moved,
            journal,
            cancelled,
            step,
        };
        let destination = operation
            .destination
            .as_ref()
            .ok_or_else(|| failure(E::InvalidPlan, false, false, false, "rename_to_temporary"))?;
        let temporary = destination
            .spelling_temporary
            .as_ref()
            .ok_or_else(|| failure(E::InvalidPlan, false, false, false, "rename_to_temporary"))?;
        let mut physical = operation.clone();
        let first_destination = physical
            .destination
            .as_mut()
            .ok_or_else(|| failure(E::InvalidPlan, false, false, false, "rename_to_temporary"))?;
        first_destination.path = temporary.clone();
        first_destination.spelling_temporary = None;
        for (index, step) in ["rename_to_temporary", "rename_from_temporary"]
            .into_iter()
            .enumerate()
        {
            let moved = index > 0;
            let validate = |session: &Session, parents: &BTreeMap<PathBuf, Stamp>| -> Result<()> {
                if !moved {
                    return session.validate_operation(plan, operation, parents);
                }
                session.validate_plan_context(plan)?;
                let policy = planning_policy()?;
                let source = physical.source.to_path()?;
                let target = destination.path.to_path()?;
                let parent = crate::authorization::checked_existing(
                    source.parent().ok_or(E::InvalidPath)?,
                    false,
                )?;
                if parent.as_path() != target.parent().ok_or(E::InvalidPath)?
                    || Stamp::capture(&platform::inspect(&parent)?)?
                        != *parents.get(&parent).ok_or(E::InvalidPlan)?
                {
                    return Err(E::ChangedSincePlan);
                }
                let labels = policy.labels(&parent);
                if labels.protected {
                    return Err(E::ProtectedZone);
                }
                if labels.atomic_root.is_some() {
                    return Err(E::AtomicBoundary);
                }
                if (labels.sensitive || crate::plan::destination_sensitive(&target))
                    && !plan
                        .preview
                        .sensitive_acknowledgements
                        .contains(&format!("{}:destination:write", operation.id))
                {
                    return Err(E::ChangedSincePlan);
                }
                if Some(session.grant_for(&source, &policy)?.id())
                    != operation.source_grant.as_ref()
                    || Some(session.grant_for(&parent, &policy)?.id())
                        != operation.destination_grant.as_ref()
                {
                    return Err(E::InvalidPlan);
                }
                let actual = session.verify_renamed(operation, &source)?;
                let original = operation.source.to_path()?;
                let reviewed = operation
                    .manifest
                    .iter()
                    .map(|entry| {
                        let path = entry.path.to_path()?;
                        Ok((
                            path.strip_prefix(&original)
                                .map_err(|_| E::InvalidPath)?
                                .to_owned(),
                            entry.sensitive,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                for entry in actual.iter().filter(|entry| entry.sensitive) {
                    let path = entry.path.to_path()?;
                    let relative = path.strip_prefix(&source).map_err(|_| E::InvalidPath)?;
                    if reviewed.get(relative) != Some(&true) {
                        return Err(E::ChangedSincePlan);
                    }
                }
                match std::fs::symlink_metadata(target) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    _ => Err(E::DestinationConflict),
                }
            };
            validate(self, changed_parents)
                .map_err(|error| failure(error, moved, false, false, step))?;
            if cancellation.is_cancelled() {
                return Err(failure(
                    E::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "execution cancelled",
                    )),
                    moved,
                    false,
                    true,
                    step,
                ));
            }
            let intent = serde_json::json!({
                "source": operation.source,
                "destination": operation.destination,
                "manifest": operation.manifest,
                "step_source": physical.source,
                "step_destination": physical.destination.as_ref().map(|d| &d.path),
            });
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)
                .and_then(|store| store.record_intent(&operation.id, step, &intent))
                .map_err(|error| failure(error, moved, true, false, step))?;
            validate(self, changed_parents)
                .map_err(|error| failure(error, moved, false, false, step))?;
            if cancellation.is_cancelled() {
                return Err(failure(
                    E::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "execution cancelled",
                    )),
                    moved,
                    false,
                    true,
                    step,
                ));
            }
            let observed = self.rename_operation(&physical, changed_parents).map_err(
                |(error, maybe_moved)| failure(error, moved || maybe_moved, false, false, step),
            )?;
            if moved {
                self.verify_renamed(
                    operation,
                    &destination
                        .path
                        .to_path()
                        .map_err(|error| failure(error, true, false, false, step))?,
                )
                .map_err(|error| failure(error, true, false, false, step))?;
            }
            let result = serde_json::json!({
                "source": physical.source,
                "destination": physical.destination.as_ref().map(|d| &d.path),
                "observed_manifest": observed,
            });
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)
                .and_then(|store| {
                    store.record_result(
                        &operation.id,
                        step,
                        &result,
                        if moved {
                            OperationState::Done
                        } else {
                            OperationState::Staged
                        },
                    )
                })
                .map_err(|error| failure(error, true, true, false, step))?;
            if !moved {
                physical.source = temporary.clone();
                physical.manifest = observed;
                physical.destination = Some(destination.clone());
                if let Some(dest) = &mut physical.destination {
                    dest.spelling_temporary = None;
                }
                #[cfg(test)]
                spelling_tests::after_stage().map_err(|error| {
                    failure(E::Io(error), true, false, false, "rename_from_temporary")
                })?;
            }
        }
        Ok(())
    }

    pub(crate) fn verify_renamed(
        &self,
        operation: &PlannedOperation,
        destination: &Path,
    ) -> Result<Vec<ManifestEntry>> {
        let source = operation.source.to_path()?;
        let mut budget = operation.manifest.len();
        let policy = planning_policy()?;
        let options = crate::plan::PlanOptions {
            include_hidden: true,
            ..Default::default()
        };
        let actual = self.manifest(
            destination,
            OperationKind::Copy,
            &options,
            &policy,
            &mut budget,
        )?;
        if actual.len() != operation.manifest.len() {
            return Err(E::ChangedSincePlan);
        }
        // Use native relative paths, since root renaming changes absolute sort order.
        let expected = operation
            .manifest
            .iter()
            .map(|entry| {
                let path = entry.path.to_path()?;
                let relative = path
                    .strip_prefix(&source)
                    .map_err(|_| E::InvalidPath)?
                    .to_owned();
                Ok((relative, entry))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for entry in &actual {
            let path = entry.path.to_path()?;
            let relative = path.strip_prefix(destination).map_err(|_| E::InvalidPath)?;
            let before = expected.get(relative).ok_or(E::ChangedSincePlan)?;
            let original = before.path.to_path()?;
            let dot_name = |path: &Path| {
                path.file_name()
                    .is_some_and(|n| n.as_encoded_bytes().first() == Some(&b'.'))
            };
            let name_hidden_changed = dot_name(&original) != dot_name(&path);
            if !before
                .stamp
                .matches_relocated(&entry.stamp, name_hidden_changed)
                || before.link_target != entry.link_target
            {
                return Err(E::ChangedSincePlan);
            }
        }
        let mut budget = operation.manifest.len();
        if self.manifest(
            destination,
            OperationKind::Copy,
            &options,
            &policy,
            &mut budget,
        )? != actual
        {
            return Err(E::ChangedSincePlan);
        }
        Ok(actual)
    }
}
