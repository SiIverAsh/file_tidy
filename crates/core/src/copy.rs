//! Confirmed ordinary-file copying through private verified staging.
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use file_tidy_platform as platform;
use serde_json::json;

use crate::CancellationToken;
use crate::approval::ApprovedPlan;
use crate::authorization::{PlanningError as E, Result, Session};
use crate::content::OperationContentPermit;
use crate::journal::OperationState;
use crate::plan::{PlannedOperation, Stamp};

pub(crate) struct CopyFailure {
    pub error: E,
    pub created: bool,
    pub journal: bool,
    pub step: &'static str,
}

impl Session {
    pub(crate) fn copy_operation(
        &mut self,
        approved: &ApprovedPlan,
        operation: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancellation: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        let mut created = false;
        let mut journal_error = false;
        let mut step = "copy_create";
        let mut run = || -> Result<()> {
            let destination = operation.destination.as_ref().ok_or(E::InvalidPlan)?;
            let target = destination.path.to_path()?;
            let temporary = destination
                .copy_temporary
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .to_path()?;
            let parent = target.parent().ok_or(E::InvalidPath)?;
            let parent_before = platform::inspect(parent)?;
            let permit = OperationContentPermit::issue(self, approved, operation)?;
            let mut source = permit.open()?;
            let intent = json!({"source": operation.source, "destination": destination.path,
                "temporary": destination.copy_temporary, "manifest": operation.manifest});
            checkpoint(cancellation)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&operation.id, step, &intent)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            self.validate_operation(&approved.plan, operation, parents)?;
            checkpoint(cancellation)?;
            created = true;
            let mut staged = platform::StagedFile::create(
                parent,
                &parent_before,
                temporary.file_name().ok_or(E::InvalidPath)?,
            )?;
            update_parent(parent, &parent_before, parents)?;
            let staged_stamp = Stamp::capture(&staged.inspect()?)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(
                    &operation.id,
                    step,
                    &json!({"temporary": destination.copy_temporary, "stamp": staged_stamp}),
                    OperationState::Staged,
                )
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            step = "copy_stream";
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&operation.id, step, &intent)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            let FileVerification {
                length,
                hash,
                stamp: verified_stamp,
            } = verified_transfer(&permit, &mut source, &mut staged, cancellation)?;
            let verified_result = json!({"temporary": destination.copy_temporary, "stamp": verified_stamp,
                "length": length.to_string(), "blake3": hash.to_hex().to_string(), "metadata": destination.copy_metadata});
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(
                    &operation.id,
                    step,
                    &verified_result,
                    OperationState::Verified,
                )
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            // The staged leaf now exists; its opened handle supplies its identity.
            // Recheck the original source and the remaining destination contract.
            let mut current = operation.clone();
            current
                .destination
                .as_mut()
                .ok_or(E::InvalidPlan)?
                .copy_temporary = None;
            self.validate_operation(&approved.plan, &current, parents)?;
            staged.verify()?;
            checkpoint(cancellation)?;
            step = "copy_publish";
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&operation.id, step, &verified_result)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            self.validate_operation(&approved.plan, &current, parents)?;
            permit.verify_after(&source)?;
            checkpoint(cancellation)?;
            if Stamp::capture(&staged.inspect()?)? != verified_stamp {
                return Err(E::ChangedSincePlan);
            }
            let published = staged
                .publish(target.file_name().ok_or(E::InvalidPath)?)
                .map_err(|e| E::Io(e.error))?;
            update_parent(parent, &parent_before, parents)?;
            let result = json!({"source": operation.source, "destination": destination.path,
                "stamp": Stamp::capture(&published)?, "length": length.to_string(),
                "blake3": hash.to_hex().to_string(), "metadata": destination.copy_metadata});
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&operation.id, step, &result, OperationState::Published)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            step = "copy_complete";
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&operation.id, step, &result)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&operation.id, step, &result, OperationState::Done)
                .inspect_err(|_| {
                    journal_error = true;
                })?;
            Ok(())
        };
        run().map_err(|error| CopyFailure {
            error,
            created,
            journal: journal_error,
            step,
        })
    }
}
pub(crate) struct FileVerification {
    pub length: u64,
    pub hash: blake3::Hash,
    pub stamp: Stamp,
}
pub(crate) fn verified_transfer(
    permit: &OperationContentPermit,
    source: &mut std::fs::File,
    staged: &mut platform::StagedFile,
    cancellation: &CancellationToken,
) -> Result<FileVerification> {
    let source_info = platform::inspect_file(source)?;
    permit.verify_after(source)?;
    let mut buffer = [0; 65_536];
    let mut length = 0u64;
    let mut source_hash = blake3::Hasher::new();
    loop {
        checkpoint(cancellation)?;
        permit.check_live()?;
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        permit.check_live()?;
        length = length.checked_add(read as u64).ok_or(E::Overflow)?;
        if length > source_info.len {
            return Err(E::ChangedSincePlan);
        }
        source_hash.update(&buffer[..read]);
        staged.file_mut().write_all(&buffer[..read])?;
        #[cfg(test)]
        faults::run()?;
    }
    if length != source_info.len {
        return Err(E::ChangedSincePlan);
    }
    staged.file_mut().flush()?;
    staged.file_mut().sync_all()?;
    staged.verify()?;
    permit.verify_after(source)?;
    let before_verification = Stamp::capture(&staged.inspect()?)?;
    staged.file_mut().seek(SeekFrom::Start(0))?;
    let mut target_hash = blake3::Hasher::new();
    let mut verified = 0u64;
    loop {
        checkpoint(cancellation)?;
        permit.check_live()?;
        let read = staged.file_mut().read(&mut buffer)?;
        if read == 0 {
            break;
        }
        verified = verified.checked_add(read as u64).ok_or(E::Overflow)?;
        if verified > length {
            return Err(E::ChangedSincePlan);
        }
        target_hash.update(&buffer[..read]);
    }
    let hash = source_hash.finalize();
    if verified != length || target_hash.finalize() != hash {
        return Err(E::ChangedSincePlan);
    }
    if Stamp::capture(&staged.inspect()?)? != before_verification {
        return Err(E::ChangedSincePlan);
    }
    let modified = source_info.modified.ok_or(E::UnsupportedSafetyGuarantee)?;
    staged
        .file_mut()
        .set_times(std::fs::FileTimes::new().set_modified(modified))?;
    staged.file_mut().sync_all()?;
    staged.verify()?;
    permit.verify_after(source)?;
    if staged.inspect()?.modified != source_info.modified {
        return Err(E::UnsupportedSafetyGuarantee);
    }
    let verified_stamp = Stamp::capture(&staged.inspect()?)?;
    Ok(FileVerification {
        length,
        hash,
        stamp: verified_stamp,
    })
}
pub(crate) fn checkpoint(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        return Err(E::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "copy cancelled",
        )));
    }
    Ok(())
}
pub(crate) fn update_parent(
    path: &Path,
    before: &platform::NodeInfo,
    parents: &mut BTreeMap<PathBuf, Stamp>,
) -> Result<()> {
    let actual = platform::inspect(path)?;
    if actual.identity != before.identity || actual.kind != before.kind {
        return Err(E::ChangedSincePlan);
    }
    parents.insert(path.into(), Stamp::capture(&actual)?);
    Ok(())
}
#[cfg(test)]
pub(crate) mod faults {
    use std::cell::RefCell;
    type Hook = RefCell<Option<Box<dyn FnOnce() -> std::io::Result<()>>>>;
    thread_local! { pub(crate) static AFTER_WRITE: Hook = RefCell::new(None); }
    pub(super) fn run() -> std::io::Result<()> {
        match AFTER_WRITE.with(|hook| hook.borrow_mut().take()) {
            Some(hook) => hook(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Confirmation;
    use crate::execution::ExecutionStatus;
    use crate::plan::{OperationKind, OperationRequest, PlanOptions};
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn interrupted_copy(mode: u8) -> TestResult {
        let root_base = std::env::var_os("FILE_TIDY_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let fixture = tempfile::tempdir_in(root_base)?;
        let root = fixture.path().canonicalize()?;
        let mut session = Session::new()?;
        let grant = session.grant(&root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        let source = root.join("source");
        let target = root.join("target");
        let bytes = vec![19u8; 140_000];
        std::fs::write(&source, &bytes)?;
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Copy,
                source: source.clone(),
                destination: Some(target.clone()),
            }],
            PlanOptions::default(),
        )?;
        let temporary = plan.preview().operations[0]
            .destination
            .as_ref()
            .ok_or("no destination")?
            .copy_temporary
            .as_ref()
            .ok_or("no temporary")?
            .to_path()?;
        let input = Confirmation {
            digest: plan.digest().to_owned(),
            ..Default::default()
        };
        let approved = session.confirm(plan, input)?;
        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let stage_path = temporary.clone();
        let source_path = source.clone();
        let target_path = target.clone();
        faults::AFTER_WRITE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                match mode {
                    0 => signal.cancel(),
                    1 => {
                        let mut file = std::fs::OpenOptions::new()
                            .append(true)
                            .open(&source_path)?;
                        file.write_all(b"changed")?;
                    }
                    2 => {
                        std::fs::write(&target_path, b"foreign")?;
                    }
                    3 => {
                        let mut file = std::fs::OpenOptions::new().write(true).open(&stage_path)?;
                        file.write_all(b"corrupt")?;
                    }
                    _ => {}
                }
                Ok(())
            }))
        });
        let report = session.execute_approved(approved, &cancellation)?;
        assert!(!report.completed(), "{report:?}");
        assert!(report.journal_error.is_none(), "{report:?}");
        assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
        assert!(temporary.exists());
        if mode == 2 {
            assert_eq!(std::fs::read(&target)?, b"foreign");
        } else {
            assert!(!target.exists());
        }
        if mode != 1 {
            assert_eq!(std::fs::read(&source)?, bytes);
        }
        let result = session.recovery_report(None, 10)?;
        assert_eq!(result.items.len(), 1);
        if mode == 0 || mode == 3 {
            assert_eq!(
                result.items[0].disposition,
                crate::recovery::RecoveryDisposition::StagedCopyObserved
            );
        }
        Ok(())
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn cancellation_keeps_identified_staging_and_source() -> TestResult {
        interrupted_copy(0)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn changing_source_prevents_publication() -> TestResult {
        interrupted_copy(1)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn concurrent_destination_is_preserved() -> TestResult {
        interrupted_copy(2)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn altered_staging_fails_full_hash_verification() -> TestResult {
        interrupted_copy(3)
    }
}
