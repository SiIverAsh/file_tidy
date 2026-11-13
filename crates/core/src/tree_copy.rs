//! Whole-directory copying and one atomic publication of the verified tree.
use crate::authorization::{
    NativePath, PlanningError as E, Result, Session, checked_existing, planning_policy,
};
use crate::content::OperationContentPermit;
use crate::copy::{CopyFailure, checkpoint, update_parent, verified_transfer};
use crate::journal::OperationState;
use crate::plan::{OperationKind, PlanOptions, PlannedOperation, Stamp};
use crate::{CancellationToken, approval::ApprovedPlan};
use file_tidy_platform as platform;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreeEntryProof {
    pub relative: NativePath,
    pub kind: String,
    pub stamp: Stamp,
    pub length: String,
    pub blake3: Option<String>,
    pub link_target: Option<NativePath>,
    pub symlink_directory: Option<bool>,
}
impl Session {
    pub(crate) fn copy_tree(
        &mut self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        let mut created = false;
        let mut journal = false;
        let mut step = "tree_create";
        let mut run = || -> Result<()> {
            let dest = op.destination.as_ref().ok_or(E::InvalidPlan)?;
            let target = dest.path.to_path()?;
            let temporary = dest
                .copy_temporary
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .to_path()?;
            let source = op.source.to_path()?;
            let parent = target.parent().ok_or(E::InvalidPath)?;
            let before = platform::inspect(parent)?;
            let intent = json!({"source":op.source,"destination":dest.path,"temporary":dest.copy_temporary,"manifest_digest":blake3::hash(&serde_json::to_vec(&op.manifest)?).to_hex().to_string()});
            checkpoint(cancel)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&op.id, step, &intent)
                .inspect_err(|_| journal = true)?;
            self.validate_operation(&approved.plan, op, parents)?;
            checkpoint(cancel)?;
            created = true;
            let mut tree = platform::StagedDirectory::create(
                parent,
                &before,
                temporary.file_name().ok_or(E::InvalidPath)?,
            )?;
            update_parent(parent, &before, parents)?;
            self.store.as_mut().ok_or(E::StorageRequired)?.record_result(&op.id,step,
                &json!({"temporary":dest.copy_temporary,"stamp":Stamp::capture(&tree.inspect()?)?}),OperationState::Staged).inspect_err(|_|journal=true)?;
            let mut entries = op
                .manifest
                .iter()
                .map(|entry| {
                    let path = entry.path.to_path()?;
                    let relative = path
                        .strip_prefix(&source)
                        .map_err(|_| E::InvalidPath)?
                        .to_path_buf();
                    Ok((relative, entry))
                })
                .collect::<Result<Vec<_>>>()?;
            entries.sort_by(|(a, _), (b, _)| {
                a.components()
                    .count()
                    .cmp(&b.components().count())
                    .then_with(|| a.cmp(b))
            });
            let mut leaves = BTreeMap::<PathBuf, TreeEntryProof>::new();
            for (relative, entry) in &entries {
                if relative.as_os_str().is_empty() {
                    continue;
                }
                checkpoint(cancel)?;
                self.validate_plan_context(&approved.plan)?;
                tree.verify()?;
                let source_path = checked_existing(&entry.path.to_path()?, true)?;
                if Stamp::capture(&platform::inspect(&source_path)?)? != entry.stamp {
                    return Err(E::ChangedSincePlan);
                }
                step = match entry.kind.as_str() {
                    "Directory" => "tree_directory",
                    "Regular" => "tree_file",
                    "Symlink" => "tree_link",
                    _ => return Err(E::UnsupportedNode),
                };
                let entry_intent = json!({"relative":NativePath::new(relative),"entry_digest":blake3::hash(&serde_json::to_vec(entry)?).to_hex().to_string()});
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_intent(&op.id, step, &entry_intent)
                    .inspect_err(|_| journal = true)?;
                checkpoint(cancel)?;
                let (info, hash) = match entry.kind.as_str() {
                    "Directory" => (tree.create_directory(relative)?, None),
                    "Regular" => {
                        let permit =
                            OperationContentPermit::issue_entry(self, approved, op, entry)?;
                        let mut source_file = permit.open()?;
                        let mut staged = tree.create_file(relative)?;
                        let verified =
                            verified_transfer(&permit, &mut source_file, &mut staged, cancel)?;
                        let info = staged.inspect()?;
                        if Stamp::capture(&info)? != verified.stamp {
                            return Err(E::ChangedSincePlan);
                        }
                        (info, Some(verified.hash.to_hex().to_string()))
                    }
                    "Symlink" => {
                        let target = entry
                            .link_target
                            .as_ref()
                            .ok_or(E::InvalidPlan)?
                            .to_path()?;
                        let info = tree.create_symlink(
                            relative,
                            &target,
                            entry.symlink_directory.ok_or(E::InvalidPlan)?,
                        )?;
                        let modified = platform::inspect(&source_path)?
                            .modified
                            .ok_or(E::UnsupportedSafetyGuarantee)?;
                        let info = tree.set_symlink_modified(relative, &info, modified)?;
                        (info, None)
                    }
                    _ => return Err(E::UnsupportedNode),
                };
                let proof = TreeEntryProof {
                    relative: NativePath::new(relative),
                    kind: entry.kind.clone(),
                    stamp: Stamp::capture(&info)?,
                    length: entry.size_bytes.clone(),
                    blake3: hash,
                    link_target: entry.link_target.clone(),
                    symlink_directory: entry.symlink_directory,
                };
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_result(&op.id, step, &proof, OperationState::Staged)
                    .inspect_err(|_| journal = true)?;
                if entry.kind != "Directory" {
                    leaves.insert(relative.clone(), proof);
                }
            }
            // Child creation changes directory times. Restore them from leaves
            // toward the root after the entire tree has been constructed.
            for (relative, entry) in entries
                .iter()
                .rev()
                .filter(|(_, entry)| entry.kind == "Directory")
            {
                checkpoint(cancel)?;
                self.validate_plan_context(&approved.plan)?;
                let source_path = checked_existing(&entry.path.to_path()?, false)?;
                let info = platform::inspect(&source_path)?;
                if Stamp::capture(&info)? != entry.stamp {
                    return Err(E::ChangedSincePlan);
                }
                step = "tree_directory_time";
                let payload = json!({"relative":NativePath::new(relative),"entry_digest":blake3::hash(&serde_json::to_vec(entry)?).to_hex().to_string()});
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_intent(&op.id, step, &payload)
                    .inspect_err(|_| journal = true)?;
                checkpoint(cancel)?;
                let actual = tree.set_directory_modified(
                    relative,
                    info.modified.ok_or(E::UnsupportedSafetyGuarantee)?,
                )?;
                let proof = TreeEntryProof {
                    relative: NativePath::new(relative),
                    kind: entry.kind.clone(),
                    stamp: Stamp::capture(&actual)?,
                    length: "0".to_owned(),
                    blake3: None,
                    link_target: None,
                    symlink_directory: None,
                };
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_result(&op.id, step, &proof, OperationState::Staged)
                    .inspect_err(|_| journal = true)?;
                leaves.insert(relative.clone(), proof);
            }
            let proof = leaves.into_values().collect::<Vec<_>>();
            step = "tree_verify";
            let proof_payload = json!({"temporary":dest.copy_temporary,"entries":proof,"metadata":dest.copy_metadata});
            let seal = tree_seal(dest, &proof)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&op.id, step, &seal)
                .inspect_err(|_| journal = true)?;
            self.verify_tree_copy_staged(&temporary, &proof, false, Some(&tree))?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&op.id, step, &proof_payload, OperationState::Verified)
                .inspect_err(|_| journal = true)?;
            let mut current = op.clone();
            current
                .destination
                .as_mut()
                .ok_or(E::InvalidPlan)?
                .copy_temporary = None;
            self.validate_operation(&approved.plan, &current, parents)?;
            checkpoint(cancel)?;
            step = "tree_publish";
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&op.id, step, &seal)
                .inspect_err(|_| journal = true)?;
            self.validate_operation(&approved.plan, &current, parents)?;
            tree.verify()?;
            self.verify_tree_copy_staged(&temporary, &proof, false, Some(&tree))?;
            checkpoint(cancel)?;
            tree.publish(target.file_name().ok_or(E::InvalidPath)?)
                .map_err(|e| E::Io(e.error))?;
            update_parent(parent, &before, parents)?;
            drop(tree);
            self.verify_tree_copy(&target, &proof, true)?;
            let published =
                json!({"destination":dest.path,"entries":proof,"metadata":dest.copy_metadata});
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&op.id, step, &published, OperationState::Published)
                .inspect_err(|_| journal = true)?;
            step = "tree_complete";
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_intent(&op.id, step, &published)
                .inspect_err(|_| journal = true)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_result(&op.id, step, &published, OperationState::Done)
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
    pub(crate) fn verify_tree_copy(
        &self,
        root: &Path,
        proof: &[TreeEntryProof],
        relocated: bool,
    ) -> Result<()> {
        self.verify_tree_copy_staged(root, proof, relocated, None)
    }
    fn verify_tree_copy_staged(
        &self,
        root: &Path,
        proof: &[TreeEntryProof],
        relocated: bool,
        staged: Option<&platform::StagedDirectory>,
    ) -> Result<()> {
        if proof.is_empty() || proof.len() > 1_000_000 {
            return Err(E::IncompleteManifest);
        }
        let mut expected = BTreeMap::new();
        for entry in proof {
            let relative = entry.relative.to_path()?;
            if relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
                || relative.is_absolute()
                || expected.insert(relative, entry).is_some()
            {
                return Err(E::StorageUnavailable);
            }
        }
        if !expected.contains_key(Path::new("")) {
            return Err(E::StorageUnavailable);
        }
        let mut budget = proof.len();
        let policy = planning_policy()?;
        let actual = self.manifest_staged(
            root,
            OperationKind::Copy,
            &PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
            &policy,
            &mut budget,
            staged,
        )?;
        if actual.len() != proof.len() {
            return Err(E::ChangedSincePlan);
        }
        for entry in actual {
            let path = entry.path.to_path()?;
            let relative = path.strip_prefix(root).map_err(|_| E::InvalidPath)?;
            let before = expected.get(relative).ok_or(E::ChangedSincePlan)?;
            if entry.kind != before.kind
                || entry.size_bytes != before.length
                || !before
                    .stamp
                    .matches_relocated(&entry.stamp, relocated && relative.as_os_str().is_empty())
                || entry.link_target != before.link_target
                || entry.symlink_directory != before.symlink_directory
            {
                return Err(E::ChangedSincePlan);
            }
        }
        Ok(())
    }
}

impl Session {
    pub(crate) fn inspect_tree_copy(
        &self,
        op: &PlannedOperation,
        history: &crate::journal::BatchHistoryDetail,
    ) -> (crate::recovery::RecoveryDisposition, String) {
        use crate::recovery::RecoveryDisposition as D;
        let inspect = || -> Result<(D, &'static str)> {
            let dest = op.destination.as_ref().ok_or(E::StorageUnavailable)?;
            let temporary = dest
                .copy_temporary
                .as_ref()
                .ok_or(E::StorageUnavailable)?
                .to_path()?;
            let target = dest.path.to_path()?;
            let parent = checked_existing(target.parent().ok_or(E::InvalidPath)?, false)?;
            if temporary.parent() != Some(parent.as_path()) || !dest.create_directories.is_empty() {
                return Err(E::StorageUnavailable);
            }
            let policy = planning_policy()?;
            self.grant_for(&parent, &policy)?;
            if policy.labels(&parent).protected {
                return Err(E::ProtectedZone);
            }
            let before = platform::inspect(&parent)?;
            if !dest.parent_stamp.same_identity(&before) {
                return Ok((D::NeedsAttention, "tree_parent_changed"));
            }
            if self.verify_renamed(op, &op.source.to_path()?).is_err() {
                return Ok((D::NeedsAttention, "tree_source_changed"));
            }
            let expected = json!({"source":op.source,"destination":dest.path,"temporary":dest.copy_temporary,"manifest_digest":blake3::hash(&serde_json::to_vec(&op.manifest)?).to_hex().to_string()});
            let mut create_intent = false;
            let mut created = None;
            let mut verified = None;
            let mut verification_intent = None;
            let mut publish = false;
            for event in history
                .events
                .iter()
                .filter(|event| event.operation_id == op.id.as_str())
            {
                if !matches!(
                    event.step.as_str(),
                    "tree_create"
                        | "tree_directory"
                        | "tree_file"
                        | "tree_link"
                        | "tree_directory_time"
                        | "tree_verify"
                        | "tree_publish"
                        | "tree_complete"
                ) || !matches!(event.phase.as_str(), "intent" | "result")
                {
                    return Err(E::StorageUnavailable);
                }
                match (event.step.as_str(), event.phase.as_str()) {
                    ("tree_create", "intent") => {
                        if create_intent || event.payload != expected {
                            return Err(E::StorageUnavailable);
                        }
                        create_intent = true;
                    }
                    ("tree_create", "result") if event.payload.get("stamp").is_some() => {
                        if !create_intent
                            || event.payload["temporary"] != json!(dest.copy_temporary)
                        {
                            return Err(E::StorageUnavailable);
                        }
                        created = Some(serde_json::from_value::<Stamp>(
                            event.payload["stamp"].clone(),
                        )?);
                    }
                    ("tree_verify", "intent") => {
                        verification_intent = Some(event.payload.clone());
                    }
                    ("tree_verify", "result") if event.payload.get("entries").is_some() => {
                        if created.is_none()
                            || event.payload["temporary"] != json!(dest.copy_temporary)
                            || event.payload["metadata"] != json!(dest.copy_metadata)
                        {
                            return Err(E::StorageUnavailable);
                        }
                        let proof: Vec<TreeEntryProof> =
                            serde_json::from_value(event.payload["entries"].clone())?;
                        validate_proof_shape(op, &proof)?;
                        let seal = tree_seal(dest, &proof)?;
                        if verification_intent.as_ref() != Some(&seal) {
                            return Err(E::StorageUnavailable);
                        }
                        verified = Some((proof, seal));
                    }
                    ("tree_publish", "intent") => {
                        if verified.as_ref().is_none_or(|(_, p)| *p != event.payload) {
                            return Err(E::StorageUnavailable);
                        }
                        publish = true;
                    }
                    _ => {}
                }
            }
            let maybe = |path: &Path| -> Result<Option<platform::NodeInfo>> {
                match platform::inspect(path) {
                    Ok(node) => Ok(Some(node)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e.into()),
                }
            };
            let outcome = match (maybe(&temporary)?, maybe(&target)?) {
                (None, None) if created.is_none() => (D::NotCommitted, "tree_not_created"),
                (Some(info), None) => {
                    if created
                        .as_ref()
                        .is_none_or(|stamp| !stamp.same_identity(&info))
                    {
                        (D::NeedsAttention, "tree_staging_ownership_unknown")
                    } else if let Some((proof, _)) = &verified {
                        if self.verify_tree_copy(&temporary, proof, false).is_ok() {
                            (
                                D::VerifiedCopyObserved,
                                "verified_tree_present_recheck_required",
                            )
                        } else {
                            (D::NeedsAttention, "verified_tree_changed")
                        }
                    } else {
                        (D::StagedCopyObserved, "identified_partial_tree_present")
                    }
                }
                (None, Some(_)) if publish => {
                    if let Some((proof, _)) = &verified {
                        if self.verify_tree_copy(&target, proof, true).is_ok() {
                            (
                                D::CopyPublishedObserved,
                                "tree_publication_observed_recheck_required",
                            )
                        } else {
                            (D::NeedsAttention, "published_tree_changed")
                        }
                    } else {
                        (D::NeedsAttention, "tree_verification_missing")
                    }
                }
                _ => (D::NeedsAttention, "tree_paths_require_review"),
            };
            if !before.matches(&platform::inspect(&parent)?) {
                return Ok((D::NeedsAttention, "tree_parent_changed_during_inspection"));
            }
            Ok(outcome)
        };
        match inspect() {
            Ok((state, reason)) => (state, reason.into()),
            Err(E::StorageUnavailable | E::Encoding(_)) => {
                (D::NeedsAttention, "tree_journal_inconsistent".into())
            }
            Err(_) => (
                D::Unavailable,
                "tree_authorization_or_media_unavailable".into(),
            ),
        }
    }
}
fn tree_seal(
    dest: &crate::plan::Destination,
    proof: &[TreeEntryProof],
) -> Result<serde_json::Value> {
    Ok(json!({"temporary":dest.copy_temporary,
        "proof_digest":blake3::hash(&serde_json::to_vec(proof)?).to_hex().to_string(),"metadata":dest.copy_metadata}))
}

fn validate_proof_shape(op: &PlannedOperation, proof: &[TreeEntryProof]) -> Result<()> {
    if proof.len() != op.manifest.len() {
        return Err(E::StorageUnavailable);
    }
    let source = op.source.to_path()?;
    let expected = op
        .manifest
        .iter()
        .map(|entry| {
            let path = entry.path.to_path()?;
            Ok((
                path.strip_prefix(&source)
                    .map_err(|_| E::InvalidPath)?
                    .to_path_buf(),
                entry,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut seen = std::collections::BTreeSet::new();
    for entry in proof {
        let relative = entry.relative.to_path()?;
        let original = expected.get(&relative).ok_or(E::StorageUnavailable)?;
        if !seen.insert(relative)
            || entry.kind != original.kind
            || entry.length != original.size_bytes
            || entry.link_target != original.link_target
            || entry.symlink_directory != original.symlink_directory
            || (entry.kind == "Regular"
                && !entry
                    .blake3
                    .as_ref()
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())))
            || (entry.kind != "Regular" && entry.blake3.is_some())
        {
            return Err(E::StorageUnavailable);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::Confirmation;
    use crate::execution::ExecutionStatus;
    use crate::plan::OperationRequest;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn interrupted(mode: u8) -> TestResult {
        let base = std::env::var_os("FILE_TIDY_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let fixture = tempfile::tempdir_in(base)?;
        let root = fixture.path().canonicalize()?;
        let mut session = Session::new()?;
        let grant = session.grant(&root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        let source = root.join("source");
        let target = root.join("target");
        std::fs::create_dir_all(source.join("nested"))?;
        let bytes = vec![19u8; 140_127];
        std::fs::write(source.join("nested/data"), &bytes)?;
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Copy,
                source: source.clone(),
                destination: Some(target.clone()),
            }],
            PlanOptions::default(),
        )?;
        let temp = plan.preview().operations[0]
            .destination
            .as_ref()
            .ok_or("no destination")?
            .copy_temporary
            .as_ref()
            .ok_or("no staging")?
            .to_path()?;
        let input = Confirmation {
            digest: plan.digest().to_owned(),
            ..Default::default()
        };
        let approved = session.confirm(plan, input)?;
        let token = CancellationToken::new();
        let signal = token.clone();
        let source_path = source.clone();
        let target_path = target.clone();
        let staged = temp.clone();
        crate::copy::faults::AFTER_WRITE.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                match mode {
                    0 => signal.cancel(),
                    1 => std::fs::write(source_path.join("added"), b"new source child")?,
                    2 => std::fs::write(&target_path, b"foreign target")?,
                    3 => std::fs::write(staged.join("unregistered"), b"unregistered child")?,
                    #[cfg(unix)]
                    4 => {
                        std::fs::rename(staged.join("nested"), staged.join("old"))?;
                        std::os::unix::fs::symlink(&source_path, staged.join("nested"))?;
                    }
                    _ => {}
                }
                Ok(())
            }))
        });
        let report = session.execute_approved(approved, &token)?;
        assert!(!report.completed(), "{report:?}");
        assert!(report.journal_error.is_none(), "{report:?}");
        assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
        assert_eq!(std::fs::read(source.join("nested/data"))?, bytes);
        assert!(temp.is_dir());
        if mode == 2 {
            assert_eq!(std::fs::read(&target)?, b"foreign target");
        } else {
            assert!(!target.exists());
        }
        if mode == 3 {
            assert_eq!(
                std::fs::read(temp.join("unregistered"))?,
                b"unregistered child"
            );
        }
        let items = session.recovery_report(None, 10)?.items;
        assert_eq!(items.len(), 1);
        Ok(())
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn cancellation_keeps_the_source_and_partial_tree() -> TestResult {
        interrupted(0)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn added_source_child_prevents_publication() -> TestResult {
        interrupted(1)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn occupied_target_preserves_the_foreign_object() -> TestResult {
        interrupted(2)
    }
    #[test]
    #[cfg_attr(
        any(target_os = "macos", windows),
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn unregistered_staging_child_prevents_publication() -> TestResult {
        interrupted(3)
    }
    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "requires independent FILE_TIDY_TEST_ROOT"
    )]
    fn swapped_staging_ancestor_is_not_followed() -> TestResult {
        interrupted(4)
    }
}
