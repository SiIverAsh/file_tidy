//! Reviewed cross-volume transfers, retained source commits, and reconciliation.
use crate::CancellationToken;
use crate::approval::ApprovedPlan;
use crate::authorization::{
    Id, NativePath, PlanningError as E, Result, Session, checked_existing, planning_policy,
};
use crate::content::OperationContentPermit;
use crate::copy::{CopyFailure, update_parent};
use crate::journal::{OperationState, id_bytes};
use crate::plan::{
    OperationKind, Plan, PlanOptions, PlannedOperation, Stamp, destination_acknowledgements,
};
use crate::quarantine::{QuarantineScope, register_retained};
use file_tidy_platform as platform;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetadataDescription {
    binding: String,
    portable: String,
    pub(crate) opaque_bytes: String,
    native_flags: String,
    attributes: Vec<AttributeDescription>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttributeDescription {
    name: NativePath,
    kind: String,
    bytes: String,
}
impl MetadataDescription {
    fn capture(value: &platform::MetadataInventory) -> Self {
        Self {
            binding: blake3::hash(value.binding_bytes()).to_hex().to_string(),
            portable: blake3::hash(value.portable_bytes()).to_hex().to_string(),
            opaque_bytes: value.opaque_bytes().to_string(),
            native_flags: value.native_flags().to_string(),
            attributes: value
                .attributes()
                .iter()
                .map(|a| AttributeDescription {
                    name: NativePath::new(Path::new(&a.name)),
                    kind: format!("{:?}", a.kind),
                    bytes: a.bytes.to_string(),
                })
                .collect(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationScope {
    pub(crate) temporary: NativePath,
    pub(crate) capture: QuarantineScope,
    pub(crate) metadata: MetadataDescription,
    preservation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acl_inheritance: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tree: Vec<directory::ReviewedEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_commit: Option<String>,
}

#[path = "migration_directory.rs"]
pub(crate) mod directory;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StreamProof {
    kind: u32,
    name: NativePath,
    bytes: String,
    blake3: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContentProof {
    length: String,
    blake3: String,
    attached: Vec<StreamProof>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationProof {
    protocol: String,
    source: NativePath,
    destination: NativePath,
    target: Stamp,
    metadata: MetadataDescription,
    content: ContentProof,
    capture: QuarantineScope,
    source_removed: bool,
}

impl Session {
    pub(crate) fn execute_migration(
        &mut self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        if op
            .migration
            .as_ref()
            .is_some_and(|scope| !scope.tree.is_empty())
        {
            return self.execute_directory_migration(approved, op, parents, cancel);
        }
        let mut created = false;
        let mut journal = false;
        let mut step = "migration_begin";
        let mut run = || -> Result<()> {
            let spec = op.migration.as_ref().ok_or(E::UnsupportedSafetyGuarantee)?;
            let source = op.source.to_path()?;
            let target = op
                .destination
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .path
                .to_path()?;
            let parent = target.parent().ok_or(E::InvalidPath)?;
            let temporary = spec.temporary.to_path()?;
            let length = op.manifest[0]
                .size_bytes
                .parse::<u64>()
                .map_err(|_| E::Overflow)?;
            macro_rules! intent {
                ($name:literal,$payload:expr) => {{
                    step = $name;
                    self.store
                        .as_mut()
                        .ok_or(E::StorageRequired)?
                        .record_intent(&op.id, step, &$payload)
                        .inspect_err(|_| journal = true)?;
                }};
            }
            macro_rules! result {
                ($payload:expr,$state:expr) => {{
                    self.store
                        .as_mut()
                        .ok_or(E::StorageRequired)?
                        .record_result(&op.id, step, &$payload, $state)
                        .inspect_err(|_| journal = true)?;
                }};
            }
            intent!(
                "migration_begin",
                json!({"source":op.source,"destination":NativePath::new(&target),"scope":spec})
            );
            self.validate_operation(&approved.plan, op, parents)?;
            result!(
                json!({"source":op.source,"scope":spec}),
                OperationState::Prepared
            );
            let (capture, made) = self
                .prepare_quarantine_directories(&approved.plan, op, &spec.capture, parents, cancel)
                .map_err(|failure| {
                    created |= failure.created;
                    journal |= failure.journal;
                    step = failure.step;
                    failure.error
                })?;
            created |= made;
            let metadata = self.migration_source_metadata(op)?;
            let permit = OperationContentPermit::issue(self, approved, op)?;
            let mut input = permit.open()?;
            let checkpoint = check(&permit, cancel);
            let before = platform::inspect(parent)?;
            intent!(
                "migration_create",
                json!({"temporary":spec.temporary,"parent":Stamp::capture(&before)?})
            );
            self.validate_operation(&approved.plan, op, parents)?;
            checkpoint()?;
            created = true;
            let mut staged = platform::MigrationFile::create(
                parent,
                &before,
                temporary.file_name().ok_or(E::InvalidPath)?,
            )?;
            update_parent(parent, &before, parents)?;
            result!(
                json!({"temporary":spec.temporary,"envelope":Stamp::capture(&staged.envelope_info()?)?,"payload":Stamp::capture(&staged.inspect()?)?}),
                OperationState::Staged
            );
            intent!(
                "migration_verify",
                json!({"source":op.source,"temporary":spec.temporary,"metadata":spec.metadata})
            );
            staged.copy_from(&source, &input, &metadata, &checkpoint)?;
            permit.verify_after(&input)?;
            let content = source_proof(&source, &mut input, &metadata, length, &checkpoint)?;
            permit.verify_after(&input)?;
            let staged_metadata = staged.metadata()?;
            let target_hash = hash_body(staged.file_mut(), length, &checkpoint)?;
            let attached =
                attached_proof(|sink| staged.visit_data(&checkpoint, &mut |event| sink(event)))?;
            if content.blake3 != target_hash
                || content.attached != attached
                || staged.metadata()?.binding_bytes() != staged_metadata.binding_bytes()
                || blake3::hash(staged_metadata.portable_bytes())
                    .to_hex()
                    .as_str()
                    != spec.metadata.portable
            {
                return Err(E::ChangedSincePlan);
            }
            let verified = json!({"temporary":spec.temporary,"payload":Stamp::capture(&staged.inspect()?)?,"content":content,"metadata":MetadataDescription::capture(&staged_metadata)});
            result!(verified, OperationState::Verified);
            self.validate_migration_source(&approved.plan, op, parents, true)?;
            intent!("migration_publish", verified);
            self.validate_migration_source(&approved.plan, op, parents, true)?;
            permit.verify_after(&input)?;
            checkpoint()?;
            let published = staged
                .publish(target.file_name().ok_or(E::InvalidPath)?)
                .map_err(|error| E::Io(error.error))?;
            update_parent(parent, &before, parents)?;
            let mut proof = MigrationProof {
                protocol: "verified_migration".into(),
                source: op.source.clone(),
                destination: NativePath::new(&target),
                target: Stamp::capture(&published)?,
                metadata: MetadataDescription::capture(&staged.metadata()?),
                content,
                capture: capture.clone(),
                source_removed: false,
            };
            result!(proof, OperationState::Published);
            intent!(
                "migration_cleanup",
                json!({"temporary":spec.temporary,"envelope":Stamp::capture(&staged.envelope_info()?)?,"proof":proof})
            );
            checkpoint()?;
            staged
                .retire_envelope()
                .map_err(|error| E::Io(error.error))?;
            update_parent(parent, &before, parents)?;
            result!(proof, OperationState::Published);
            self.validate_migration_source(&approved.plan, op, parents, false)?;
            permit.verify_after(&input)?;
            self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            let mut target_file = platform::open_verified(&target, &platform::inspect(&target)?)?;
            intent!(
                "migration_capture",
                json!({"proof":proof,"capture":capture,"manifest":op.manifest})
            );
            checkpoint()?;
            drop(input);
            self.validate_migration_source(&approved.plan, op, parents, false)?;
            self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            let payload = capture.payload.to_path()?;
            let from = source.parent().ok_or(E::InvalidPath)?;
            let to = payload.parent().ok_or(E::InvalidPath)?;
            let from_before = platform::inspect(from)?;
            let to_before = platform::inspect(to)?;
            let original = platform::inspect(&source)?;
            let _pins = self.validate_scope(&capture, parents)?;
            platform::capture_migration_source(
                &source,
                &original,
                &metadata,
                &payload,
                &from_before,
                &to_before,
            )
            .map_err(|error| E::Io(error.error))?;
            let observed = self.payload_manifest(
                &capture,
                &PlanOptions {
                    include_hidden: true,
                    max_entries: 1,
                    ..Default::default()
                },
            )?;
            crate::quarantine::compare_relocated(&source, &op.manifest, &payload, &observed)?;
            update_parent(from, &from_before, parents)?;
            update_parent(to, &to_before, parents)?;
            self.store
                .as_mut()
                .ok_or(E::StorageRequired)?
                .record_managed_result(
                    &op.id,
                    step,
                    &json!({"proof":proof,"capture":capture,"observed_manifest":observed}),
                    OperationState::Published,
                    |tx| register_retained(tx, op, &capture),
                )
                .inspect_err(|_| journal = true)?;
            #[cfg(test)]
            tests::after_capture();
            let owned = self.payload_permit(&capture)?;
            let captured = platform::inspect(&payload)?;
            let captured_permit = permit.relocated_to_payload(&payload, &captured, &owned)?;
            let captured_check = check(&captured_permit, cancel);
            intent!(
                "migration_commit_verify",
                json!({"proof":proof,"capture":capture})
            );
            let mut captured_file = captured_permit.open()?;
            let captured_metadata = platform::metadata_inventory(&payload, &captured)?;
            if blake3::hash(captured_metadata.portable_bytes())
                .to_hex()
                .as_str()
                != spec.metadata.portable
            {
                return Err(E::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "captured permissions differ from the reviewed source",
                )));
            }
            if source_proof(
                &payload,
                &mut captured_file,
                &captured_metadata,
                length,
                &captured_check,
            )? != proof.content
            {
                return Err(E::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "captured content differs from the verified copy",
                )));
            }
            captured_permit.verify_after(&captured_file)?;
            let target_metadata =
                self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            if source_proof(
                &target,
                &mut target_file,
                &target_metadata,
                length,
                &checkpoint,
            )? != proof.content
            {
                return Err(E::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "published content differs from the verified copy",
                )));
            }
            self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            result!(
                json!({"proof":proof,"capture":capture,"captured_metadata":MetadataDescription::capture(&captured_metadata)}),
                OperationState::Published
            );
            step = "migration_source_remove";
            let remove = json!({"proof":proof,"capture":capture,"captured":Stamp::capture(&captured)?,"captured_metadata":MetadataDescription::capture(&captured_metadata)});
            self.store.as_mut().ok_or(E::StorageRequired)?.record_source_remove_intent(&op.id,step,&remove,|tx| {
                if tx.execute("UPDATE quarantine_items SET state='needs_recovery' WHERE item_id=?1 AND state='stored'",[id_bytes(&op.id)?])?!=1 { return Err(E::StorageUnavailable); } Ok(())
            }).inspect_err(|_|journal=true)?;
            captured_check()?;
            self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            self.validate_scope(&capture, parents)?;
            captured_permit.verify_after(&captured_file)?;
            drop(captured_file);
            if platform::metadata_inventory(&payload, &captured)?.binding_bytes()
                != captured_metadata.binding_bytes()
            {
                return Err(E::ChangedSincePlan);
            }
            let parent_before = platform::inspect(to)?;
            platform::remove_verified(&payload, &captured, &parent_before)
                .map_err(|error| E::Io(error.error))?;
            update_parent(to, &parent_before, parents)?;
            proof.source_removed = true;
            self.store.as_mut().ok_or(E::StorageRequired)?.record_managed_result(&op.id,step,&json!({"removed":true,"proof":proof}),OperationState::SourceRemoveIntent,|tx| {
                if tx.execute("UPDATE quarantine_items SET state='purged' WHERE item_id=?1 AND state='needs_recovery'",[id_bytes(&op.id)?])?!=1 { return Err(E::StorageUnavailable); } Ok(())
            }).inspect_err(|_|journal=true)?;
            intent!("migration_complete", proof);
            self.validate_migration_target(&approved.plan, op, &proof, parents)?;
            result!(proof, OperationState::Done);
            Ok(())
        };
        run().map_err(|error| CopyFailure {
            error,
            created,
            journal,
            step,
        })
    }
    pub(crate) fn prepare_migration_review(
        &self,
        op: &mut PlannedOperation,
        batch: &Id,
        options: &PlanOptions,
        force: bool,
    ) -> Result<()> {
        if op.kind != OperationKind::Move
            || !op.manifest.iter().any(|entry| {
                entry.path == op.source && matches!(entry.kind.as_str(), "Regular" | "Directory")
            })
        {
            return Ok(());
        }
        let source = op.source.to_path()?;
        let dest = op.destination.as_ref().ok_or(E::InvalidPlan)?;
        let parent = dest.existing_parent.to_path()?;
        let source_node = platform::inspect(&source)?;
        let destination_node = platform::inspect(&parent)?;
        let different = source_node
            .identity
            .ok_or(E::UnsupportedSafetyGuarantee)?
            .volume
            != destination_node
                .identity
                .ok_or(E::UnsupportedSafetyGuarantee)?
                .volume
            || platform::classify_location(&source)?.mount_root
                != platform::classify_location(&parent)?.mount_root;
        #[cfg(test)]
        let force = force || tests::force_cross_device();
        if !different && !force {
            return Ok(());
        }
        let metadata = platform::metadata_inventory(&source, &source_node)?;
        platform::check_migration_metadata(&metadata)?;
        let (_, capture) = self.plan_quarantine(&source, batch, &op.id, options)?;
        let target = dest.path.to_path()?;
        op.migration = Some(MigrationScope {
            temporary: NativePath::new(
                &target
                    .parent()
                    .ok_or(E::InvalidPath)?
                    .join(format!(".file-tidy-{}.stage", op.id)),
            ),
            capture,
            metadata: MetadataDescription::capture(&metadata),
            preservation: "native_permissions_and_attached_data".into(),
            acl_inheritance: cfg!(windows).then(|| "preserve_source_rules".into()),
            tree: if source_node.kind == platform::NodeKind::Directory {
                directory::reviewed_entries(op)?
            } else {
                Vec::new()
            },
            source_commit: (source_node.kind == platform::NodeKind::Directory)
                .then(|| "retain_original_tree".into()),
        });
        Ok(())
    }
    pub(crate) fn validate_migration_review(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        parents: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<()> {
        let Some(scope) = &op.migration else {
            return Ok(());
        };
        if op.kind != OperationKind::Move
            || op.managed.is_some()
            || op.permanent.is_some()
            || (scope.tree.is_empty()
                && (op.manifest.len() != 1
                    || op.manifest[0].kind != "Regular"
                    || op.manifest[0].path != op.source))
            || scope.preservation != "native_permissions_and_attached_data"
            || scope.acl_inheritance.as_deref() != cfg!(windows).then_some("preserve_source_rules")
            || scope.source_commit.as_deref()
                != (!scope.tree.is_empty()).then_some("retain_original_tree")
        {
            return Err(E::InvalidPlan);
        }
        let destination = op
            .destination
            .as_ref()
            .ok_or(E::InvalidPlan)?
            .path
            .to_path()?;
        let expected = destination
            .parent()
            .ok_or(E::InvalidPath)?
            .join(format!(".file-tidy-{}.stage", op.id));
        let capture = scope
            .capture
            .root
            .to_path()?
            .join(".file-tidy/quarantine")
            .join(plan.preview.id.as_str())
            .join(op.id.as_str())
            .join("payload");
        if scope.temporary.to_path()? != expected || scope.capture.payload.to_path()? != capture {
            return Err(E::InvalidPlan);
        }
        absent(&expected)?;
        absent(&capture)?;
        self.validate_scope(&scope.capture, parents)?;
        self.migration_source_metadata(op)?;
        if !scope.tree.is_empty() && directory::reviewed_entries(op)? != scope.tree {
            return Err(E::ChangedSincePlan);
        }
        Ok(())
    }
    fn migration_source_metadata(
        &self,
        op: &PlannedOperation,
    ) -> Result<platform::MetadataInventory> {
        let scope = op.migration.as_ref().ok_or(E::InvalidPlan)?;
        let source = op.source.to_path()?;
        let metadata = platform::metadata_inventory(&source, &platform::inspect(&source)?)?;
        platform::check_migration_metadata(&metadata)?;
        if MetadataDescription::capture(&metadata) != scope.metadata {
            return Err(E::ChangedSincePlan);
        }
        Ok(metadata)
    }
    fn validate_migration_source(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        parents: &BTreeMap<PathBuf, Stamp>,
        destination: bool,
    ) -> Result<()> {
        let mut current = op.clone();
        current.migration = None;
        if !destination {
            current.destination = None;
            current.destination_grant = None;
        }
        self.validate_operation(plan, &current, parents)?;
        self.migration_source_metadata(op)?;
        Ok(())
    }
    fn validate_migration_target(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        proof: &MigrationProof,
        parents: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<platform::MetadataInventory> {
        self.validate_plan_context(plan)?;
        let target = proof.destination.to_path()?;
        let parent = checked_existing(target.parent().ok_or(E::InvalidPath)?, false)?;
        let policy = planning_policy()?;
        let labels = policy.labels(&parent);
        if labels.protected || labels.atomic_root.is_some() {
            return Err(E::ProtectedZone);
        }
        if self.grant_for(&parent, &policy)?.id()
            != op.destination_grant.as_ref().ok_or(E::OutsideGrant)?
        {
            return Err(E::OutsideGrant);
        }
        if Stamp::capture(&platform::inspect(&parent)?)?
            != *parents.get(&parent).ok_or(E::InvalidPlan)?
        {
            return Err(E::DestinationConflict);
        }
        for key in destination_acknowledgements(op, &policy)? {
            if !plan.preview.sensitive_acknowledgements.contains(&key) {
                return Err(E::ConfirmationRequired);
            }
        }
        let node = platform::inspect(&checked_existing(&target, true)?)?;
        if Stamp::capture(&node)? != proof.target {
            return Err(E::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "published object stamp changed before source commit",
            )));
        }
        let metadata = platform::metadata_inventory(&target, &node)?;
        if MetadataDescription::capture(&metadata) != proof.metadata {
            return Err(E::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "published metadata version changed before source commit",
            )));
        }
        Ok(metadata)
    }
}

fn absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(E::DestinationConflict),
    }
}
fn check<'a>(
    permit: &'a OperationContentPermit,
    cancel: &'a CancellationToken,
) -> impl Fn() -> std::io::Result<()> + Sync + 'a {
    move || {
        if cancel.is_cancelled() {
            return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        }
        permit.check_live().map_err(std::io::Error::other)
    }
}
fn hash_body(
    file: &mut File,
    length: u64,
    checkpoint: &(impl Fn() -> std::io::Result<()> + Sync),
) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut read = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        checkpoint()?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read = read.checked_add(count as u64).ok_or(E::Overflow)?;
        if read > length {
            return Err(E::ChangedSincePlan);
        }
        hasher.update(&buffer[..count]);
    }
    if read != length {
        return Err(E::ChangedSincePlan);
    }
    Ok(hasher.finalize().to_hex().to_string())
}
fn attached_proof(
    run: impl FnOnce(
        &mut dyn FnMut(platform::MigrationData<'_>) -> std::io::Result<()>,
    ) -> std::io::Result<()>,
) -> Result<Vec<StreamProof>> {
    let mut streams = BTreeMap::<(u32, OsString), StreamProof>::new();
    let mut current: Option<(u32, OsString, u64, u64, blake3::Hasher)> = None;
    let mut sink = |event: platform::MigrationData<'_>| -> std::io::Result<()> {
        match event {
            platform::MigrationData::Begin { kind, name, bytes } => {
                if current.is_some() {
                    return Err(std::io::Error::other("nested attached stream"));
                }
                current = Some((kind, name.to_owned(), bytes, 0, blake3::Hasher::new()));
            }
            platform::MigrationData::Chunk(bytes) => {
                let (_, _, expected, read, hasher) = current
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("unframed attached stream"))?;
                *read = read
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| std::io::Error::other("stream size overflow"))?;
                if *read > *expected {
                    return Err(std::io::Error::other("attached stream grew"));
                }
                hasher.update(bytes);
            }
            platform::MigrationData::End => {
                let (kind, name, expected, read, hasher) = current
                    .take()
                    .ok_or_else(|| std::io::Error::other("unframed attached stream end"))?;
                if read != expected
                    || streams
                        .insert(
                            (kind, name.clone()),
                            StreamProof {
                                kind,
                                name: NativePath::new(Path::new(&name)),
                                bytes: read.to_string(),
                                blake3: hasher.finalize().to_hex().to_string(),
                            },
                        )
                        .is_some()
                {
                    return Err(std::io::Error::other(
                        "changed or duplicate attached stream",
                    ));
                }
            }
        }
        Ok(())
    };
    run(&mut sink)?;
    if current.is_some() {
        return Err(E::ChangedSincePlan);
    }
    Ok(streams.into_values().collect())
}
fn source_proof(
    path: &Path,
    file: &mut File,
    metadata: &platform::MetadataInventory,
    length: u64,
    checkpoint: &(impl Fn() -> std::io::Result<()> + Sync),
) -> Result<ContentProof> {
    let blake3 = hash_body(file, length, checkpoint)?;
    let attached = attached_proof(|sink| {
        platform::visit_migration_data(path, file, metadata, checkpoint, &mut |event| sink(event))
    })?;
    Ok(ContentProof {
        length: length.to_string(),
        blake3,
        attached,
    })
}

pub(crate) fn completed_proof(
    op: &PlannedOperation,
    history: &crate::journal::BatchHistoryDetail,
) -> Result<Option<MigrationProof>> {
    let recorded = history
        .operations
        .iter()
        .find(|record| record.id == op.id.as_str())
        .ok_or(E::StorageUnavailable)?;
    let Some(value) = &recorded.after_fingerprint else {
        return Ok(None);
    };
    if value.get("protocol").and_then(|v| v.as_str()) != Some("verified_migration") {
        return Ok(None);
    }
    let proof: MigrationProof = serde_json::from_value(value.clone())?;
    let scope = op.migration.as_ref().ok_or(E::StorageUnavailable)?;
    if recorded.state != OperationState::Done
        || op.kind != OperationKind::Move
        || op.manifest.len() != 1
        || proof.source != op.source
        || proof.destination != op.destination.as_ref().ok_or(E::StorageUnavailable)?.path
        || !proof.source_removed
        || proof.capture.payload != scope.capture.payload
        || proof.capture.root != scope.capture.root
        || proof.capture.identity != scope.capture.identity
        || proof.metadata.portable != scope.metadata.portable
        || proof.metadata.attributes != scope.metadata.attributes
        || proof.content.length != op.manifest[0].size_bytes
        || !hash_valid(&proof.content.blake3)
        || proof.content.attached.len() > 65536
        || proof
            .content
            .attached
            .iter()
            .any(|part| !hash_valid(&part.blake3) || part.bytes.parse::<u64>().is_err())
    {
        return Err(E::StorageUnavailable);
    }
    Ok(Some(proof))
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationObservation {
    Absent,
    MatchesMetadata,
    MatchesIdentity,
    Changed,
    DifferentObject,
    Unrecorded,
}
#[derive(Debug, Serialize)]
pub struct MigrationProgress {
    pub original_source: MigrationObservation,
    pub destination: MigrationObservation,
    pub temporary: MigrationObservation,
    pub retained_source: MigrationObservation,
    pub retained_path: NativePath,
    pub retained_state: Option<String>,
    pub source_remove_confirmed: bool,
    pub source_remove_unconfirmed: bool,
    pub content_verification_required: bool,
    pub disposition: crate::recovery::RecoveryDisposition,
    pub reason: String,
}
impl Session {
    pub(crate) fn migration_started(&self, op: &PlannedOperation) -> Result<bool> {
        if op.migration.is_none() {
            return Ok(false);
        }
        self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db|{
            Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM operation_events WHERE op_id=?1 AND step='migration_begin' AND phase='intent')",[id_bytes(&op.id)?],|row|row.get(0))?)
        })
    }
    pub(crate) fn inspect_migration_progress(
        &self,
        op: &PlannedOperation,
    ) -> Result<MigrationProgress> {
        if op
            .migration
            .as_ref()
            .is_some_and(|scope| !scope.tree.is_empty())
        {
            return self.inspect_directory_migration_progress(op);
        }
        use crate::recovery::RecoveryDisposition as D;
        let scope = op.migration.as_ref().ok_or(E::StorageUnavailable)?;
        let destination = op.destination.as_ref().ok_or(E::StorageUnavailable)?;
        let policy = planning_policy()?;
        if self
            .grant_for(&scope.capture.root.to_path()?, &policy)?
            .id()
            != op.source_grant.as_ref().ok_or(E::OutsideGrant)?
            || self
                .grant_for(&destination.existing_parent.to_path()?, &policy)?
                .id()
                != op.destination_grant.as_ref().ok_or(E::OutsideGrant)?
        {
            return Err(E::OutsideGrant);
        }
        let (events,retained_state)=self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
            let mut query=db.prepare("SELECT event_id,step,phase,payload FROM operation_events WHERE op_id=?1 AND step LIKE 'migration_%' ORDER BY event_id LIMIT 65")?;
            let mut rows=query.query([id_bytes(&op.id)?])?;
            let mut events=Vec::new();let mut total=0usize;
            while let Some(row)=rows.next()? {
                let bytes:Vec<u8>=row.get(3)?;
                total=total.checked_add(bytes.len()).ok_or(E::Overflow)?;
                if bytes.len()>64*1024*1024 || total>192*1024*1024 { return Err(E::Overflow); }
                let event_id=row.get::<_,i64>(0)?;
                if event_id<0 {return Err(E::StorageUnavailable);}
                events.push((event_id,row.get::<_,String>(1)?,row.get::<_,String>(2)?,serde_json::from_slice::<serde_json::Value>(&bytes)?));
            }
            if events.len()>64 { return Err(E::StorageUnavailable); }
            let state=db.query_row("SELECT state FROM quarantine_items WHERE item_id=?1 AND op_id=?1",[id_bytes(&op.id)?],|row|row.get::<_,String>(0)).optional()?;
            Ok((events,state))
        })?;
        let publication = events.iter().rev().find(|(_, step, phase, value)| {
            step == "migration_publish"
                && phase == "result"
                && value.get("protocol").and_then(|v| v.as_str()) == Some("verified_migration")
        });
        let proof = publication
            .map(|(_, _, _, value)| serde_json::from_value::<MigrationProof>(value.clone()))
            .transpose()?;
        if let Some(proof) = &proof
            && (proof.source != op.source
                || proof.destination != destination.path
                || proof.capture.payload != scope.capture.payload
                || proof.capture.root != scope.capture.root
                || proof.capture.identity != scope.capture.identity
                || proof.metadata.portable != scope.metadata.portable)
        {
            return Err(E::StorageUnavailable);
        }
        let mut prepared = proof.as_ref().map(|p| p.capture.clone());
        if prepared.is_none() {
            prepared = events
                .iter()
                .rev()
                .find(|(_, step, phase, _)| step == "migration_capture" && phase == "intent")
                .and_then(|(_, _, _, value)| value.get("capture"))
                .map(|value| serde_json::from_value(value.clone()))
                .transpose()?;
        }
        if let Some(prepared) = &prepared {
            if prepared.payload != scope.capture.payload
                || prepared.root != scope.capture.root
                || prepared.identity != scope.capture.identity
            {
                return Err(E::StorageUnavailable);
            }
            self.payload_permit(prepared)?;
        }
        let original = op
            .manifest
            .iter()
            .find(|entry| entry.path == op.source)
            .ok_or(E::StorageUnavailable)?;
        let source = op.source.to_path()?;
        let original_source =
            observe(&source, Some(&original.stamp), Some(&scope.metadata), false)?;
        let target = destination.path.to_path()?;
        let destination = observe(
            &target,
            proof.as_ref().map(|proof| &proof.target),
            proof.as_ref().map(|proof| &proof.metadata),
            false,
        )?;
        let envelope = events
            .iter()
            .find(|(_, step, phase, value)| {
                step == "migration_create" && phase == "result" && value.get("envelope").is_some()
            })
            .and_then(|(_, _, _, value)| value.get("envelope"))
            .map(|value| serde_json::from_value::<Stamp>(value.clone()))
            .transpose()?;
        let temporary = observe(&scope.temporary.to_path()?, envelope.as_ref(), None, true)?;
        if matches!(
            temporary,
            MigrationObservation::MatchesIdentity | MigrationObservation::MatchesMetadata
        ) {
            let node = platform::inspect(&scope.temporary.to_path()?)?;
            let pin = platform::open_directory_pinned(&scope.temporary.to_path()?, &node)?;
            platform::verify_private_file(&pin.try_clone_file()?, true)?;
        }
        let retained_source = observe(
            &scope.capture.payload.to_path()?,
            prepared.as_ref().map(|_| &original.stamp),
            None,
            true,
        )?;
        let source_remove_confirmed = events.iter().any(|(_, step, phase, value)| {
            step == "migration_source_remove"
                && phase == "result"
                && value.get("removed").and_then(|v| v.as_bool()) == Some(true)
        });
        let source_remove_unconfirmed = !source_remove_confirmed
            && events
                .iter()
                .any(|(_, step, phase, _)| step == "migration_source_remove" && phase == "intent");
        let changed = [original_source, destination, temporary, retained_source]
            .iter()
            .any(|value| {
                matches!(
                    value,
                    MigrationObservation::Changed
                        | MigrationObservation::DifferentObject
                        | MigrationObservation::Unrecorded
                )
            });
        let reason = if changed {
            "migration_objects_require_review"
        } else if source_remove_confirmed {
            "migration_source_removal_recorded"
        } else if source_remove_unconfirmed {
            "migration_source_removal_unconfirmed"
        } else if retained_source == MigrationObservation::MatchesIdentity {
            "migration_original_retained"
        } else if proof.is_some() {
            "migration_copy_published_source_not_committed"
        } else {
            "migration_source_commit_not_started"
        };
        Ok(MigrationProgress {
            original_source,
            destination,
            temporary,
            retained_source,
            retained_path: scope.capture.payload.clone(),
            retained_state,
            source_remove_confirmed,
            source_remove_unconfirmed,
            content_verification_required: true,
            disposition: if changed {
                D::NeedsAttention
            } else {
                D::MigrationProgressObserved
            },
            reason: reason.into(),
        })
    }
}
fn observe(
    path: &Path,
    expected: Option<&Stamp>,
    metadata: Option<&MetadataDescription>,
    identity_only: bool,
) -> Result<MigrationObservation> {
    let checked = match checked_existing(path, true) {
        Ok(path) => path,
        Err(E::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MigrationObservation::Absent);
        }
        Err(error) => return Err(error),
    };
    let node = platform::inspect(&checked)?;
    let Some(expected) = expected else {
        return Ok(MigrationObservation::Unrecorded);
    };
    if !expected.same_identity(&node) {
        return Ok(MigrationObservation::DifferentObject);
    }
    if identity_only {
        return Ok(MigrationObservation::MatchesIdentity);
    }
    if Stamp::capture(&node)? != *expected {
        return Ok(MigrationObservation::Changed);
    }
    if let Some(expected) = metadata
        && MetadataDescription::capture(&platform::metadata_inventory(path, &node)?) != *expected
    {
        return Ok(MigrationObservation::Changed);
    }
    Ok(MigrationObservation::MatchesMetadata)
}
impl Session {
    pub(crate) fn verify_migration_undo_metadata(&self, proof: &MigrationProof) -> Result<()> {
        let target = checked_existing(&proof.destination.to_path()?, true)?;
        let info = platform::inspect(&target)?;
        let metadata = MetadataDescription::capture(&platform::metadata_inventory(&target, &info)?);
        if Stamp::capture(&info)? != proof.target
            || metadata.portable != proof.metadata.portable
            || metadata.attributes != proof.metadata.attributes
            || metadata.native_flags != proof.metadata.native_flags
        {
            return Err(E::ChangedSincePlan);
        }
        Ok(())
    }
    pub(crate) fn verify_inverse_migration_content(
        &self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if op.inverse.is_some() {
            let (original, history) = self.inverse_original(op)?;
            if let Some(proof) = directory::completed_directory_proof(&original, &history)? {
                return self
                    .verify_directory_migration_inverse_content(approved, op, &proof, cancel);
            }
        }
        if op.kind != OperationKind::Move || op.inverse.is_none() {
            return Ok(());
        }
        let (original, history) = self.inverse_original(op)?;
        let Some(proof) = completed_proof(&original, &history)? else {
            return Ok(());
        };
        self.verify_migration_undo_metadata(&proof)?;
        let permit = OperationContentPermit::issue(self, approved, op)?;
        let mut file = permit.open()?;
        let path = op.source.to_path()?;
        let metadata = self.migration_source_metadata(op)?;
        if source_proof(
            &path,
            &mut file,
            &metadata,
            proof
                .content
                .length
                .parse()
                .map_err(|_| E::StorageUnavailable)?,
            &check(&permit, cancel),
        )? != proof.content
        {
            return Err(E::ChangedSincePlan);
        }
        permit.verify_after(&file)?;
        self.verify_migration_undo_metadata(&proof)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::approval::Confirmation;
    use crate::execution::ExecutionStatus;
    use std::cell::{Cell, RefCell};
    thread_local! { static FORCE:Cell<bool>=const {Cell::new(false)}; static AFTER_CAPTURE:RefCell<Option<Box<dyn FnOnce()>>>=RefCell::new(None); }
    pub(crate) fn force_cross_device() -> bool {
        FORCE.with(Cell::get)
    }
    pub(super) fn after_capture() {
        if let Some(hook) = AFTER_CAPTURE.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
    }
    struct Forced;
    impl Forced {
        fn new() -> Self {
            FORCE.with(|flag| flag.set(true));
            Self
        }
    }
    impl Drop for Forced {
        fn drop(&mut self) {
            FORCE.with(|flag| flag.set(false));
            AFTER_CAPTURE.with(|hook| {
                hook.borrow_mut().take();
            });
        }
    }
    fn fixture()
    -> std::result::Result<(tempfile::TempDir, PathBuf, Session), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir_in(
            std::env::var_os("FILE_TIDY_TEST_ROOT").ok_or("FILE_TIDY_TEST_ROOT required")?,
        )?;
        let root = directory.path().canonicalize()?;
        let mut session = Session::new()?;
        let grant = session.grant(&root, false)?;
        let storage = session.storage_plan(&grant)?;
        let digest = storage.digest().to_owned();
        session.initialize_storage(storage, &digest)?;
        Ok((directory, root, session))
    }
    fn confirm(session: &mut Session, plan: Plan) -> Result<ApprovedPlan> {
        let input = Confirmation {
            digest: plan.digest().to_owned(),
            sensitive_acknowledgements: plan.preview.sensitive_acknowledgements.clone(),
            item_count: plan
                .preview
                .requires_count_confirmation
                .then_some(plan.preview.confirmation_count),
            ..Default::default()
        };
        session.confirm(plan, input)
    }
    fn plan(session: &Session, source: &Path, target: &Path) -> Result<Plan> {
        session.build_plan(
            vec![crate::plan::OperationRequest {
                kind: OperationKind::Move,
                source: source.into(),
                destination: Some(target.into()),
            }],
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )
    }
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn migration_commits_verified_content_and_undo_uses_a_new_confirmation() -> TestResult {
        let _force = Forced::new();
        let (_fixture, root, mut session) = fixture()?;
        let source = root.join(".env");
        let target = root.join("moved");
        let body = vec![37u8; 150000];
        std::fs::write(&source, &body)?;
        #[cfg(target_os = "macos")]
        std::fs::write(source.join("..namedfork/rsrc"), b"migration-resource-fork")?;
        #[cfg(windows)]
        {
            let mut stream = source.as_os_str().to_os_string();
            stream.push(":file_tidy");
            std::fs::write(PathBuf::from(stream), b"migration-named-stream")?;
        }
        let preview = plan(&session, &source, &target)?;
        assert!(preview.preview.operations[0].migration.is_some());
        assert!(!target.exists());
        let incomplete = Confirmation {
            digest: preview.digest().to_owned(),
            ..Default::default()
        };
        assert!(session.confirm(preview, incomplete).is_err());
        let preview = plan(&session, &source, &target)?;
        let approved = confirm(&mut session, preview)?;
        let original = approved.preview().id.clone();
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        assert!(!source.exists());
        assert_eq!(std::fs::read(&target)?, body);
        let retained = session.quarantine_items(10, false)?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].state, "purged");
        let modified = platform::inspect(&target)?
            .modified
            .ok_or("missing modification time")?;
        let corrupt = vec![93u8; body.len()];
        std::fs::write(&target, &corrupt)?;
        File::options()
            .write(true)
            .open(&target)?
            .set_times(std::fs::FileTimes::new().set_modified(modified))?;
        let tampered = session.build_undo_plan(
            &original,
            &[],
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )?;
        let temporary = tampered.preview.operations[0]
            .migration
            .as_ref()
            .ok_or("missing inverse migration")?
            .temporary
            .to_path()?;
        let approved = confirm(&mut session, tampered)?;
        let rejected = session.execute_approved(approved, &CancellationToken::new())?;
        assert_eq!(
            rejected.operations[0].status,
            ExecutionStatus::Failed,
            "{rejected:?}"
        );
        assert!(!temporary.exists() && !source.exists());
        assert_eq!(std::fs::read(&target)?, corrupt);
        std::fs::write(&target, &body)?;
        File::options()
            .write(true)
            .open(&target)?
            .set_times(std::fs::FileTimes::new().set_modified(modified))?;
        let inverse = session
            .build_undo_plan(
                &original,
                &[],
                PlanOptions {
                    include_hidden: true,
                    ..Default::default()
                },
            )
            .map_err(|error| format!("build migration undo: {error}"))?;
        assert!(
            inverse
                .preview
                .sensitive_acknowledgements
                .iter()
                .any(|key| key.ends_with(":content"))
        );
        let approved = confirm(&mut session, inverse)?;
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        assert_eq!(std::fs::read(&source)?, body);
        assert!(!target.exists());
        #[cfg(target_os = "macos")]
        assert_eq!(
            std::fs::read(source.join("..namedfork/rsrc"))?,
            b"migration-resource-fork"
        );
        Ok(())
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn cancelled_migration_retains_the_captured_original_for_reviewed_restoration() -> TestResult {
        let _force = Forced::new();
        let (_fixture, root, mut session) = fixture()?;
        let source = root.join("source");
        let target = root.join("target");
        std::fs::write(&source, b"original")?;
        let preview = plan(&session, &source, &target)?;
        let item = preview.preview.operations[0].id.clone();
        let approved = confirm(&mut session, preview)?;
        let cancellation = CancellationToken::new();
        let token = cancellation.clone();
        AFTER_CAPTURE.with(|hook| *hook.borrow_mut() = Some(Box::new(move || token.cancel())));
        let report = session.execute_approved(approved, &cancellation)?;
        assert_eq!(
            report.operations[0].status,
            ExecutionStatus::NeedsRecovery,
            "{report:?}"
        );
        assert!(!source.exists());
        assert_eq!(std::fs::read(&target)?, b"original");
        let retained = session.quarantine_items(10, false)?;
        assert_eq!(retained[0].id, item);
        assert_eq!(
            std::fs::read(retained[0].storage_path.to_path()?)?,
            b"original"
        );
        let recovery = session.recovery_report(Some(&report.batch_id), 10)?;
        assert_eq!(
            recovery.items[0].disposition,
            crate::recovery::RecoveryDisposition::MigrationProgressObserved
        );
        let progress = recovery.items[0]
            .migration
            .as_ref()
            .ok_or("missing migration progress")?;
        assert_eq!(
            progress.retained_source,
            MigrationObservation::MatchesIdentity
        );
        assert!(!progress.source_remove_confirmed && !progress.source_remove_unconfirmed);
        let restore = session.build_restore_plan(&[item], None, PlanOptions::default())?;
        let approved = confirm(&mut session, restore)?;
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        assert_eq!(std::fs::read(&source)?, b"original");
        Ok(())
    }

    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn source_removal_result_failure_is_reported_as_unconfirmed_without_writes() -> TestResult {
        let _force = Forced::new();
        let (_fixture, root, mut session) = fixture()?;
        let source = root.join("source");
        let target = root.join("target");
        std::fs::write(&source, b"verified-original")?;
        let preview = plan(&session, &source, &target)?;
        let payload = preview.preview.operations[0]
            .migration
            .as_ref()
            .ok_or("no migration")?
            .capture
            .payload
            .to_path()?;
        let approved = confirm(&mut session, preview)?;
        let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
        db.execute_batch("CREATE TRIGGER reject_source_removal_result BEFORE INSERT ON operation_events WHEN NEW.step='migration_source_remove' AND NEW.phase='result' BEGIN SELECT RAISE(ABORT,'injected source result failure'); END;")?;
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.journal_error.is_some(), "{report:?}");
        assert!(!source.exists() && !payload.exists());
        assert_eq!(std::fs::read(&target)?, b"verified-original");
        let before: i64 = db.query_row("SELECT count(*) FROM operation_events", [], |row| {
            row.get(0)
        })?;
        let recovery = session.recovery_report(Some(&report.batch_id), 10)?;
        let progress = recovery.items[0]
            .migration
            .as_ref()
            .ok_or("missing migration progress")?;
        assert!(progress.source_remove_unconfirmed);
        assert!(!progress.source_remove_confirmed);
        assert_eq!(progress.retained_source, MigrationObservation::Absent);
        assert_eq!(progress.destination, MigrationObservation::MatchesMetadata);
        let after: i64 = db.query_row("SELECT count(*) FROM operation_events", [], |row| {
            row.get(0)
        })?;
        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT and two local volumes"]
    fn migration_uses_the_native_cross_device_error_between_windows_volumes() -> TestResult {
        use std::io::Write;
        let (_fixture, root, mut session) = fixture()?;
        let base = directories::BaseDirs::new().ok_or("profile unavailable")?;
        let volume_root = base
            .cache_dir()
            .ancestors()
            .last()
            .ok_or("volume root unavailable")?;
        let outer = tempfile::Builder::new()
            .prefix("file-tidy-cross-")
            .tempdir_in(volume_root)?;
        let outer_path = outer.path().canonicalize()?;
        let outer_pin =
            platform::open_directory_pinned(&outer_path, &platform::inspect(&outer_path)?)?;
        let source_root_file =
            platform::create_private_directory(&outer_pin, "source-grant".as_ref())?;
        let source_root = outer_path.join("source-grant");
        let source_pin = platform::open_directory_pinned(
            &source_root,
            &platform::inspect_file(&source_root_file)?,
        )?;
        let mut source_file = platform::create_private_file(&source_pin, ".env".as_ref())?;
        let body = vec![71u8; 90003];
        source_file.write_all(&body)?;
        source_file.sync_all()?;
        drop(source_file);
        let source = source_root.join(".env");
        let target = root.join("moved");
        let source_volume = platform::inspect(&source)?
            .identity
            .ok_or("source identity unavailable")?
            .volume;
        let target_volume = platform::inspect(&root)?
            .identity
            .ok_or("target identity unavailable")?
            .volume;
        if source_volume == target_volume && std::env::var_os("GITHUB_ACTIONS").is_none() {
            return Ok(());
        }
        assert_ne!(
            source_volume, target_volume,
            "CI needs distinct local volumes"
        );
        let mut stream = source.as_os_str().to_os_string();
        stream.push(":file_tidy");
        std::fs::write(PathBuf::from(stream), b"cross-device-stream")?;
        session.grant(&source_root, false)?;
        let preview = plan(&session, &source, &target)?;
        assert!(preview.preview.operations[0].migration.is_some());
        let approved = confirm(&mut session, preview)?;
        let batch = approved.preview().id.clone();
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        assert!(!source.exists());
        assert_eq!(std::fs::read(&target)?, body);
        let history = session.batch_history(&batch)?;
        assert!(history.events.iter().any(|event| {
            event.step == "rename"
                && event.phase == "result"
                && event
                    .payload
                    .get("cross_device")
                    .and_then(|value| value.as_bool())
                    == Some(true)
        }));
        let inverse = session.build_undo_plan(
            &batch,
            &[],
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )?;
        let approved = confirm(&mut session, inverse)?;
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        assert_eq!(std::fs::read(&source)?, body);
        assert!(!target.exists());
        Ok(())
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn directory_migration_retains_original_objects_and_undo_restores_their_identity()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let _forced = Forced::new();
        let (_fixture, root, mut session) = fixture()?;
        let source = root.join("source");
        let target = root.join("target");
        std::fs::create_dir_all(source.join("nested/empty"))?;
        std::fs::write(source.join("nested/.env"), vec![23u8; 131173])?;
        std::fs::hard_link(source.join("nested/.env"), source.join("alias"))?;
        std::fs::hard_link(source.join("nested/.env"), root.join("external-alias"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("missing", source.join("dangling"))?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file("missing", source.join("dangling"))?;
        #[cfg(target_os = "macos")]
        assert!(
            std::process::Command::new("/usr/bin/xattr")
                .args(["-w", "com.file-tidy.directory-core", "directory-attached"])
                .arg(&source)
                .status()?
                .success()
        );
        #[cfg(windows)]
        {
            let mut name = source.as_os_str().to_os_string();
            name.push(":directory_core");
            std::fs::write(PathBuf::from(name), b"directory-attached")?;
        }
        let original = platform::inspect(&source)?;
        let original_leaf = platform::inspect(&source.join("nested/.env"))?;
        let preview = plan(&session, &source, &target)?;
        let scope = preview.preview.operations[0]
            .migration
            .as_ref()
            .ok_or("missing tree migration")?;
        assert_eq!(
            scope.tree.len(),
            preview.preview.operations[0].manifest.len()
        );
        #[cfg(any(target_os = "macos", windows))]
        assert!(scope.opaque_bytes()? > 0);
        let no_content = preview
            .preview
            .sensitive_acknowledgements
            .iter()
            .filter(|k| !k.ends_with(":content"))
            .cloned()
            .collect();
        let confirmation = Confirmation {
            digest: preview.digest().into(),
            sensitive_acknowledgements: no_content,
            ..Default::default()
        };
        assert!(session.confirm(preview, confirmation).is_err());
        let preview = plan(&session, &source, &target)?;
        let approved = confirm(&mut session, preview)?;
        let batch = approved.preview().id.clone();
        let result = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(result.completed(), "{result:?}");
        assert!(!source.exists());
        assert_eq!(
            std::fs::read(target.join("nested/.env"))?,
            vec![23u8; 131173]
        );
        assert_eq!(
            platform::inspect(&target.join("nested/.env"))?.identity,
            platform::inspect(&target.join("alias"))?.identity
        );
        assert_ne!(
            original_leaf.identity,
            platform::inspect(&target.join("alias"))?.identity
        );
        let retained = session.quarantine_items(10, false)?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].state, "stored");
        let payload = retained[0].storage_path.to_path()?;
        assert_eq!(platform::inspect(&payload)?.identity, original.identity);
        assert_eq!(
            platform::inspect(&payload.join("nested/.env"))?.identity,
            original_leaf.identity
        );
        let undo = session.build_undo_plan(
            &batch,
            &[],
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )?;
        assert_eq!(undo.preview.operations.len(), 2);
        let approved = confirm(&mut session, undo)?;
        let result = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(result.completed(), "{result:?}");
        assert!(!target.exists());
        assert_eq!(platform::inspect(&source)?.identity, original.identity);
        assert_eq!(
            platform::inspect(&source.join("nested/.env"))?.identity,
            platform::inspect(&root.join("external-alias"))?.identity
        );
        assert_eq!(
            std::fs::read_link(source.join("dangling"))?,
            PathBuf::from("missing")
        );
        Ok(())
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn interrupted_directory_migration_reports_and_restores_the_retained_original()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let _forced = Forced::new();
        let (_fixture, root, mut session) = fixture()?;
        let source = root.join("source");
        let target = root.join("target");
        std::fs::create_dir(&source)?;
        std::fs::write(source.join("data"), b"original")?;
        let original = platform::inspect(&source)?;
        let preview = plan(&session, &source, &target)?;
        let approved = confirm(&mut session, preview)?;
        let batch = approved.preview().id.clone();
        let cancel = CancellationToken::new();
        let signal = cancel.clone();
        AFTER_CAPTURE.with(|h| *h.borrow_mut() = Some(Box::new(move || signal.cancel())));
        let result = session.execute_approved(approved, &cancel)?;
        assert!(!result.completed());
        let before = session.batch_history(&batch)?;
        let recovery = session.recovery_report(Some(&batch), 10)?;
        assert_eq!(recovery.items.len(), 1);
        assert!(recovery.items[0].migration.is_some());
        assert_eq!(
            serde_json::to_value(session.batch_history(&batch)?)?,
            serde_json::to_value(before)?
        );
        let retained = session.quarantine_items(10, false)?;
        assert_eq!(retained.len(), 1);
        let restore = session.build_restore_plan(
            &[retained[0].id.clone()],
            None,
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )?;
        let approved = confirm(&mut session, restore)?;
        let result = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(result.completed(), "{result:?}");
        assert_eq!(platform::inspect(&source)?.identity, original.identity);
        assert_eq!(std::fs::read(source.join("data"))?, b"original");
        assert!(target.exists());
        Ok(())
    }
    #[test]
    #[cfg(windows)]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT and two local volumes"]
    fn directory_migration_uses_native_windows_volumes_and_restores_the_original_tree() -> TestResult
    {
        let (_fixture, root, mut session) = fixture()?;
        let base = directories::BaseDirs::new().ok_or("profile unavailable")?;
        let volume_root = base
            .cache_dir()
            .ancestors()
            .last()
            .ok_or("volume root unavailable")?;
        let outer = tempfile::Builder::new()
            .prefix("file-tidy-tree-cross-")
            .tempdir_in(volume_root)?;
        let outer_path = outer.path().canonicalize()?;
        let outer_pin =
            platform::open_directory_pinned(&outer_path, &platform::inspect(&outer_path)?)?;
        let source_root_file =
            platform::create_private_directory(&outer_pin, "source-grant".as_ref())?;
        let source_grant = outer_path.join("source-grant");
        drop(source_root_file);
        let source = source_grant.join("source");
        std::fs::create_dir(&source)?;
        let target = root.join("target");
        std::fs::write(source.join("data"), b"native-directory-migration")?;
        std::fs::hard_link(source.join("data"), source.join("alias"))?;
        let original = platform::inspect(&source)?;
        let leaf = platform::inspect(&source.join("data"))?;
        if original.identity.ok_or("source ID missing")?.volume
            == platform::inspect(&root)?
                .identity
                .ok_or("target ID missing")?
                .volume
        {
            assert!(
                std::env::var_os("GITHUB_ACTIONS").is_none(),
                "CI needs distinct local volumes"
            );
            return Ok(());
        }
        session.grant(&source_grant, false)?;
        let preview = plan(&session, &source, &target)?;
        let approved = confirm(&mut session, preview)?;
        let batch = approved.preview().id.clone();
        let result = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(result.completed(), "{result:?}");
        let history = session.batch_history(&batch)?;
        assert!(history.events.iter().any(|e| e.step == "rename"
            && e.phase == "result"
            && e.payload.get("cross_device").and_then(|v| v.as_bool()) == Some(true)));
        let inverse = session.build_undo_plan(
            &batch,
            &[],
            PlanOptions {
                include_hidden: true,
                ..Default::default()
            },
        )?;
        let approved = confirm(&mut session, inverse)?;
        let result = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(result.completed(), "{result:?}");
        assert_eq!(platform::inspect(&source)?.identity, original.identity);
        assert_eq!(
            platform::inspect(&source.join("alias"))?.identity,
            leaf.identity
        );
        assert!(!target.exists());
        Ok(())
    }
}
