//! Reviewed tree transfers retain the original objects for restoration.
use super::*;
use crate::plan::{ManifestEntry, OperationRequest};
use crate::quarantine::{ManagedOperation, retain_sensitivity};
use crate::undo::InverseReference;
use std::collections::{BTreeSet, HashMap};

fn live<'a>(
    approved: &ApprovedPlan,
    cancel: &'a CancellationToken,
) -> impl Fn() -> std::io::Result<()> + Sync + 'a {
    let expires = approved.preview().expires_at;
    move || {
        crate::copy::checkpoint(cancel).map_err(std::io::Error::other)?;
        if crate::plan::now().map_err(std::io::Error::other)? >= expires {
            return Err(std::io::Error::other("migration confirmation expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewedEntry {
    relative: NativePath,
    metadata: MetadataDescription,
}

pub(crate) fn completed_directory_proof(
    op: &PlannedOperation,
    history: &crate::journal::BatchHistoryDetail,
) -> Result<Option<DirectoryProof>> {
    let recorded = history
        .operations
        .iter()
        .find(|r| r.id == op.id.as_str())
        .ok_or(E::StorageUnavailable)?;
    let Some(value) = &recorded.after_fingerprint else {
        return Ok(None);
    };
    if value.get("protocol").and_then(|v| v.as_str()) != Some("verified_directory_migration") {
        return Ok(None);
    }
    let proof: DirectoryProof = serde_json::from_value(value.clone())?;
    let scope = op.migration.as_ref().ok_or(E::StorageUnavailable)?;
    if recorded.state != OperationState::Done
        || proof.source != op.source
        || proof.destination != op.destination.as_ref().ok_or(E::StorageUnavailable)?.path
        || proof.capture.payload != scope.capture.payload
        || proof.capture.root != scope.capture.root
        || proof.capture.identity != scope.capture.identity
        || proof.target.len() != op.manifest.len()
        || proof.retained.len() != op.manifest.len()
        || scope.tree.len() != op.manifest.len()
    {
        return Err(E::StorageUnavailable);
    }
    same_values(&proof.retained, &proof.target).map_err(|_| E::StorageUnavailable)?;
    let ordered = ordered(op)?;
    for (((a, b), reviewed), (relative, entry)) in proof
        .target
        .iter()
        .zip(&proof.retained)
        .zip(&scope.tree)
        .zip(ordered)
    {
        let old_path = entry.path.to_path()?;
        let new_path = proof.capture.payload.to_path()?.join(&relative);
        let hidden = |p: &Path| {
            p.file_name()
                .is_some_and(|n| n.as_encoded_bytes().first() == Some(&b'.'))
        };
        if a.relative != reviewed.relative
            || a.relative != NativePath::new(&relative)
            || a.kind != entry.kind
            || a.length != entry.size_bytes
            || a.link_target != entry.link_target
            || a.symlink_directory != entry.symlink_directory
            || a.body.is_some() != (entry.kind == "Regular")
            || !entry
                .stamp
                .matches_relocated(&b.stamp, hidden(&old_path) != hidden(&new_path))
            || a.metadata.portable != reviewed.metadata.portable
            || b.metadata.portable != reviewed.metadata.portable
            || a.body.as_ref().is_some_and(|h| !hash_valid(h))
            || a.attached
                .iter()
                .any(|p| !hash_valid(&p.blake3) || p.bytes.parse::<u64>().is_err())
        {
            return Err(E::StorageUnavailable);
        }
    }
    Ok(Some(proof))
}
pub(crate) fn target_stamps(value: &serde_json::Value) -> Result<Vec<Stamp>> {
    let proof: DirectoryProof = serde_json::from_value(value.clone())?;
    Ok(proof.target.into_iter().map(|entry| entry.stamp).collect())
}

impl Session {
    pub(crate) fn inspect_directory_migration_progress(
        &self,
        op: &PlannedOperation,
    ) -> Result<MigrationProgress> {
        let scope = op.migration.as_ref().ok_or(E::StorageUnavailable)?;
        let dest = op.destination.as_ref().ok_or(E::StorageUnavailable)?;
        let policy = planning_policy()?;
        if self
            .grant_for(&scope.capture.root.to_path()?, &policy)?
            .id()
            != op.source_grant.as_ref().ok_or(E::OutsideGrant)?
            || self
                .grant_for(&dest.existing_parent.to_path()?, &policy)?
                .id()
                != op.destination_grant.as_ref().ok_or(E::OutsideGrant)?
        {
            return Err(E::OutsideGrant);
        }
        let (events,retained_state)=self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db|{
            let mut query=db.prepare("SELECT step,phase,payload FROM operation_events WHERE op_id=?1 AND step IN ('migration_create','migration_publish','migration_capture','migration_commit_verify','migration_complete') ORDER BY event_id LIMIT 17")?;
            let rows=query.query_map([id_bytes(&op.id)?],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if rows.len()>16 {return Err(E::StorageUnavailable);}
            let mut total=0usize;
            let mut events=Vec::new();
            for (step,phase,bytes) in rows {
                total=total.checked_add(bytes.len()).ok_or(E::Overflow)?;
                if bytes.len()>64*1024*1024 || total>192*1024*1024 {return Err(E::Overflow);}
                events.push((step,phase,serde_json::from_slice::<serde_json::Value>(&bytes)?));
            }
            let state=db.query_row("SELECT state FROM quarantine_items WHERE item_id=?1",[id_bytes(&op.id)?],|row|row.get::<_,String>(0)).optional()?;
            Ok((events,state))
        })?;
        let proof = events
            .iter()
            .rev()
            .filter(|(_, phase, _)| phase == "result")
            .find_map(|(_, _, v)| {
                let v = v.get("proof").unwrap_or(v);
                (v.get("protocol").and_then(|p| p.as_str()) == Some("verified_directory_migration"))
                    .then_some(v)
            })
            .map(|v| serde_json::from_value::<DirectoryProof>(v.clone()))
            .transpose()?;
        if let Some(proof) = &proof
            && (proof.source != op.source
                || proof.destination != dest.path
                || proof.capture.payload != scope.capture.payload
                || proof.capture.root != scope.capture.root
                || proof.capture.identity != scope.capture.identity)
        {
            return Err(E::StorageUnavailable);
        }
        let original = op
            .manifest
            .iter()
            .find(|e| e.path == op.source)
            .ok_or(E::StorageUnavailable)?;
        let original_source = observe(
            &op.source.to_path()?,
            Some(&original.stamp),
            Some(&scope.metadata),
            false,
        )?;
        let root = proof.as_ref().and_then(|p| p.target.first());
        let mut destination = observe(
            &dest.path.to_path()?,
            root.map(|e| &e.stamp),
            root.map(|e| &e.metadata),
            false,
        )?;
        if destination == MigrationObservation::MatchesMetadata
            && self
                .directory_proof_manifest(
                    &dest.path.to_path()?,
                    &proof.as_ref().ok_or(E::StorageUnavailable)?.target,
                    None,
                )
                .is_err()
        {
            destination = MigrationObservation::Changed;
        }
        let envelope = events
            .iter()
            .find(|(step, phase, _)| step == "migration_create" && phase == "result")
            .and_then(|(_, _, v)| v.get("envelope"))
            .map(|v| serde_json::from_value::<Stamp>(v.clone()))
            .transpose()?;
        let temporary = observe(&scope.temporary.to_path()?, envelope.as_ref(), None, true)?;
        let retained_root = proof.as_ref().and_then(|p| p.retained.first());
        let mut retained_source = observe(
            &scope.capture.payload.to_path()?,
            Some(retained_root.map_or(&original.stamp, |p| &p.stamp)),
            retained_root.map(|p| &p.metadata),
            retained_root.is_none(),
        )?;
        if matches!(
            retained_source,
            MigrationObservation::MatchesMetadata | MigrationObservation::MatchesIdentity
        ) {
            let capture = &proof.as_ref().ok_or(E::StorageUnavailable)?.capture;
            let owned = self.payload_permit(capture)?;
            if let Some(proof) = &proof
                && !proof.retained.is_empty()
                && self
                    .directory_proof_manifest(
                        &capture.payload.to_path()?,
                        &proof.retained,
                        Some(&owned),
                    )
                    .is_err()
            {
                retained_source = MigrationObservation::Changed;
            }
        }
        let changed = [original_source, destination, temporary, retained_source]
            .iter()
            .any(|v| {
                matches!(
                    v,
                    MigrationObservation::Changed
                        | MigrationObservation::DifferentObject
                        | MigrationObservation::Unrecorded
                )
            });
        Ok(MigrationProgress {
            original_source,
            destination,
            temporary,
            retained_source,
            retained_path: scope.capture.payload.clone(),
            retained_state,
            source_remove_confirmed: false,
            source_remove_unconfirmed: false,
            content_verification_required: true,
            disposition: if changed {
                crate::recovery::RecoveryDisposition::NeedsAttention
            } else {
                crate::recovery::RecoveryDisposition::MigrationProgressObserved
            },
            reason: if changed {
                "directory_migration_objects_require_review"
            } else if matches!(
                retained_source,
                MigrationObservation::MatchesMetadata | MigrationObservation::MatchesIdentity
            ) {
                "directory_migration_original_retained"
            } else {
                "directory_migration_source_not_captured"
            }
            .into(),
        })
    }
    pub(crate) fn is_directory_migration_inverse(&self, op: &PlannedOperation) -> Result<bool> {
        if op.inverse.is_none() {
            return Ok(false);
        }
        let (original, history) = self.inverse_original(op)?;
        Ok(completed_directory_proof(&original, &history)?.is_some())
    }
    pub(crate) fn build_directory_migration_undo(
        &self,
        original: &PlannedOperation,
        proof: &DirectoryProof,
        batch: &Id,
        options: &PlanOptions,
    ) -> Result<Vec<PlannedOperation>> {
        self.directory_proof_manifest(&proof.destination.to_path()?, &proof.target, None)?;
        let owned = self.payload_permit(&proof.capture)?;
        self.directory_proof_manifest(
            &proof.capture.payload.to_path()?,
            &proof.retained,
            Some(&owned),
        )?;
        let mut restore =
            self.build_restore_plan(std::slice::from_ref(&original.id), None, options.clone())?;
        let mut remove = self.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Quarantine,
                source: proof.destination.to_path()?,
                destination: None,
            }],
            options.clone(),
        )?;
        let mut restore = restore.preview.operations.remove(0);
        let mut remove = remove.preview.operations.remove(0);
        let source = remove.source.to_path()?;
        retain_sensitivity(original, &mut remove.manifest, &source)?;
        let reference = InverseReference {
            batch: batch.clone(),
            operation: original.id.clone(),
        };
        restore.inverse = Some(reference.clone());
        remove.inverse = Some(reference);
        Ok(vec![restore, remove])
    }
    pub(crate) fn validate_directory_migration_inverse(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        original: &PlannedOperation,
        proof: &DirectoryProof,
    ) -> Result<()> {
        let pair = plan
            .preview
            .operations
            .iter()
            .filter(|entry| {
                entry
                    .inverse
                    .as_ref()
                    .is_some_and(|i| i.operation == original.id)
            })
            .collect::<Vec<_>>();
        if pair.len() != 2
            || !pair.iter().any(|entry| {
                entry.kind == OperationKind::Restore && entry.source == proof.capture.payload
            })
            || !pair.iter().any(|entry| {
                entry.kind == OperationKind::Quarantine && entry.source == proof.destination
            })
        {
            return Err(E::InvalidPlan);
        }
        match (&op.managed, op.kind) {
            (
                Some(ManagedOperation::Restore {
                    item,
                    scope,
                    remaining: false,
                }),
                OperationKind::Restore,
            ) if item == &original.id
                && op.source == proof.capture.payload
                && scope.payload == proof.capture.payload
                && op
                    .destination
                    .as_ref()
                    .is_some_and(|d| d.path == original.source) =>
            {
                let owned = self.payload_permit(&proof.capture)?;
                self.directory_proof_manifest(
                    &proof.capture.payload.to_path()?,
                    &proof.retained,
                    Some(&owned),
                )?;
            }
            (Some(ManagedOperation::Quarantine(_)), OperationKind::Quarantine)
                if op.source == proof.destination => {}
            _ => return Err(E::InvalidPlan),
        }
        self.directory_proof_manifest(&proof.destination.to_path()?, &proof.target, None)?;
        Ok(())
    }
    pub(crate) fn verify_directory_migration_inverse_content(
        &self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        proof: &DirectoryProof,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let source = op.source.to_path()?;
        let (expected, scope) = if op.kind == OperationKind::Restore {
            (&proof.retained, Some(&proof.capture))
        } else {
            (&proof.target, None)
        };
        let mut actual = Vec::new();
        let mut entries = op
            .manifest
            .iter()
            .map(|entry| Ok((relative(&source, &entry.path.to_path()?)?, entry)))
            .collect::<Result<Vec<_>>>()?;
        entries.sort_by(|(a, _), (b, _)| {
            a.components()
                .count()
                .cmp(&b.components().count())
                .then_with(|| a.cmp(b))
        });
        let owned = scope.map(|scope| self.payload_permit(scope)).transpose()?;
        for (relative, entry) in entries {
            let permit = OperationContentPermit::issue_entry(self, approved, op, entry)?;
            let mut file = permit.open()?;
            let path = entry.path.to_path()?;
            if let Some(owned) = &owned {
                owned.relative(&source, &path)?;
            }
            let info = platform::inspect(&path)?;
            let metadata = platform::metadata_inventory(&path, &info)?;
            let (body, attached) =
                values(&path, &mut file, &info, &metadata, &check(&permit, cancel))?;
            permit.verify_after(&file)?;
            actual.push(EntryProof {
                relative: NativePath::new(&relative),
                stamp: entry.stamp.clone(),
                kind: entry.kind.clone(),
                length: entry.size_bytes.clone(),
                link_target: entry.link_target.clone(),
                symlink_directory: entry.symlink_directory,
                metadata: MetadataDescription::capture(&metadata),
                body,
                attached,
            });
        }
        if actual != *expected {
            return Err(E::ChangedSincePlan);
        }
        if op.kind == OperationKind::Restore {
            // Check both copies before restoring the retained original.
            self.verify_directory_proofs(
                &proof.destination.to_path()?,
                &proof.target,
                None,
                approved,
                cancel,
                true,
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryProof {
    relative: NativePath,
    stamp: Stamp,
    kind: String,
    length: String,
    link_target: Option<NativePath>,
    symlink_directory: Option<bool>,
    metadata: MetadataDescription,
    body: Option<String>,
    attached: Vec<StreamProof>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryProof {
    protocol: String,
    source: NativePath,
    destination: NativePath,
    capture: QuarantineScope,
    target: Vec<EntryProof>,
    retained: Vec<EntryProof>,
}

impl MigrationScope {
    pub(crate) fn review_description(&self) -> String {
        let mut text = format!(
            "\n   跨卷迁移：保留普通权限、修改时间和附属数据\n   校验暂存：{}\n   源端保留位置：{}",
            self.temporary.display, self.capture.payload.display
        );
        if self.tree.is_empty() {
            text.push_str("\n   完整性校验后移除源端载荷");
        } else {
            text.push_str(&format!(
                "\n   原目录保留 {} 天，显式清理隔离副本后释放源卷空间",
                self.capture.retention_days
            ));
        }
        let descriptions = if self.tree.is_empty() {
            vec![(".".to_owned(), &self.metadata)]
        } else {
            self.tree
                .iter()
                .map(|e| {
                    (
                        if e.relative.display.is_empty() {
                            ".".into()
                        } else {
                            e.relative.display.clone()
                        },
                        &e.metadata,
                    )
                })
                .collect()
        };
        for (relative, metadata) in descriptions {
            for attribute in &metadata.attributes {
                text.push_str(&format!(
                    "\n   附属数据：{relative} / {}（{}，{} 字节）",
                    attribute.name.display, attribute.kind, attribute.bytes
                ));
            }
        }
        text
    }
    pub(crate) fn opaque_bytes(&self) -> Result<u64> {
        if self.tree.is_empty() {
            return self.metadata.opaque_bytes.parse().map_err(|_| E::Overflow);
        }
        self.tree.iter().try_fold(0u64, |total, entry| {
            total
                .checked_add(
                    entry
                        .metadata
                        .opaque_bytes
                        .parse::<u64>()
                        .map_err(|_| E::Overflow)?,
                )
                .ok_or(E::Overflow)
        })
    }
}
fn relative(root: &Path, path: &Path) -> Result<PathBuf> {
    let value = path.strip_prefix(root).map_err(|_| E::InvalidPlan)?;
    if value
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(E::InvalidPlan);
    }
    Ok(value.into())
}
fn ordered(op: &PlannedOperation) -> Result<Vec<(PathBuf, &ManifestEntry)>> {
    let root = op.source.to_path()?;
    let mut result = op
        .manifest
        .iter()
        .map(|entry| Ok((relative(&root, &entry.path.to_path()?)?, entry)))
        .collect::<Result<Vec<_>>>()?;
    result.sort_by(|(a, _), (b, _)| {
        a.components()
            .count()
            .cmp(&b.components().count())
            .then_with(|| a.cmp(b))
    });
    if result
        .first()
        .is_none_or(|(p, e)| !p.as_os_str().is_empty() || e.kind != "Directory")
    {
        return Err(E::InvalidPlan);
    }
    let mut seen = BTreeSet::new();
    for (path, entry) in &result {
        if !matches!(entry.kind.as_str(), "Directory" | "Regular" | "Symlink")
            || !seen.insert(path.clone())
        {
            return Err(E::UnsupportedNode);
        }
        if !path.as_os_str().is_empty() && !seen.contains(path.parent().ok_or(E::InvalidPlan)?) {
            return Err(E::IncompleteManifest);
        }
    }
    Ok(result)
}
pub(super) fn reviewed_entries(op: &PlannedOperation) -> Result<Vec<ReviewedEntry>> {
    ordered(op)?
        .into_iter()
        .map(|(relative, entry)| {
            let path = entry.path.to_path()?;
            let info = platform::inspect(&path)?;
            if Stamp::capture(&info)? != entry.stamp {
                return Err(E::ChangedSincePlan);
            }
            let metadata = platform::metadata_inventory(&path, &info)?;
            platform::check_migration_metadata(&metadata)?;
            Ok(ReviewedEntry {
                relative: NativePath::new(&relative),
                metadata: MetadataDescription::capture(&metadata),
            })
        })
        .collect()
}
fn open_values(path: &Path, info: &platform::NodeInfo) -> Result<File> {
    Ok(match info.kind {
        platform::NodeKind::Regular => platform::open_verified(path, info)?,
        platform::NodeKind::Directory => platform::open_directory_attached_data(path, info)?,
        platform::NodeKind::Symlink => platform::open_symlink_attached_data(path, info)?,
        _ => return Err(E::UnsupportedNode),
    })
}
fn values(
    path: &Path,
    file: &mut File,
    info: &platform::NodeInfo,
    metadata: &platform::MetadataInventory,
    checkpoint: &(impl Fn() -> std::io::Result<()> + Sync),
) -> Result<(Option<String>, Vec<StreamProof>)> {
    let body = if info.kind == platform::NodeKind::Regular {
        Some(hash_body(file, info.len, checkpoint)?)
    } else {
        None
    };
    let attached = attached_proof(|sink| {
        platform::visit_migration_data(path, file, metadata, checkpoint, &mut |event| sink(event))
    })?;
    Ok((body, attached))
}
fn same_values(source: &[EntryProof], target: &[EntryProof]) -> Result<()> {
    if source.len() != target.len() {
        return Err(E::ChangedSincePlan);
    }
    let mut forward = BTreeMap::new();
    let mut reverse = BTreeMap::new();
    for (a, b) in source.iter().zip(target) {
        if a.relative != b.relative
            || a.kind != b.kind
            || a.length != b.length
            || a.link_target != b.link_target
            || a.symlink_directory != b.symlink_directory
            || a.metadata.portable != b.metadata.portable
            || a.body != b.body
            || a.attached != b.attached
        {
            return Err(E::ChangedSincePlan);
        }
        let key_a = a.stamp.object_key();
        let key_b = b.stamp.object_key();
        if forward.insert(key_a, key_b).is_some_and(|old| old != key_b)
            || reverse.insert(key_b, key_a).is_some_and(|old| old != key_a)
        {
            return Err(E::ChangedSincePlan);
        }
    }
    Ok(())
}
fn source_proofs(
    session: &Session,
    approved: &ApprovedPlan,
    op: &PlannedOperation,
    cancel: &CancellationToken,
) -> Result<Vec<EntryProof>> {
    let reviewed = &op.migration.as_ref().ok_or(E::InvalidPlan)?.tree;
    ordered(op)?
        .into_iter()
        .zip(reviewed)
        .map(|((relative, entry), expected)| {
            let permit = OperationContentPermit::issue_entry(session, approved, op, entry)?;
            let checkpoint = check(&permit, cancel);
            let path = entry.path.to_path()?;
            let mut file = permit.open()?;
            let info = platform::inspect(&path)?;
            let metadata = platform::metadata_inventory(&path, &info)?;
            if MetadataDescription::capture(&metadata) != expected.metadata {
                return Err(E::ChangedSincePlan);
            }
            let (body, attached) = values(&path, &mut file, &info, &metadata, &checkpoint)?;
            permit.verify_after(&file)?;
            Ok(EntryProof {
                relative: NativePath::new(&relative),
                stamp: entry.stamp.clone(),
                kind: entry.kind.clone(),
                length: entry.size_bytes.clone(),
                link_target: entry.link_target.clone(),
                symlink_directory: entry.symlink_directory,
                metadata: expected.metadata.clone(),
                body,
                attached,
            })
        })
        .collect()
}
fn staged_proofs(
    tree: &platform::MigrationDirectory,
    op: &PlannedOperation,
    checkpoint: &(impl Fn() -> std::io::Result<()> + Sync),
) -> Result<Vec<EntryProof>> {
    tree.verify_contents(checkpoint)?;
    ordered(op)?
        .into_iter()
        .map(|(relative, entry)| {
            let before = tree.metadata(&relative)?;
            let body = if entry.kind == "Regular" {
                let mut hasher = blake3::Hasher::new();
                let mut size = 0u64;
                tree.visit_body(&relative, checkpoint, &mut |bytes| {
                    size = size
                        .checked_add(bytes.len() as u64)
                        .ok_or_else(|| std::io::Error::other("body size overflow"))?;
                    hasher.update(bytes);
                    Ok(())
                })?;
                if size.to_string() != entry.size_bytes {
                    return Err(E::ChangedSincePlan);
                }
                Some(hasher.finalize().to_hex().to_string())
            } else {
                None
            };
            let attached = attached_proof(|sink| {
                tree.visit_data(&relative, checkpoint, &mut |event| sink(event))
            })?;
            let after = tree.metadata(&relative)?;
            if before.binding_bytes() != after.binding_bytes() {
                return Err(E::ChangedSincePlan);
            }
            // The owned API validates each native identity, type and link target.
            let path = tree.path().join(&relative);
            let info = platform::inspect(&path)?;
            if format!("{:?}", info.kind) != entry.kind
                || info.modified != platform::inspect(&entry.path.to_path()?)?.modified
            {
                return Err(E::ChangedSincePlan);
            }
            Ok(EntryProof {
                relative: NativePath::new(&relative),
                stamp: Stamp::capture(&info)?,
                kind: entry.kind.clone(),
                length: entry.size_bytes.clone(),
                link_target: entry.link_target.clone(),
                symlink_directory: entry.symlink_directory,
                metadata: MetadataDescription::capture(&after),
                body,
                attached,
            })
        })
        .collect()
}

impl Session {
    fn validate_directory_source(
        &self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        parents: &BTreeMap<PathBuf, Stamp>,
        destination: bool,
    ) -> Result<()> {
        self.validate_migration_source(&approved.plan, op, parents, destination)?;
        if reviewed_entries(op)? != op.migration.as_ref().ok_or(E::InvalidPlan)?.tree {
            return Err(E::ChangedSincePlan);
        }
        Ok(())
    }
    pub(crate) fn execute_directory_migration(
        &mut self,
        approved: &ApprovedPlan,
        op: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        let mut created = false;
        let mut journal = false;
        let mut step = "migration_begin";
        let mut run = || -> Result<()> {
            let mut current = op.clone();
            let spec = op.migration.as_ref().ok_or(E::InvalidPlan)?;
            if spec.tree.len() != op.manifest.len() {
                return Err(E::InvalidPlan);
            }
            let source = op.source.to_path()?;
            let target = op
                .destination
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .path
                .to_path()?;
            let parent = target.parent().ok_or(E::InvalidPath)?;
            let checkpoint = live(approved, cancel);
            checkpoint()?;
            macro_rules! intent {
                ($name:literal,$value:expr) => {{
                    step = $name;
                    self.store
                        .as_mut()
                        .ok_or(E::StorageRequired)?
                        .record_intent(&op.id, step, &$value)
                        .inspect_err(|_| journal = true)?;
                }};
            }
            macro_rules! result {
                ($value:expr,$state:expr) => {{
                    self.store
                        .as_mut()
                        .ok_or(E::StorageRequired)?
                        .record_result(&op.id, step, &$value, $state)
                        .inspect_err(|_| journal = true)?;
                }};
            }
            intent!(
                "migration_begin",
                json!({"source":op.source,"destination":NativePath::new(&target),"scope":spec})
            );
            self.validate_directory_source(approved, &current, parents, true)?;
            result!(json!({"scope":spec}), OperationState::Prepared);
            let (capture, made) = self
                .prepare_quarantine_directories(&approved.plan, op, &spec.capture, parents, cancel)
                .map_err(|f| {
                    created |= f.created;
                    journal |= f.journal;
                    step = f.step;
                    f.error
                })?;
            created |= made;
            let before = platform::inspect(parent)?;
            intent!(
                "migration_create",
                json!({"temporary":spec.temporary,"parent":Stamp::capture(&before)?})
            );
            self.validate_directory_source(approved, &current, parents, true)?;
            created = true;
            let mut tree = platform::MigrationDirectory::create(
                parent,
                &before,
                spec.temporary
                    .to_path()?
                    .file_name()
                    .ok_or(E::InvalidPath)?,
            )?;
            update_parent(parent, &before, parents)?;
            result!(
                json!({"temporary":spec.temporary,"envelope":Stamp::capture(&tree.envelope_info()?)?}),
                OperationState::Staged
            );
            let descriptions = spec
                .tree
                .iter()
                .map(|entry| Ok((entry.relative.to_path()?, &entry.metadata)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            let mut aliases = HashMap::<(String, String, String), PathBuf>::new();
            for (relative, entry) in ordered(op)?.into_iter().skip(1) {
                intent!(
                    "migration_tree_entry",
                    json!({"relative":NativePath::new(&relative)})
                );
                if entry.kind == "Directory" {
                    tree.create_directory(&relative)?;
                } else {
                    let permit = OperationContentPermit::issue_entry(self, approved, op, entry)?;
                    let checkpoint = check(&permit, cancel);
                    let path = entry.path.to_path()?;
                    let file = permit.open()?;
                    let metadata = platform::metadata_inventory(&path, &platform::inspect(&path)?)?;
                    let expected = descriptions.get(&relative).ok_or(E::InvalidPlan)?;
                    if MetadataDescription::capture(&metadata) != **expected {
                        return Err(E::ChangedSincePlan);
                    }
                    let key = entry.stamp.object_key();
                    let key = (key.0.to_owned(), key.1.to_owned(), key.2.to_owned());
                    if let Some(existing) = aliases.get(&key) {
                        tree.create_hard_link(existing, &relative)?;
                    } else {
                        if entry.kind == "Regular" {
                            tree.copy_file(&relative, &path, &file, &metadata, &checkpoint)?;
                        } else {
                            tree.copy_symlink(&relative, &path, &file, &metadata, &checkpoint)?;
                        }
                        aliases.insert(key, relative.clone());
                    }
                    permit.verify_after(&file)?;
                }
                result!(
                    json!({"relative":NativePath::new(&relative)}),
                    OperationState::Staged
                );
            }
            for (relative, entry) in ordered(op)?
                .into_iter()
                .rev()
                .filter(|(_, e)| e.kind == "Directory")
            {
                intent!(
                    "migration_tree_metadata",
                    json!({"relative":NativePath::new(&relative)})
                );
                let permit = OperationContentPermit::issue_entry(self, approved, op, entry)?;
                let file = permit.open()?;
                let path = entry.path.to_path()?;
                let metadata = platform::metadata_inventory(&path, &platform::inspect(&path)?)?;
                let expected = descriptions.get(&relative).ok_or(E::InvalidPlan)?;
                if MetadataDescription::capture(&metadata) != **expected {
                    return Err(E::ChangedSincePlan);
                }
                tree.copy_directory_metadata(
                    &relative,
                    &path,
                    &file,
                    &metadata,
                    &check(&permit, cancel),
                )?;
                permit.verify_after(&file)?;
                result!(
                    json!({"relative":NativePath::new(&relative)}),
                    OperationState::Staged
                );
            }
            intent!("migration_verify", json!({"scope":spec}));
            let original = source_proofs(self, approved, &current, cancel)?;
            let checkpoint = live(approved, cancel);
            let verified = staged_proofs(&tree, op, &checkpoint)?;
            same_values(&original, &verified)?;
            self.validate_directory_source(approved, &current, parents, true)?;
            result!(json!({"entries":verified}), OperationState::Verified);
            intent!("migration_publish", json!({"entries":verified}));
            self.validate_directory_source(approved, &current, parents, true)?;
            crate::copy::checkpoint(cancel)?;
            tree.publish(target.file_name().ok_or(E::InvalidPath)?)
                .map_err(|e| E::Io(e.error))?;
            update_parent(parent, &before, parents)?;
            let checkpoint = live(approved, cancel);
            let mut proof = DirectoryProof {
                protocol: "verified_directory_migration".into(),
                source: op.source.clone(),
                destination: NativePath::new(&target),
                capture: capture.clone(),
                target: staged_proofs(&tree, op, &checkpoint)?,
                retained: Vec::new(),
            };
            same_values(&original, &proof.target)?;
            result!(proof, OperationState::Published);
            intent!(
                "migration_cleanup",
                json!({"proof":proof,"envelope":Stamp::capture(&tree.envelope_info()?)?})
            );
            tree.retire_envelope().map_err(|e| E::Io(e.error))?;
            update_parent(parent, &before, parents)?;
            result!(proof, OperationState::Published);
            self.validate_directory_source(approved, &current, parents, false)?;
            // Freeze descendants before ancestors; each identity is mutated once.
            let ordered_entries = ordered(op)?;
            let indices = spec
                .tree
                .iter()
                .enumerate()
                .map(|(i, e)| Ok((e.relative.to_path()?, i)))
                .collect::<Result<BTreeMap<_, _>>>()?;
            let mut groups = BTreeMap::<(String, String, String), Vec<usize>>::new();
            for (relative, entry) in &ordered_entries {
                let key = entry.stamp.object_key();
                groups
                    .entry((key.0.into(), key.1.into(), key.2.into()))
                    .or_default()
                    .push(*indices.get(relative).ok_or(E::InvalidPlan)?);
            }
            let mut frozen = BTreeSet::new();
            for (relative, entry) in ordered_entries.into_iter().rev() {
                let key = entry.stamp.object_key();
                if !frozen.insert((key.0.to_owned(), key.1.to_owned(), key.2.to_owned())) {
                    continue;
                }
                self.validate_plan_context(&approved.plan)?;
                let path = entry.path.to_path()?;
                let info = platform::inspect(&path)?;
                let metadata = platform::metadata_inventory(&path, &info)?;
                let expected = &current.migration.as_ref().ok_or(E::InvalidPlan)?.tree
                    [*indices.get(&relative).ok_or(E::InvalidPlan)?]
                .metadata;
                if Stamp::capture(&info)? != entry.stamp
                    || MetadataDescription::capture(&metadata) != *expected
                {
                    return Err(E::ChangedSincePlan);
                }
                intent!(
                    "migration_access",
                    json!({"relative":NativePath::new(&relative),"metadata":MetadataDescription::capture(&metadata)})
                );
                let checkpoint = live(approved, cancel);
                let after =
                    platform::freeze_migration_access(&path, &info, &metadata, &checkpoint)?;
                if after.portable_bytes() != metadata.portable_bytes() {
                    return Err(E::ChangedSincePlan);
                }
                // Refresh every alias of this object after our own DACL mutation.
                let scope = current.migration.as_mut().ok_or(E::InvalidPlan)?;
                for index in groups
                    .get(&(key.0.into(), key.1.into(), key.2.into()))
                    .ok_or(E::InvalidPlan)?
                {
                    let reviewed = &mut scope.tree[*index];
                    let candidate = source.join(reviewed.relative.to_path()?);
                    let observed = platform::inspect(&candidate)?;
                    if observed.identity != info.identity {
                        return Err(E::ChangedSincePlan);
                    }
                    let description = MetadataDescription::capture(&platform::metadata_inventory(
                        &candidate, &observed,
                    )?);
                    if description.portable != reviewed.metadata.portable {
                        return Err(E::ChangedSincePlan);
                    }
                    reviewed.metadata = description;
                }
                scope.metadata = scope.tree.first().ok_or(E::InvalidPlan)?.metadata.clone();
                result!(
                    json!({"relative":NativePath::new(&relative),"metadata":MetadataDescription::capture(&after)}),
                    OperationState::Published
                );
            }
            self.validate_directory_source(approved, &current, parents, false)?;
            self.verify_directory_proofs(&target, &proof.target, None, approved, cancel, true)?;
            intent!(
                "migration_capture",
                json!({"proof":proof,"capture":capture})
            );
            crate::copy::checkpoint(cancel)?;
            self.validate_directory_source(approved, &current, parents, false)?;
            let payload = capture.payload.to_path()?;
            let from = source.parent().ok_or(E::InvalidPath)?;
            let to = payload.parent().ok_or(E::InvalidPath)?;
            let from_before = platform::inspect(from)?;
            let to_before = platform::inspect(to)?;
            let _pins = self.validate_scope(&capture, parents)?;
            platform::rename_noreplace(
                &source,
                &platform::inspect(&source)?,
                &payload,
                &from_before,
                &to_before,
            )
            .map_err(|e| E::Io(e.error))?;
            update_parent(from, &from_before, parents)?;
            update_parent(to, &to_before, parents)?;
            let observed = self.payload_manifest(
                &capture,
                &PlanOptions {
                    include_hidden: true,
                    max_entries: op.manifest.len(),
                    ..Default::default()
                },
            )?;
            crate::quarantine::compare_relocated(&source, &op.manifest, &payload, &observed)?;
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
            super::tests::after_capture();
            intent!("migration_commit_verify", json!({"proof":proof}));
            let owned = self.payload_permit(&capture)?;
            proof.retained =
                self.read_directory_proofs(&payload, &observed, Some(&owned), approved, cancel)?;
            same_values(&original, &proof.retained)?;
            self.verify_directory_proofs(&target, &proof.target, None, approved, cancel, true)?;
            result!(proof, OperationState::Published);
            intent!("migration_complete", proof);
            crate::copy::checkpoint(cancel)?;
            self.validate_plan_context(&approved.plan)?;
            self.payload_permit(&capture)?;
            absent(&source)?;
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
    fn read_directory_proofs(
        &self,
        root: &Path,
        manifest: &[ManifestEntry],
        owned: Option<&crate::quarantine::ManagedPayloadPermit>,
        approved: &ApprovedPlan,
        cancel: &CancellationToken,
    ) -> Result<Vec<EntryProof>> {
        let mut entries = manifest
            .iter()
            .map(|e| Ok((relative(root, &e.path.to_path()?)?, e)))
            .collect::<Result<Vec<_>>>()?;
        entries.sort_by(|(a, _), (b, _)| {
            a.components()
                .count()
                .cmp(&b.components().count())
                .then_with(|| a.cmp(b))
        });
        entries
            .into_iter()
            .map(|(relative, entry)| {
                let path = entry.path.to_path()?;
                if let Some(owned) = owned {
                    owned.relative(root, &path)?;
                }
                let info = platform::inspect(&path)?;
                if Stamp::capture(&info)? != entry.stamp {
                    return Err(E::ChangedSincePlan);
                }
                let metadata = platform::metadata_inventory(&path, &info)?;
                let mut file = open_values(&path, &info)?;
                let checkpoint = live(approved, cancel);
                let (body, attached) = values(&path, &mut file, &info, &metadata, &checkpoint)?;
                if !info.matches(&platform::inspect_file(&file)?)
                    || platform::metadata_inventory(&path, &info)?.binding_bytes()
                        != metadata.binding_bytes()
                {
                    return Err(E::ChangedSincePlan);
                }
                Ok(EntryProof {
                    relative: NativePath::new(&relative),
                    stamp: entry.stamp.clone(),
                    kind: entry.kind.clone(),
                    length: entry.size_bytes.clone(),
                    link_target: entry.link_target.clone(),
                    symlink_directory: entry.symlink_directory,
                    metadata: MetadataDescription::capture(&metadata),
                    body,
                    attached,
                })
            })
            .collect()
    }
    pub(crate) fn verify_directory_proofs(
        &self,
        root: &Path,
        proof: &[EntryProof],
        owned: Option<&crate::quarantine::ManagedPayloadPermit>,
        approved: &ApprovedPlan,
        cancel: &CancellationToken,
        content: bool,
    ) -> Result<()> {
        let manifest = self.directory_proof_manifest(root, proof, owned)?;
        if content && self.read_directory_proofs(root, &manifest, owned, approved, cancel)? != proof
        {
            return Err(E::ChangedSincePlan);
        }
        Ok(())
    }
    fn directory_proof_manifest(
        &self,
        root: &Path,
        proof: &[EntryProof],
        owned: Option<&crate::quarantine::ManagedPayloadPermit>,
    ) -> Result<Vec<ManifestEntry>> {
        if proof.is_empty() || proof.len() > 1_000_000 {
            return Err(E::StorageUnavailable);
        }
        let options = PlanOptions {
            include_hidden: true,
            max_entries: proof.len(),
            ..Default::default()
        };
        let actual = if let Some(owned) = owned {
            {
                let mut budget = proof.len();
                self.manifest_with_access(
                    root,
                    OperationKind::Restore,
                    &options,
                    &planning_policy()?,
                    &mut budget,
                    crate::plan::ManifestAccess::Managed(owned),
                )?
            }
        } else {
            let mut budget = proof.len();
            self.manifest(
                root,
                OperationKind::Move,
                &options,
                &planning_policy()?,
                &mut budget,
            )?
        };
        let expected = proof
            .iter()
            .map(|p| Ok((p.relative.to_path()?, p)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        if expected.len() != proof.len()
            || actual.len() != proof.len()
            || !expected.contains_key(Path::new(""))
        {
            return Err(E::ChangedSincePlan);
        }
        for entry in &actual {
            let path = entry.path.to_path()?;
            let p = expected
                .get(&relative(root, &path)?)
                .ok_or(E::ChangedSincePlan)?;
            if p.stamp != entry.stamp
                || p.kind != entry.kind
                || p.length != entry.size_bytes
                || p.link_target != entry.link_target
                || p.symlink_directory != entry.symlink_directory
                || MetadataDescription::capture(&platform::metadata_inventory(
                    &path,
                    &platform::inspect(&path)?,
                )?) != p.metadata
            {
                return Err(E::ChangedSincePlan);
            }
        }
        Ok(actual)
    }
}
