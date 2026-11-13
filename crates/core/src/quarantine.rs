//! Retained objects remain on their original volume and restore through new plans.
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use file_tidy_platform as platform;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::CancellationToken;
use crate::authorization::{
    Id, Identity, NativePath, PlanningError as E, Result, Session, checked_existing,
    planning_policy,
};
use crate::copy::{CopyFailure, checkpoint, update_parent};
use crate::journal::{OperationState, id_bytes, native_path, path_bytes};
use crate::plan::{
    Destination, ManifestAccess, ManifestEntry, OperationKind, OperationRequest, Plan, PlanOptions,
    PlannedOperation, Stamp, destination_acknowledgements, now, resolve_destination,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedDirectory {
    path: NativePath,
    identity: Option<Identity>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuarantineScope {
    root: NativePath,
    identity: Identity,
    directories: Vec<ManagedDirectory>,
    payload: NativePath,
    retention_days: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ManagedOperation {
    Quarantine(QuarantineScope),
    Restore { item: Id, scope: QuarantineScope },
}
impl ManagedOperation {
    fn scope(&self) -> &QuarantineScope {
        match self {
            Self::Quarantine(s) | Self::Restore { scope: s, .. } => s,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootRecord {
    root: NativePath,
    identity: Identity,
    container: Option<Identity>,
    quarantine: Option<Identity>,
}

/// A path-bound capability constructed only after checking owned directory identities.
pub(crate) struct ManagedPayloadPermit {
    path: PathBuf,
}
impl ManagedPayloadPermit {
    pub(crate) fn relative<'a>(&self, source: &Path, path: &'a Path) -> Result<&'a Path> {
        if source != self.path {
            return Err(E::InvalidPlan);
        }
        path.strip_prefix(&self.path).map_err(|_| E::InvalidPath)
    }
}

#[derive(Debug, Serialize)]
pub struct QuarantineItem {
    pub id: Id,
    pub batch_id: Id,
    pub original_path: NativePath,
    pub storage_path: NativePath,
    pub retained_at: u64,
    pub expires_at: u64,
    pub due: bool,
    pub state: String,
}

fn root_key(identity: &Identity) -> Result<String> {
    Ok(format!(
        "quarantine-root:{}",
        blake3::hash(&serde_json::to_vec(identity)?).to_hex()
    ))
}
fn item_key(item: &Id) -> String {
    format!("quarantine-item:{item}")
}
fn metadata<T: for<'de> Deserialize<'de>>(session: &Session, key: &str) -> Result<Option<T>> {
    session
        .store
        .as_ref()
        .ok_or(E::StorageRequired)?
        .journal_read(|db| {
            let bytes: Option<Vec<u8>> = db
                .query_row(
                    "SELECT value FROM store_metadata WHERE key=?1 AND length(value)<=1048576",
                    [key],
                    |row| row.get(0),
                )
                .optional()?;
            bytes
                .map(|b| serde_json::from_slice(&b).map_err(E::from))
                .transpose()
        })
}
fn save_metadata(tx: &rusqlite::Transaction<'_>, key: &str, value: &impl Serialize) -> Result<()> {
    tx.execute("INSERT INTO store_metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, serde_json::to_vec(value)?])?;
    Ok(())
}
fn absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(E::DestinationConflict),
    }
}

impl Session {
    pub(crate) fn plan_quarantine(
        &self,
        source: &Path,
        batch: &Id,
        operation: &Id,
        options: &PlanOptions,
    ) -> Result<(Destination, QuarantineScope)> {
        let policy = planning_policy()?;
        let grant = self.grant_for(source, &policy)?;
        let root = grant.validate(&policy)?;
        if policy.labels(&root).sensitive || policy.labels(&root).atomic_root.is_some() {
            return Err(E::ProtectedRoot);
        }
        let key = root_key(&grant.identity)?;
        let record: RootRecord = match metadata(self, &key)? {
            Some(record) => record,
            None => RootRecord {
                root: grant.root.clone(),
                identity: grant.identity.clone(),
                container: self
                    .store
                    .as_ref()
                    .ok_or(E::StorageRequired)?
                    .managed_anchor(&root, &grant.identity)?,
                quarantine: None,
            },
        };
        if record.root != grant.root || record.identity != grant.identity {
            return Err(E::StorageUnavailable);
        }
        let container = root.join(".file-tidy");
        let quarantine = container.join("quarantine");
        let batch_dir = quarantine.join(batch.as_str());
        let op_dir = batch_dir.join(operation.as_str());
        let scope = QuarantineScope {
            root: grant.root.clone(),
            identity: grant.identity.clone(),
            directories: vec![
                ManagedDirectory {
                    path: NativePath::new(&container),
                    identity: record.container,
                },
                ManagedDirectory {
                    path: NativePath::new(&quarantine),
                    identity: record.quarantine,
                },
                ManagedDirectory {
                    path: NativePath::new(&batch_dir),
                    identity: None,
                },
                ManagedDirectory {
                    path: NativePath::new(&op_dir),
                    identity: None,
                },
            ],
            payload: NativePath::new(&op_dir.join("payload")),
            retention_days: options.quarantine_retention_days,
        };
        self.validate_scope(&scope, &BTreeMap::new())?;
        let existing_parent = scope
            .directories
            .iter()
            .rev()
            .find(|d| d.identity.is_some())
            .map(|d| d.path.to_path())
            .transpose()?
            .unwrap_or(root);
        let destination = Destination {
            path: scope.payload.clone(),
            existing_parent: NativePath::new(&existing_parent),
            create_directories: scope
                .directories
                .iter()
                .filter(|d| d.identity.is_none())
                .map(|d| d.path.clone())
                .collect(),
            renamed_for_conflict: false,
            spelling_temporary: None,
            copy_temporary: None,
            copy_metadata: None,
            parent_stamp: Stamp::capture(&platform::inspect(&existing_parent)?)?,
        };
        absent(&destination.path.to_path()?)?;
        Ok((destination, scope))
    }

    fn validate_scope(
        &self,
        scope: &QuarantineScope,
        changed: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<Vec<platform::PinnedDirectory>> {
        let root = scope.root.to_path()?;
        let policy = planning_policy()?;
        let grant = self.grant_for(&root, &policy)?;
        if grant.root != scope.root
            || grant.identity != scope.identity
            || scope.directories.len() != 4
            || policy.labels(&root).protected
            || policy.labels(&root).sensitive
            || policy.labels(&root).atomic_root.is_some()
            || !(1..=36500).contains(&scope.retention_days)
        {
            return Err(E::ProtectedRoot);
        }
        let mut expected = root.join(".file-tidy");
        let mut pins = Vec::new();
        for (index, directory) in scope.directories.iter().enumerate() {
            let path = directory.path.to_path()?;
            if index == 1 {
                expected.push("quarantine");
            }
            if index >= 2 {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(E::InvalidPath)?;
                let _: Id = name.parse()?;
                expected.push(name);
            }
            if path != expected {
                return Err(E::InvalidPlan);
            }
            match &directory.identity {
                Some(identity) => {
                    checked_existing(&path, false)?;
                    if platform::is_mount_boundary(&root, &path)? {
                        return Err(E::ProtectedRoot);
                    }
                    let node = platform::inspect(&path)?;
                    if node.identity.map(Identity::from).as_ref() != Some(identity)
                        || identity.volume != scope.identity.volume
                    {
                        return Err(E::ChangedSincePlan);
                    }
                    let pin = platform::open_directory_pinned(&path, &node)?;
                    platform::verify_private_file(&pin.try_clone_file()?, true)?;
                    pins.push(pin);
                }
                None => {
                    if let Some(stamp) = changed.get(&path) {
                        if platform::is_mount_boundary(&root, &path)? {
                            return Err(E::ProtectedRoot);
                        }
                        let node = platform::inspect(&checked_existing(&path, false)?)?;
                        if !stamp.same_identity(&node) {
                            return Err(E::ChangedSincePlan);
                        }
                        let pin = platform::open_directory_pinned(&path, &node)?;
                        platform::verify_private_file(&pin.try_clone_file()?, true)?;
                        pins.push(pin);
                    } else {
                        absent(&path)?;
                    }
                }
            }
        }
        if scope.payload.to_path()? != expected.join("payload") {
            return Err(E::InvalidPlan);
        }
        Ok(pins)
    }

    fn payload_permit(&self, scope: &QuarantineScope) -> Result<ManagedPayloadPermit> {
        if scope.directories.iter().any(|d| d.identity.is_none()) {
            return Err(E::StorageUnavailable);
        }
        self.validate_scope(scope, &BTreeMap::new())?;
        Ok(ManagedPayloadPermit {
            path: scope.payload.to_path()?,
        })
    }
    fn payload_manifest(
        &self,
        scope: &QuarantineScope,
        options: &PlanOptions,
    ) -> Result<Vec<ManifestEntry>> {
        let permit = self.payload_permit(scope)?;
        let mut budget = options.max_entries;
        self.manifest_with_access(
            &scope.payload.to_path()?,
            OperationKind::Restore,
            options,
            &planning_policy()?,
            &mut budget,
            ManifestAccess::Managed(&permit),
        )
    }

    pub(crate) fn validate_managed_operation(
        &self,
        plan: &Plan,
        op: &PlannedOperation,
        parents: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<()> {
        self.validate_plan_context(plan)?;
        let policy = planning_policy()?;
        let managed = op.managed.as_ref().ok_or(E::InvalidPlan)?;
        let scope = managed.scope();
        let _pins = self.validate_scope(scope, parents)?;
        let source = op.source.to_path()?;
        let destination = op.destination.as_ref().ok_or(E::InvalidPlan)?;
        let target = destination.path.to_path()?;
        let actual = match managed {
            ManagedOperation::Quarantine(_) if op.kind == OperationKind::Quarantine => {
                if target != scope.payload.to_path()? || !source.starts_with(scope.root.to_path()?)
                {
                    return Err(E::InvalidPlan);
                }
                self.check_source(&source, op.kind, &policy)?;
                let mut budget = plan.preview.options.max_entries;
                self.manifest(
                    &source,
                    op.kind,
                    &plan.preview.options,
                    &policy,
                    &mut budget,
                )?
            }
            ManagedOperation::Restore { item, .. } if op.kind == OperationKind::Restore => {
                if source != scope.payload.to_path()? {
                    return Err(E::InvalidPlan);
                }
                self.load_quarantine_item(item)?;
                if target
                    .components()
                    .any(|c| crate::authorization::managed_component(c.as_os_str()))
                {
                    return Err(E::ProtectedRoot);
                }
                let parent = checked_existing(&destination.existing_parent.to_path()?, false)?;
                let labels = policy.labels(&parent);
                if labels.protected
                    || labels.atomic_root.is_some()
                    || !destination.create_directories.is_empty()
                {
                    return Err(E::ProtectedRoot);
                }
                if self.grant_for(&parent, &policy)?.id()
                    != op.destination_grant.as_ref().ok_or(E::OutsideGrant)?
                {
                    return Err(E::InvalidPlan);
                }
                if Stamp::capture(&platform::inspect(&parent)?)?
                    != *parents.get(&parent).unwrap_or(&destination.parent_stamp)
                {
                    return Err(E::DestinationConflict);
                }
                self.payload_manifest(scope, &plan.preview.options)?
            }
            _ => return Err(E::InvalidPlan),
        };
        if self.grant_for(&source, &policy)?.id()
            != op.source_grant.as_ref().ok_or(E::OutsideGrant)?
        {
            return Err(E::InvalidPlan);
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
        for key in destination_acknowledgements(op, &policy)? {
            if !plan.preview.sensitive_acknowledgements.contains(&key) {
                return Err(E::ChangedSincePlan);
            }
        }
        absent(&target)
    }

    pub fn quarantine_items(&self, limit: usize, due_only: bool) -> Result<Vec<QuarantineItem>> {
        self.quarantine_items_in_batch(None, limit, due_only)
    }
    pub fn quarantine_items_in_batch(
        &self,
        batch: Option<&Id>,
        limit: usize,
        due_only: bool,
    ) -> Result<Vec<QuarantineItem>> {
        if !(1..=1000).contains(&limit) {
            return Err(E::InvalidRequest);
        }
        let at = now()?;
        self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
            let mut query = db.prepare("SELECT hex(q.item_id),hex(o.batch_id),q.path_encoding,q.original_path,q.storage_path,q.retained_at_s,q.expires_at_s,q.state FROM quarantine_items q JOIN operations o ON q.op_id=o.op_id WHERE (?1=0 OR (q.state='stored' AND q.expires_at_s<=?2)) AND (?4 IS NULL OR o.batch_id=?4) ORDER BY q.retained_at_s DESC,q.rowid DESC LIMIT ?3")?;
            let mut rows = query.query(params![due_only, at as i64, limit as i64, batch.map(id_bytes).transpose()?])?;
            let mut items = Vec::new();
            while let Some(row) = rows.next()? {
                let encoding: String = row.get(2)?;
                let retained: i64 = row.get(5)?;
                let expires: i64 = row.get(6)?;
                items.push(QuarantineItem { id: row.get::<_,String>(0)?.parse()?, batch_id: row.get::<_,String>(1)?.parse()?,
                    original_path: native_path(&encoding, &row.get::<_,Vec<u8>>(3)?)?, storage_path: native_path(&encoding, &row.get::<_,Vec<u8>>(4)?)?,
                    retained_at: retained.try_into().map_err(|_| E::StorageUnavailable)?, expires_at: expires.try_into().map_err(|_| E::StorageUnavailable)?, due: expires <= at as i64, state: row.get(7)? });
            }
            Ok(items)
        })
    }

    fn load_quarantine_item(&self, item: &Id) -> Result<(QuarantineScope, PlannedOperation)> {
        let (batch, digest, original, storage) = self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
            db.query_row("SELECT hex(o.batch_id),q.manifest_digest,q.original_path,q.storage_path FROM quarantine_items q JOIN operations o ON q.op_id=o.op_id WHERE q.item_id=?1 AND q.op_id=q.item_id AND q.state='stored' AND o.state='done'", [id_bytes(item)?], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?))).map_err(E::from)
        })?;
        let history = self.batch_history(&batch.parse()?)?;
        let preview: crate::plan::PlanPreview = serde_json::from_value(history.snapshot)?;
        let op = preview
            .operations
            .into_iter()
            .find(|op| &op.id == item && op.kind == OperationKind::Quarantine)
            .ok_or(E::StorageUnavailable)?;
        let scope: QuarantineScope =
            metadata(self, &item_key(item))?.ok_or(E::StorageUnavailable)?;
        let Some(ManagedOperation::Quarantine(planned)) = &op.managed else {
            return Err(E::StorageUnavailable);
        };
        if planned.payload != scope.payload
            || planned.root != scope.root
            || planned.identity != scope.identity
            || digest != blake3::hash(&serde_json::to_vec(&op.manifest)?).as_bytes()
            || path_bytes(&op.source)?.1 != original
            || path_bytes(&scope.payload)?.1 != storage
        {
            return Err(E::StorageUnavailable);
        }
        self.payload_permit(&scope)?;
        Ok((scope, op))
    }

    pub fn build_batch_restore_plan(
        &self,
        batch: &Id,
        destination: Option<&Path>,
        options: PlanOptions,
    ) -> Result<Plan> {
        let ids = self.store.as_ref().ok_or(E::StorageRequired)?.journal_read(|db| {
            let mut query = db.prepare("SELECT hex(q.item_id) FROM quarantine_items q JOIN operations o ON q.op_id=o.op_id WHERE o.batch_id=?1 AND q.state='stored' ORDER BY o.ordinal LIMIT 1001")?;
            let values = query.query_map([id_bytes(batch)?], |row|row.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if values.len()>1000 { return Err(E::Overflow); }
            values.iter().map(|v|v.parse()).collect::<Result<Vec<Id>>>()
        })?;
        self.build_restore_plan(&ids, destination, options)
    }

    pub fn build_restore_plan(
        &self,
        items: &[Id],
        destination: Option<&Path>,
        options: PlanOptions,
    ) -> Result<Plan> {
        // Reuse the option validation before examining retained objects.
        if items.is_empty()
            || items.len() > 1000
            || BTreeSet::from_iter(items).len() != items.len()
            || !(1..=1_000_000).contains(&options.max_entries)
            || !(1..=900).contains(&options.expires_after_seconds)
            || options.large_item_count > 100
            || options.large_byte_count > 10 * 1024 * 1024 * 1024
            || options.permanent_item_count > 10
            || options.permanent_byte_count > 1024 * 1024 * 1024
            || !(1..=36500).contains(&options.quarantine_retention_days)
        {
            return Err(E::InvalidRequest);
        }
        let policy = planning_policy()?;
        let mut operations = Vec::new();
        let mut requests = Vec::new();
        let mut reserved = HashSet::new();
        let mut budget = options.max_entries;
        for item in items {
            let (scope, original) = self.load_quarantine_item(item)?;
            if !options.include_hidden && original.manifest.iter().any(|e| e.hidden) {
                return Err(E::HiddenEntry);
            }
            let source = scope.payload.to_path()?;
            let mut manifest = self.payload_manifest(&scope, &options)?;
            compare_relocated(
                &original.source.to_path()?,
                &original.manifest,
                &source,
                &manifest,
            )?;
            budget = budget
                .checked_sub(manifest.len())
                .ok_or(E::IncompleteManifest)?;
            let old_source = original.source.to_path()?;
            let original_entries = original
                .manifest
                .iter()
                .map(|entry| {
                    Ok((
                        entry
                            .path
                            .to_path()?
                            .strip_prefix(&old_source)
                            .map_err(|_| E::InvalidPath)?
                            .to_owned(),
                        entry,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            for entry in &mut manifest {
                let path = entry.path.to_path()?;
                let relative = path.strip_prefix(&source).map_err(|_| E::InvalidPath)?;
                entry.sensitive |= original_entries
                    .get(relative)
                    .ok_or(E::ChangedSincePlan)?
                    .sensitive;
            }
            let target = match destination {
                None => old_source,
                Some(root) if items.len() > 1 => {
                    root.join(old_source.file_name().ok_or(E::InvalidPath)?)
                }
                Some(path) => path.to_owned(),
            };
            let target = resolve_destination(
                &target,
                &reserved,
                &source,
                OperationKind::Restore,
                options.max_entries,
            )?;
            if !target.create_directories.is_empty()
                || target
                    .path
                    .to_path()?
                    .components()
                    .any(|p| crate::authorization::managed_component(p.as_os_str()))
            {
                return Err(E::ProtectedRoot);
            }
            let parent = target.existing_parent.to_path()?;
            if platform::inspect(&parent)?
                .identity
                .ok_or(E::UnsupportedSafetyGuarantee)?
                .volume
                .to_string()
                != scope.identity.volume
            {
                return Err(E::UnsupportedSafetyGuarantee);
            }
            reserved.insert(target.path.to_path()?);
            requests.push(OperationRequest {
                kind: OperationKind::Restore,
                source: source.clone(),
                destination: Some(target.path.to_path()?),
            });
            operations.push(PlannedOperation {
                id: Id::new()?,
                kind: OperationKind::Restore,
                source: NativePath::new(&source),
                destination_grant: Some(self.grant_for(&parent, &policy)?.id().clone()),
                source_grant: Some(self.grant_for(&source, &policy)?.id().clone()),
                destination: Some(target),
                manifest,
                source_parent_stamp: Stamp::capture(&platform::inspect(
                    source.parent().ok_or(E::InvalidPath)?,
                )?)?,
                managed: Some(ManagedOperation::Restore {
                    item: item.clone(),
                    scope,
                }),
            });
        }
        self.seal_plan(operations, requests, options, Id::new()?)
    }

    pub(crate) fn select_restores(&self, plan: &Plan, wanted: &BTreeSet<&Id>) -> Result<Plan> {
        let mut selected = Vec::new();
        let mut requests = Vec::new();
        for (op, request) in plan.preview.operations.iter().zip(&plan.requests) {
            if wanted.contains(&op.id) {
                let mut op = op.clone();
                op.id = Id::new()?;
                selected.push(op);
                requests.push(request.clone());
            }
        }
        self.seal_plan(selected, requests, plan.preview.options.clone(), Id::new()?)
    }

    pub(crate) fn inspect_interrupted_managed(
        &self,
        op: &PlannedOperation,
        history: &crate::journal::BatchHistoryDetail,
    ) -> Result<(crate::recovery::RecoveryDisposition, String)> {
        use crate::recovery::RecoveryDisposition as D;
        let managed = op.managed.as_ref().ok_or(E::StorageUnavailable)?;
        let source = op.source.to_path()?;
        let target = op
            .destination
            .as_ref()
            .ok_or(E::StorageUnavailable)?
            .path
            .to_path()?;
        let step = if op.kind == OperationKind::Quarantine {
            "quarantine_move"
        } else {
            "restore_move"
        };
        let intent = history.events.iter().find(|event| {
            event.operation_id == op.id.as_str() && event.step == step && event.phase == "intent"
        });
        let options = PlanOptions {
            include_hidden: true,
            max_entries: op.manifest.len(),
            ..Default::default()
        };
        let policy = planning_policy()?;
        let current_scope = if let Some(intent) = intent {
            if intent.payload.get("source") != Some(&serde_json::to_value(&op.source)?)
                || intent.payload.get("destination")
                    != Some(&serde_json::to_value(&op.destination)?)
                || intent
                    .payload
                    .get("manifest_digest")
                    .and_then(|v| v.as_str())
                    != Some(
                        blake3::hash(&serde_json::to_vec(&op.manifest)?)
                            .to_hex()
                            .as_str(),
                    )
            {
                return Err(E::StorageUnavailable);
            }
            let scope: QuarantineScope = serde_json::from_value(
                intent
                    .payload
                    .get("scope")
                    .ok_or(E::StorageUnavailable)?
                    .clone(),
            )?;
            if scope.payload != managed.scope().payload
                || scope.root != managed.scope().root
                || scope.identity != managed.scope().identity
            {
                return Err(E::StorageUnavailable);
            }
            self.payload_permit(&scope)?;
            Some(scope)
        } else {
            None
        };
        let source_exists = match std::fs::symlink_metadata(&source) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let target_exists = match std::fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        if source_exists && !target_exists {
            let actual = if op.kind == OperationKind::Restore {
                self.payload_manifest(current_scope.as_ref().unwrap_or(managed.scope()), &options)?
            } else {
                self.check_source(&source, op.kind, &policy)?;
                let mut budget = options.max_entries;
                self.manifest(&source, op.kind, &options, &policy, &mut budget)?
            };
            compare_relocated(&source, &op.manifest, &source, &actual)?;
            return Ok((
                D::NotCommitted,
                "source_retained_managed_directories_listed_in_history".into(),
            ));
        }
        if !source_exists
            && target_exists
            && let Some(scope) = current_scope
        {
            let actual = if op.kind == OperationKind::Quarantine {
                if target != scope.payload.to_path()? {
                    return Err(E::StorageUnavailable);
                }
                self.payload_manifest(&scope, &options)?
            } else {
                let parent = checked_existing(target.parent().ok_or(E::InvalidPath)?, false)?;
                self.grant_for(&parent, &policy)?;
                if target
                    .components()
                    .any(|c| crate::authorization::managed_component(c.as_os_str()))
                {
                    return Err(E::ProtectedRoot);
                }
                let mut budget = options.max_entries;
                self.manifest(&target, op.kind, &options, &policy, &mut budget)?
            };
            compare_relocated(&source, &op.manifest, &target, &actual)?;
            return Ok((
                D::RenameObserved,
                "managed_rename_observed_journal_completion_requires_review".into(),
            ));
        }
        Ok((
            D::NeedsAttention,
            "managed_operation_outcome_is_ambiguous".into(),
        ))
    }

    pub(crate) fn execute_managed(
        &mut self,
        plan: &Plan,
        op: &PlannedOperation,
        parents: &mut BTreeMap<PathBuf, Stamp>,
        cancel: &CancellationToken,
    ) -> std::result::Result<(), CopyFailure> {
        let mut created = false;
        let mut journal = false;
        let mut step = "quarantine_directory";
        let mut run = || -> Result<()> {
            let managed = op.managed.as_ref().ok_or(E::InvalidPlan)?;
            let mut scope = managed.scope().clone();
            for index in 0..scope.directories.len() {
                let path = scope.directories[index].path.to_path()?;
                if scope.directories[index].identity.is_some() {
                    continue;
                }
                if parents.contains_key(&path) {
                    scope.directories[index].identity = Some(
                        platform::inspect(&path)?
                            .identity
                            .ok_or(E::UnsupportedSafetyGuarantee)?
                            .into(),
                    );
                    continue;
                }
                checkpoint(cancel)?;
                self.validate_managed_operation(plan, op, parents)?;
                let parent = path.parent().ok_or(E::InvalidPath)?;
                let before = platform::inspect(parent)?;
                let pin = platform::open_directory_pinned(parent, &before)?;
                let intent = json!({"directory": NativePath::new(&path), "parent": Stamp::capture(&before)?});
                self.store
                    .as_mut()
                    .ok_or(E::StorageRequired)?
                    .record_intent(&op.id, step, &intent)
                    .inspect_err(|_| journal = true)?;
                self.validate_managed_operation(plan, op, parents)?;
                checkpoint(cancel)?;
                created = true;
                let file = platform::create_private_directory(
                    &pin,
                    path.file_name().ok_or(E::InvalidPath)?,
                )?;
                let node = platform::inspect(&checked_existing(&path, false)?)?;
                if node.identity != platform::inspect_file(&file)?.identity {
                    return Err(E::ChangedSincePlan);
                }
                #[cfg(unix)]
                file.sync_all()?;
                let identity = Identity::from(node.identity.ok_or(E::UnsupportedSafetyGuarantee)?);
                scope.directories[index].identity = Some(identity);
                update_parent(parent, &before, parents)?;
                parents.insert(path.clone(), Stamp::capture(&node)?);
                let record = RootRecord {
                    root: scope.root.clone(),
                    identity: scope.identity.clone(),
                    container: scope.directories[0].identity.clone(),
                    quarantine: scope.directories[1].identity.clone(),
                };
                let key = root_key(&scope.identity)?;
                self.store.as_mut().ok_or(E::StorageRequired)?.record_managed_result(&op.id, step, &json!({"directory": NativePath::new(&path), "stamp": Stamp::capture(&node)?}), OperationState::Prepared,
                    |tx| save_metadata(tx, &key, &record)).inspect_err(|_| journal = true)?;
            }
            #[cfg(test)]
            faults::after_directories()?;
            step = if op.kind == OperationKind::Quarantine {
                "quarantine_move"
            } else {
                "restore_move"
            };
            checkpoint(cancel)?;
            self.validate_managed_operation(plan, op, parents)?;
            let _pins = self.validate_scope(&scope, parents)?;
            let source = op.source.to_path()?;
            let destination = op
                .destination
                .as_ref()
                .ok_or(E::InvalidPlan)?
                .path
                .to_path()?;
            let source_parent = source.parent().ok_or(E::InvalidPath)?;
            let target_parent = destination.parent().ok_or(E::InvalidPath)?;
            let source_before = platform::inspect(&source)?;
            let source_parent_before = platform::inspect(source_parent)?;
            let target_parent_before = platform::inspect(target_parent)?;
            self.store.as_mut().ok_or(E::StorageRequired)?.record_intent(&op.id, step, &json!({"source": op.source, "destination": op.destination, "scope": scope, "manifest_digest": blake3::hash(&serde_json::to_vec(&op.manifest)?).to_hex().to_string()})).inspect_err(|_| journal = true)?;
            self.validate_managed_operation(plan, op, parents)?;
            checkpoint(cancel)?;
            // All fallible native outcomes retain both locations for diagnosis.
            platform::rename_noreplace(
                &source,
                &source_before,
                &destination,
                &source_parent_before,
                &target_parent_before,
            )
            .map_err(|error| {
                created |= error.may_have_moved;
                E::from(error.error)
            })?;
            created = true;
            #[cfg(test)]
            faults::after_move()?;
            let verify = || -> Result<Vec<ManifestEntry>> {
                let options = PlanOptions {
                    include_hidden: true,
                    max_entries: op.manifest.len(),
                    ..Default::default()
                };
                if op.kind == OperationKind::Quarantine {
                    self.payload_manifest(&scope, &options)
                } else {
                    let mut budget = op.manifest.len();
                    self.manifest(
                        &destination,
                        OperationKind::Restore,
                        &options,
                        &planning_policy()?,
                        &mut budget,
                    )
                }
            };
            let actual = verify()?;
            compare_relocated(&source, &op.manifest, &destination, &actual)?;
            if verify()? != actual {
                return Err(E::ChangedSincePlan);
            }
            absent(&source)?;
            update_parent(source_parent, &source_parent_before, parents)?;
            update_parent(target_parent, &target_parent_before, parents)?;
            self.validate_scope(&scope, parents)?;
            let retained = now()?;
            let expires = retained
                .checked_add(scope.retention_days.checked_mul(86400).ok_or(E::Overflow)?)
                .ok_or(E::Overflow)?;
            let result = json!({"source": op.source, "destination": NativePath::new(&destination), "observed_manifest": actual});
            self.store.as_mut().ok_or(E::StorageRequired)?.record_managed_result(&op.id, step, &result, OperationState::Done, |tx| {
                match managed {
                    ManagedOperation::Quarantine(_) => {
                        let (encoding, original) = path_bytes(&op.source)?;
                        tx.execute("INSERT INTO quarantine_items(item_id,op_id,grant_id,path_encoding,original_path,storage_path,manifest_digest,retained_at_s,expires_at_s,state) VALUES(?1,?1,?2,?3,?4,?5,?6,?7,?8,'stored')",
                            params![id_bytes(&op.id)?, id_bytes(op.source_grant.as_ref().ok_or(E::OutsideGrant)?)?, encoding, original, path_bytes(&scope.payload)?.1, blake3::hash(&serde_json::to_vec(&op.manifest)?).as_bytes(), retained as i64, expires as i64])?;
                        save_metadata(tx, &item_key(&op.id), &scope)?;
                    }
                    ManagedOperation::Restore { item, .. } => {
                        if tx.execute("UPDATE quarantine_items SET state='restored' WHERE item_id=?1 AND state='stored'", [id_bytes(item)?])? != 1 { return Err(E::StorageUnavailable); }
                    }
                }
                Ok(())
            }).inspect_err(|_| journal = true)?;
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

fn compare_relocated(
    source: &Path,
    expected: &[ManifestEntry],
    destination: &Path,
    actual: &[ManifestEntry],
) -> Result<()> {
    if expected.len() != actual.len() {
        return Err(E::ChangedSincePlan);
    }
    let entries = expected
        .iter()
        .map(|entry| {
            Ok((
                entry
                    .path
                    .to_path()?
                    .strip_prefix(source)
                    .map_err(|_| E::InvalidPath)?
                    .to_owned(),
                entry,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for entry in actual {
        let path = entry.path.to_path()?;
        let relative = path.strip_prefix(destination).map_err(|_| E::InvalidPath)?;
        let before = entries.get(relative).ok_or(E::ChangedSincePlan)?;
        let dot = |path: &Path| {
            path.file_name()
                .is_some_and(|n| n.as_encoded_bytes().first() == Some(&b'.'))
        };
        if !before
            .stamp
            .matches_relocated(&entry.stamp, dot(&before.path.to_path()?) != dot(&path))
            || before.link_target != entry.link_target
            || before.symlink_directory != entry.symlink_directory
        {
            return Err(E::ChangedSincePlan);
        }
    }
    Ok(())
}

#[cfg(test)]
mod faults {
    use super::*;
    use std::cell::RefCell;
    type Hook = RefCell<Option<Box<dyn FnOnce() -> Result<()>>>>;
    thread_local! {
        static AFTER_DIRECTORIES: Hook = RefCell::new(None);
        static AFTER_MOVE: Hook = RefCell::new(None);
    }
    pub(super) fn after_directories() -> Result<()> {
        AFTER_DIRECTORIES
            .with(|h| h.borrow_mut().take())
            .map_or(Ok(()), |hook| hook())
    }
    pub(super) fn after_move() -> Result<()> {
        AFTER_MOVE
            .with(|h| h.borrow_mut().take())
            .map_or(Ok(()), |hook| hook())
    }
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    fn setup() -> std::result::Result<(tempfile::TempDir, Session), Box<dyn std::error::Error>> {
        let root = std::env::var_os("FILE_TIDY_TEST_ROOT").ok_or("FILE_TIDY_TEST_ROOT required")?;
        let directory = tempfile::tempdir_in(root)?;
        let mut session = Session::new()?;
        let grant = session.grant(directory.path(), false)?;
        let plan = session.storage_plan(&grant)?;
        let digest = plan.digest().to_owned();
        session.initialize_storage(plan, &digest)?;
        std::fs::write(directory.path().join("source"), b"original")?;
        Ok((directory, session))
    }
    fn approved(session: &mut Session, root: &Path) -> Result<crate::approval::ApprovedPlan> {
        let plan = session.build_plan(
            vec![OperationRequest {
                kind: OperationKind::Quarantine,
                source: root.join("source"),
                destination: None,
            }],
            PlanOptions::default(),
        )?;
        let confirmation = crate::approval::Confirmation {
            digest: plan.digest().into(),
            ..Default::default()
        };
        session.confirm(plan, confirmation)
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn cancellation_after_directory_creation_keeps_the_source_and_registered_artifacts()
    -> TestResult {
        let (directory, mut session) = setup()?;
        let approved = approved(&mut session, directory.path())?;
        let token = CancellationToken::new();
        let cancel = token.clone();
        AFTER_DIRECTORIES.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                cancel.cancel();
                Ok(())
            }))
        });
        let report = session.execute_approved(approved, &token)?;
        assert_eq!(
            report.operations[0].status,
            crate::execution::ExecutionStatus::NeedsRecovery,
            "{report:?}"
        );
        assert_eq!(std::fs::read(directory.path().join("source"))?, b"original");
        assert!(session.quarantine_items(10, false)?.is_empty());
        assert_eq!(
            session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
            crate::recovery::RecoveryDisposition::NotCommitted
        );
        let approved = self::approved(&mut session, directory.path())?;
        assert!(
            session
                .execute_approved(approved, &CancellationToken::new())?
                .completed()
        );
        Ok(())
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn interrupted_quarantine_is_observed_without_inventing_an_item_record() -> TestResult {
        let (directory, mut session) = setup()?;
        let approved = approved(&mut session, directory.path())?;
        AFTER_MOVE.with(|h| *h.borrow_mut() = Some(Box::new(|| Err(E::ChangedSincePlan))));
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert_eq!(
            report.operations[0].status,
            crate::execution::ExecutionStatus::NeedsRecovery,
            "{report:?}"
        );
        let payload = report.operations[0]
            .destination
            .as_ref()
            .ok_or("destination")?
            .to_path()?;
        assert_eq!(std::fs::read(&payload)?, b"original");
        assert!(!directory.path().join("source").exists());
        assert!(session.quarantine_items(10, false)?.is_empty());
        let before = session.batch_history(&report.batch_id)?;
        assert_eq!(
            session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
            crate::recovery::RecoveryDisposition::RenameObserved
        );
        assert_eq!(
            serde_json::to_value(before)?,
            serde_json::to_value(session.batch_history(&report.batch_id)?)?
        );
        Ok(())
    }
    #[test]
    #[ignore = "requires independent FILE_TIDY_TEST_ROOT"]
    fn interrupted_restore_reports_the_relocated_object_and_keeps_original_audit() -> TestResult {
        let (directory, mut session) = setup()?;
        let approved = approved(&mut session, directory.path())?;
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert!(report.completed(), "{report:?}");
        let item = session.quarantine_items(10, false)?.remove(0).id;
        let plan = session.build_restore_plan(&[item], None, PlanOptions::default())?;
        let confirmation = crate::approval::Confirmation {
            digest: plan.digest().into(),
            ..Default::default()
        };
        let approved = session.confirm(plan, confirmation)?;
        AFTER_MOVE.with(|h| *h.borrow_mut() = Some(Box::new(|| Err(E::ChangedSincePlan))));
        let report = session.execute_approved(approved, &CancellationToken::new())?;
        assert_eq!(
            report.operations[0].status,
            crate::execution::ExecutionStatus::NeedsRecovery,
            "{report:?}"
        );
        assert_eq!(std::fs::read(directory.path().join("source"))?, b"original");
        assert_eq!(
            session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
            crate::recovery::RecoveryDisposition::RenameObserved
        );
        assert_eq!(session.quarantine_items(10, false)?[0].state, "stored");
        Ok(())
    }
}
