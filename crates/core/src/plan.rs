//! Read-only operation planning and complete directory manifests.
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use file_tidy_platform::{NodeInfo, NodeKind};
use serde::{Deserialize, Serialize};

use crate::authorization::{
    Id, Identity, NativePath, PlanningError as E, Result, Session, checked_existing,
    planning_policy,
};
use crate::policy::Policy;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Copy,
    Move,
    Rename,
    Quarantine,
    PermanentDelete,
}
impl OperationKind {
    pub(crate) fn modifies_source(self) -> bool {
        self != Self::Copy
    }
    fn needs_destination(self) -> bool {
        matches!(self, Self::Copy | Self::Move | Self::Rename)
    }
}

#[derive(Clone, Debug)]
pub struct OperationRequest {
    pub kind: OperationKind,
    pub source: PathBuf,
    pub destination: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanOptions {
    pub include_hidden: bool,
    pub max_entries: usize,
    pub expires_after_seconds: u64,
    pub large_item_count: u64,
    pub large_byte_count: u64,
    pub permanent_item_count: u64,
    pub permanent_byte_count: u64,
}
impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_entries: 100_000,
            expires_after_seconds: 900,
            large_item_count: 100,
            large_byte_count: 10 * 1024 * 1024 * 1024,
            permanent_item_count: 10,
            permanent_byte_count: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stamp {
    kind: String,
    identity: Identity,
    length: String,
    modified: String,
    hidden: bool,
    links: u64,
}
impl Stamp {
    pub(crate) fn capture(node: &NodeInfo) -> Result<Self> {
        Ok(Self {
            kind: format!("{:?}", node.kind),
            identity: node.identity.ok_or(E::UnsupportedSafetyGuarantee)?.into(),
            length: node.len.to_string(),
            modified: format!("{:?}", node.modified.ok_or(E::UnsupportedSafetyGuarantee)?),
            hidden: node.hidden,
            links: node.links,
        })
    }
    pub(crate) fn same_identity(&self, node: &NodeInfo) -> bool {
        node.identity.map(Identity::from).as_ref() == Some(&self.identity)
            && self.kind == format!("{:?}", node.kind)
    }
    pub(crate) fn matches_relocated(&self, other: &Self, name_hidden_changed: bool) -> bool {
        let mut actual = other.clone();
        // A rename can change the dot-name hidden flag without changing the object.
        if name_hidden_changed {
            actual.hidden = self.hidden;
        }
        *self == actual
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub path: NativePath,
    pub kind: String,
    pub size_bytes: String,
    pub hidden: bool,
    pub sensitive: bool,
    pub link_target: Option<NativePath>,
    pub(crate) stamp: Stamp,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub path: NativePath,
    pub existing_parent: NativePath,
    pub create_directories: Vec<NativePath>,
    pub renamed_for_conflict: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spelling_temporary: Option<NativePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_temporary: Option<NativePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_metadata: Option<CopyMetadataPolicy>,
    pub(crate) parent_stamp: Stamp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CopyMetadataPolicy {
    PrivateDataStreamAndMtime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedOperation {
    pub id: Id,
    pub kind: OperationKind,
    pub source: NativePath,
    pub destination: Option<Destination>,
    pub manifest: Vec<ManifestEntry>,
    pub source_grant: Option<Id>,
    pub destination_grant: Option<Id>,
    pub(crate) source_parent_stamp: Stamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPreview {
    pub id: Id,
    pub created_at: u64,
    pub expires_at: u64,
    pub authorization_epoch: u64,
    pub policy_digest: String,
    pub operations: Vec<PlannedOperation>,
    pub files_and_links: u64,
    pub directories: u64,
    pub empty_directories: u64,
    pub confirmation_count: u64,
    pub total_bytes: String,
    pub requires_count_confirmation: bool,
    pub sensitive_acknowledgements: Vec<String>,
    pub permanent_challenge: Option<String>,
    pub options: PlanOptions,
}

/// The serialized preview is review data; only the live session can confirm it.
pub struct Plan {
    pub(crate) session: Id,
    pub(crate) digest: String,
    pub(crate) preview: PlanPreview,
    pub(crate) requests: Vec<OperationRequest>,
}
impl Plan {
    pub fn preview(&self) -> &PlanPreview {
        &self.preview
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn acknowledgement_description(&self, key: &str) -> Result<String> {
        let mut parts = key.split(':');
        let operation_id = parts.next().ok_or(E::InvalidRequest)?;
        let entry_id = parts.next().ok_or(E::InvalidRequest)?;
        let scope = parts.next().ok_or(E::InvalidRequest)?;
        let operation = self
            .preview
            .operations
            .iter()
            .find(|op| op.id.as_str() == operation_id)
            .ok_or(E::InvalidRequest)?;
        let path = if entry_id == "destination" {
            operation
                .destination
                .as_ref()
                .ok_or(E::InvalidRequest)?
                .path
                .display
                .clone()
        } else {
            operation
                .manifest
                .iter()
                .find(|entry| {
                    serde_json::to_vec(&entry.path)
                        .is_ok_and(|bytes| blake3::hash(&bytes).to_hex().as_str() == entry_id)
                })
                .ok_or(E::InvalidRequest)?
                .path
                .display
                .clone()
        };
        Ok(format!(
            "敏感项逐项许可：{path}（{}）",
            if scope == "content" {
                "读取内容用于复制和完整性校验"
            } else {
                "修改文件或目标位置"
            }
        ))
    }
    pub fn review_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Review<'a> {
            digest: &'a str,
            plan: &'a PlanPreview,
        }
        Ok(serde_json::to_string_pretty(&Review {
            digest: &self.digest,
            plan: &self.preview,
        })?)
    }
}

impl Session {
    pub fn build_plan(
        &self,
        requests: Vec<OperationRequest>,
        options: PlanOptions,
    ) -> Result<Plan> {
        if requests.is_empty()
            || requests.len() > 10_000
            || !(1..=1_000_000).contains(&options.max_entries)
            || !(1..=900).contains(&options.expires_after_seconds)
            || options.large_item_count > 100
            || options.large_byte_count > 10 * 1024 * 1024 * 1024
            || options.permanent_item_count > 10
            || options.permanent_byte_count > 1024 * 1024 * 1024
        {
            return Err(E::InvalidRequest);
        }
        let policy = planning_policy()?;
        let mut operations = Vec::new();
        let mut resolved = Vec::new();
        let mut reserved = HashSet::new();
        let mut budget = options.max_entries;
        for request in requests {
            if request.kind.needs_destination() != request.destination.is_some() {
                return Err(E::InvalidRequest);
            }
            let source = checked_existing(&request.source, true)?;
            self.check_source(&source, request.kind, &policy)?;
            let manifest = self.manifest(&source, request.kind, &options, &policy, &mut budget)?;
            let source_grant = if request.kind.modifies_source() {
                Some(self.grant_for(&source, &policy)?.id().clone())
            } else {
                None
            };
            let destination = request
                .destination
                .as_deref()
                .map(|path| {
                    resolve_destination(path, &reserved, &source, request.kind, options.max_entries)
                })
                .transpose()?;
            let destination_grant = if let Some(destination) = &destination {
                let parent = destination.existing_parent.to_path()?;
                if policy.labels(&parent).protected {
                    return Err(E::ProtectedZone);
                }
                let grant = self.grant_for(&parent, &policy)?;
                let path = destination.path.to_path()?;
                if source.starts_with(&path) || path.starts_with(&source) {
                    return Err(E::OverlappingOperations);
                }
                if path
                    .components()
                    .any(|c| crate::authorization::managed_component(c.as_os_str()))
                {
                    return Err(E::ProtectedRoot);
                }
                let parent_labels = policy.labels(&parent);
                if parent_labels.atomic_root.is_some() {
                    return Err(E::AtomicBoundary);
                }
                reserved.insert(path);
                for temporary in destination
                    .spelling_temporary
                    .iter()
                    .chain(&destination.copy_temporary)
                {
                    reserved.insert(temporary.to_path()?);
                }
                Some(grant.id().clone())
            } else {
                None
            };
            resolved.push(OperationRequest {
                kind: request.kind,
                source: source.clone(),
                destination: destination.as_ref().map(|d| d.path.to_path()).transpose()?,
            });
            operations.push(PlannedOperation {
                id: Id::new()?,
                kind: request.kind,
                source: NativePath::new(&source),
                destination,
                manifest,
                source_grant,
                destination_grant,
                source_parent_stamp: Stamp::capture(&file_tidy_platform::inspect(
                    source.parent().ok_or(E::InvalidPath)?,
                )?)?,
            });
        }
        for (index, request) in resolved.iter().enumerate() {
            for other in resolved.iter().skip(index + 1) {
                if request
                    .destination
                    .as_ref()
                    .zip(other.destination.as_ref())
                    .is_some_and(|(a, b)| a.starts_with(b) || b.starts_with(a))
                {
                    return Err(E::OverlappingOperations);
                }
                if request.source.starts_with(&other.source)
                    || other.source.starts_with(&request.source)
                    || request.destination.as_ref().is_some_and(|dest| {
                        dest.starts_with(&other.source) || other.source.starts_with(dest)
                    })
                    || other.destination.as_ref().is_some_and(|dest| {
                        dest.starts_with(&request.source) || request.source.starts_with(dest)
                    })
                {
                    return Err(E::OverlappingOperations);
                }
            }
        }
        // Sensitive names propagate across known hardlink aliases in this plan.
        let sensitive_ids: BTreeSet<_> = operations
            .iter()
            .flat_map(|op| &op.manifest)
            .filter(|entry| entry.sensitive)
            .map(|entry| entry.stamp.identity.file.clone() + ":" + &entry.stamp.identity.volume)
            .collect();
        for entry in operations.iter_mut().flat_map(|op| &mut op.manifest) {
            entry.sensitive |= sensitive_ids.contains(
                &(entry.stamp.identity.file.clone() + ":" + &entry.stamp.identity.volume),
            );
        }
        let mut files = 0u64;
        let mut directories = 0u64;
        let mut empty_directories = 0u64;
        let mut bytes = 0u64;
        let mut sensitive = BTreeSet::new();
        let mut permanent = false;
        for operation in &operations {
            permanent |= operation.kind == OperationKind::PermanentDelete;
            let mut nonempty_directories = HashSet::new();
            for child in &operation.manifest {
                if let Some(parent) = child.path.to_path()?.parent() {
                    nonempty_directories.insert(parent.to_path_buf());
                }
            }
            for entry in &operation.manifest {
                if entry.kind == "Directory" {
                    directories = directories.checked_add(1).ok_or(E::Overflow)?;
                    let entry_path = entry.path.to_path()?;
                    if !nonempty_directories.contains(&entry_path) {
                        empty_directories = empty_directories.checked_add(1).ok_or(E::Overflow)?;
                    }
                } else {
                    files = files.checked_add(1).ok_or(E::Overflow)?;
                }
                if entry.kind == "Regular" {
                    bytes = bytes
                        .checked_add(entry.size_bytes.parse::<u64>().map_err(|_| E::Overflow)?)
                        .ok_or(E::Overflow)?;
                }
                if entry.sensitive {
                    let path_digest = blake3::hash(&serde_json::to_vec(&entry.path)?)
                        .to_hex()
                        .to_string();
                    if operation.kind.modifies_source() {
                        sensitive.insert(format!("{}:{path_digest}:write", operation.id));
                    }
                    let cross_volume = operation.destination.as_ref().is_some_and(|d| {
                        d.parent_stamp.identity.volume != entry.stamp.identity.volume
                    });
                    if operation.kind == OperationKind::Copy
                        || (operation.kind == OperationKind::Move && cross_volume)
                    {
                        sensitive.insert(format!("{}:{path_digest}:content", operation.id));
                    }
                }
            }
            if let Some(dest) = &operation.destination {
                let parent = dest.existing_parent.to_path()?;
                if policy.labels(&parent).sensitive || destination_sensitive(&dest.path.to_path()?)
                {
                    sensitive.insert(format!("{}:destination:write", operation.id));
                }
            }
        }
        if bytes > i64::MAX as u64 {
            return Err(E::Overflow);
        }
        let confirmation_count = files.checked_add(empty_directories).ok_or(E::Overflow)?;
        let created_at = now()?;
        let preview = PlanPreview {
            id: Id::new()?,
            created_at,
            expires_at: created_at
                .checked_add(options.expires_after_seconds)
                .ok_or(E::Overflow)?,
            authorization_epoch: self.epoch,
            policy_digest: policy_digest(),
            requires_count_confirmation: confirmation_count > options.large_item_count
                || bytes > options.large_byte_count
                || (permanent
                    && (confirmation_count > options.permanent_item_count
                        || bytes > options.permanent_byte_count)),
            options,
            operations,
            files_and_links: files,
            directories,
            empty_directories,
            confirmation_count,
            total_bytes: bytes.to_string(),
            sensitive_acknowledgements: sensitive.into_iter().collect(),
            permanent_challenge: if permanent {
                Some(Id::new()?.to_string())
            } else {
                None
            },
        };
        let digest = blake3::hash(&serde_json::to_vec(&preview)?)
            .to_hex()
            .to_string();
        let plan = Plan {
            session: self.id.clone(),
            digest,
            preview,
            requests: resolved,
        };
        self.validate_plan(&plan)?;
        Ok(plan)
    }

    pub fn select_operations(&self, plan: &Plan, ids: &[Id]) -> Result<Plan> {
        self.validate_plan(plan)?;
        let wanted: BTreeSet<_> = ids.iter().collect();
        if wanted.len() != ids.len()
            || wanted.is_empty()
            || wanted
                .iter()
                .any(|id| !plan.preview.operations.iter().any(|op| &op.id == *id))
        {
            return Err(E::InvalidRequest);
        }
        let requests = plan
            .preview
            .operations
            .iter()
            .zip(&plan.requests)
            .filter(|(op, _)| wanted.contains(&op.id))
            .map(|(_, req)| req.clone())
            .collect();
        self.build_plan(requests, plan.preview.options.clone())
    }

    pub fn validate_plan(&self, plan: &Plan) -> Result<()> {
        self.validate_plan_context(plan)?;
        let parents = BTreeMap::new();
        for operation in &plan.preview.operations {
            self.validate_operation(plan, operation, &parents)?;
        }
        Ok(())
    }

    pub(crate) fn validate_plan_context(&self, plan: &Plan) -> Result<()> {
        if plan.session != self.id
            || plan.preview.authorization_epoch != self.epoch
            || plan.preview.policy_digest != policy_digest()
            || now()? >= plan.preview.expires_at
        {
            return Err(E::InvalidPlan);
        }
        Ok(())
    }

    pub(crate) fn validate_operation(
        &self,
        plan: &Plan,
        operation: &PlannedOperation,
        changed_parents: &BTreeMap<PathBuf, Stamp>,
    ) -> Result<()> {
        self.validate_plan_context(plan)?;
        let policy = planning_policy()?;
        let source = operation.source.to_path()?;
        self.check_source(&source, operation.kind, &policy)?;
        let source_parent = checked_existing(source.parent().ok_or(E::InvalidPath)?, false)?;
        let expected_parent = changed_parents
            .get(&source_parent)
            .unwrap_or(&operation.source_parent_stamp);
        if Stamp::capture(&file_tidy_platform::inspect(&source_parent)?)? != *expected_parent {
            return Err(E::ChangedSincePlan);
        }
        let mut budget = plan.preview.options.max_entries;
        let manifest = self.manifest(
            &source,
            operation.kind,
            &plan.preview.options,
            &policy,
            &mut budget,
        )?;
        // Sensitive flags also include cross-operation hardlink propagation.
        if manifest.len() != operation.manifest.len()
            || manifest.iter().zip(&operation.manifest).any(|(a, b)| {
                a.path != b.path
                    || a.stamp != b.stamp
                    || a.link_target != b.link_target
                    || a.hidden != b.hidden
                    || (a.sensitive && !b.sensitive)
            })
        {
            return Err(E::ChangedSincePlan);
        }
        if let Some(id) = &operation.source_grant
            && self.grant_for(&source, &policy)?.id() != id
        {
            return Err(E::InvalidPlan);
        }
        if let Some(dest) = &operation.destination {
            let parent = checked_existing(&dest.existing_parent.to_path()?, false)?;
            let expected = changed_parents.get(&parent).unwrap_or(&dest.parent_stamp);
            if Stamp::capture(&file_tidy_platform::inspect(&parent)?)? != *expected {
                return Err(E::DestinationConflict);
            }
            let labels = policy.labels(&parent);
            if labels.protected {
                return Err(E::ProtectedZone);
            }
            if labels.atomic_root.is_some() {
                return Err(E::AtomicBoundary);
            }
            if self.grant_for(&parent, &policy)?.id()
                != operation
                    .destination_grant
                    .as_ref()
                    .ok_or(E::OutsideGrant)?
            {
                return Err(E::InvalidPlan);
            }
            // A newly sensitive destination needs a new per-item confirmation.
            if (labels.sensitive || destination_sensitive(&dest.path.to_path()?))
                && !plan
                    .preview
                    .sensitive_acknowledgements
                    .contains(&format!("{}:destination:write", operation.id))
            {
                return Err(E::ChangedSincePlan);
            }
            let mut missing_paths = dest.create_directories.iter().collect::<Vec<_>>();
            if let Some(temporary) = &dest.copy_temporary {
                if operation.kind != OperationKind::Copy
                    || temporary.to_path()?.parent() != dest.path.to_path()?.parent()
                    || dest.copy_metadata != Some(CopyMetadataPolicy::PrivateDataStreamAndMtime)
                {
                    return Err(E::InvalidPlan);
                }
                missing_paths.push(temporary);
            }
            if let Some(temporary) = &dest.spelling_temporary {
                if operation.kind != OperationKind::Rename
                    || !dest.create_directories.is_empty()
                    || !same_entry_spelling(
                        &source,
                        &dest.path.to_path()?,
                        plan.preview.options.max_entries,
                    )?
                    || temporary.to_path()?.parent() != source.parent()
                {
                    return Err(E::DestinationConflict);
                }
                missing_paths.push(temporary);
            } else {
                missing_paths.push(&dest.path);
            }
            for missing in missing_paths {
                match std::fs::symlink_metadata(missing.to_path()?) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(E::DestinationConflict),
                }
            }
        }
        Ok(())
    }

    fn check_source(&self, source: &Path, kind: OperationKind, policy: &Policy) -> Result<()> {
        let labels = if file_tidy_platform::inspect(source)?.kind == NodeKind::Symlink {
            policy.labels(source.parent().ok_or(E::InvalidPath)?)
        } else {
            policy.labels(source)
        };
        if source
            .components()
            .any(|p| crate::authorization::managed_component(p.as_os_str()))
        {
            return Err(E::ProtectedRoot);
        }
        if labels
            .atomic_root
            .as_deref()
            .is_some_and(|root| root != source)
        {
            return Err(E::AtomicBoundary);
        }
        if kind.modifies_source() {
            if labels.protected {
                return Err(E::ProtectedZone);
            }
            self.grant_for(source, policy)?;
            for grant in self.grants.values().filter(|grant| !grant.revoked) {
                if grant.root.to_path()?.starts_with(source) {
                    return Err(E::ProtectedRoot);
                }
            }
            if file_tidy_platform::classify_location(source)?.mount_root == source {
                return Err(E::ProtectedRoot);
            }
        }
        Ok(())
    }

    pub(crate) fn manifest(
        &self,
        source: &Path,
        kind: OperationKind,
        options: &PlanOptions,
        policy: &Policy,
        budget: &mut usize,
    ) -> Result<Vec<ManifestEntry>> {
        let mut stack = vec![source.to_path_buf()];
        let mut entries = Vec::new();
        while let Some(path) = stack.pop() {
            if *budget == 0 {
                return Err(E::IncompleteManifest);
            }
            *budget -= 1;
            let path = checked_existing(&path, true)?;
            if file_tidy_platform::is_mount_boundary(source, &path)? {
                return Err(E::ProtectedRoot);
            }
            let node = file_tidy_platform::inspect(&path)?;
            if !matches!(
                node.kind,
                NodeKind::Regular | NodeKind::Directory | NodeKind::Symlink
            ) {
                return Err(E::UnsupportedNode);
            }
            if node.hidden && !options.include_hidden {
                return Err(E::HiddenEntry);
            }
            if path
                .components()
                .any(|p| crate::authorization::managed_component(p.as_os_str()))
            {
                return Err(E::ProtectedRoot);
            }
            let labels = policy.labels(&path);
            let protected = if node.kind == NodeKind::Symlink {
                policy
                    .labels(path.parent().ok_or(E::InvalidPath)?)
                    .protected
            } else {
                labels.protected
            };
            if kind.modifies_source() && protected {
                return Err(E::ProtectedZone);
            }
            let stamp = Stamp::capture(&node)?;
            if node.kind == NodeKind::Directory {
                let listing = file_tidy_platform::read_directory_verified(&path, &node, *budget)?;
                if listing.truncated {
                    return Err(E::IncompleteManifest);
                }
                for name in listing.names {
                    stack.push(path.join(name));
                }
            }
            entries.push(ManifestEntry {
                path: NativePath::new(&path),
                kind: format!("{:?}", node.kind),
                size_bytes: if node.kind == NodeKind::Regular {
                    node.len.to_string()
                } else {
                    "0".to_owned()
                },
                hidden: node.hidden,
                sensitive: labels.sensitive,
                link_target: if node.kind == NodeKind::Symlink {
                    Some(NativePath::new(&std::fs::read_link(&path)?))
                } else {
                    None
                },
                stamp,
            });
        }
        entries.sort_by(|a, b| a.path.units_for_order().cmp(b.path.units_for_order()));
        Ok(entries)
    }
}

fn resolve_destination(
    path: &Path,
    reserved: &HashSet<PathBuf>,
    source: &Path,
    kind: OperationKind,
    max_entries: usize,
) -> Result<Destination> {
    let path = crate::authorization::absolute(path)?;
    validate_name(path.file_name().ok_or(E::InvalidPath)?)?;
    let mut parent = path.parent().ok_or(E::InvalidPath)?.to_path_buf();
    let mut missing_names = Vec::new();
    loop {
        match std::fs::symlink_metadata(&parent) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = parent.file_name().ok_or(E::InvalidPath)?.to_os_string();
                validate_name(&name)?;
                missing_names.push(name);
                parent = parent.parent().ok_or(E::InvalidPath)?.to_path_buf();
            }
            Err(e) => return Err(e.into()),
        }
    }
    parent = checked_existing(&parent, false)?;
    let node = file_tidy_platform::inspect(&parent)?;
    if node.kind != NodeKind::Directory {
        return Err(E::UnsupportedNode);
    }
    let existing_parent = NativePath::new(&parent);
    let parent_stamp = Stamp::capture(&node)?;
    let mut create_directories = Vec::new();
    for name in missing_names.into_iter().rev() {
        parent.push(name);
        create_directories.push(NativePath::new(&parent));
    }
    let original = parent.join(path.file_name().ok_or(E::InvalidPath)?);
    if kind.modifies_source() && original == source {
        return Err(E::InvalidRequest);
    }
    if kind == OperationKind::Rename && original.parent() != source.parent() {
        return Err(E::InvalidRequest);
    }
    if kind == OperationKind::Rename
        && !reserved.contains(&original)
        && same_entry_spelling(source, &original, max_entries)?
    {
        let temporary = parent.join(format!(".file-tidy-{}.rename", Id::new()?));
        if reserved.contains(&temporary) {
            return Err(E::DestinationConflict);
        }
        match std::fs::symlink_metadata(&temporary) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(E::DestinationConflict),
        }
        return Ok(Destination {
            path: NativePath::new(&original),
            existing_parent,
            create_directories,
            renamed_for_conflict: false,
            spelling_temporary: Some(NativePath::new(&temporary)),
            copy_temporary: None,
            copy_metadata: None,
            parent_stamp,
        });
    }
    let mut candidate = original.clone();
    for index in 0..=10_000u32 {
        match std::fs::symlink_metadata(&candidate) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && !reserved.contains(&candidate) =>
            {
                return Ok(Destination {
                    renamed_for_conflict: candidate != original,
                    spelling_temporary: None,
                    copy_temporary: if kind == OperationKind::Copy {
                        Some(NativePath::new(
                            &parent.join(format!(".file-tidy-{}.part", Id::new()?)),
                        ))
                    } else {
                        None
                    },
                    copy_metadata: (kind == OperationKind::Copy)
                        .then_some(CopyMetadataPolicy::PrivateDataStreamAndMtime),
                    path: NativePath::new(&candidate),
                    existing_parent,
                    create_directories,
                    parent_stamp,
                });
            }
            Ok(_) | Err(_) if index == 10_000 => return Err(E::DestinationConflict),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        candidate = collision_name(&original, index + 1)?;
    }
    Err(E::DestinationConflict)
}

/// Prove that two native spellings address one directory entry, rather than two
/// hard links. The filesystem decides equivalence; no Unicode/case folding is
/// approximated in Rust. Ambiguous aliases are treated as ordinary conflicts.
pub(crate) fn same_entry_spelling(
    source: &Path,
    destination: &Path,
    max_entries: usize,
) -> Result<bool> {
    if source == destination || source.parent() != destination.parent() {
        return Ok(false);
    }
    let target = match file_tidy_platform::inspect(destination) {
        Ok(node) => node,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let original = file_tidy_platform::inspect(source)?;
    if !original.matches(&target) {
        return Ok(false);
    }
    let parent = source.parent().ok_or(E::InvalidPath)?;
    let parent_info = file_tidy_platform::inspect(parent)?;
    let listing = file_tidy_platform::read_directory_verified(parent, &parent_info, max_entries)?;
    if listing.truncated {
        return Err(E::IncompleteManifest);
    }
    let source_name = source.file_name().ok_or(E::InvalidPath)?;
    let target_name = destination.file_name().ok_or(E::InvalidPath)?;
    if !listing.names.iter().any(|name| name == source_name)
        || listing.names.iter().any(|name| name == target_name)
    {
        return Ok(false);
    }
    let mut aliases = 0usize;
    for name in &listing.names {
        let node = file_tidy_platform::inspect(&parent.join(name))?;
        if node.identity == original.identity {
            aliases += 1;
        }
    }
    if !parent_info.matches(&file_tidy_platform::inspect(parent)?)
        || !original.matches(&file_tidy_platform::inspect(source)?)
        || !original.matches(&file_tidy_platform::inspect(destination)?)
    {
        return Err(E::ChangedSincePlan);
    }
    Ok(aliases == 1)
}

fn collision_name(path: &Path, count: u32) -> Result<PathBuf> {
    let name = Path::new(path.file_name().ok_or(E::InvalidPath)?);
    let mut stem = name.file_stem().ok_or(E::InvalidPath)?.to_os_string();
    let mut extension = name.extension().map(|ext| ext.to_os_string());
    if matches!(
        name.extension().and_then(|e| e.to_str()),
        Some("gz" | "bz2" | "xz" | "zst")
    ) && Path::new(&stem).extension().is_some_and(|e| e == "tar")
    {
        let tar = Path::new(&stem)
            .file_stem()
            .ok_or(E::InvalidPath)?
            .to_os_string();
        let mut ext = std::ffi::OsString::from("tar.");
        ext.push(name.extension().ok_or(E::InvalidPath)?);
        stem = tar;
        extension = Some(ext);
    }
    stem.push(format!(" ({count})"));
    if let Some(ext) = extension {
        stem.push(".");
        stem.push(ext);
    }
    validate_name(&stem)?;
    Ok(path.with_file_name(stem))
}

fn validate_name(name: &std::ffi::OsStr) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(E::InvalidPath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let units: Vec<_> = name.encode_wide().collect();
        if units.iter().any(|u| {
            *u < 32
                || b"<>:\"/\\|?*"
                    .iter()
                    .any(|b| u32::from(*b) == u32::from(*u))
        }) || matches!(units.last(), Some(32 | 46))
        {
            return Err(E::InvalidPath);
        }
        let upper = name
            .to_string_lossy()
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                upper
                    .strip_prefix(prefix)
                    .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit() && n != "0")
            })
        {
            return Err(E::InvalidPath);
        }
    }
    Ok(())
}

pub(crate) fn destination_sensitive(path: &Path) -> bool {
    path.components()
        .any(|component| crate::policy::sensitive_name(component.as_os_str()))
}

pub(crate) fn policy_digest() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(include_bytes!("policy.rs"));
    hasher.update(include_bytes!("authorization.rs"));
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| E::InvalidPlan)?
        .as_secs())
}

impl Plan {
    pub fn review_text(&self) -> Result<String> {
        let mut output = String::new();
        for (index, operation) in self.preview.operations.iter().enumerate() {
            let action = match operation.kind {
                OperationKind::Copy => "复制",
                OperationKind::Move => "移动",
                OperationKind::Rename => "重命名",
                OperationKind::Quarantine => "移入隔离区",
                OperationKind::PermanentDelete => "永久删除（不可撤销）",
            };
            output.push_str(&format!(
                "{}. {action}\n   {}",
                index + 1,
                operation.source.display
            ));
            if let Some(destination) = &operation.destination {
                if let Some(temporary) = &destination.spelling_temporary {
                    output.push_str(&format!(
                        "\n   → {}（名称调整的中间位置）",
                        temporary.display
                    ));
                }
                output.push_str(&format!("\n   → {}", destination.path.display));
                if let Some(temporary) = &destination.copy_temporary {
                    output.push_str(&format!(
                        "\n   校验暂存：{}\n   副本：主数据流、修改时间、当前用户私有权限",
                        temporary.display
                    ));
                }
                if destination.renamed_for_conflict {
                    output.push_str("（同名冲突，已预览新名称）");
                }
                for directory in &destination.create_directories {
                    output.push_str(&format!("\n   创建目录：{}", directory.display));
                }
            }
            output.push_str("\n   完整清单：\n");
            let root = operation.source.to_path()?;
            for entry in &operation.manifest {
                let path = entry.path.to_path()?;
                let relative = path.strip_prefix(&root).map_err(|_| E::InvalidPath)?;
                let label = if relative.as_os_str().is_empty() {
                    operation.source.display.clone()
                } else {
                    crate::display_path(relative)
                };
                let kind = match entry.kind.as_str() {
                    "Directory" => "目录",
                    "Symlink" => "链接",
                    _ => "文件",
                };
                output.push_str(&format!("     {kind} {label}"));
                if entry.kind == "Regular" {
                    output.push_str(&format!(" · {} 字节", entry.size_bytes));
                }
                if entry.hidden {
                    output.push_str(" · 隐藏");
                }
                if entry.sensitive {
                    output.push_str(" · 敏感项");
                }
                if let Some(target) = &entry.link_target {
                    output.push_str(&format!(" → {}", target.display));
                }
                output.push('\n');
            }
        }
        output.push_str(&format!(
            "\n文件/链接：{}，目录：{}，空目录：{}，逻辑总大小：{} 字节\n",
            self.preview.files_and_links,
            self.preview.directories,
            self.preview.empty_directories,
            self.preview.total_bytes
        ));
        if self.preview.requires_count_confirmation {
            output.push_str(&format!(
                "数量确认：{} 项（文件、链接及空目录）\n",
                self.preview.confirmation_count
            ));
        }
        for acknowledgement in &self.preview.sensitive_acknowledgements {
            output.push_str(&format!(
                "{}\n",
                self.acknowledgement_description(acknowledgement)?
            ));
        }
        output.push_str(&format!("计划摘要：{}\n", self.digest));
        Ok(output)
    }
}
