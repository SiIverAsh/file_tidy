//! Directory grants and native-path validation used by the planner.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use file_tidy_platform::{FileIdentity, LocationKind, MountTable, NodeInfo, NodeKind};
use serde::{Deserialize, Serialize};

use crate::policy::Policy;

pub type Result<T> = std::result::Result<T, PlanningError>;

#[derive(Debug, thiserror::Error)]
pub enum PlanningError {
    #[error("path must be local, absolute after resolution, and contain no parent traversal")]
    InvalidPath,
    #[error("symbolic links, reparse points or special nodes are not supported here")]
    UnsupportedNode,
    #[error("system-protected paths cannot be authorized for modification")]
    ProtectedZone,
    #[error("path is outside a current directory grant")]
    OutsideGrant,
    #[error("directory or file identity changed; review a new plan")]
    ChangedSincePlan,
    #[error("operation would split a protected project or dependency tree")]
    AtomicBoundary,
    #[error("managed storage, grant roots and mount roots cannot be modified")]
    ProtectedRoot,
    #[error("directory manifest is incomplete or exceeds the entry budget")]
    IncompleteManifest,
    #[error("hidden entries require explicit selection")]
    HiddenEntry,
    #[error("source and destination overlap or the plan contains overlapping operations")]
    OverlappingOperations,
    #[error("destination is occupied or its parent changed")]
    DestinationConflict,
    #[error("invalid operation arguments or confirmation thresholds")]
    InvalidRequest,
    #[error("plan expired, belongs to another session, or its authorization changed")]
    InvalidPlan,
    #[error("confirmation does not match the reviewed plan and its required acknowledgements")]
    ConfirmationRequired,
    #[error("persistent authorization requires initialized state storage")]
    StorageRequired,
    #[error("state storage is unavailable, unsafe, or contains an incomplete record")]
    StorageUnavailable,
    #[error("required policy or filesystem guarantees could not be established")]
    UnsupportedSafetyGuarantee,
    #[error("this operation requires a consistent database or virtual-machine snapshot")]
    ConsistencyRequired,
    #[error("size or counter exceeds the supported integer range")]
    Overflow,
    #[error("operating-system randomness is unavailable")]
    Randomness,
    #[error("filesystem inspection failed")]
    Io(#[from] std::io::Error),
    #[error("state database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("state encoding failed")]
    Encoding(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id(String);
impl Id {
    pub(crate) fn new() -> Result<Self> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| PlanningError::Randomness)?;
        Ok(Self(
            bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        ))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::str::FromStr for Id {
    type Err = PlanningError;
    fn from_str(value: &str) -> Result<Self> {
        if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PlanningError::InvalidRequest);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

/// A lossless native path, never decoded from display text.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativePath {
    pub display: String,
    encoding: String,
    units: Vec<u32>,
}
impl NativePath {
    pub fn new(path: &Path) -> Self {
        #[cfg(unix)]
        let (encoding, units) = {
            use std::os::unix::ffi::OsStrExt;
            (
                "unix_bytes",
                path.as_os_str()
                    .as_bytes()
                    .iter()
                    .map(|b| u32::from(*b))
                    .collect(),
            )
        };
        #[cfg(windows)]
        let (encoding, units) = {
            use std::os::windows::ffi::OsStrExt;
            (
                "windows_wide",
                path.as_os_str().encode_wide().map(u32::from).collect(),
            )
        };
        Self {
            display: crate::display_path(path),
            encoding: encoding.to_owned(),
            units,
        }
    }
    pub(crate) fn units_for_order(&self) -> &[u32] {
        &self.units
    }
    pub fn to_path(&self) -> Result<PathBuf> {
        #[cfg(unix)]
        if self.encoding == "unix_bytes" {
            use std::os::unix::ffi::OsStringExt;
            let bytes = self
                .units
                .iter()
                .map(|u| u8::try_from(*u).map_err(|_| PlanningError::InvalidPath))
                .collect::<Result<Vec<_>>>()?;
            if bytes.contains(&0) {
                return Err(PlanningError::InvalidPath);
            }
            return Ok(std::ffi::OsString::from_vec(bytes).into());
        }
        #[cfg(windows)]
        if self.encoding == "windows_wide" {
            use std::os::windows::ffi::OsStringExt;
            let units = self
                .units
                .iter()
                .map(|u| u16::try_from(*u).map_err(|_| PlanningError::InvalidPath))
                .collect::<Result<Vec<_>>>()?;
            if units.contains(&0) {
                return Err(PlanningError::InvalidPath);
            }
            return Ok(std::ffi::OsString::from_wide(&units).into());
        }
        Err(PlanningError::InvalidPath)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub(crate) volume: String,
    pub(crate) file: String,
}
impl From<FileIdentity> for Identity {
    fn from(id: FileIdentity) -> Self {
        Self {
            volume: id.volume.to_string(),
            file: id.file.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub(crate) id: Id,
    pub(crate) root: NativePath,
    pub(crate) identity: Identity,
    pub(crate) mount: NativePath,
    pub(crate) persistent: bool,
    pub(crate) revoked: bool,
}
impl Grant {
    pub fn id(&self) -> &Id {
        &self.id
    }
    pub fn root(&self) -> &NativePath {
        &self.root
    }
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub(crate) fn validate(&self, policy: &Policy) -> Result<PathBuf> {
        if self.revoked {
            return Err(PlanningError::OutsideGrant);
        }
        let root = checked_existing(&self.root.to_path()?, false)?;
        let node = file_tidy_platform::inspect(&root)?;
        if node.kind != NodeKind::Directory
            || node.identity.map(Identity::from).as_ref() != Some(&self.identity)
        {
            return Err(PlanningError::ChangedSincePlan);
        }
        if policy.labels(&root).protected {
            return Err(PlanningError::ProtectedZone);
        }
        let location = file_tidy_platform::classify_location(&root)?;
        if location.kind != LocationKind::Local
            || NativePath::new(&location.mount_root) != self.mount
        {
            return Err(PlanningError::ChangedSincePlan);
        }
        Ok(root)
    }
}

pub struct Session {
    pub(crate) id: Id,
    pub(crate) epoch: u64,
    pub(crate) grants: BTreeMap<Id, Grant>,
    pub(crate) store: Option<crate::storage::StateStore>,
}
impl Session {
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: Id::new()?,
            epoch: 0,
            grants: BTreeMap::new(),
            store: None,
        })
    }
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }
    pub fn preview_grant(path: &Path) -> Result<Grant> {
        let mut session = Self::new()?;
        let id = session.grant(path, false)?;
        session
            .grants
            .remove(&id)
            .ok_or(PlanningError::InvalidRequest)
    }
    pub fn grant_reviewed(&mut self, review: &Grant, persistent: bool) -> Result<Id> {
        review.validate(&planning_policy()?)?;
        if persistent && self.store.is_none() {
            return Err(PlanningError::StorageRequired);
        }
        if let Some(existing) = self
            .grants
            .values()
            .find(|g| !g.revoked && g.identity == review.identity)
        {
            if !persistent || existing.persistent {
                return Ok(existing.id.clone());
            }
            return Err(PlanningError::InvalidRequest);
        }
        if self.grants.len() >= 1000 {
            return Err(PlanningError::InvalidRequest);
        }
        let mut next = self.grants.clone();
        let mut grant = review.clone();
        grant.persistent = persistent;
        next.insert(grant.id.clone(), grant);
        self.update_grants(next)?;
        Ok(review.id.clone())
    }
    pub fn grant(&mut self, path: &Path, persistent: bool) -> Result<Id> {
        let policy = planning_policy()?;
        let root = checked_existing(path, false)?;
        let info = file_tidy_platform::inspect(&root)?;
        if info.kind != NodeKind::Directory {
            return Err(PlanningError::UnsupportedNode);
        }
        if policy.labels(&root).protected {
            return Err(PlanningError::ProtectedZone);
        }
        if root.parent().is_none() || root.components().any(|p| managed_component(p.as_os_str())) {
            return Err(PlanningError::ProtectedRoot);
        }
        let location = file_tidy_platform::classify_location(&root)?;
        if root == location.mount_root {
            return Err(PlanningError::ProtectedRoot);
        }
        let identity = info
            .identity
            .ok_or(PlanningError::UnsupportedSafetyGuarantee)?
            .into();
        // A repeated grant does not silently upgrade session scope to persistence.
        if let Some(existing) = self
            .grants
            .values()
            .find(|g| !g.revoked && g.identity == identity)
        {
            if !persistent || existing.persistent {
                return Ok(existing.id.clone());
            }
            return Err(PlanningError::InvalidRequest);
        }
        if persistent && self.store.is_none() {
            return Err(PlanningError::StorageRequired);
        }
        if self.grants.len() >= 1000 {
            return Err(PlanningError::InvalidRequest);
        }
        let id = Id::new()?;
        let grant = Grant {
            id: id.clone(),
            root: NativePath::new(&root),
            identity,
            mount: NativePath::new(&location.mount_root),
            persistent,
            revoked: false,
        };
        let mut next = self.grants.clone();
        next.insert(id.clone(), grant);
        self.update_grants(next)?;
        Ok(id)
    }
    pub fn revoke(&mut self, id: &Id) -> Result<()> {
        let mut next = self.grants.clone();
        let grant = next.get_mut(id).ok_or(PlanningError::OutsideGrant)?;
        grant.revoked = true;
        let closes_store = self
            .store
            .as_ref()
            .is_some_and(|store| store.root_grant() == id);
        self.update_grants(next)?;
        if closes_store {
            self.store = None;
        }
        Ok(())
    }
    pub(crate) fn update_grants(&mut self, next: BTreeMap<Id, Grant>) -> Result<()> {
        let epoch = self.epoch.checked_add(1).ok_or(PlanningError::Overflow)?;
        let durable_before: BTreeMap<_, _> =
            self.grants.iter().filter(|(_, g)| g.persistent).collect();
        let durable_after: BTreeMap<_, _> = next.iter().filter(|(_, g)| g.persistent).collect();
        if durable_before != durable_after
            && let Some(store) = &mut self.store
        {
            store.save(&next, epoch, None)?;
        }
        self.grants = next;
        self.epoch = epoch;
        Ok(())
    }
    pub(crate) fn grant_for(&self, path: &Path, policy: &Policy) -> Result<&Grant> {
        for grant in self.grants.values().filter(|g| !g.revoked) {
            let root_path = grant.root.to_path()?;
            if !path.starts_with(&root_path) {
                continue;
            }
            let root = grant.validate(policy)?;
            if !file_tidy_platform::is_mount_boundary(&root, path)? {
                return Ok(grant);
            }
        }
        Err(PlanningError::OutsideGrant)
    }
}

pub(crate) fn planning_policy() -> Result<Policy> {
    let policy = Policy::new();
    if !policy.warnings().is_empty() {
        return Err(PlanningError::UnsupportedSafetyGuarantee);
    }
    Ok(policy)
}

pub(crate) fn absolute(path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(PlanningError::InvalidPath);
    }
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    })
}

pub(crate) fn checked_existing(path: &Path, allow_leaf_link: bool) -> Result<PathBuf> {
    let path = absolute(path)?;
    let mounts = MountTable::read()?;
    // Validate from root outward; never canonicalize through an unchecked link.
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if mounts.classify(ancestor).kind != LocationKind::Local {
            return Err(PlanningError::UnsupportedSafetyGuarantee);
        }
        let node = file_tidy_platform::inspect(ancestor)?;
        if ancestor == path && allow_leaf_link && node.kind == NodeKind::Symlink {
            continue;
        }
        if ancestor != path && node.kind != NodeKind::Directory {
            return Err(PlanningError::UnsupportedNode);
        }
        if !matches!(node.kind, NodeKind::Directory | NodeKind::Regular) {
            return Err(PlanningError::UnsupportedNode);
        }
    }
    if allow_leaf_link && file_tidy_platform::inspect(&path)?.kind == NodeKind::Symlink {
        let parent = path
            .parent()
            .ok_or(PlanningError::InvalidPath)?
            .canonicalize()?;
        return Ok(parent.join(path.file_name().ok_or(PlanningError::InvalidPath)?));
    }
    Ok(path.canonicalize()?)
}

pub(crate) fn same_identity(node: &NodeInfo, id: &Identity) -> bool {
    node.identity.map(Identity::from).as_ref() == Some(id)
}

pub(crate) fn managed_component(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(".file-tidy"))
}
