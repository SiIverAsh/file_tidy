//! Native primitives for verified reads and private application state.
//!
//! Native FFI is confined to this crate. Content opens never follow symbolic links,
//! and the opened object's identity and metadata must match the inspected object.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

mod mounts;
mod mutation;
pub use mutation::{RenameError, capture_migration_source, rename_noreplace};
mod metadata_inventory;
pub use metadata_inventory::{
    MetadataAttribute, MetadataAttributeKind, MetadataInventory, metadata_inventory,
};
mod migration;
pub use migration::{
    MigrationData, MigrationDirectory, MigrationFile, MigrationTreeFile, check_migration_metadata,
    open_directory_attached_data, visit_migration_data,
};
mod removal;
pub use removal::{RemovalError, remove_verified};
mod staged_directory;
pub use staged_directory::StagedDirectory;
mod staged_file;
pub use staged_file::{StagedFile, available_bytes};
mod private_storage;
pub use private_storage::{
    PinnedDirectory, create_private_directory, create_private_file, open_directory_pinned,
    verify_private_file,
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use mounts::{LocationInfo, LocationKind, MountTable};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    pub volume: u64,
    pub file: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Regular,
    Directory,
    Symlink,
    Reparse,
    Special,
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub kind: NodeKind,
    pub len: u64,
    pub identity: Option<FileIdentity>,
    pub modified: Option<SystemTime>,
    pub allocated: Option<u64>,
    pub hidden: bool,
    pub links: u64,
}

#[derive(Clone, Debug)]
pub struct DirectoryListing {
    pub names: Vec<OsString>,
    pub truncated: bool,
}

/// Enumerate only a verified local directory, using no-follow native handles.
/// `limit` bounds returned names; at most one further non-dot name is read to
/// determine truncation. Names are single native components, never display text.
pub fn read_directory_verified(
    path: &Path,
    expected: &NodeInfo,
    limit: usize,
) -> io::Result<DirectoryListing> {
    read_directory_verified_cancellable(path, expected, limit, &|| false)
}

/// Like [`read_directory_verified`], with a cancellation checkpoint before each
/// directory entry. An in-flight OS call must return before cancellation can be
/// observed. Names remain in filesystem order; the inventory owns final ordering.
pub fn read_directory_verified_cancellable(
    path: &Path,
    expected: &NodeInfo,
    limit: usize,
    cancelled: &impl Fn() -> bool,
) -> io::Result<DirectoryListing> {
    if cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    if expected.kind != NodeKind::Directory || expected.identity.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory reads require an identified directory",
        ));
    }
    if MountTable::read()?.classify(path).kind != LocationKind::Local {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory read rejected on a non-local or unknown filesystem",
        ));
    }
    #[cfg(unix)]
    {
        unix::read_directory_verified_cancellable(path, expected, limit, cancelled)
    }
    #[cfg(windows)]
    {
        windows::read_directory_verified_cancellable(path, expected, limit, cancelled)
    }
}

impl NodeInfo {
    /// Compare fields relevant to an ordinary read. Unavailable identities/times
    /// cannot establish a trustworthy match and fail closed.
    pub fn matches(&self, other: &Self) -> bool {
        self.identity.is_some()
            && self.modified.is_some()
            && self.kind == other.kind
            && self.identity == other.identity
            && self.len == other.len
            && self.modified == other.modified
    }
}

pub fn inspect(path: &Path) -> io::Result<NodeInfo> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        Ok(unix::node_info(path, &metadata))
    }
    #[cfg(windows)]
    {
        windows::inspect_with_metadata(path, &metadata)
    }
}

/// Open only the exact regular file represented by `expected`, without following
/// any symlink or reparse point in the supplied path. Read permission for the
/// *content* is a separate core policy decision and must precede this call.
pub fn open_verified(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    if expected.kind != NodeKind::Regular || expected.identity.is_none() {
        return Err(io::Error::other(
            "content reads require an identified regular file",
        ));
    }
    if MountTable::read()?.classify(path).kind != LocationKind::Local {
        return Err(io::Error::other(
            "content read rejected on a non-local or unknown filesystem",
        ));
    }
    #[cfg(unix)]
    {
        unix::open_verified(path, expected)
    }
    #[cfg(windows)]
    {
        windows::open_verified(path, expected)
    }
}

/// Recheck the opened file, not just its path, after reading.
pub fn inspect_file(file: &File) -> io::Result<NodeInfo> {
    #[cfg(unix)]
    {
        Ok(unix::node_info(Path::new(""), &file.metadata()?))
    }
    #[cfg(windows)]
    {
        windows::node_info_from_file(file)
    }
}

pub fn classify_location(path: &Path) -> io::Result<LocationInfo> {
    Ok(MountTable::read()?.classify(path))
}

pub fn scan_roots() -> io::Result<Vec<PathBuf>> {
    Ok(MountTable::read()?.roots())
}

pub fn is_mount_boundary(root: &Path, path: &Path) -> io::Result<bool> {
    Ok(MountTable::read()?.is_boundary(root, path))
}

/// Additional native protected roots. Unix's fixed roots live in core policy.
pub fn protected_system_roots() -> io::Result<Vec<PathBuf>> {
    #[cfg(windows)]
    {
        windows::protected_system_roots()
    }
    #[cfg(unix)]
    {
        Ok(Vec::new())
    }
}

/// Native link type, obtained without querying the link target.
pub fn symlink_directory(path: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_symlink() {
        return Err(io::Error::other("symbolic link required"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
            != 0)
    }
    #[cfg(unix)]
    {
        Ok(false)
    }
}
