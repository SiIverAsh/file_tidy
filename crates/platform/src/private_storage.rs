//! Narrow primitives for private, explicitly authorized application state.
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path};

use crate::{LocationKind, NodeInfo, NodeKind};

pub struct PinnedDirectory {
    file: File,
    _ancestors: Vec<File>,
}
impl PinnedDirectory {
    pub(crate) fn from_staged(file: File, ancestors: Vec<File>) -> io::Result<Self> {
        verify_private_file(&file, true)?;
        Ok(Self {
            file,
            _ancestors: ancestors,
        })
    }
    pub fn try_clone_file(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}

pub fn open_directory_pinned(path: &Path, expected: &NodeInfo) -> io::Result<PinnedDirectory> {
    if expected.kind != NodeKind::Directory
        || crate::classify_location(path)?.kind != LocationKind::Local
    {
        return Err(io::Error::other("local identified directory required"));
    }
    #[cfg(unix)]
    let (file, ancestors) = (crate::unix::open_nofollow(path, true)?, Vec::new());
    #[cfg(windows)]
    let (file, ancestors) = crate::windows::open_state_directory(path)?;
    if crate::inspect_file(&file)?.identity != expected.identity || expected.identity.is_none() {
        return Err(io::Error::other("directory changed before opening"));
    }
    Ok(PinnedDirectory {
        file,
        _ancestors: ancestors,
    })
}

pub fn create_private_directory(parent: &PinnedDirectory, name: &OsStr) -> io::Result<File> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(io::Error::other("one native directory component required"));
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, mkdirat, openat};
        mkdirat(&parent.file, name, Mode::from_raw_mode(0o700))?;
        let file = File::from(openat(
            &parent.file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        verify_private_file(&file, true)?;
        parent.file.sync_all()?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        windows::create_directory(&parent.file, name)
    }
}

/// Exclusively create a state file inside a verified private state directory.
pub fn create_private_file(parent: &PinnedDirectory, name: &OsStr) -> io::Result<File> {
    verify_private_file(&parent.file, true)?;
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(io::Error::other("one native file component required"));
    }
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let file = File::from(openat(
            &parent.file,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )?);
        verify_private_file(&file, false)?;
        parent.file.sync_all()?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        windows::create_file(&parent.file, name)
    }
}

pub fn verify_private_file(file: &File, directory: bool) -> io::Result<()> {
    let info = crate::inspect_file(file)?;
    if info.kind
        != if directory {
            NodeKind::Directory
        } else {
            NodeKind::Regular
        }
        || (!directory && info.links != 1)
    {
        return Err(io::Error::other(
            "private state object has unexpected type or link count",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "state must be owned by the current user with private permissions",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::verify(file, directory)
    }
}

#[cfg(windows)]
#[path = "private_storage_windows.rs"]
mod windows;

#[cfg(windows)]
pub(crate) fn create_staged_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::create_staged_file(parent, name)
}
#[cfg(windows)]
pub(crate) fn create_migration_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::create_migration_file(parent, name)
}

#[cfg(windows)]
pub(crate) fn create_migration_directory_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::create_migration_directory(parent, name)
}

#[cfg(windows)]
pub(crate) fn open_migration_directory_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::open_migration_directory(parent, name)
}

#[cfg(windows)]
pub(crate) fn open_migration_read_handle(
    parent: &File,
    name: &OsStr,
    directory: bool,
) -> io::Result<File> {
    windows::open_migration_read(parent, name, directory)
}

#[cfg(windows)]
pub(crate) fn open_migration_link_handle(
    parent: &File,
    name: &OsStr,
    write: bool,
) -> io::Result<File> {
    windows::open_migration_link(parent, name, write)
}

#[cfg(windows)]
pub(crate) fn create_staged_directory_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::create_staged_directory(parent, name)
}
#[cfg(windows)]
pub(crate) fn open_staged_directory_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::open_staged_directory(parent, name)
}
#[cfg(windows)]
pub(crate) fn open_staged_link_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    windows::open_staged_link(parent, name)
}
