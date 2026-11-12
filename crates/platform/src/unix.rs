use std::fs::{File, Metadata};
use std::io;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags, open, openat};

use crate::{DirectoryListing, FileIdentity, NodeInfo, NodeKind};

pub(crate) fn node_info(path: &Path, metadata: &Metadata) -> NodeInfo {
    let kind = if metadata.file_type().is_symlink() {
        NodeKind::Symlink
    } else if metadata.is_dir() {
        NodeKind::Directory
    } else if metadata.is_file() {
        NodeKind::Regular
    } else {
        NodeKind::Special
    };
    // SF_DATALESS is defined in the macOS SDK's sys/stat.h. libc does not expose
    // it yet. Reading such iCloud/FileProvider objects could trigger hydration.
    #[cfg(target_os = "macos")]
    let kind = {
        const SF_DATALESS: u32 = 0x4000_0000;
        if metadata.st_flags() & SF_DATALESS != 0 {
            NodeKind::Reparse
        } else {
            kind
        }
    };
    let hidden = path
        .file_name()
        .is_some_and(|name| name.as_bytes().first() == Some(&b'.'));
    #[cfg(target_os = "macos")]
    let hidden = hidden || metadata.st_flags() & libc::UF_HIDDEN != 0;
    NodeInfo {
        kind,
        len: metadata.len(),
        identity: Some(FileIdentity {
            volume: metadata.dev(),
            file: u128::from(metadata.ino()),
        }),
        modified: metadata.modified().ok(),
        allocated: metadata.blocks().checked_mul(512),
        hidden,
        links: metadata.nlink(),
    }
}

pub(crate) fn open_verified(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    let file = open_nofollow(path, false)?;
    let actual = node_info(path, &file.metadata()?);
    if !expected.matches(&actual) || actual.kind != NodeKind::Regular {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed or is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn read_directory_verified(
    path: &Path,
    expected: &NodeInfo,
    limit: usize,
) -> io::Result<DirectoryListing> {
    let file = open_nofollow(path, true)?;
    if !expected.matches(&node_info(path, &file.metadata()?)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed before enumeration",
        ));
    }
    let mut names = Vec::new();
    let mut truncated = false;
    for entry in rustix::fs::Dir::read_from(&file)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::ffi::OsString::from_vec(bytes.to_vec());
        let mut components = Path::new(&name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid directory entry name",
            ));
        }
        if names.len() == limit {
            truncated = true;
            break;
        }
        names.push(name);
    }
    if !expected.matches(&node_info(path, &file.metadata()?))
        || !expected.matches(&crate::inspect(path)?)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed during enumeration",
        ));
    }
    names.sort();
    Ok(DirectoryListing { names, truncated })
}

fn open_nofollow(path: &Path, directory: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "content path must be absolute",
        ));
    }
    let mut components = path.components().peekable();
    let mut parent = open(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    while let Some(component) = components.next() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                if components.peek().is_some() {
                    parent = openat(
                        &parent,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?;
                } else {
                    // NONBLOCK prevents a concurrent regular-file -> FIFO swap
                    // from hanging before fstat detects the replacement.
                    let mut flags =
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
                    if directory {
                        flags |= OFlags::DIRECTORY;
                    }
                    let fd = openat(&parent, name, flags, Mode::empty())?;
                    return Ok(File::from(fd));
                }
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unresolved parent or prefix in content path",
                ));
            }
        }
    }
    if directory {
        return Ok(File::from(parent));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "path has no regular-file leaf",
    ))
}
