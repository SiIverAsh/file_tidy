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

pub(crate) fn read_directory_verified_cancellable(
    path: &Path,
    expected: &NodeInfo,
    limit: usize,
    cancelled: &impl Fn() -> bool,
) -> io::Result<DirectoryListing> {
    if cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    let file = open_nofollow(path, true)?;
    if !expected.matches(&node_info(path, &file.metadata()?)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed before enumeration",
        ));
    }
    let mut names = Vec::new();
    let mut truncated = false;
    let mut entries = rustix::fs::Dir::read_from(&file)?;
    loop {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
        }
        let Some(entry) = entries.next() else {
            break;
        };
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
    if cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "scan cancelled"));
    }
    if !expected.matches(&node_info(path, &file.metadata()?))
        || !expected.matches(&crate::inspect(path)?)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed during enumeration",
        ));
    }
    Ok(DirectoryListing { names, truncated })
}

fn ancestor_flags() -> OFlags {
    #[cfg(target_os = "linux")]
    {
        // A path handle requires no directory-listing permission. DIRECTORY plus
        // NOFOLLOW rejects a symlink instead of giving access to its target.
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    }
    #[cfg(target_os = "macos")]
    {
        // rustix does not expose Darwin O_SEARCH yet. Its existing safe openat
        // wrapper preserves these SDK-defined flag bits without any extra FFI.
        // O_SEARCH allows ancestor traversal with search permission only, while
        // DIRECTORY and NOFOLLOW retain the directory/no-link requirements.
        OFlags::from_bits_retain(libc::O_SEARCH as u32) | OFlags::CLOEXEC | OFlags::NOFOLLOW
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    }
}

pub(crate) fn open_nofollow(path: &Path, directory: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "content path must be absolute",
        ));
    }
    let mut components = path.components().peekable();
    let root_only = !path
        .components()
        .any(|part| matches!(part, Component::Normal(_)));
    // A root selected for enumeration is the leaf, so unlike intermediate
    // ancestors it must be opened for directory reading.
    let root_flags = if directory && root_only {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    } else {
        ancestor_flags()
    };
    let mut parent = open(Path::new("/"), root_flags, Mode::empty())?;
    while let Some(component) = components.next() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                if components.peek().is_some() {
                    parent = openat(&parent, name, ancestor_flags(), Mode::empty())?;
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
