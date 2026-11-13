//! Handle-relative, no-overwrite mutations. Authorization belongs to core.
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::{Component, Path};

use crate::{LocationKind, NodeInfo, NodeKind};

/// A failed durability or identity check after rename requires reconciliation.
#[derive(Debug)]
pub struct RenameError {
    pub error: io::Error,
    pub may_have_moved: bool,
    cross_device: bool,
}

impl fmt::Display for RenameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for RenameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl From<io::Error> for RenameError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            may_have_moved: false,
            cross_device: false,
        }
    }
}

impl RenameError {
    fn after_rename(error: io::Error) -> Self {
        Self {
            error,
            may_have_moved: true,
            cross_device: false,
        }
    }

    /// True only when the actual rename syscall reports another device.
    pub fn is_cross_device(&self) -> bool {
        self.cross_device
    }

    fn from_rename(error: io::Error) -> Self {
        #[cfg(unix)]
        let code = rustix::io::Errno::XDEV.raw_os_error();
        #[cfg(windows)]
        let code = windows_sys::Win32::Foundation::ERROR_NOT_SAME_DEVICE as i32;
        Self {
            cross_device: error.raw_os_error() == Some(code),
            error,
            may_have_moved: false,
        }
    }
}

/// Atomically rename an identified object without replacing any destination.
/// Parents are opened component by component without following links. The
/// caller must check authorization and the complete directory manifest first.
/// Unix rename is name-based: concurrent source replacement is detected by the
/// post-rename identity check and reported as `may_have_moved`, never retried.
pub fn rename_noreplace(
    source: &Path,
    expected_source: &NodeInfo,
    destination: &Path,
    expected_source_parent: &NodeInfo,
    expected_destination_parent: &NodeInfo,
) -> Result<(), RenameError> {
    let (source_parent, source_name) = split(source)?;
    let (destination_parent, destination_name) = split(destination)?;
    if source == destination
        || expected_source.identity.is_none()
        || expected_source.modified.is_none()
        || !matches!(
            expected_source.kind,
            NodeKind::Regular | NodeKind::Directory | NodeKind::Symlink
        )
    {
        return Err(invalid("identified regular file, directory or symbolic link required").into());
    }
    for (path, expected) in [
        (source_parent, expected_source_parent),
        (destination_parent, expected_destination_parent),
    ] {
        if expected.kind != NodeKind::Directory
            || expected.identity.is_none()
            || crate::classify_location(path)?.kind != LocationKind::Local
        {
            return Err(invalid("local identified parent directory required").into());
        }
    }
    #[cfg(unix)]
    return unix::rename(
        source_parent,
        source_name,
        expected_source,
        destination_parent,
        destination_name,
        expected_source_parent,
        expected_destination_parent,
    );
    #[cfg(windows)]
    return windows::rename(
        source_parent,
        source_name,
        expected_source,
        destination_parent,
        destination_name,
        expected_source_parent,
        expected_destination_parent,
    );
}

fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid("absolute path without parent traversal required"));
    }
    let parent = path.parent().ok_or_else(|| invalid("path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("path has no native leaf"))?;
    Ok((parent, name))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parent_matches(expected: &NodeInfo, actual: &NodeInfo) -> io::Result<()> {
    if actual.kind != NodeKind::Directory || expected.identity != actual.identity {
        Err(invalid("parent directory identity changed"))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use rustix::fs::{AtFlags, FileType, RenameFlags, renameat_with, statat};
    use std::fs::File;

    #[allow(clippy::unnecessary_cast)] // Native stat field widths vary by platform.
    fn leaf(parent: &File, name: &OsStr) -> io::Result<NodeInfo> {
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, UNIX_EPOCH};
        let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => NodeKind::Regular,
            FileType::Directory => NodeKind::Directory,
            FileType::Symlink => NodeKind::Symlink,
            _ => NodeKind::Special,
        };
        #[cfg(target_os = "macos")]
        let kind = if stat.st_flags & 0x4000_0000 != 0 {
            NodeKind::Reparse
        } else {
            kind
        };
        let nanos = i128::from(stat.st_mtime_nsec);
        if !(0..1_000_000_000).contains(&nanos) {
            return Err(invalid("invalid source timestamp"));
        }
        let timestamp = i128::from(stat.st_mtime) * 1_000_000_000 + nanos;
        let magnitude = timestamp.unsigned_abs();
        let duration = Duration::new(
            u64::try_from(magnitude / 1_000_000_000)
                .map_err(|_| invalid("source timestamp overflow"))?,
            (magnitude % 1_000_000_000) as u32,
        );
        let modified = if timestamp < 0 {
            UNIX_EPOCH.checked_sub(duration)
        } else {
            UNIX_EPOCH.checked_add(duration)
        };
        let hidden = name.as_bytes().first() == Some(&b'.');
        #[cfg(target_os = "macos")]
        let hidden = hidden || stat.st_flags & libc::UF_HIDDEN != 0;
        Ok(NodeInfo {
            kind,
            len: u64::try_from(stat.st_size).map_err(|_| invalid("invalid source length"))?,
            identity: Some(crate::FileIdentity {
                volume: stat.st_dev as u64,
                file: stat.st_ino as u128,
            }),
            modified,
            allocated: None,
            hidden,
            links: stat.st_nlink as u64,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn rename(
        source_parent: &Path,
        source_name: &OsStr,
        expected: &NodeInfo,
        destination_parent: &Path,
        destination_name: &OsStr,
        expected_source_parent: &NodeInfo,
        expected_destination_parent: &NodeInfo,
    ) -> Result<(), RenameError> {
        let from = crate::unix::open_nofollow(source_parent, true)?;
        let to = crate::unix::open_nofollow(destination_parent, true)?;
        parent_matches(expected_source_parent, &crate::inspect_file(&from)?)?;
        parent_matches(expected_destination_parent, &crate::inspect_file(&to)?)?;
        let held_source = leaf(&from, source_name)?;
        if !expected.matches(&held_source) {
            return Err(invalid("source changed before rename").into());
        }
        // Reject aliases of the source as well: some filesystems return success
        // for a no-op rename even with NOREPLACE.
        match leaf(&to, destination_name) {
            Ok(_) => {
                return Err(
                    io::Error::new(io::ErrorKind::AlreadyExists, "destination exists").into(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        parent_matches(expected_source_parent, &crate::inspect(source_parent)?)?;
        parent_matches(
            expected_destination_parent,
            &crate::inspect(destination_parent)?,
        )?;
        let latest_source = leaf(&from, source_name)?;
        if !expected.matches(&latest_source) {
            return Err(invalid("source changed before rename").into());
        }
        #[cfg(test)]
        faults::run(&faults::BEFORE_RENAME)?;
        // Preserve EXDEV exclusively from this call, rather than path traversal.
        renameat_with(
            &from,
            source_name,
            &to,
            destination_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| RenameError::from_rename(io::Error::from(error)))?;
        let after = || -> io::Result<()> {
            #[cfg(test)]
            faults::run(&faults::AFTER_RENAME)?;
            from.sync_all()?;
            if expected_source_parent.identity != expected_destination_parent.identity {
                to.sync_all()?;
            }
            let moved = leaf(&to, destination_name)?;
            if !expected.matches(&moved) {
                return Err(invalid("destination changed during rename"));
            }
            parent_matches(expected_source_parent, &crate::inspect(source_parent)?)?;
            parent_matches(
                expected_destination_parent,
                &crate::inspect(destination_parent)?,
            )?;
            Ok(())
        };
        after().map_err(RenameError::after_rename)
    }

    #[cfg(test)]
    mod faults {
        use super::*;
        use std::cell::RefCell;
        type Hook = RefCell<Option<Box<dyn FnOnce() -> io::Result<()>>>>;
        thread_local! {
            pub(super) static BEFORE_RENAME: Hook = RefCell::new(None);
            pub(super) static AFTER_RENAME: Hook = RefCell::new(None);
        }
        pub(super) fn run(key: &'static std::thread::LocalKey<Hook>) -> io::Result<()> {
            match key.with(|hook| hook.borrow_mut().take()) {
                Some(hook) => hook(),
                None => Ok(()),
            }
        }

        #[test]
        fn successful_rename_then_sync_failure_requires_reconciliation() -> io::Result<()> {
            let temp = tempfile::tempdir()?;
            let root = std::fs::canonicalize(temp.path())?;
            let source = root.join("source");
            let destination = root.join("destination");
            std::fs::write(&source, b"original")?;
            let before = crate::inspect(&source)?;
            let parent = crate::inspect(&root)?;
            AFTER_RENAME.with(|hook| {
                *hook.borrow_mut() =
                    Some(Box::new(|| Err(io::Error::other("injected sync failure"))))
            });
            let error = rename_noreplace(&source, &before, &destination, &parent, &parent)
                .err()
                .ok_or_else(|| invalid("injected failure was not reported"))?;
            assert!(error.may_have_moved);
            assert!(!error.is_cross_device());
            assert!(!source.try_exists()?);
            assert!(before.matches(&crate::inspect(&destination)?));
            Ok(())
        }

        #[test]
        fn source_swap_at_commit_is_detected_without_retry_or_rollback() -> io::Result<()> {
            let temp = tempfile::tempdir()?;
            let root = std::fs::canonicalize(temp.path())?;
            let source = root.join("source");
            let destination = root.join("destination");
            let replacement = root.join("replacement");
            let original = root.join("original");
            std::fs::write(&source, b"original")?;
            std::fs::write(&replacement, b"replacement")?;
            let before = crate::inspect(&source)?;
            let parent = crate::inspect(&root)?;
            let moved_source = source.clone();
            let moved_original = original.clone();
            BEFORE_RENAME.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(&moved_source, &moved_original)?;
                    std::fs::rename(&replacement, &moved_source)
                }))
            });
            let error = rename_noreplace(&source, &before, &destination, &parent, &parent)
                .err()
                .ok_or_else(|| invalid("source swap was not reported"))?;
            assert!(error.may_have_moved);
            assert!(!error.is_cross_device());
            assert_eq!(std::fs::read(&destination)?, b"replacement");
            assert_eq!(std::fs::read(&original)?, b"original");
            Ok(())
        }

        #[test]
        fn destination_created_at_commit_is_not_overwritten() -> io::Result<()> {
            let temp = tempfile::tempdir()?;
            let root = std::fs::canonicalize(temp.path())?;
            let source = root.join("source");
            let destination = root.join("destination");
            std::fs::write(&source, b"source")?;
            let before = crate::inspect(&source)?;
            let parent = crate::inspect(&root)?;
            let occupied = destination.clone();
            BEFORE_RENAME.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    std::fs::write(&occupied, b"racing target")
                }));
            });
            let error = rename_noreplace(&source, &before, &destination, &parent, &parent)
                .err()
                .ok_or_else(|| invalid("occupied target was overwritten"))?;
            assert!(!error.may_have_moved);
            assert!(!error.is_cross_device());
            assert_eq!(error.error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(std::fs::read(&source)?, b"source");
            assert_eq!(std::fs::read(&destination)?, b"racing target");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_actual_rename_errors_allow_cross_device_fallback() {
        #[cfg(unix)]
        let code = rustix::io::Errno::XDEV.raw_os_error();
        #[cfg(windows)]
        let code = windows_sys::Win32::Foundation::ERROR_NOT_SAME_DEVICE as i32;
        assert!(!RenameError::from(io::Error::from_raw_os_error(code)).is_cross_device());
        assert!(!RenameError::after_rename(io::Error::from_raw_os_error(code)).is_cross_device());
        assert!(RenameError::from_rename(io::Error::from_raw_os_error(code)).is_cross_device());
    }
}

#[cfg(windows)]
#[path = "mutation_windows.rs"]
mod windows;
