//! Single-entry removal. Core supplies reviewed manifests and private payload scope.
use crate::{NodeInfo, NodeKind};
use std::io;
use std::path::{Component, Path};

#[derive(Debug)]
pub struct RemovalError {
    pub error: io::Error,
    pub may_have_removed: bool,
}
impl From<io::Error> for RemovalError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            may_have_removed: false,
        }
    }
}
impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for RemovalError {}

/// Remove one matching leaf without following links or recursively deleting children.
/// Unix unlink is name-based; core uses this only inside an owned private payload.
/// Windows disposition is bound to the checked DELETE handle.
pub fn remove_verified(
    path: &Path,
    expected: &NodeInfo,
    expected_parent: &NodeInfo,
) -> Result<(), RemovalError> {
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || expected.identity.is_none()
        || expected.modified.is_none()
        || !matches!(
            expected.kind,
            NodeKind::Regular | NodeKind::Directory | NodeKind::Symlink
        )
    {
        return Err(invalid("identified local leaf required").into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("leaf parent required"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("leaf name required"))?;
    crate::staged_file::component(name)?;
    let pin = crate::open_directory_pinned(parent, expected_parent)?;
    let directory = pin.try_clone_file()?;
    if crate::is_mount_boundary(parent, path)? {
        return Err(invalid("mounted leaf cannot be removed").into());
    }
    #[cfg(unix)]
    {
        let actual = crate::mutation::inspect_relative(&directory, name)?;
        if !expected.matches(&actual) {
            return Err(invalid("leaf changed before removal").into());
        }
        #[cfg(test)]
        faults::before_remove()?;
        // Repeat the identity check after the injectable checkpoint. No source
        // content open is needed, including for unreadable files and symlinks.
        if !expected.matches(&crate::mutation::inspect_relative(&directory, name)?)
            || !expected_parent.matches(&crate::inspect(parent)?)
        {
            return Err(invalid("leaf or parent changed before removal").into());
        }
        let flags = if expected.kind == NodeKind::Directory {
            rustix::fs::AtFlags::REMOVEDIR
        } else {
            rustix::fs::AtFlags::empty()
        };
        rustix::fs::unlinkat(&directory, name, flags).map_err(io::Error::from)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let file = crate::mutation::open_mutation_source(&directory, name)?;
        if !expected.matches(&crate::inspect_file(&file)?)
            || !expected_parent.matches(&crate::inspect(parent)?)
        {
            return Err(invalid("leaf or parent changed before removal").into());
        }
        #[cfg(test)]
        faults::before_remove()?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: file owns the verified no-follow DELETE handle; disposition is
        // initialized, correctly sized and live for the synchronous call. The
        // kernel marks this exact object for deletion on handle close.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&disposition) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        drop(file);
    }
    let after = || -> io::Result<()> {
        #[cfg(test)]
        faults::after_remove()?;
        #[cfg(unix)]
        directory.sync_all()?;
        if expected_parent.identity != crate::inspect(parent)?.identity {
            return Err(invalid("parent changed after removal"));
        }
        match crate::inspect(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(invalid("leaf name was occupied after removal")),
        }
    };
    after().map_err(|error| RemovalError {
        error,
        may_have_removed: true,
    })
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod faults {
    use super::*;
    use std::cell::RefCell;
    type Hook = RefCell<Option<Box<dyn FnOnce() -> io::Result<()>>>>;
    thread_local! {static BEFORE:Hook=RefCell::new(None);static AFTER:Hook=RefCell::new(None);}
    pub(super) fn before_remove() -> io::Result<()> {
        BEFORE
            .with(|h| h.borrow_mut().take())
            .map_or(Ok(()), |h| h())
    }
    pub(super) fn after_remove() -> io::Result<()> {
        AFTER
            .with(|h| h.borrow_mut().take())
            .map_or(Ok(()), |h| h())
    }
    #[test]
    fn permanent_sync_failure_after_removal_has_an_uncertain_result() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        let source = root.join("source");
        std::fs::write(&source, b"fixture")?;
        let before = crate::inspect(&source)?;
        let parent = crate::inspect(&root)?;
        AFTER.with(|h| {
            *h.borrow_mut() = Some(Box::new(|| Err(io::Error::other("fixture sync failure"))))
        });
        let error = remove_verified(&source, &before, &parent)
            .err()
            .ok_or_else(|| invalid("failure expected"))?;
        assert!(error.may_have_removed);
        assert!(!source.exists());
        Ok(())
    }
    #[test]
    #[cfg(unix)]
    fn permanent_replacement_at_the_checkpoint_is_retained() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        let source = root.join("source");
        let kept = root.join("kept");
        std::fs::write(&source, b"original")?;
        let before = crate::inspect(&source)?;
        let parent = crate::inspect(&root)?;
        let path = source.clone();
        BEFORE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&path, kept)?;
                std::fs::write(path, b"replacement")
            }))
        });
        let error = remove_verified(&source, &before, &parent)
            .err()
            .ok_or_else(|| invalid("failure expected"))?;
        assert!(!error.may_have_removed);
        assert_eq!(std::fs::read(&source)?, b"replacement");
        assert_eq!(std::fs::read(root.join("kept"))?, b"original");
        Ok(())
    }
}
