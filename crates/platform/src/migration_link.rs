use super::*;

/// Open a symbolic link itself for attached-data reads, using a caller-owned
/// content permission. Its target is neither opened nor traversed.
pub fn open_symlink_attached_data(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    if !path.is_absolute()
        || expected.kind != NodeKind::Symlink
        || expected.identity.is_none()
        || crate::classify_location(path)?.kind != crate::LocationKind::Local
    {
        return Err(invalid("identified local symbolic link required"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("link parent missing"))?;
    let guard = pin_metadata_parent(parent)?;
    #[cfg(unix)]
    let file = open_link_at(
        &guard.try_clone_file()?,
        path.file_name()
            .ok_or_else(|| invalid("link name missing"))?,
        false,
    )?;
    #[cfg(windows)]
    let file = {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let _ = &guard;
        OpenOptions::new()
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_BACKUP_SEMANTICS
                    | FILE_FLAG_OPEN_NO_RECALL,
            )
            .open(path)?
    };
    if !expected.matches(&crate::inspect_file(&file)?) || !expected.matches(&crate::inspect(path)?)
    {
        return Err(invalid("symbolic link changed before attached-data read"));
    }
    Ok(file)
}

pub(super) fn open_link_at(parent: &File, name: &OsStr, write: bool) -> io::Result<File> {
    crate::staged_file::component(name)?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let _ = write;
        #[cfg(target_os = "linux")]
        let access = OFlags::PATH | OFlags::NOFOLLOW;
        #[cfg(target_os = "macos")]
        // O_SYMLINK selects the link vnode; O_NOFOLLOW would reject that vnode.
        let access = OFlags::RDONLY | OFlags::from_bits_retain(libc::O_SYMLINK as _);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(unsupported("native symbolic-link handles are required"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Ok(File::from(openat(
            parent,
            name,
            access | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }
    #[cfg(windows)]
    {
        crate::private_storage::open_migration_link_handle(parent, name, write)
    }
}
