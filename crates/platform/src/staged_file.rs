//! Exclusive private staging in an explicitly authorized destination directory.
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{NodeInfo, PinnedDirectory, RenameError};

pub struct StagedFile {
    file: File,
    parent: PinnedDirectory,
    parent_path: PathBuf,
    parent_info: NodeInfo,
    path: PathBuf,
    identity: crate::FileIdentity,
}
impl StagedFile {
    /// Exclusive creation never follows a pre-existing leaf. Errors can leave a
    /// newly created file; callers must have persisted intent before this call.
    pub fn create(parent_path: &Path, expected: &NodeInfo, name: &OsStr) -> io::Result<Self> {
        component(name)?;
        let parent = crate::open_directory_pinned(parent_path, expected)?;
        let directory = parent.try_clone_file()?;
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags, openat};
            File::from(openat(
                &directory,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
            )?)
        };
        #[cfg(windows)]
        let file = crate::private_storage::create_staged_handle(&directory, name)?;
        crate::verify_private_file(&file, false)?;
        file.sync_all()?;
        #[cfg(unix)]
        directory.sync_all()?;
        let staged = Self {
            identity: crate::inspect_file(&file)?
                .identity
                .ok_or_else(|| io::Error::other("staging identity missing"))?,
            file,
            parent,
            parent_path: parent_path.into(),
            parent_info: expected.clone(),
            path: parent_path.join(name),
        };
        staged.verify()?;
        Ok(staged)
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn inspect(&self) -> io::Result<NodeInfo> {
        let mut info = crate::inspect_file(&self.file)?;
        info.hidden |= self
            .path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        Ok(info)
    }
    pub fn verify(&self) -> io::Result<()> {
        let opened = self.inspect()?;
        if opened.identity != Some(self.identity)
            || !opened.matches(&crate::inspect(&self.path)?)
            || crate::inspect(&self.parent_path)?.identity != self.parent_info.identity
            || crate::inspect_file(&self.parent.try_clone_file()?)?.identity
                != self.parent_info.identity
        {
            return Err(io::Error::other("staging object or parent changed"));
        }
        crate::verify_private_file(&self.file, false)
    }
    /// The file keeps its private permissions; only the reviewed data stream and
    /// modification time are copied. Publication never replaces a target.
    pub fn publish(&mut self, name: &OsStr) -> Result<NodeInfo, RenameError> {
        component(name)?;
        self.verify()?;
        let expected = self.inspect()?;
        let target = self.parent_path.join(name);
        #[cfg(unix)]
        crate::rename_noreplace(
            &self.path,
            &expected,
            &target,
            &self.parent_info,
            &self.parent_info,
        )?;
        #[cfg(windows)]
        {
            crate::mutation::publish_open_file(&self.file, &self.parent.try_clone_file()?, name)
                .map_err(RenameError::from_rename)?;
        }
        self.path = target;
        self.verify().map_err(RenameError::after_rename)?;
        let actual = crate::inspect(&self.path).map_err(RenameError::after_rename)?;
        if !expected.matches(&actual) {
            return Err(RenameError::after_rename(io::Error::other(
                "published object changed",
            )));
        }
        Ok(actual)
    }
}
fn component(name: &OsStr) -> io::Result<()> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
        || name.as_encoded_bytes().contains(&0)
    {
        return Err(io::Error::other("one native component required"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if name.encode_wide().any(|u| matches!(u, 0 | 58 | 47 | 92)) {
            return Err(io::Error::other("invalid native component"));
        }
    }
    Ok(())
}
/// Available bytes for the current caller, using the pinned destination volume.
pub fn available_bytes(directory: &PinnedDirectory) -> io::Result<u64> {
    let file = directory.try_clone_file()?;
    #[cfg(unix)]
    {
        let stats = rustix::fs::fstatvfs(&file)?;
        (stats.f_bavail as u64)
            .checked_mul(stats.f_frsize as u64)
            .ok_or_else(|| io::Error::other("available space overflow"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Wdk::Storage::FileSystem::{
            FileFsFullSizeInformation, NtQueryVolumeInformationFile,
        };
        use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
        let mut info = FILE_FS_FULL_SIZE_INFORMATION::default();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: info is correctly aligned and sized, both output buffers live
        // through this synchronous call, and file pins the queried volume.
        let status = unsafe {
            NtQueryVolumeInformationFile(
                file.as_raw_handle(),
                &mut status_block,
                (&mut info as *mut FILE_FS_FULL_SIZE_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                FileFsFullSizeInformation,
            )
        };
        if status < 0 {
            // SAFETY: NTSTATUS conversion has no pointers or retained state.
            return Err(io::Error::from_raw_os_error(unsafe {
                windows_sys::Win32::Foundation::RtlNtStatusToDosError(status)
            } as i32));
        }
        u64::try_from(info.CallerAvailableAllocationUnits)
            .ok()
            .and_then(|n| n.checked_mul(u64::from(info.SectorsPerAllocationUnit)))
            .and_then(|n| n.checked_mul(u64::from(info.BytesPerSector)))
            .ok_or_else(|| io::Error::other("available space overflow"))
    }
}
