//! A private staged tree whose directory identities are retained until publication.
use crate::{FileIdentity, NodeInfo, NodeKind, PinnedDirectory, RenameError, StagedFile};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

pub struct StagedDirectory {
    root: File,
    parent: PinnedDirectory,
    parent_path: PathBuf,
    parent_info: NodeInfo,
    path: PathBuf,
    directories: BTreeMap<PathBuf, FileIdentity>,
}
impl StagedDirectory {
    pub fn create(parent_path: &Path, expected: &NodeInfo, name: &OsStr) -> io::Result<Self> {
        crate::staged_file::component(name)?;
        let parent = crate::open_directory_pinned(parent_path, expected)?;
        #[cfg(unix)]
        let root = crate::create_private_directory(&parent, name)?;
        #[cfg(windows)]
        let root = crate::private_storage::create_staged_directory_handle(
            &parent.try_clone_file()?,
            name,
        )?;
        let identity = crate::inspect_file(&root)?
            .identity
            .ok_or_else(|| io::Error::other("directory identity unavailable"))?;
        let result = Self {
            root,
            parent,
            parent_path: parent_path.into(),
            parent_info: expected.clone(),
            path: parent_path.join(name),
            directories: BTreeMap::from([(PathBuf::new(), identity)]),
        };
        result.verify()?;
        Ok(result)
    }
    pub fn inspect(&self) -> io::Result<NodeInfo> {
        let mut info = crate::inspect_file(&self.root)?;
        info.hidden |= self
            .path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        Ok(info)
    }
    pub fn verify(&self) -> io::Result<()> {
        #[cfg(unix)]
        let named = {
            if crate::classify_location(&self.path)?.kind != crate::LocationKind::Local {
                return Err(io::Error::other("staging location changed"));
            }
            let file = crate::unix::open_nofollow(&self.path, true)?;
            crate::inspect_file(&file)?
        };
        #[cfg(windows)]
        let named = crate::inspect(&self.path)?;
        if named.identity != crate::inspect_file(&self.root)?.identity
            || self.directories.get(Path::new("")) != named.identity.as_ref()
            || crate::inspect_file(&self.parent.try_clone_file()?)?.identity
                != self.parent_info.identity
        {
            return Err(io::Error::other(
                "staged tree or destination parent changed",
            ));
        }
        crate::verify_private_file(&self.root, true)
    }
    fn directory(&self, relative: &Path) -> io::Result<PinnedDirectory> {
        relative_path(relative)?;
        self.verify()?;
        let mut file = self.root.try_clone()?;
        let mut guards = Vec::new();
        let mut prefix = PathBuf::new();
        for part in relative.components() {
            let Component::Normal(name) = part else {
                return Err(io::Error::other("relative component required"));
            };
            prefix.push(name);
            let expected = self
                .directories
                .get(&prefix)
                .ok_or_else(|| io::Error::other("directory was not created by this tree"))?;
            #[cfg(unix)]
            let child = {
                use rustix::fs::{Mode, OFlags, openat};
                File::from(openat(
                    &file,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?)
            };
            #[cfg(windows)]
            let child = crate::private_storage::open_staged_directory_handle(&file, name)?;
            let actual = crate::inspect_file(&child)?;
            if actual.kind != NodeKind::Directory || actual.identity.as_ref() != Some(expected) {
                return Err(io::Error::other("owned directory changed"));
            }
            crate::verify_private_file(&child, true)?;
            guards.push(file);
            file = child;
        }
        PinnedDirectory::from_staged(file, guards)
    }
    pub fn read_directory(
        &self,
        relative: &Path,
        expected: &NodeInfo,
        limit: usize,
    ) -> io::Result<crate::DirectoryListing> {
        let directory = self.directory(relative)?;
        #[cfg(windows)]
        {
            let path = self.path.join(relative);
            crate::windows::read_directory_using_pin(
                &path,
                expected,
                &directory.try_clone_file()?,
                limit,
                &|| false,
            )
        }
        #[cfg(unix)]
        {
            let _ = directory;
            crate::read_directory_verified(&self.path.join(relative), expected, limit)
        }
    }
    pub fn create_directory(&mut self, relative: &Path) -> io::Result<NodeInfo> {
        relative_path(relative)?;
        let parent = self.directory(
            relative
                .parent()
                .ok_or_else(|| io::Error::other("child path required"))?,
        )?;
        let file = crate::create_private_directory(
            &parent,
            relative
                .file_name()
                .ok_or_else(|| io::Error::other("child name required"))?,
        )?;
        let info = crate::inspect_file(&file)?;
        let identity = info
            .identity
            .ok_or_else(|| io::Error::other("directory identity unavailable"))?;
        if self.directories.insert(relative.into(), identity).is_some() {
            return Err(io::Error::other("duplicate directory"));
        }
        self.verify()?;
        let mut actual = crate::inspect_file(&file)?;
        actual.hidden |= relative
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        Ok(actual)
    }
    pub fn create_file(&self, relative: &Path) -> io::Result<StagedFile> {
        relative_path(relative)?;
        let relative_parent = relative
            .parent()
            .ok_or_else(|| io::Error::other("child path required"))?;
        let parent = self.directory(relative_parent)?;
        let parent_path = self.path.join(relative_parent);
        let info = crate::inspect_file(&parent.try_clone_file()?)?;
        StagedFile::create_pinned(
            &parent_path,
            &info,
            parent,
            relative
                .file_name()
                .ok_or_else(|| io::Error::other("child name required"))?,
        )
    }
    #[cfg(windows)]
    pub(crate) fn create_migration_file(&self) -> io::Result<File> {
        let parent = self.directory(Path::new(""))?;
        crate::private_storage::create_migration_handle(
            &parent.try_clone_file()?,
            OsStr::new("payload"),
        )
    }
    pub fn create_symlink(
        &self,
        relative: &Path,
        target: &Path,
        directory: bool,
    ) -> io::Result<NodeInfo> {
        relative_path(relative)?;
        let parent = self.directory(
            relative
                .parent()
                .ok_or_else(|| io::Error::other("child path required"))?,
        )?;
        let path = self.path.join(relative);
        #[cfg(unix)]
        {
            let _ = directory;
            rustix::fs::symlinkat(
                target,
                &parent.try_clone_file()?,
                relative
                    .file_name()
                    .ok_or_else(|| io::Error::other("child name required"))?,
            )?;
            parent.try_clone_file()?.sync_all()?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                CreateSymbolicLinkW, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
                SYMBOLIC_LINK_FLAG_DIRECTORY,
            };
            let wide = |p: &Path| -> io::Result<Vec<u16>> {
                let mut units = p.as_os_str().encode_wide().collect::<Vec<_>>();
                if units.contains(&0) {
                    return Err(io::Error::other("NUL in symbolic link"));
                }
                units.push(0);
                Ok(units)
            };
            let path_units = wide(&path)?;
            let target_units = wide(target)?;
            let flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
                | if directory {
                    SYMBOLIC_LINK_FLAG_DIRECTORY
                } else {
                    0
                };
            // SAFETY: both strings are live and terminated. Every ancestor of
            // path is pinned against deletion/replacement; the API exclusively
            // creates the leaf and records target text without traversing it.
            if !unsafe { CreateSymbolicLinkW(path_units.as_ptr(), target_units.as_ptr(), flags) } {
                return Err(io::Error::last_os_error());
            }
        }
        self.verify()?;
        #[cfg(unix)]
        let (info, actual_target) = {
            use std::os::unix::ffi::OsStringExt;
            let name = relative
                .file_name()
                .ok_or_else(|| io::Error::other("child name required"))?;
            let file = parent.try_clone_file()?;
            let info = crate::mutation::inspect_relative(&file, name)?;
            let actual = rustix::fs::readlinkat(&file, name, Vec::new())?;
            (
                info,
                PathBuf::from(std::ffi::OsString::from_vec(actual.to_bytes().to_vec())),
            )
        };
        #[cfg(windows)]
        let (info, actual_target) = (crate::inspect(&path)?, std::fs::read_link(&path)?);
        let _ = path;
        drop(parent);
        if info.kind != NodeKind::Symlink || actual_target != target {
            return Err(io::Error::other("created symbolic link differs"));
        }
        Ok(info)
    }
    pub fn set_symlink_modified(
        &self,
        relative: &Path,
        expected: &NodeInfo,
        modified: SystemTime,
    ) -> io::Result<NodeInfo> {
        relative_path(relative)?;
        let parent = self.directory(
            relative
                .parent()
                .ok_or_else(|| io::Error::other("child path required"))?,
        )?;
        let name = relative
            .file_name()
            .ok_or_else(|| io::Error::other("child name required"))?;
        #[cfg(unix)]
        let info = {
            use rustix::fs::{AtFlags, Timespec, Timestamps, UTIME_OMIT, utimensat};
            let file = parent.try_clone_file()?;
            if !expected.matches(&crate::mutation::inspect_relative(&file, name)?) {
                return Err(io::Error::other("symbolic link changed"));
            }
            let nanos = match modified.duration_since(std::time::UNIX_EPOCH) {
                Ok(value) => value.as_nanos() as i128,
                Err(error) => -(error.duration().as_nanos() as i128),
            };
            let times = Timestamps {
                last_access: Timespec {
                    tv_sec: 0,
                    tv_nsec: UTIME_OMIT,
                },
                last_modification: Timespec {
                    tv_sec: nanos
                        .div_euclid(1_000_000_000)
                        .try_into()
                        .map_err(|_| io::Error::other("timestamp overflow"))?,
                    tv_nsec: nanos
                        .rem_euclid(1_000_000_000)
                        .try_into()
                        .map_err(|_| io::Error::other("timestamp overflow"))?,
                },
            };
            utimensat(&file, name, &times, AtFlags::SYMLINK_NOFOLLOW)?;
            file.sync_all()?;
            crate::mutation::inspect_relative(&file, name)?
        };
        #[cfg(windows)]
        let info = {
            let file =
                crate::private_storage::open_staged_link_handle(&parent.try_clone_file()?, name)?;
            if !expected.matches(&crate::inspect_file(&file)?) {
                return Err(io::Error::other("symbolic link changed"));
            }
            file.set_times(std::fs::FileTimes::new().set_modified(modified))?;
            crate::inspect_file(&file)?
        };
        let mut info = info;
        info.hidden |= relative
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        if info.kind != NodeKind::Symlink
            || info.identity != expected.identity
            || info.modified != Some(modified)
        {
            return Err(io::Error::other("symbolic link time cannot be preserved"));
        }
        self.verify()?;
        Ok(info)
    }
    pub fn set_directory_modified(
        &self,
        relative: &Path,
        modified: SystemTime,
    ) -> io::Result<NodeInfo> {
        let directory = self.directory(relative)?;
        let file = directory.try_clone_file()?;
        file.set_times(std::fs::FileTimes::new().set_modified(modified))?;
        #[cfg(unix)]
        file.sync_all()?;
        self.verify()?;
        let mut info = crate::inspect_file(&file)?;
        info.hidden |= relative
            .file_name()
            .or_else(|| self.path.file_name())
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        if info.modified != Some(modified) {
            return Err(io::Error::other("modification time cannot be preserved"));
        }
        Ok(info)
    }
    pub fn publish(&mut self, name: &OsStr) -> Result<NodeInfo, RenameError> {
        crate::staged_file::component(name)?;
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
        crate::mutation::publish_open_file(&self.root, &self.parent.try_clone_file()?, name)
            .map_err(RenameError::from_rename)?;
        self.path = target;
        self.verify().map_err(RenameError::after_rename)?;
        let actual = self.inspect().map_err(RenameError::after_rename)?;
        if !expected.matches(&actual) {
            return Err(RenameError::after_rename(io::Error::other(
                "published directory changed",
            )));
        }
        Ok(actual)
    }
}
fn relative_path(relative: &Path) -> io::Result<()> {
    for part in relative.components() {
        let Component::Normal(name) = part else {
            return Err(io::Error::other("relative child path required"));
        };
        crate::staged_file::component(name)?;
    }
    Ok(())
}
