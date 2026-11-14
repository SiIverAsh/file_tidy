//! Owned directory payloads whose public permissions stay inside a private envelope.
use super::*;
use crate::PinnedDirectory;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;

/// Opens one identified directory for attached-data reads. The caller must
/// authorize those values separately from ordinary directory enumeration.
pub fn open_directory_attached_data(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    if expected.kind != NodeKind::Directory {
        return Err(invalid("identified directory required"));
    }
    open_attached_data(path, expected)
}

fn open_attached_data(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    if !path.is_absolute()
        || !matches!(expected.kind, NodeKind::Directory | NodeKind::Regular)
        || expected.identity.is_none()
        || crate::classify_location(path)?.kind != crate::LocationKind::Local
    {
        return Err(invalid("identified local directory required"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("directory parent missing"))?;
    let _guard = pin_metadata_parent(parent)?;
    #[cfg(unix)]
    let file = crate::unix::open_nofollow(path, expected.kind == NodeKind::Directory)?;
    #[cfg(windows)]
    let file = {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        OpenOptions::new()
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
    };
    if !expected.matches(&crate::inspect_file(&file)?) || !expected.matches(&crate::inspect(path)?)
    {
        return Err(invalid("directory changed before attached-data read"));
    }
    Ok(file)
}

pub struct MigrationDirectory {
    envelope: StagedDirectory,
    tree: Option<StagedDirectory>,
    root: Option<File>,
    envelope_path: PathBuf,
    parent_path: PathBuf,
    parent_info: NodeInfo,
    path: PathBuf,
    identity: FileIdentity,
    directories: BTreeMap<PathBuf, FileIdentity>,
    files: BTreeMap<PathBuf, FileIdentity>,
    symlinks: BTreeMap<PathBuf, LinkRecord>,
    finalized: BTreeSet<PathBuf>,
    published: bool,
}

#[derive(Clone)]
struct LinkRecord {
    identity: FileIdentity,
    target: PathBuf,
    directory: bool,
}

impl MigrationDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Creation and subsequent mutations belong to a durable caller-owned plan.
    pub fn create(parent: &Path, expected: &NodeInfo, name: &OsStr) -> io::Result<Self> {
        let envelope = StagedDirectory::create(parent, expected, name)?;
        let envelope_path = parent.join(name);
        let tree = StagedDirectory::create_migration_payload(&envelope, OsStr::new("payload"))?;
        let identity = tree
            .inspect()?
            .identity
            .ok_or_else(|| invalid("directory payload identity missing"))?;
        let value = Self {
            path: envelope_path.join("payload"),
            envelope_path,
            parent_path: parent.into(),
            parent_info: expected.clone(),
            envelope,
            tree: Some(tree),
            root: None,
            identity,
            directories: BTreeMap::from([(PathBuf::new(), identity)]),
            files: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            finalized: BTreeSet::new(),
            published: false,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn inspect(&self) -> io::Result<NodeInfo> {
        let mut info = if let Some(tree) = &self.tree {
            tree.inspect()?
        } else {
            crate::inspect_file(self.root.as_ref().ok_or_else(|| invalid("root missing"))?)?
        };
        info.hidden |= self
            .path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().first() == Some(&b'.'));
        Ok(info)
    }

    pub fn envelope_info(&self) -> io::Result<NodeInfo> {
        self.envelope.inspect()
    }

    pub fn verify(&self) -> io::Result<()> {
        self.envelope.verify()?;
        if let Some(tree) = &self.tree {
            tree.verify()?;
        }
        let opened = self.inspect()?;
        if opened.kind != NodeKind::Directory
            || opened.identity != Some(self.identity)
            || !opened.matches(&crate::inspect(&self.path)?)
            || crate::inspect(&self.parent_path)?.identity != self.parent_info.identity
            || crate::classify_location(&self.path)?.kind != crate::LocationKind::Local
        {
            return Err(invalid("migration directory or parent changed"));
        }
        Ok(())
    }

    fn building(&self, relative: &Path) -> io::Result<&StagedDirectory> {
        relative_path(relative)?;
        self.verify()?;
        if self.published
            || self.root.is_some()
            || self.finalized.iter().any(|done| relative.starts_with(done))
        {
            return Err(invalid("directory metadata already finalized"));
        }
        self.tree
            .as_ref()
            .ok_or_else(|| invalid("tree already sealed"))
    }

    pub fn create_directory(&mut self, relative: &Path) -> io::Result<NodeInfo> {
        if relative.as_os_str().is_empty() {
            return Err(invalid("child directory required"));
        }
        self.building(relative)?;
        let info = self
            .tree
            .as_mut()
            .ok_or_else(|| invalid("tree already sealed"))?
            .create_directory(relative)?;
        self.directories.insert(
            relative.into(),
            info.identity
                .ok_or_else(|| invalid("directory identity missing"))?,
        );
        Ok(info)
    }

    pub fn copy_file(
        &mut self,
        relative: &Path,
        source_path: &Path,
        source: &File,
        metadata: &MetadataInventory,
        check: &(impl Fn() -> io::Result<()> + Sync),
    ) -> io::Result<MigrationTreeFile<'_>> {
        check_migration_metadata(metadata)?;
        check()?;
        let tree = self.building(relative)?;
        let parent = tree.directory(
            relative
                .parent()
                .ok_or_else(|| invalid("child file required"))?,
        )?;
        let source_info = crate::inspect(source_path)?;
        if source_info.kind != NodeKind::Regular
            || !source_info.matches(&crate::inspect_file(source)?)
        {
            return Err(invalid("identified regular migration source required"));
        }
        let source_parent = source_path
            .parent()
            .ok_or_else(|| invalid("source parent missing"))?;
        let _guard = pin_metadata_parent(source_parent)?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
        {
            return Err(invalid("source metadata changed before transfer"));
        }
        let mut file = tree.migration_file(relative)?;
        let identity = crate::inspect_file(&file)?
            .identity
            .ok_or_else(|| invalid("file payload identity missing"))?;
        native::copy(source, &mut file, metadata, check)?;
        file.sync_all()?;
        check()?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
        {
            return Err(invalid("source metadata changed during transfer"));
        }
        let path = self.path.join(relative);
        let copied = crate::metadata_inventory::inventory_open(&path, &file)?;
        compare_metadata(metadata, &copied)?;
        self.files.insert(relative.into(), identity);
        let value = MigrationTreeFile {
            owner: self,
            path,
            file,
            identity,
            _parent: parent,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn copy_symlink(
        &mut self,
        relative: &Path,
        source_path: &Path,
        source: &File,
        metadata: &MetadataInventory,
        check: &(impl Fn() -> io::Result<()> + Sync),
    ) -> io::Result<NodeInfo> {
        check_migration_metadata(metadata)?;
        check()?;
        let tree = self.building(relative)?;
        let source_info = crate::inspect(source_path)?;
        if source_info.kind != NodeKind::Symlink
            || !source_info.matches(&crate::inspect_file(source)?)
        {
            return Err(invalid(
                "identified symbolic-link migration source required",
            ));
        }
        let source_parent = source_path
            .parent()
            .ok_or_else(|| invalid("source parent missing"))?;
        let _source_guard = pin_metadata_parent(source_parent)?;
        let source_parent_file = metadata_parent_file(&_source_guard)?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
        {
            return Err(invalid("link metadata changed before transfer"));
        }
        let target_text = std::fs::read_link(source_path)?;
        let directory = crate::symlink_directory(source_path)?;
        let parent = tree.directory(
            relative
                .parent()
                .ok_or_else(|| invalid("link parent missing"))?,
        )?;
        let parent_file = parent.try_clone_file()?;
        let name = relative
            .file_name()
            .ok_or_else(|| invalid("link name missing"))?;
        let created = tree.create_symlink(relative, &target_text, directory)?;
        let mut target = super::link::open_link_at(&parent_file, name, true)?;
        if !created.matches(&crate::inspect_file(&target)?) {
            return Err(invalid("created link changed before metadata transfer"));
        }
        native::copy_link_metadata(
            source,
            &mut target,
            metadata,
            LinkLocation {
                parent: &source_parent_file,
                name: source_path
                    .file_name()
                    .ok_or_else(|| invalid("source name missing"))?,
            },
            LinkLocation {
                parent: &parent_file,
                name,
            },
            check,
        )?;
        check()?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
            || std::fs::read_link(source_path)? != target_text
            || crate::symlink_directory(source_path)? != directory
        {
            return Err(invalid("link source changed during transfer"));
        }
        let path = self.path.join(relative);
        let copied = crate::metadata_inventory::inventory_open(&path, &target)?;
        compare_metadata(metadata, &copied)?;
        let info = crate::inspect(&path)?;
        if info.identity != created.identity
            || info.kind != NodeKind::Symlink
            || info.modified != source_info.modified
            || std::fs::read_link(&path)? != target_text
            || crate::symlink_directory(&path)? != directory
        {
            return Err(invalid("copied symbolic link differs from source"));
        }
        self.symlinks.insert(
            relative.into(),
            LinkRecord {
                identity: info
                    .identity
                    .ok_or_else(|| invalid("link identity missing"))?,
                target: target_text,
                directory,
            },
        );
        self.verify()?;
        Ok(info)
    }

    /// Create another name for an already copied file or link inside this payload.
    pub fn create_hard_link(&mut self, existing: &Path, relative: &Path) -> io::Result<NodeInfo> {
        relative_path(existing)?;
        let tree = self.building(relative)?;
        let link = self.symlinks.get(existing).cloned();
        let identity = self
            .files
            .get(existing)
            .copied()
            .or_else(|| link.as_ref().map(|link| link.identity))
            .ok_or_else(|| invalid("owned link source required"))?;
        let before = self.entry(existing)?;
        let from = tree.directory(
            existing
                .parent()
                .ok_or_else(|| invalid("link source parent missing"))?,
        )?;
        let to = tree.directory(
            relative
                .parent()
                .ok_or_else(|| invalid("link parent missing"))?,
        )?;
        let name = relative
            .file_name()
            .ok_or_else(|| invalid("link name missing"))?;
        #[cfg(unix)]
        {
            let from_file = from.try_clone_file()?;
            let to_file = to.try_clone_file()?;
            let source_name = existing
                .file_name()
                .ok_or_else(|| invalid("link source name missing"))?;
            if !before.matches(&crate::mutation::inspect_relative(&from_file, source_name)?) {
                return Err(invalid("link source changed"));
            }
            rustix::fs::linkat(
                &from_file,
                source_name,
                &to_file,
                name,
                rustix::fs::AtFlags::empty(),
            )?;
            to_file.sync_all()?;
        }
        #[cfg(windows)]
        {
            let source = self.read_entry(existing)?;
            crate::mutation::link_open_file(&source.file, &to.try_clone_file()?, name)?;
        }
        let _ = from;
        let info = crate::inspect(&self.path.join(relative))?;
        if info.kind != before.kind
            || info.identity != Some(identity)
            || info.modified != before.modified
            || info.len != before.len
            || info.links
                != before
                    .links
                    .checked_add(1)
                    .ok_or_else(|| invalid("link count overflow"))?
        {
            return Err(invalid("created hard link differs from owned source"));
        }
        if let Some(link) = link {
            self.symlinks.insert(relative.into(), link);
        } else {
            self.files.insert(relative.into(), identity);
        }
        self.verify()?;
        Ok(info)
    }

    /// Finalize each child directory before its parent. Finalizing the root
    /// seals construction; publication is available only after that transition.
    pub fn copy_directory_metadata(
        &mut self,
        relative: &Path,
        source_path: &Path,
        source: &File,
        metadata: &MetadataInventory,
        check: &(impl Fn() -> io::Result<()> + Sync),
    ) -> io::Result<NodeInfo> {
        check_migration_metadata(metadata)?;
        check()?;
        self.building(relative)?;
        if self.directories.keys().any(|child| {
            child != relative && child.parent() == Some(relative) && !self.finalized.contains(child)
        }) {
            return Err(invalid("child directories must be finalized first"));
        }
        if relative.as_os_str().is_empty() {
            self.verify_contents(check)?;
        }
        let source_info = crate::inspect(source_path)?;
        if source_info.kind != NodeKind::Directory
            || !source_info.matches(&crate::inspect_file(source)?)
        {
            return Err(invalid("identified directory migration source required"));
        }
        let source_parent = source_path
            .parent()
            .ok_or_else(|| invalid("source parent missing"))?;
        let _guard = pin_metadata_parent(source_parent)?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
        {
            return Err(invalid("directory metadata changed before transfer"));
        }
        let mut target = self
            .tree
            .as_ref()
            .ok_or_else(|| invalid("tree sealed"))?
            .migration_directory(relative)?;
        native::copy_directory_metadata(source, &mut target, metadata, check)?;
        #[cfg(unix)]
        target.sync_all()?;
        check()?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != metadata.binding_bytes()
        {
            return Err(invalid("directory metadata changed during transfer"));
        }
        let path = self.path.join(relative);
        let copied = crate::metadata_inventory::inventory_open(&path, &target)?;
        compare_metadata(metadata, &copied)?;
        let info = crate::inspect(&path)?;
        if info.identity.as_ref() != self.directories.get(relative)
            || info.modified != source_info.modified
        {
            return Err(invalid("directory identity or modification time changed"));
        }
        self.finalized.insert(relative.into());
        if relative.as_os_str().is_empty() {
            self.root = Some(
                self.tree
                    .take()
                    .ok_or_else(|| invalid("tree sealed"))?
                    .into_migration_root(),
            );
        }
        self.verify()?;
        Ok(info)
    }

    pub fn metadata(&self, relative: &Path) -> io::Result<MetadataInventory> {
        let opened = self.read_entry(relative)?;
        let result =
            crate::metadata_inventory::inventory_open(&self.path.join(relative), &opened.file)?;
        self.verify()?;
        Ok(result)
    }

    pub fn visit_body(
        &self,
        relative: &Path,
        check: &(impl Fn() -> io::Result<()> + Sync),
        sink: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        use std::io::Read;
        check()?;
        let mut opened = self.read_entry(relative)?;
        if crate::inspect_file(&opened.file)?.kind != NodeKind::Regular {
            return Err(invalid("regular migration payload required"));
        }
        let path = self.path.join(relative);
        let before = crate::metadata_inventory::inventory_open(&path, &opened.file)?;
        let mut buffer = [0u8; 65536];
        loop {
            check()?;
            let count = opened.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            sink(&buffer[..count])?;
        }
        check()?;
        if crate::metadata_inventory::inventory_open(&path, &opened.file)?.binding_bytes()
            != before.binding_bytes()
        {
            return Err(invalid("payload changed during body verification"));
        }
        self.verify()
    }

    pub fn visit_data(
        &self,
        relative: &Path,
        check: &(impl Fn() -> io::Result<()> + Sync),
        sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let path = self.path.join(relative);
        let mut opened = self.read_entry(relative)?;
        let metadata = crate::metadata_inventory::inventory_open(&path, &opened.file)?;
        let location = opened
            ._ancestors
            .last()
            .zip(path.file_name())
            .map(|(parent, name)| LinkLocation { parent, name });
        super::visit_pinned_data(&path, &mut opened.file, &metadata, location, check, sink)?;
        self.verify()
    }

    fn read_directory(&self, relative: &Path) -> io::Result<OpenedEntry> {
        relative_path(relative)?;
        self.verify()?;
        let mut file = if let Some(root) = &self.root {
            root.try_clone()?
        } else {
            self.tree
                .as_ref()
                .ok_or_else(|| invalid("root missing"))?
                .clone_root_file()?
        };
        let mut ancestors = Vec::new();
        let mut prefix = PathBuf::new();
        for part in relative.components() {
            let std::path::Component::Normal(name) = part else {
                return Err(invalid("relative directory component required"));
            };
            prefix.push(name);
            let expected = self
                .directories
                .get(&prefix)
                .ok_or_else(|| invalid("unrecorded directory"))?;
            let next = open_owned_read(&file, name, true)?;
            let info = crate::inspect_file(&next)?;
            if info.kind != NodeKind::Directory || info.identity != Some(*expected) {
                return Err(invalid("owned directory changed before reading"));
            }
            ancestors.push(file);
            file = next;
        }
        Ok(OpenedEntry {
            file,
            _ancestors: ancestors,
        })
    }

    fn read_entry(&self, relative: &Path) -> io::Result<OpenedEntry> {
        let expected = self.entry(relative)?;
        let opened = if expected.kind == NodeKind::Directory {
            self.read_directory(relative)?
        } else {
            let parent = relative
                .parent()
                .ok_or_else(|| invalid("entry parent missing"))?;
            let mut opened = self.read_directory(parent)?;
            let name = relative
                .file_name()
                .ok_or_else(|| invalid("entry name missing"))?;
            let file = if expected.kind == NodeKind::Symlink {
                super::link::open_link_at(&opened.file, name, false)?
            } else {
                open_owned_read(&opened.file, name, false)?
            };
            opened._ancestors.push(opened.file);
            OpenedEntry {
                file,
                _ancestors: opened._ancestors,
            }
        };
        if !expected.matches(&crate::inspect_file(&opened.file)?) {
            return Err(invalid("owned entry changed before reading"));
        }
        Ok(opened)
    }

    fn entry(&self, relative: &Path) -> io::Result<NodeInfo> {
        relative_path(relative)?;
        self.verify()?;
        let (identity, kind) = if let Some(id) = self.directories.get(relative) {
            (id, NodeKind::Directory)
        } else if let Some(link) = self.symlinks.get(relative) {
            (&link.identity, NodeKind::Symlink)
        } else {
            (
                self.files
                    .get(relative)
                    .ok_or_else(|| invalid("unrecorded tree entry"))?,
                NodeKind::Regular,
            )
        };
        let info = crate::inspect(&self.path.join(relative))?;
        if info.identity.as_ref() != Some(identity) || info.kind != kind {
            return Err(invalid("owned tree entry changed"));
        }
        if let Some(link) = self.symlinks.get(relative) {
            let path = self.path.join(relative);
            if std::fs::read_link(&path)? != link.target
                || crate::symlink_directory(&path)? != link.directory
            {
                return Err(invalid("owned symbolic-link target changed"));
            }
        }
        Ok(info)
    }

    pub fn verify_contents(&self, check: &(impl Fn() -> io::Result<()> + Sync)) -> io::Result<()> {
        self.verify()?;
        let mut counts = HashMap::<FileIdentity, u64>::new();
        for identity in self
            .files
            .values()
            .chain(self.symlinks.values().map(|link| &link.identity))
        {
            *counts.entry(*identity).or_default() += 1;
        }
        let mut children = self
            .directories
            .keys()
            .map(|path| (path.clone(), BTreeSet::<OsString>::new()))
            .collect::<BTreeMap<_, _>>();
        for path in self
            .directories
            .keys()
            .chain(self.files.keys())
            .chain(self.symlinks.keys())
            .filter(|path| !path.as_os_str().is_empty())
        {
            let parent = path
                .parent()
                .ok_or_else(|| invalid("entry parent missing"))?;
            let name = path
                .file_name()
                .ok_or_else(|| invalid("entry name missing"))?;
            if !children
                .get_mut(parent)
                .ok_or_else(|| invalid("unrecorded parent"))?
                .insert(name.to_os_string())
            {
                return Err(invalid("duplicate tree entry"));
            }
        }
        for relative in self.files.keys().chain(self.symlinks.keys()) {
            check()?;
            let info = self.entry(relative)?;
            if info.links
                != *counts
                    .get(
                        &info
                            .identity
                            .ok_or_else(|| invalid("file identity missing"))?,
                    )
                    .ok_or_else(|| invalid("link count missing"))?
            {
                return Err(invalid("payload has links outside the recorded tree"));
            }
        }
        for relative in self.directories.keys() {
            check()?;
            let info = self.entry(relative)?;
            let expected = children
                .get(relative)
                .ok_or_else(|| invalid("directory children missing"))?;
            #[cfg(unix)]
            let listing = crate::read_directory_verified(
                &self.path.join(relative),
                &info,
                expected
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| invalid("child count overflow"))?,
            )?;
            #[cfg(windows)]
            let listing = {
                let path = self.path.join(relative);
                let directory = self.read_directory(relative)?;
                crate::windows::read_directory_using_pin(
                    &path,
                    &info,
                    &directory.file,
                    expected
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| invalid("child count overflow"))?,
                    &|| false,
                )?
            };
            if listing.truncated || listing.names.into_iter().collect::<BTreeSet<_>>() != *expected
            {
                return Err(invalid("migration directory contents changed"));
            }
        }
        self.verify()
    }

    pub fn publish(&mut self, name: &OsStr) -> Result<NodeInfo, RenameError> {
        crate::staged_file::component(name)?;
        self.verify()?;
        if self.published || self.root.is_none() {
            return Err(invalid("directory payload must be sealed once before publication").into());
        }
        let target = self.parent_path.join(name);
        #[cfg(unix)]
        crate::rename_noreplace(
            &self.path,
            &self.inspect()?,
            &target,
            &self.envelope.inspect()?,
            &crate::inspect(&self.parent_path)?,
        )?;
        #[cfg(windows)]
        {
            let parent = crate::open_directory_pinned(&self.parent_path, &self.parent_info)?;
            crate::mutation::publish_open_file(
                self.root.as_ref().ok_or_else(|| invalid("root missing"))?,
                &parent.try_clone_file()?,
                name,
            )
            .map_err(RenameError::from_rename)?;
        }
        self.path = target;
        self.published = true;
        self.verify().map_err(RenameError::after_rename)?;
        self.inspect().map_err(RenameError::after_rename)
    }

    pub fn retire_envelope(self) -> Result<(), crate::RemovalError> {
        self.verify()?;
        if !self.published {
            return Err(invalid("directory payload has not been published").into());
        }
        let info = self.envelope.inspect()?;
        let listing = self.envelope.read_directory(Path::new(""), &info, 1)?;
        if listing.truncated || !listing.names.is_empty() {
            return Err(invalid("envelope is not empty").into());
        }
        let path = self.envelope_path.clone();
        let parent = crate::inspect(&self.parent_path)?;
        drop(self);
        crate::remove_verified(&path, &info, &parent)
    }
}

struct OpenedEntry {
    file: File,
    _ancestors: Vec<File>,
}

fn open_owned_read(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    crate::staged_file::component(name)?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, openat};
        let flags = OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        Ok(File::from(openat(parent, name, flags, Mode::empty())?))
    }
    #[cfg(windows)]
    {
        crate::private_storage::open_migration_read_handle(parent, name, directory)
    }
}

pub struct MigrationTreeFile<'a> {
    owner: &'a MigrationDirectory,
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    _parent: PinnedDirectory,
}
impl MigrationTreeFile<'_> {
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
        self.owner.verify()?;
        let info = self.inspect()?;
        if info.identity != Some(self.identity)
            || info.kind != NodeKind::Regular
            || !info.matches(&crate::inspect(&self.path)?)
        {
            return Err(invalid("migration tree file changed"));
        }
        Ok(())
    }
    pub fn metadata(&self) -> io::Result<MetadataInventory> {
        self.verify()?;
        let value = crate::metadata_inventory::inventory_open(&self.path, &self.file)?;
        self.verify()?;
        Ok(value)
    }
    pub fn visit_data(
        &mut self,
        check: &(impl Fn() -> io::Result<()> + Sync),
        sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.verify()?;
        let before = self.metadata()?;
        native::visit(&mut self.file, &before, check, sink)?;
        if self.metadata()?.binding_bytes() != before.binding_bytes() {
            return Err(invalid("tree file metadata changed during verification"));
        }
        self.verify()
    }
}

fn relative_path(path: &Path) -> io::Result<()> {
    for part in path.components() {
        let std::path::Component::Normal(name) = part else {
            return Err(invalid("relative child path required"));
        };
        crate::staged_file::component(name)?;
    }
    Ok(())
}
fn compare_metadata(expected: &MetadataInventory, actual: &MetadataInventory) -> io::Result<()> {
    if expected.portable_bytes() != actual.portable_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "migration metadata field {} could not be preserved",
                metadata_difference(expected.portable_bytes(), actual.portable_bytes())
            ),
        ));
    }
    Ok(())
}
