//! Metadata-preserving payloads inside an owner-private staging directory.
use crate::{FileIdentity, MetadataInventory, NodeInfo, NodeKind, RenameError, StagedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[path = "migration_unix.rs"]
mod native;
#[cfg(windows)]
#[path = "migration_windows.rs"]
mod native;

/// Framed opaque streams. Callers can hash each stream independently and sort
/// the resulting fingerprints by (kind, native name), without buffering values.
pub enum MigrationData<'a> {
    Begin {
        kind: u32,
        name: &'a OsStr,
        bytes: u64,
    },
    Chunk(&'a [u8]),
    End,
}

pub fn check_migration_metadata(metadata: &MetadataInventory) -> io::Result<()> {
    if !metadata.owner_is_current() || metadata.privileged_permissions() {
        return Err(unsupported(
            "migration requires current ownership and ordinary permissions",
        ));
    }
    native::check_metadata(metadata)
}

pub struct MigrationFile {
    envelope: StagedDirectory,
    envelope_path: PathBuf,
    parent_path: PathBuf,
    parent_info: NodeInfo,
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    published: bool,
}
impl MigrationFile {
    /// Persist the envelope creation intent before calling: a failed creation
    /// can leave an owned directory or payload requiring reconciliation.
    pub fn create(parent: &Path, expected: &NodeInfo, name: &OsStr) -> io::Result<Self> {
        let envelope = StagedDirectory::create(parent, expected, name)?;
        let file = envelope.create_file(Path::new("payload"))?.into_file();
        let envelope_path = parent.join(name);
        let value = Self {
            path: envelope_path.join("payload"),
            envelope_path,
            parent_path: parent.into(),
            parent_info: expected.clone(),
            identity: crate::inspect_file(&file)?
                .identity
                .ok_or_else(|| invalid("payload identity missing"))?,
            file,
            envelope,
            published: false,
        };
        value.verify()?;
        Ok(value)
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn inspect(&self) -> io::Result<NodeInfo> {
        let mut info = crate::inspect_file(&self.file)?;
        info.hidden |= self
            .path
            .file_name()
            .is_some_and(|n| n.as_encoded_bytes().first() == Some(&b'.'));
        Ok(info)
    }
    pub fn envelope_info(&self) -> io::Result<NodeInfo> {
        self.envelope.inspect()
    }
    pub fn verify(&self) -> io::Result<()> {
        self.envelope.verify()?;
        let opened = self.inspect()?;
        if opened.kind != NodeKind::Regular
            || opened.identity != Some(self.identity)
            || !opened.matches(&crate::inspect(&self.path)?)
            || crate::inspect(&self.parent_path)?.identity != self.parent_info.identity
        {
            return Err(invalid("migration payload or parent changed"));
        }
        Ok(())
    }
    pub fn metadata(&self) -> io::Result<MetadataInventory> {
        self.verify()?;
        let metadata = crate::metadata_inventory::inventory_open(&self.path, &self.file)?;
        self.verify()?;
        Ok(metadata)
    }
    /// The caller supplies a live content-permit checkpoint, including consent
    /// for attached data. The source remains untouched throughout the transfer.
    pub fn copy_from(
        &mut self,
        source_path: &Path,
        source: &File,
        expected: &MetadataInventory,
        check: &(impl Fn() -> io::Result<()> + Sync),
    ) -> io::Result<()> {
        if self.published {
            return Err(invalid("payload already published"));
        }
        check_migration_metadata(expected)?;
        check()?;
        self.verify()?;
        let source_info = crate::inspect(source_path)?;
        if source_info.kind != NodeKind::Regular
            || !source_info.matches(&crate::inspect_file(source)?)
        {
            return Err(invalid("identified regular migration source required"));
        }
        let parent = source_path
            .parent()
            .ok_or_else(|| invalid("source parent missing"))?;
        let parent_info = crate::inspect(parent)?;
        let _guard = crate::open_directory_pinned(parent, &parent_info)?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != expected.binding_bytes()
        {
            return Err(invalid("source metadata changed before transfer"));
        }
        native::copy(source, &mut self.file, expected, check)?;
        self.file.sync_all()?;
        check()?;
        self.verify()?;
        if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
            != expected.binding_bytes()
            || self.metadata()?.portable_bytes() != expected.portable_bytes()
        {
            return Err(unsupported("migration metadata could not be preserved"));
        }
        Ok(())
    }
    pub fn visit_data(
        &mut self,
        check: &(impl Fn() -> io::Result<()> + Sync),
        sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.verify()?;
        let before = self.metadata()?;
        native::visit(&mut self.file, check, sink)?;
        if self.metadata()?.binding_bytes() != before.binding_bytes() {
            return Err(invalid("payload metadata changed during verification"));
        }
        self.verify()
    }
    pub fn publish(&mut self, name: &OsStr) -> Result<NodeInfo, RenameError> {
        crate::staged_file::component(name)?;
        if self.published {
            return Err(invalid("payload already published").into());
        }
        self.verify()?;
        self.file.sync_all()?;
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
            crate::mutation::publish_open_file(&self.file, &parent.try_clone_file()?, name)
                .map_err(RenameError::from_rename)?;
        }
        self.path = target;
        self.published = true;
        self.verify().map_err(RenameError::after_rename)?;
        self.inspect().map_err(RenameError::after_rename)
    }
    /// Called after a durable cleanup intent; it removes only the now-empty,
    /// identified envelope. The published payload is retained.
    pub fn retire_envelope(self) -> Result<(), crate::RemovalError> {
        self.verify()?;
        if !self.published {
            return Err(invalid("payload has not been published").into());
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

pub fn visit_migration_data(
    source_path: &Path,
    source: &mut File,
    expected: &MetadataInventory,
    check: &(impl Fn() -> io::Result<()> + Sync),
    sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let parent = source_path
        .parent()
        .ok_or_else(|| invalid("source parent missing"))?;
    let _guard = crate::open_directory_pinned(parent, &crate::inspect(parent)?)?;
    if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
        != expected.binding_bytes()
    {
        return Err(invalid("source metadata changed before verification"));
    }
    native::visit(source, check, sink)?;
    check()?;
    if crate::metadata_inventory::inventory_open(source_path, source)?.binding_bytes()
        != expected.binding_bytes()
    {
        return Err(invalid("source metadata changed during verification"));
    }
    Ok(())
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
