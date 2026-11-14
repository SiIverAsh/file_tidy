//! Migration metadata descriptions. Attribute values and file bodies are not read.
use crate::{NodeInfo, NodeKind};
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path};

const MAX_DESCRIPTOR: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataAttributeKind {
    ExtendedAttribute,
    ResourceFork,
    AlternateStream,
    ExtendedAttributes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataAttribute {
    pub name: OsString,
    pub kind: MetadataAttributeKind,
    pub bytes: u64,
}
#[derive(Clone, PartialEq, Eq)]
pub struct MetadataInventory {
    kind: NodeKind,
    attributes: Vec<MetadataAttribute>,
    opaque_bytes: u64,
    owner_is_current: bool,
    privileged_permissions: bool,
    native_flags: u64,
    binding: Vec<u8>,
    portable: Vec<u8>,
}
impl std::fmt::Debug for MetadataInventory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataInventory")
            .field("attribute_count", &self.attributes.len())
            .field("opaque_bytes", &self.opaque_bytes)
            .field("owner_is_current", &self.owner_is_current)
            .field("privileged_permissions", &self.privileged_permissions)
            .finish_non_exhaustive()
    }
}
impl MetadataInventory {
    pub fn kind(&self) -> NodeKind {
        self.kind
    }
    pub fn attributes(&self) -> &[MetadataAttribute] {
        &self.attributes
    }
    pub fn opaque_bytes(&self) -> u64 {
        self.opaque_bytes
    }
    pub fn owner_is_current(&self) -> bool {
        self.owner_is_current
    }
    pub fn privileged_permissions(&self) -> bool {
        self.privileged_permissions
    }
    pub fn native_flags(&self) -> u64 {
        self.native_flags
    }

    /// Identity and metadata change time bind this description to its source version.
    pub fn binding_bytes(&self) -> &[u8] {
        &self.binding
    }
    /// Permission metadata and attribute names/sizes, without source identity or change time.
    pub fn portable_bytes(&self) -> &[u8] {
        &self.portable
    }
}

pub fn metadata_inventory(path: &Path, expected: &NodeInfo) -> io::Result<MetadataInventory> {
    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || !matches!(
            expected.kind,
            NodeKind::Regular | NodeKind::Directory | NodeKind::Symlink
        )
        || expected.identity.is_none()
        || !expected.matches(&crate::inspect(path)?)
        || crate::classify_location(path)?.kind != crate::LocationKind::Local
    {
        return Err(invalid("identified local metadata source required"));
    }
    #[cfg(unix)]
    let result = unix::inventory(path, expected)?;
    #[cfg(windows)]
    let result = windows::inventory(path, expected)?;
    if !expected.matches(&crate::inspect(path)?) {
        return Err(invalid("metadata source changed during inspection"));
    }
    Ok(result)
}
pub(crate) fn inventory_open(path: &Path, file: &std::fs::File) -> io::Result<MetadataInventory> {
    #[cfg(unix)]
    {
        let _ = file;
        metadata_inventory(path, &crate::inspect(path)?)
    }
    #[cfg(windows)]
    windows::inventory_open(path, &crate::inspect(path)?, file)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn field(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .and_then(|n| n.checked_add(8))
        .is_none_or(|n| n > MAX_DESCRIPTOR)
    {
        return Err(invalid("metadata description exceeds limit"));
    }
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}
fn finish(
    expected: &NodeInfo,
    portable: Vec<u8>,
    change: &[u8],
    mut attributes: Vec<MetadataAttribute>,
    owner_is_current: bool,
    privileged_permissions: bool,
    native_flags: u64,
) -> io::Result<MetadataInventory> {
    attributes.sort_by(|a, b| a.name.cmp(&b.name));
    let mut portable = portable;
    let mut opaque_bytes = 0u64;
    for attribute in &attributes {
        field(&mut portable, attribute.name.as_encoded_bytes())?;
        field(&mut portable, &attribute.bytes.to_le_bytes())?;
        field(&mut portable, &[attribute.kind as u8])?;
        opaque_bytes = opaque_bytes
            .checked_add(attribute.bytes)
            .ok_or_else(|| invalid("attribute length overflow"))?;
    }
    let identity = expected
        .identity
        .ok_or_else(|| invalid("metadata identity required"))?;
    let mut binding = Vec::new();
    field(&mut binding, b"file-tidy.metadata")?;
    field(&mut binding, &identity.volume.to_le_bytes())?;
    field(&mut binding, &identity.file.to_le_bytes())?;
    field(&mut binding, format!("{:?}", expected.kind).as_bytes())?;
    field(&mut binding, &expected.len.to_le_bytes())?;
    field(&mut binding, format!("{:?}", expected.modified).as_bytes())?;
    field(&mut binding, &expected.links.to_le_bytes())?;
    field(&mut binding, &[u8::from(expected.hidden)])?;
    field(&mut binding, change)?;
    field(&mut binding, &portable)?;
    Ok(MetadataInventory {
        kind: expected.kind,
        attributes,
        opaque_bytes,
        owner_is_current,
        privileged_permissions,
        native_flags,
        binding,
        portable,
    })
}

#[cfg(unix)]
mod unix {
    use super::*;
    #[cfg(target_os = "macos")]
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;
    fn change(metadata: &std::fs::Metadata) -> Vec<u8> {
        [
            metadata.ctime().to_le_bytes(),
            metadata.ctime_nsec().to_le_bytes(),
        ]
        .concat()
    }
    pub(super) fn inventory(path: &Path, expected: &NodeInfo) -> io::Result<MetadataInventory> {
        // O_PATH on Linux and O_EVTONLY on Darwin grant no file-data read access.
        // Link metadata uses no-follow pathname xattr queries instead of opening its target.
        let file = if expected.kind == NodeKind::Symlink {
            None
        } else {
            Some(crate::unix::open_metadata_nofollow(
                path,
                expected.kind == NodeKind::Directory,
            )?)
        };
        let before = match &file {
            Some(file) => file.metadata()?,
            None => std::fs::symlink_metadata(path)?,
        };
        if !expected.matches(&crate::unix::node_info(path, &before)) {
            return Err(invalid("metadata source changed before opening"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("metadata parent required"))?;
        let parent_info = crate::inspect(parent)?;
        let parent_file = crate::unix::open_metadata_nofollow(parent, true)?;
        if crate::inspect_file(&parent_file)?.identity != parent_info.identity {
            return Err(invalid("metadata parent changed"));
        }
        let mut portable = Vec::new();
        field(&mut portable, &before.mode().to_le_bytes())?;
        field(&mut portable, &before.uid().to_le_bytes())?;
        field(&mut portable, &before.gid().to_le_bytes())?;
        #[cfg(target_os = "linux")]
        let native_flags = {
            use rustix::fs::{AtFlags, StatxFlags, statx};
            let metadata = match &file {
                Some(file) => statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::BASIC_STATS)?,
                None => statx(
                    rustix::fs::CWD,
                    path,
                    AtFlags::SYMLINK_NOFOLLOW,
                    StatxFlags::BASIC_STATS,
                )?,
            };
            metadata.stx_attributes.bits()
        };
        #[cfg(target_os = "macos")]
        let native_flags = u64::from(before.st_flags());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let native_flags = 0;
        #[cfg(target_os = "linux")]
        field(&mut portable, &native_flags.to_le_bytes())?;
        #[cfg(target_os = "macos")]
        field(&mut portable, &before.st_flags().to_le_bytes())?;
        #[cfg(target_os = "macos")]
        field(
            &mut portable,
            &match &file {
                Some(file) => acl::read(file)?,
                None => acl::read_link(path)?,
            },
        )?;
        let names = match rustix::fs::llistxattr_query(path) {
            Ok(size) if size <= MAX_DESCRIPTOR => {
                let mut buffer = vec![0u8; size];
                if size != 0 {
                    let used = rustix::fs::llistxattr(path, buffer.as_mut_slice())?;
                    buffer.truncate(used);
                }
                buffer
            }
            Ok(_) => return Err(invalid("attribute names exceed limit")),
            Err(rustix::io::Errno::NOTSUP) => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let mut attributes = Vec::new();
        if !names.is_empty() && names.last() != Some(&0) {
            return Err(invalid("malformed attribute list"));
        }
        for name in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let name = OsString::from_vec(name.to_vec());
            // A null-buffer size query does not return attribute contents.
            let bytes = rustix::fs::lgetxattr_query(path, &name)? as u64;
            let kind = if name == "com.apple.ResourceFork" {
                MetadataAttributeKind::ResourceFork
            } else {
                MetadataAttributeKind::ExtendedAttribute
            };
            attributes.push(MetadataAttribute { name, kind, bytes });
        }
        let after = match &file {
            Some(file) => file.metadata()?,
            None => std::fs::symlink_metadata(path)?,
        };
        if change(&before) != change(&after)
            || before.mode() != after.mode()
            || before.uid() != after.uid()
            || before.gid() != after.gid()
            || !expected.matches(&crate::unix::node_info(path, &after))
            || parent_info.identity != crate::inspect(parent)?.identity
        {
            return Err(invalid("metadata changed during inspection"));
        }
        let privileged = before.mode() & 0o4000 != 0
            || (expected.kind != NodeKind::Directory && before.mode() & 0o2000 != 0)
            || attributes
                .iter()
                .any(|attribute| attribute.name == "security.capability");
        finish(
            expected,
            portable,
            &change(&before),
            attributes,
            before.uid() == rustix::process::geteuid().as_raw(),
            privileged,
            native_flags,
        )
    }
    #[cfg(target_os = "macos")]
    mod acl {
        use super::*;
        use std::ffi::c_void;
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
            fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut c_void;
            fn acl_size(acl: *mut c_void) -> libc::ssize_t;
            fn acl_copy_ext(
                buffer: *mut c_void,
                acl: *mut c_void,
                size: libc::ssize_t,
            ) -> libc::ssize_t;
            fn acl_free(acl: *mut c_void) -> libc::c_int;
        }
        struct Acl(*mut c_void);
        impl Drop for Acl {
            fn drop(&mut self) {
                // SAFETY: acl_get_fd_np allocated this unique object; acl_free releases it once.
                unsafe {
                    acl_free(self.0);
                }
            }
        }
        pub(super) fn read(file: &std::fs::File) -> io::Result<Vec<u8>> {
            // SAFETY: the live metadata-only descriptor is borrowed for this synchronous call.
            // ACL_TYPE_EXTENDED is 0x100 in the installed Darwin sys/acl.h.
            let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
            encode(acl)
        }
        pub(super) fn read_link(path: &Path) -> io::Result<Vec<u8>> {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| invalid("ACL path contains NUL"))?;
            // SAFETY: the terminated pathname is live for the synchronous no-follow
            // link ACL query. No link target or file content is opened.
            encode(unsafe { acl_get_link_np(name.as_ptr(), 0x100) })
        }
        fn encode(acl: *mut c_void) -> io::Result<Vec<u8>> {
            if acl.is_null() {
                let error = io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ENOATTR | libc::ENOTSUP)
                ) {
                    return Ok(Vec::new());
                }
                return Err(error);
            }
            let acl = Acl(acl);
            // SAFETY: acl owns a valid ACL object for the duration of both queries.
            let size = unsafe { acl_size(acl.0) };
            let size = usize::try_from(size).map_err(|_| io::Error::last_os_error())?;
            if size > MAX_DESCRIPTOR {
                return Err(invalid("ACL exceeds limit"));
            }
            let mut buffer = vec![0u8; size];
            // SAFETY: buffer has the queried byte capacity and acl remains live. Binary
            // serialization avoids account-name resolution through directory services.
            let copied =
                unsafe { acl_copy_ext(buffer.as_mut_ptr().cast(), acl.0, size as libc::ssize_t) };
            if copied < 0 {
                return Err(io::Error::last_os_error());
            }
            let copied = usize::try_from(copied).map_err(|_| invalid("ACL size overflow"))?;
            if copied > buffer.len() {
                return Err(invalid("ACL serialization grew"));
            }
            buffer.truncate(copied);
            Ok(buffer)
        }
    }
}

#[cfg(windows)]
#[path = "metadata_inventory_windows.rs"]
mod windows;
