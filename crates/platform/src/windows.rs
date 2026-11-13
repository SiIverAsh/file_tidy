//! Windows native reads. These paths have not yet been exercised on Windows.
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::*;

#[cfg(test)]
use crate::MountTable;
use crate::{DirectoryListing, FileIdentity, LocationInfo, LocationKind, NodeInfo, NodeKind};

const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut units: Vec<_> = value.encode_wide().collect();
    if units.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    units.push(0);
    Ok(units)
}

// Accept only the documented volume GUID namespace, never an arbitrary
// Verbatim device name (GLOBALROOT, PhysicalDrive, named pipe, and so on).
fn is_volume_guid_prefix(value: &OsStr) -> bool {
    let units: Vec<_> = value.encode_wide().collect();
    if units.len() != 44
        || !units[..7]
            .iter()
            .zip(b"Volume{")
            .all(|(a, b)| u8::try_from(*a).is_ok_and(|a| a.eq_ignore_ascii_case(b)))
        || units[43] != u16::from(b'}')
    {
        return false;
    }
    (7..43).all(|index| {
        if matches!(index, 15 | 20 | 25 | 30) {
            units[index] == u16::from(b'-')
        } else {
            u8::try_from(units[index]).is_ok_and(|byte| byte.is_ascii_hexdigit())
        }
    })
}

pub(crate) fn is_volume_guid_root(path: &Path) -> bool {
    let mut parts = path.components();
    matches!(parts.next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Verbatim(value) if is_volume_guid_prefix(value)))
        && matches!(parts.next(), Some(Component::RootDir))
        && parts.next().is_none()
}

fn metadata_kind(metadata: &Metadata) -> NodeKind {
    // Explicitly inspect REPARSE_POINT, including junctions, mount points and
    // cloud tags that std::FileType::is_symlink alone would miss.
    let attributes = metadata.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if metadata.file_type().is_symlink() {
            NodeKind::Symlink
        } else {
            NodeKind::Reparse
        }
    } else if attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            | FILE_ATTRIBUTE_RECALL_ON_OPEN)
        != 0
    {
        NodeKind::Reparse
    } else if metadata.is_dir() {
        NodeKind::Directory
    } else if metadata.is_file() {
        NodeKind::Regular
    } else {
        NodeKind::Special
    }
}

fn base_info(metadata: &Metadata) -> NodeInfo {
    NodeInfo {
        kind: metadata_kind(metadata),
        len: metadata.len(),
        identity: None,
        modified: metadata.modified().ok(),
        allocated: None,
        hidden: metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0,
        links: 0,
    }
}

pub(crate) fn inspect_with_metadata(path: &Path, metadata: &Metadata) -> io::Result<NodeInfo> {
    let mut info = base_info(metadata);
    // Dot files are hidden by product policy even without the Windows hidden bit.
    info.hidden |= path
        .file_name()
        .is_some_and(|name| name.encode_wide().next() == Some(u16::from(b'.')));
    if matches!(info.kind, NodeKind::Reparse | NodeKind::Special) {
        return Ok(info);
    }
    // A metadata-only handle does not request file content or hydrate cloud
    // reparse points. Caller still applies the core sensitive-content policy.
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let actual = node_info_from_file(&file)?;
    if actual.kind != info.kind || actual.len != info.len || actual.modified != info.modified {
        return Err(io::Error::other("file changed during metadata inspection"));
    }
    info.identity = actual.identity;
    info.links = actual.links;
    Ok(info)
}

pub(crate) fn node_info_from_file(file: &File) -> io::Result<NodeInfo> {
    let mut native = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid HANDLE and native points to initialized writable
    // storage of the ABI-prescribed type, valid for this synchronous call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut native) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut info = base_info(&file.metadata()?);
    let mut identity = FILE_ID_INFO::default();
    // SAFETY: identity is a correctly sized writable FILE_ID_INFO, file owns
    // the live handle, and this synchronous call does not retain its pointer.
    let identified = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    // Preserve ReFS's complete 128-bit file ID. If the filesystem cannot supply
    // that identity, metadata remains reportable but content access fails closed.
    info.identity = (identified != 0).then_some(FileIdentity {
        volume: identity.VolumeSerialNumber,
        file: u128::from_le_bytes(identity.FileId.Identifier),
    });
    info.links = u64::from(native.nNumberOfLinks);
    Ok(info)
}

pub(crate) fn open_verified(path: &Path, expected: &NodeInfo) -> io::Result<File> {
    let (file, _guards) = open_pinned(path, false)?;
    if !expected.matches(&node_info_from_file(&file)?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed before content read",
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
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "directory enumeration cancelled",
        ));
    }
    let (directory, _guards) = open_pinned(path, true)?;
    read_directory_using_pin(path, expected, &directory, limit, cancelled)
}

pub(crate) fn read_directory_using_pin(
    path: &Path,
    expected: &NodeInfo,
    directory: &File,
    limit: usize,
    cancelled: &impl Fn() -> bool,
) -> io::Result<DirectoryListing> {
    if !expected.matches(&node_info_from_file(directory)?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed before enumeration",
        ));
    }
    let mut names = Vec::new();
    let mut truncated = false;
    // The directory and every ancestor remain pinned against delete/rename and
    // incompatible write handles throughout this path-based enumeration. Reparse
    // points were rejected while acquiring those handles, before read_dir opens.
    let mut entries = std::fs::read_dir(path)?;
    loop {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "directory enumeration cancelled",
            ));
        }
        let Some(entry) = entries.next() else {
            break;
        };
        let name = entry?.file_name();
        let mut parts = Path::new(&name).components();
        if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
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
    if !expected.matches(&node_info_from_file(directory)?)
        || !expected.matches(&crate::inspect(path)?)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory changed during enumeration",
        ));
    }
    if cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "directory enumeration cancelled",
        ));
    }
    Ok(DirectoryListing { names, truncated })
}

pub(crate) fn open_pinned(path: &Path, directory: bool) -> io::Result<(File, Vec<File>)> {
    open_pinned_impl(path, directory, false)
}

pub(crate) fn open_state_directory(path: &Path) -> io::Result<(File, Vec<File>)> {
    open_pinned_impl(path, true, true)
}

fn open_pinned_impl(path: &Path, directory: bool, state: bool) -> io::Result<(File, Vec<File>)> {
    let mut prefix = PathBuf::new();
    let mut guards = Vec::<File>::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        match component {
            Component::Prefix(value) => {
                if !matches!(value.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
                    && !matches!(value.kind(), Prefix::Verbatim(value) if is_volume_guid_prefix(value))
                {
                    return Err(io::Error::other(
                        "UNC and device paths are not accepted for content reads",
                    ));
                }
                prefix.push(value.as_os_str());
                continue;
            }
            Component::RootDir => {
                prefix.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(io::Error::other("unresolved parent component")),
            Component::Normal(name) => {
                if name.encode_wide().any(|u| u == u16::from(b':')) {
                    return Err(io::Error::other("alternate data streams are not scanned"));
                }
                prefix.push(name);
            }
        }
        if !prefix.is_absolute() {
            return Err(io::Error::other("content path must be absolute"));
        }
        let last = components.peek().is_none();
        let access = if last && !directory {
            FILE_GENERIC_READ
        } else if last && state {
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
        } else {
            FILE_READ_ATTRIBUTES
        };
        let file = OpenOptions::new()
            .access_mode(access)
            .share_mode(if state {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            })
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&prefix)?;
        let actual = node_info_from_file(&file)?;
        if last {
            let kind = if directory {
                NodeKind::Directory
            } else {
                NodeKind::Regular
            };
            if actual.kind != kind {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file changed or has an unexpected type",
                ));
            }
            return Ok((file, guards));
        }
        if actual.kind != NodeKind::Directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "symbolic link or reparse point in content path",
            ));
        }
        // Excluding FILE_SHARE_DELETE pins each ancestor's directory entry
        // against renames/deletions until the verified leaf has been opened.
        guards.push(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "path has no leaf",
    ))
}

struct VolumeSearch(windows_sys::Win32::Foundation::HANDLE);
impl Drop for VolumeSearch {
    fn drop(&mut self) {
        // SAFETY: this handle was returned by FindFirstVolumeW and is owned here.
        unsafe { FindVolumeClose(self.0) };
    }
}

pub(crate) fn mounts() -> io::Result<Vec<LocationInfo>> {
    let mut buffer = vec![0u16; 1024];
    // SAFETY: writable buffer length is the count passed to the API; it lives
    // through this synchronous enumeration call.
    let handle = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let search = VolumeSearch(handle);
    let mut result = Vec::new();
    loop {
        let length = buffer
            .iter()
            .position(|u| *u == 0)
            .ok_or_else(|| io::Error::other("unterminated volume name"))?;
        let volume = &buffer[..=length];
        let guid_root = PathBuf::from(OsString::from_wide(&buffer[..length]));
        if !is_volume_guid_root(&guid_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid native volume GUID root",
            ));
        }
        // FindFirstVolume enumerates local volume GUIDs, including volumes with
        // no drive letter or mounted-folder alias. Keep this root even if an
        // optional alias query fails; later per-root metadata errors are reported.
        result.push(LocationInfo {
            kind: LocationKind::Local,
            mount_root: guid_root,
            filesystem: "windows-volume-guid".into(),
        });
        let mut paths = vec![0u16; 1024];
        let mut required = 0;
        // SAFETY: volume is NUL terminated; paths/required are writable buffers.
        let mut success = unsafe {
            GetVolumePathNamesForVolumeNameW(
                volume.as_ptr(),
                paths.as_mut_ptr(),
                paths.len() as u32,
                &mut required,
            )
        };
        if success == 0 && io::Error::last_os_error().raw_os_error() == Some(ERROR_MORE_DATA as i32)
        {
            paths.resize(required as usize, 0);
            // SAFETY: same as above, now using the API's requested capacity.
            success = unsafe {
                GetVolumePathNamesForVolumeNameW(
                    volume.as_ptr(),
                    paths.as_mut_ptr(),
                    required,
                    &mut required,
                )
            };
        }
        let aliases = if success != 0 { paths.as_slice() } else { &[] };
        for path in aliases.split(|u| *u == 0).take_while(|p| !p.is_empty()) {
            let root = PathBuf::from(OsString::from_wide(path));
            let terminated = wide(root.as_os_str())?;
            // SAFETY: terminated is a valid NUL-terminated UTF-16 string.
            let drive_type = unsafe { GetDriveTypeW(terminated.as_ptr()) };
            let kind = match drive_type {
                DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK => LocationKind::Local,
                DRIVE_REMOTE => LocationKind::Remote,
                _ => LocationKind::Unknown,
            };
            result.push(LocationInfo {
                kind,
                mount_root: root,
                filesystem: "windows-volume".into(),
            });
        }
        // SAFETY: search remains valid; buffer is writable with the passed length.
        if unsafe { FindNextVolumeW(search.0, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                return Err(error);
            }
            break;
        }
    }
    // Network drive letters can be missing from FindFirstVolume. They are still
    // marked Remote so explicit user roots are rejected before content I/O.
    let mut drives = vec![0u16; 512];
    // SAFETY: initialized writable UTF-16 buffer and its actual capacity.
    let count = unsafe { GetLogicalDriveStringsW(drives.len() as u32, drives.as_mut_ptr()) };
    if count == 0 || count as usize >= drives.len() {
        return Err(io::Error::last_os_error());
    }
    for path in drives.split(|u| *u == 0).take_while(|p| !p.is_empty()) {
        let root = PathBuf::from(OsString::from_wide(path));
        if result.iter().any(|entry| entry.mount_root == root) {
            continue;
        }
        let terminated = wide(root.as_os_str())?;
        // SAFETY: terminated is a NUL-terminated UTF-16 drive root.
        let kind = match unsafe { GetDriveTypeW(terminated.as_ptr()) } {
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK => LocationKind::Local,
            DRIVE_REMOTE => LocationKind::Remote,
            _ => LocationKind::Unknown,
        };
        result.push(LocationInfo {
            kind,
            mount_root: root,
            filesystem: "windows-drive".into(),
        });
    }
    Ok(result)
}

pub(crate) fn protected_system_roots() -> io::Result<Vec<PathBuf>> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
    };
    let mut roots = Vec::new();
    let mut buffer = vec![0u16; 32768];
    // SAFETY: buffer has the capacity passed to the API and lives through call.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    roots.push(PathBuf::from(OsString::from_wide(
        &buffer[..length as usize],
    )));
    for id in [
        &FOLDERID_ProgramFiles,
        &FOLDERID_ProgramFilesX86,
        &FOLDERID_ProgramData,
    ] {
        let mut pointer = std::ptr::null_mut();
        // SAFETY: id references a static GUID, pointer is a writable out-pointer,
        // and no user token is supplied. KF_FLAG_DONT_VERIFY avoids filesystem I/O.
        let status =
            unsafe { SHGetKnownFolderPath(id, 0x4000, std::ptr::null_mut(), &mut pointer) };
        if status < 0 {
            return Err(io::Error::other(format!(
                "known-folder lookup failed: {status:#x}"
            )));
        }
        if pointer.is_null() {
            return Err(io::Error::other("known-folder lookup returned null"));
        }
        let mut length = 0;
        // SAFETY: on success SHGetKnownFolderPath returns an allocated,
        // NUL-terminated wide string. It remains valid until CoTaskMemFree below.
        unsafe {
            while *pointer.add(length) != 0 {
                length += 1;
            }
            let units = std::slice::from_raw_parts(pointer, length);
            roots.push(PathBuf::from(OsString::from_wide(units)));
            CoTaskMemFree(pointer.cast());
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roots_are_strict_and_device_names_are_rejected() {
        assert!(is_volume_guid_root(Path::new(
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
        )));
        assert!(is_volume_guid_prefix(OsStr::new(
            "Volume{01234567-89ab-cdef-0123-456789abcdef}"
        )));
        for invalid in [
            "Volume{bad}",
            "GLOBALROOT",
            "PhysicalDrive0",
            "Volume{01234567-89ab-cdef-0123-456789abcdeg}",
        ] {
            assert!(!is_volume_guid_prefix(OsStr::new(invalid)));
        }
        assert!(!is_volume_guid_root(Path::new(
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\directory"
        )));
        assert!(!is_volume_guid_root(Path::new(r"\\?\GLOBALROOT\")));
    }

    #[test]
    fn all_scan_prefers_guids_and_preserves_drive_lookup() -> io::Result<()> {
        let table = MountTable::read()?;
        let roots = table.roots();
        assert!(!roots.is_empty());
        assert!(roots.iter().all(|root| is_volume_guid_root(root)));
        for entry in table
            .entries()
            .iter()
            .filter(|entry| entry.kind == LocationKind::Local)
        {
            assert_eq!(table.classify(&entry.mount_root).kind, LocationKind::Local);
        }
        Ok(())
    }
}
