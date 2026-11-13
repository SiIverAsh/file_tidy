use super::*;
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_EA_INFORMATION, FileEaInformation, NtQueryInformationFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_MORE_DATA, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemServices::{
    FILE_NAMED_STREAMS, FILE_PERSISTENT_ACLS, FILE_SUPPORTS_EXTENDED_ATTRIBUTES,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalDescriptor(*mut c_void);
impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated this owned descriptor with LocalAlloc.
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn basic(file: &File) -> io::Result<FILE_BASIC_INFO> {
    let mut value = FILE_BASIC_INFO::default();
    // SAFETY: a live metadata handle and a correctly sized, writable structure
    // are borrowed only for the duration of the synchronous query.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut value as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of_val(&value) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}
fn current_owner(owner: PSID) -> io::Result<bool> {
    let mut token = ptr::null_mut();
    // SAFETY: GetCurrentProcess is a valid pseudo-handle and token is an output slot.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken transferred ownership of a valid token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0u32;
    // SAFETY: a null zero-length buffer queries the required token-user size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 65536 {
        return Err(invalid("token user size invalid"));
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the aligned allocation covers length bytes and lives through the query.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initialized this structure and its SID
    // within buffer; GetSecurityInfo keeps owner live until the caller returns.
    Ok(!owner.is_null()
        && unsafe { EqualSid(owner, (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid) } != 0)
}
fn security(file: &File, output: &mut Vec<u8>) -> io::Result<bool> {
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut label = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: all output slots are initialized. The API returns a single owned
    // descriptor containing the SID/ACL pointers, which remain live below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | LABEL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut label,
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _owned = LocalDescriptor(descriptor);
    for sid in [owner, group] {
        let bytes = if sid.is_null() {
            &[][..]
        } else {
            // SAFETY: GetSecurityInfo returned a SID within the live descriptor.
            let length = unsafe { GetLengthSid(sid) } as usize;
            if length > 65536 {
                return Err(invalid("SID exceeds limit"));
            }
            // SAFETY: the validated SID has length bytes in the descriptor.
            unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }
        };
        field(output, bytes)?;
    }
    for acl in [dacl, label] {
        let bytes = if acl.is_null() {
            &[][..]
        } else {
            // SAFETY: the returned ACL points into the live security descriptor.
            let length = unsafe { (*acl).AclSize } as usize;
            if length < std::mem::size_of::<ACL>() {
                return Err(invalid("ACL header is truncated"));
            }
            // SAFETY: GetSecurityInfo initialized the complete ACL of AclSize bytes.
            unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), length) }
        };
        field(output, bytes)?;
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor is valid and both scalar output slots are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    field(output, &control.to_le_bytes())?;
    current_owner(owner)
}
fn streams(file: &File) -> io::Result<Vec<MetadataAttribute>> {
    let mut capacity = 4096usize;
    let buffer = loop {
        let mut buffer = vec![0u64; capacity.div_ceil(8)];
        // SAFETY: u64 storage aligns FILE_STREAM_INFO and covers capacity bytes;
        // the live metadata handle permits this metadata-only stream-name query.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
            )
        } != 0
        {
            break buffer;
        }
        // SAFETY: GetLastError has no pointer arguments or retained state.
        let error = unsafe { GetLastError() };
        if error == ERROR_HANDLE_EOF {
            return Ok(Vec::new());
        }
        if error != ERROR_MORE_DATA || capacity >= MAX_DESCRIPTOR {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        capacity = (capacity * 2).min(MAX_DESCRIPTOR);
    };
    // SAFETY: buffer is initialized storage; viewing its complete byte range is valid.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
    let mut offset = 0usize;
    let mut result = Vec::new();
    loop {
        let header = bytes
            .get(offset..offset + 24)
            .ok_or_else(|| invalid("stream header exceeds buffer"))?;
        let u32_at = |start| -> io::Result<u32> {
            Ok(u32::from_le_bytes(
                header[start..start + 4]
                    .try_into()
                    .map_err(|_| invalid("stream header width"))?,
            ))
        };
        let next = u32_at(0)? as usize;
        let length = u32_at(4)? as usize;
        let size = i64::from_le_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| invalid("stream size width"))?,
        );
        let size = u64::try_from(size).map_err(|_| invalid("negative stream size"))?;
        if !length.is_multiple_of(2) {
            return Err(invalid("stream name has invalid width"));
        }
        let name = bytes
            .get(
                offset + 24
                    ..offset
                        .checked_add(24)
                        .and_then(|n| n.checked_add(length))
                        .ok_or_else(|| invalid("stream name overflow"))?,
            )
            .ok_or_else(|| invalid("stream name exceeds buffer"))?;
        let units = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect::<Vec<_>>();
        if units.is_empty() || units.first() != Some(&58) || units.contains(&0) {
            return Err(invalid("stream name contains NUL"));
        }
        let name = OsString::from_wide(&units);
        if name != "::$DATA" {
            result.push(MetadataAttribute {
                name,
                kind: MetadataAttributeKind::AlternateStream,
                bytes: size,
            });
        }
        if next == 0 {
            break;
        }
        if !next.is_multiple_of(8) || next < 24 + length {
            return Err(invalid("stream record offset invalid"));
        }
        offset = offset
            .checked_add(next)
            .ok_or_else(|| invalid("stream record overflow"))?;
    }
    Ok(result)
}
pub(super) fn inventory(path: &Path, expected: &NodeInfo) -> io::Result<MetadataInventory> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("metadata parent required"))?;
    let before_parent = crate::inspect(parent)?;
    let _guard = crate::open_directory_pinned(parent, &before_parent)?;
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(invalid("metadata path contains NUL"));
    }
    wide.push(0);
    // SAFETY: wide is a live terminated path. Ancestors are pinned, the leaf is
    // opened as a reparse object without recall, and only metadata rights are requested.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW transferred ownership of this live handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if !expected.matches(&crate::inspect_file(&file)?) {
        return Err(invalid("metadata handle does not match source"));
    }
    let before = basic(&file)?;
    let mut portable = Vec::new();
    field(&mut portable, &before.FileAttributes.to_le_bytes())?;
    let mut flags = 0u32;
    // SAFETY: optional strings are null with zero capacity and flags is writable.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            ptr::null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let owner_is_current = if flags & FILE_PERSISTENT_ACLS != 0 {
        security(&file, &mut portable)?
    } else {
        true
    };
    let mut attributes = if flags & FILE_NAMED_STREAMS != 0 {
        streams(&file)?
    } else {
        Vec::new()
    };
    if flags & FILE_SUPPORTS_EXTENDED_ATTRIBUTES != 0 {
        let mut ea = FILE_EA_INFORMATION::default();
        let mut ios = IO_STATUS_BLOCK::default();
        // SAFETY: the queried EA-size structure and IO status block are aligned,
        // writable, correctly sized and live for this synchronous metadata query.
        let status = unsafe {
            NtQueryInformationFile(
                file.as_raw_handle(),
                &mut ios,
                (&mut ea as *mut FILE_EA_INFORMATION).cast(),
                std::mem::size_of_val(&ea) as u32,
                FileEaInformation,
            )
        };
        if status < 0 {
            // SAFETY: status conversion is a pure scalar operation.
            return Err(io::Error::from_raw_os_error(unsafe {
                windows_sys::Win32::Foundation::RtlNtStatusToDosError(status)
            } as i32));
        }
        if ea.EaSize != 0 {
            attributes.push(MetadataAttribute {
                name: OsString::from("$EA"),
                kind: MetadataAttributeKind::ExtendedAttributes,
                bytes: u64::from(ea.EaSize),
            });
        }
    }
    let after = basic(&file)?;
    if before.ChangeTime != after.ChangeTime
        || before.FileAttributes != after.FileAttributes
        || !expected.matches(&crate::inspect_file(&file)?)
        || before_parent.identity != crate::inspect(parent)?.identity
    {
        return Err(invalid("metadata source changed during inspection"));
    }
    finish(
        expected,
        portable,
        &before.ChangeTime.to_le_bytes(),
        attributes,
        owner_is_current,
        false,
    )
}
