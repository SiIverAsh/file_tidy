//! Handle-relative directory creation with a private, inheritable user DACL.
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    LocalFree, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalBuffer(*mut c_void);
impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: these buffers are allocated by the security APIs with
            // LocalAlloc; this owner frees each allocation exactly once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct User {
    buffer: Vec<usize>,
}
impl User {
    fn current() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: the pseudo process handle is valid, token is a writable handle
        // slot, and the resulting owned token is closed on every return path.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcessToken transferred this unique handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut length = 0u32;
        // SAFETY: a null zero-length buffer requests the required buffer size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut length,
            );
        }
        if length < std::mem::size_of::<TOKEN_USER>() as u32 || length > 65_536 {
            return Err(io::Error::other("invalid token user size"));
        }
        let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: the aligned buffer has at least length bytes; the API writes
        // TOKEN_USER and its SID within it and does not retain the pointer.
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
        Ok(Self { buffer })
    }
    fn sid(&self) -> PSID {
        // SAFETY: current() filled this aligned, sufficiently sized TOKEN_USER
        // buffer; its internal SID pointer remains valid while self is alive.
        unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn sid_text(&self) -> io::Result<String> {
        let mut text = ptr::null_mut();
        // SAFETY: sid points to the live token buffer; text receives an owned
        // NUL-terminated allocation freed by LocalBuffer below.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _owner = LocalBuffer(text.cast());
        let mut length = 0usize;
        // SAFETY: the API returns a valid NUL-terminated SID string. SID text has
        // a bounded representation; the cap also rejects anomalous output.
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(io::Error::other("SID text exceeds limit"));
        }
        // SAFETY: length was measured inside the live UTF-16 allocation.
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| io::Error::other("invalid SID text"))
    }
}

pub(super) fn create_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(parent, name, true, false, 0)
}
pub(super) fn create_file(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(parent, name, false, false, 0)
}
pub(super) fn create_staged_file(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(parent, name, false, true, 0)
}
pub(super) fn create_migration_file(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(parent, name, false, true, WRITE_DAC | WRITE_OWNER)
}
pub(super) fn create_migration_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(
        parent,
        name,
        true,
        true,
        WRITE_DAC | WRITE_OWNER | FILE_READ_EA | FILE_WRITE_EA,
    )
}
pub(super) fn open_migration_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    open_staged_object_with_access(
        parent,
        name,
        true,
        WRITE_DAC | WRITE_OWNER | FILE_READ_EA | FILE_WRITE_EA,
    )
}

pub(super) fn open_migration_read(
    parent: &File,
    name: &OsStr,
    directory: bool,
) -> io::Result<File> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.iter().any(|unit| matches!(*unit, 0 | 58 | 47 | 92)) {
        return Err(io::Error::other("invalid owned migration component"));
    }
    let length =
        u16::try_from(units.len() * 2).map_err(|_| io::Error::other("migration name too long"))?;
    let native = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &native,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let mut ios = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    // SAFETY: the owner holds the parent handle and validates every returned
    // identity. One native leaf is opened synchronously without following reparse
    // points. Read rights suffice after the original permissions are restored.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ,
            &attributes,
            &mut ios,
            ptr::null(),
            0,
            if directory {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            windows_sys::Wdk::Storage::FileSystem::FILE_OPEN,
            (if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            }) | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: NTSTATUS conversion is a scalar operation.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: a successful create transferred ownership of this live handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}
fn create_object(
    parent: &File,
    name: &OsStr,
    directory: bool,
    staged: bool,
    extra_access: u32,
) -> io::Result<File> {
    let user = User::current()?;
    let sid = user.sid_text()?;
    let inheritance = if directory { "OICI" } else { "" };
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: sddl is NUL terminated, revision 1 is documented, descriptor is
    // writable and receives a self-relative descriptor owned by LocalBuffer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _owner = LocalBuffer(descriptor);
    let mut units: Vec<u16> = name.encode_wide().collect();
    let bytes = units
        .len()
        .checked_mul(2)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| io::Error::other("directory name too long"))?;
    if units.contains(&0) {
        return Err(io::Error::other("NUL in directory name"));
    }
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: descriptor.cast(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    // SAFETY: all input buffers and the parent handle stay live through this
    // synchronous call. ObjectName is one validated native component relative
    // to the pinned parent. FILE_CREATE rejects existing objects; the explicit
    // DACL applies at creation. No DELETE sharing permits directory replacement.
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            if directory {
                FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE
                    | if staged { DELETE } else { 0 }
            } else {
                FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | READ_CONTROL
                    | if staged { DELETE } else { 0 }
            } | extra_access,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            (if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            }) | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: translates a returned NTSTATUS without dereferencing memory.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: successful NtCreateFile transferred a unique valid file handle.
    let file = unsafe { File::from_raw_handle(handle) };
    super::verify_private_file(&file, directory)?;
    Ok(file)
}

pub(super) fn verify(file: &File, directory: bool) -> io::Result<()> {
    let user = User::current()?;
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: file owns a live handle with READ_CONTROL. All outputs are valid
    // writable slots; owner and acl borrow the returned descriptor allocation.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _allocation = LocalBuffer(descriptor);
    if owner.is_null() || acl.is_null() {
        return Err(io::Error::other("missing private owner or DACL"));
    }
    // SAFETY: owner and the current SID are valid descriptors retained above.
    if unsafe { EqualSid(owner, user.sid()) } == 0 {
        return Err(io::Error::other("state is owned by another user"));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor and output slots are live for this synchronous call.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (directory && control & SE_DACL_PROTECTED == 0)
    {
        return Err(io::Error::other("state DACL must be protected"));
    }
    // SAFETY: GetSecurityInfo returned a valid ACL inside the live allocation.
    let count = unsafe { (*acl).AceCount };
    if count == 0 || count > 1024 {
        return Err(io::Error::other("invalid state ACL"));
    }
    for index in 0..u32::from(count) {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the OS-returned ACL; ace is writable.
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce supplied a valid ACE_HEADER in the live ACL allocation.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::Error::other("unexpected state ACE"));
        }
        // SAFETY: type and size have been checked. SidStart is the start of the
        // SID within this OS-validated ACE; EqualSid only reads those SIDs.
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        let sid = unsafe { ptr::addr_of!((*allowed).SidStart).cast_mut().cast() };
        if unsafe { EqualSid(sid, user.sid()) } == 0 {
            return Err(io::Error::other("state ACL grants another identity"));
        }
    }
    Ok(())
}

pub(super) fn create_staged_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    create_object(parent, name, true, true, 0)
}
pub(super) fn open_staged_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    open_staged_object(parent, name, true)
}
pub(super) fn open_staged_link(parent: &File, name: &OsStr) -> io::Result<File> {
    open_staged_object(parent, name, false)
}
fn open_staged_object(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    open_staged_object_with_access(parent, name, directory, 0)
}
fn open_staged_object_with_access(
    parent: &File,
    name: &OsStr,
    directory: bool,
    extra_access: u32,
) -> io::Result<File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    let mut units: Vec<u16> = name.encode_wide().collect();
    if units.is_empty() || units.iter().any(|u| matches!(u, 0 | 58 | 47 | 92)) {
        return Err(io::Error::other("invalid relative directory name"));
    }
    let bytes =
        u16::try_from(units.len() * 2).map_err(|_| io::Error::other("directory name too long"))?;
    let native = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &native,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let mut ios = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    // SAFETY: buffers and parent handle remain live during the synchronous call.
    // One validated component is opened relative to a held directory; reparse
    // points are opened themselves and subsequently rejected by private checks.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            (if directory {
                FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE
            } else {
                0
            }) | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE
                | extra_access,
            &attrs,
            &mut ios,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            (if directory { FILE_DIRECTORY_FILE } else { 0 })
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: scalar NTSTATUS conversion retains no buffers.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    // SAFETY: successful NtCreateFile transfers ownership of the returned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if directory {
        super::verify_private_file(&file, true)?;
    } else if crate::inspect_file(&file)?.kind != crate::NodeKind::Symlink {
        return Err(io::Error::other("symbolic link changed"));
    }
    Ok(file)
}
