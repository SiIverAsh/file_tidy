use super::*;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

fn source_handle(parent: &File, name: &OsStr) -> io::Result<File> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.iter().any(|unit| matches!(*unit, 0 | 58 | 47 | 92)) {
        return Err(invalid("invalid native source component"));
    }
    let bytes = u16::try_from(units.len() * 2).map_err(|_| invalid("source name too long"))?;
    let mut native_name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut native_name,
        ..Default::default()
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    // SAFETY: all buffers are initialized and live through the synchronous call.
    // RootDirectory is pinned; the name is a single component and reparse targets
    // are never traversed. DELETE is needed for handle-bound rename.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    // SAFETY: successful NtCreateFile transferred ownership of a live handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn nt_error(status: i32) -> io::Error {
    // SAFETY: status conversion has no pointer arguments or retained state.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn rename(
    source_parent: &Path,
    source_name: &OsStr,
    expected: &NodeInfo,
    destination_parent: &Path,
    destination_name: &OsStr,
    expected_source_parent: &NodeInfo,
    expected_destination_parent: &NodeInfo,
) -> Result<(), RenameError> {
    let (from, _from_guards) = crate::windows::open_state_directory(source_parent)?;
    let (to, _to_guards) = crate::windows::open_state_directory(destination_parent)?;
    parent_matches(expected_source_parent, &crate::inspect_file(&from)?)?;
    parent_matches(expected_destination_parent, &crate::inspect_file(&to)?)?;
    let source = source_handle(&from, source_name)?;
    if !expected.matches(&crate::inspect_file(&source)?) {
        return Err(invalid("source changed before rename").into());
    }
    let destination = destination_parent.join(destination_name);
    match crate::inspect(&destination) {
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists").into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    rename_open_file(&source, &to, destination_name).map_err(RenameError::from_rename)?;
    // Win32 does not provide a portable directory fsync. Keep the source handle
    // and no-delete ancestor guards until metadata and namespace checks finish.
    let after = || -> io::Result<()> {
        if !expected.matches(&crate::inspect_file(&source)?)
            || !expected.matches(&crate::inspect(&destination)?)
        {
            return Err(invalid("destination changed during rename"));
        }
        parent_matches(expected_source_parent, &crate::inspect(source_parent)?)?;
        parent_matches(
            expected_destination_parent,
            &crate::inspect(destination_parent)?,
        )?;
        Ok(())
    };
    after().map_err(RenameError::after_rename)
}

pub(crate) fn rename_open_file(
    source: &File,
    parent: &File,
    destination_name: &OsStr,
) -> io::Result<()> {
    let units = destination_name.encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.iter().any(|unit| matches!(*unit, 0 | 58 | 47 | 92)) {
        return Err(invalid("invalid native destination component"));
    }
    let name_bytes = units
        .len()
        .checked_mul(2)
        .ok_or_else(|| invalid("destination name too long"))?;
    let allocation_bytes = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes)
        .ok_or_else(|| invalid("destination name too long"))?;
    let native_bytes =
        u32::try_from(allocation_bytes).map_err(|_| invalid("destination name too long"))?;
    // usize storage provides FILE_RENAME_INFORMATION's pointer alignment, and
    // the extra allocation includes the variable-length UTF-16 filename.
    let mut allocation = vec![0usize; allocation_bytes.div_ceil(size_of::<usize>())];
    let information = allocation.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: allocation is aligned, zeroed and at least struct+filename bytes;
    // the two pointers refer to disjoint live allocations. The default false
    // ReplaceIfExists is deliberately retained. All handles live until return.
    unsafe {
        (*information).RootDirectory = parent.as_raw_handle();
        (*information).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            units.as_ptr(),
            information
                .cast::<u8>()
                .add(offset_of!(FILE_RENAME_INFORMATION, FileName))
                .cast::<u16>(),
            units.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: source is synchronous and owns DELETE access; information and all
    // its handles remain live for this synchronous, no-replace rename request.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle(),
            &mut status_block,
            information.cast(),
            native_bytes,
            FileRenameInformation,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    Ok(())
}
