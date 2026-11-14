//! Named streams opened through a pinned parent and checked against a no-follow link.
use super::*;
use std::io::{Read, Write};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

fn status_error(action: &str, status: i32) -> io::Error {
    // SAFETY: status conversion is a scalar operation.
    let error = io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn stream(base: &File, location: LinkLocation<'_>, name: &OsStr, create: bool) -> io::Result<File> {
    let mut units = name.encode_wide().collect::<Vec<_>>();
    let suffix = [58, 36, 68, 65, 84, 65];
    if units.len() <= suffix.len() + 1
        || units.first() != Some(&58)
        || !units.ends_with(&suffix)
        || units.iter().any(|unit| matches!(*unit, 0 | 47 | 92))
        || units[1..units.len() - suffix.len()].contains(&58)
    {
        return Err(invalid("named link data stream required"));
    }
    crate::staged_file::component(location.name)?;
    let mut qualified = location.name.encode_wide().collect::<Vec<_>>();
    qualified.append(&mut units);
    let length = u16::try_from(qualified.len() * 2).map_err(|_| invalid("stream name too long"))?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: qualified.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: location.parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        ..Default::default()
    };
    let identity = crate::inspect_file(base)?.identity;
    let mut handle = ptr::null_mut();
    let mut ios = IO_STATUS_BLOCK::default();
    // SAFETY: the relative name contains a single named stream, the source
    // object is already open without reparse traversal, and all storage remains
    // live for this synchronous request. FILE_CREATE excludes stream replacement.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | if create { FILE_GENERIC_WRITE } else { 0 },
            &attributes,
            &mut ios,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            if create { FILE_CREATE } else { FILE_OPEN },
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(status_error("open link-owned data stream", status));
    }
    // SAFETY: successful NtCreateFile transferred ownership of this live handle.
    let file = unsafe { File::from_raw_handle(handle) };
    if identity.is_none() || crate::inspect_file(&file)?.identity != identity {
        return Err(invalid("named stream belongs to a different object"));
    }
    Ok(file)
}

pub(super) fn copy(
    source: &File,
    target: &mut File,
    metadata: &MetadataInventory,
    source_location: LinkLocation<'_>,
    target_location: LinkLocation<'_>,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    check()?;
    if crate::inspect_file(source)?.len != 0 {
        return Err(unsupported("symbolic link contains a default data stream"));
    }
    let mut buffer = [0u8; 65536];
    for attribute in metadata
        .attributes()
        .iter()
        .filter(|a| a.kind == crate::MetadataAttributeKind::AlternateStream)
    {
        check()?;
        let mut input = stream(source, source_location, &attribute.name, false)?;
        if input.metadata()?.len() != attribute.bytes {
            return Err(invalid("link stream size changed"));
        }
        let mut output = stream(target, target_location, &attribute.name, true)?;
        let mut remaining = attribute.bytes;
        while remaining > 0 {
            check()?;
            let count = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..count])?;
            output.write_all(&buffer[..count])?;
            remaining -= count as u64;
        }
        if input.read(&mut buffer[..1])? != 0 {
            return Err(invalid("link stream grew"));
        }
        output.sync_all()?;
    }
    restore_access(source, target)?;
    restore_basic(source, target, true)?;
    check()
}

pub(super) fn visit(
    file: &mut File,
    metadata: &MetadataInventory,
    location: LinkLocation<'_>,
    check: &(impl Fn() -> io::Result<()> + Sync),
    sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    if crate::inspect_file(file)?.len != 0 {
        return Err(unsupported("symbolic link contains a default data stream"));
    }
    let mut buffer = [0u8; 65536];
    for attribute in metadata
        .attributes()
        .iter()
        .filter(|a| a.kind == crate::MetadataAttributeKind::AlternateStream)
    {
        check()?;
        let mut input = stream(file, location, &attribute.name, false)?;
        if input.metadata()?.len() != attribute.bytes {
            return Err(invalid("link stream size changed"));
        }
        sink(MigrationData::Begin {
            kind: ALTERNATE,
            name: &attribute.name,
            bytes: attribute.bytes,
        })?;
        let mut remaining = attribute.bytes;
        while remaining > 0 {
            check()?;
            let count = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..count])?;
            sink(MigrationData::Chunk(&buffer[..count]))?;
            remaining -= count as u64;
        }
        if input.read(&mut buffer[..1])? != 0 {
            return Err(invalid("link stream grew"));
        }
        sink(MigrationData::End)?;
    }
    check()
}
