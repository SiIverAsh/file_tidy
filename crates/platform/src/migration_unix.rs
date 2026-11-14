use super::*;
use std::os::unix::ffi::OsStringExt;
#[cfg(not(target_os = "macos"))]
use std::os::unix::fs::MetadataExt;

const MAX_ATTRIBUTE: usize = 1024 * 1024;
pub(super) fn check_metadata(metadata: &MetadataInventory) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    if metadata.native_flags()
        & u64::from(libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND)
        != 0
    {
        return Err(unsupported(
            "immutable or append-only source cannot be migrated",
        ));
    }
    #[cfg(target_os = "linux")]
    if metadata.native_flags() & !rustix::fs::StatxAttributes::NODUMP.bits() != 0 {
        return Err(unsupported(
            "source inode attributes require a different migration capability",
        ));
    }
    for attribute in metadata.attributes() {
        if attribute.kind == crate::MetadataAttributeKind::ResourceFork {
            if attribute.bytes > u64::from(u32::MAX) {
                return Err(unsupported("resource fork exceeds positioned-read limit"));
            }
        } else if attribute.bytes > MAX_ATTRIBUTE as u64 {
            return Err(unsupported("extended attribute exceeds transfer limit"));
        }
    }
    Ok(())
}

pub(super) fn copy(
    source: &File,
    target: &mut File,
    metadata: &MetadataInventory,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    check()?;
    #[cfg(target_os = "macos")]
    darwin_copy(
        source,
        target,
        libc::COPYFILE_METADATA | libc::COPYFILE_DATA | libc::COPYFILE_DATA_SPARSE,
        check,
    )?;
    #[cfg(not(target_os = "macos"))]
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        #[cfg(target_os = "linux")]
        copy_inode_flags(source, target)?;
        let mut input = source.try_clone()?;
        input.seek(SeekFrom::Start(0))?;
        target.seek(SeekFrom::Start(0))?;
        let expected = source.metadata()?.len();
        let mut length = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            check()?;
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            length = length
                .checked_add(read as u64)
                .ok_or_else(|| invalid("file size overflow"))?;
            if length > expected {
                return Err(invalid("source grew during migration"));
            }
            if buffer[..read].iter().all(|byte| *byte == 0) {
                target.seek(SeekFrom::Current(read as i64))?;
            } else {
                target.write_all(&buffer[..read])?;
            }
        }
        if length != expected {
            return Err(invalid("source length changed during migration"));
        }
        target.set_len(length)?;
        copy_permissions_and_attributes(source, target, metadata, check)?;
    }
    let _ = metadata;
    check()
}

pub(super) fn copy_directory_metadata(
    source: &File,
    target: &mut File,
    metadata: &MetadataInventory,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    check()?;
    #[cfg(target_os = "macos")]
    darwin_copy(source, target, libc::COPYFILE_METADATA, check)?;
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        copy_inode_flags(source, target)?;
        copy_permissions_and_attributes(source, target, metadata, check)?;
    }
    let _ = metadata;
    check()
}

#[cfg(not(target_os = "macos"))]
fn copy_permissions_and_attributes(
    source: &File,
    target: &File,
    metadata: &MetadataInventory,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    let stat = source.metadata()?;
    if target.metadata()?.gid() != stat.gid() {
        rustix::fs::fchown(
            target,
            None,
            Some(rustix::process::Gid::from_raw(stat.gid())),
        )?;
    }
    for name in names(target)? {
        check()?;
        if !metadata.attributes().iter().any(|a| a.name == name) {
            rustix::fs::fremovexattr(target, &name)?;
        }
    }
    let mut attributes = metadata.attributes().iter().collect::<Vec<_>>();
    attributes.sort_by_key(|attribute| attribute.name == "system.posix_acl_access");
    for attribute in attributes {
        check()?;
        let mut value = vec![
            0u8;
            usize::try_from(attribute.bytes)
                .map_err(|_| invalid("attribute length overflow"))?
        ];
        let used = rustix::fs::fgetxattr(source, &attribute.name, value.as_mut_slice())?;
        if used != value.len() {
            return Err(invalid("attribute changed during migration"));
        }
        rustix::fs::fsetxattr(
            target,
            &attribute.name,
            &value,
            rustix::fs::XattrFlags::empty(),
        )?;
    }
    rustix::fs::fchmod(
        target,
        rustix::fs::Mode::from_raw_mode(stat.mode() & 0o1777),
    )?;
    target.set_times(std::fs::FileTimes::new().set_modified(stat.modified()?))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn copy_inode_flags(source: &File, target: &File) -> io::Result<()> {
    use rustix::fs::{IFlags, ioctl_getflags, ioctl_setflags};
    // EXTENTS describes the filesystem's representation. The other accepted
    // flags have user-visible behavior and are applied before allocating data.
    const EXTENTS: u32 = 0x0008_0000;
    const USER: u32 = 0x0080_00c8; // NOCOW, NOATIME, NODUMP, SYNC
    let flags = match ioctl_getflags(source) {
        Ok(flags) => flags.bits(),
        Err(rustix::io::Errno::NOTTY | rustix::io::Errno::NOTSUP) => 0,
        Err(error) => return Err(error.into()),
    };
    let representation = EXTENTS
        | if source.metadata()?.is_dir() {
            0x1000
        } else {
            0
        };
    if flags & !(USER | representation) != 0 {
        return Err(unsupported("source inode flags cannot be preserved"));
    }
    match ioctl_getflags(target) {
        Ok(current) => {
            let desired = IFlags::from_bits_retain((current.bits() & !USER) | (flags & USER));
            if desired != current {
                ioctl_setflags(target, desired)?;
            }
            if ioctl_getflags(target)?.bits() & USER != flags & USER {
                return Err(unsupported("target inode flags differ"));
            }
        }
        Err(rustix::io::Errno::NOTTY | rustix::io::Errno::NOTSUP) if flags & USER == 0 => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn names(file: &File) -> io::Result<Vec<std::ffi::OsString>> {
    let size = match rustix::fs::flistxattr_query(file) {
        Ok(size) => size,
        Err(rustix::io::Errno::NOTSUP) => 0,
        Err(error) => return Err(error.into()),
    };
    if size > MAX_ATTRIBUTE {
        return Err(invalid("attribute name list exceeds limit"));
    }
    let mut bytes = vec![0; size];
    if size != 0 {
        let used = rustix::fs::flistxattr(file, bytes.as_mut_slice())?;
        bytes.truncate(used);
        if bytes.last() != Some(&0) {
            return Err(invalid("attribute list is unterminated"));
        }
    }
    let mut names = bytes
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .map(|name| std::ffi::OsString::from_vec(name.to_vec()))
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

pub(super) fn visit(
    file: &mut File,
    check: &(impl Fn() -> io::Result<()> + Sync),
    sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
) -> io::Result<()> {
    for name in names(file)? {
        check()?;
        let size = rustix::fs::fgetxattr_query(&*file, &name)?;
        sink(MigrationData::Begin {
            kind: 1,
            name: &name,
            bytes: size as u64,
        })?;
        #[cfg(target_os = "macos")]
        if name == "com.apple.ResourceFork" {
            visit_fork(file, size, check, sink)?;
            sink(MigrationData::End)?;
            continue;
        }
        if size > MAX_ATTRIBUTE {
            return Err(unsupported("attribute exceeds verification limit"));
        }
        let mut value = vec![0u8; size];
        let used = rustix::fs::fgetxattr(&*file, &name, value.as_mut_slice())?;
        if used != size {
            return Err(invalid("attribute changed during verification"));
        }
        check()?;
        sink(MigrationData::Chunk(&value))?;
        sink(MigrationData::End)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn visit_fork(
    file: &File,
    size: usize,
    check: &(impl Fn() -> io::Result<()> + Sync),
    sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if size > u32::MAX as usize {
        return Err(unsupported("resource fork exceeds positioned-read limit"));
    }
    let mut offset = 0usize;
    let mut buffer = [0u8; 65536];
    while offset < size {
        check()?;
        let length = buffer.len().min(size - offset);
        // SAFETY: the verified regular descriptor remains live; the terminated
        // attribute name and output buffer cover this bounded positioned read.
        let used = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"com.apple.ResourceFork".as_ptr(),
                buffer.as_mut_ptr().cast(),
                length,
                offset as u32,
                0,
            )
        };
        if used < 0 {
            return Err(io::Error::last_os_error());
        }
        let used = used as usize;
        if used == 0 || used > length {
            return Err(invalid("resource fork length changed"));
        }
        sink(MigrationData::Chunk(&buffer[..used]))?;
        offset += used;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn darwin_copy(
    source: &File,
    target: &File,
    flags: libc::copyfile_flags_t,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    struct State(libc::copyfile_state_t);
    impl Drop for State {
        fn drop(&mut self) {
            // SAFETY: the non-null native state was allocated once and is freed once.
            unsafe {
                libc::copyfile_state_free(self.0);
            }
        }
    }
    struct Context<'a> {
        check: &'a (dyn Fn() -> io::Result<()> + Sync),
        error: Mutex<Option<io::Error>>,
    }
    unsafe extern "C" fn callback(
        _what: i32,
        stage: i32,
        _state: libc::copyfile_state_t,
        _from: *const libc::c_char,
        _to: *const libc::c_char,
        context: *mut c_void,
    ) -> i32 {
        // SAFETY: fcopyfile borrows this context only during its synchronous call.
        let context = unsafe { &*context.cast::<Context<'_>>() };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (context.check)()))
            .unwrap_or_else(|_| Err(io::Error::other("migration checkpoint panicked")));
        let result = if stage == libc::COPYFILE_ERR {
            result.and(Err(io::Error::other("native metadata copy failed")))
        } else {
            result
        };
        if let Err(error) = result {
            if let Ok(mut saved) = context.error.lock()
                && saved.is_none()
            {
                *saved = Some(error);
            }
            libc::COPYFILE_QUIT
        } else {
            libc::COPYFILE_CONTINUE
        }
    }
    // SAFETY: allocation returns an owned state or null, with no borrowed pointers.
    let state = State(unsafe { libc::copyfile_state_alloc() });
    if state.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    let context = Context {
        check,
        error: Mutex::new(None),
    };
    // SAFETY: callback and context remain live until fcopyfile returns. Setters
    // retain these pointer values, not a reference to temporary pointer storage.
    let setup = unsafe {
        libc::copyfile_state_set(
            state.0,
            libc::COPYFILE_STATE_STATUS_CB as u32,
            callback as *const c_void,
        ) == 0
            && libc::copyfile_state_set(
                state.0,
                libc::COPYFILE_STATE_STATUS_CTX as u32,
                (&context as *const Context<'_>).cast(),
            ) == 0
    };
    if !setup {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both identified descriptors are live. The destination lies in a
    // private envelope. Directory calls select metadata alone; regular-file
    // calls also select sparse data. No recursive, MOVE or UNLINK flag is used.
    let result = unsafe { libc::fcopyfile(source.as_raw_fd(), target.as_raw_fd(), state.0, flags) };
    let native_error = io::Error::last_os_error();
    if let Some(error) = context
        .error
        .into_inner()
        .map_err(|_| io::Error::other("migration callback state poisoned"))?
    {
        return Err(error);
    }
    if result != 0 {
        return Err(native_error);
    }
    check()
}
