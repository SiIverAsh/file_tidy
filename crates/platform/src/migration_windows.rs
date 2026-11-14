use super::*;
use std::ffi::{OsString, c_void};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    FSCTL_GET_COMPRESSION, FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE,
};

const MAX_DESCRIPTOR: usize = 1024 * 1024;
const DATA: u32 = 1;
const EA: u32 = 2;
const SECURITY: u32 = 3;
const ALTERNATE: u32 = 4;
const SPARSE: u32 = 9;
fn native_error(action: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

pub(super) fn check_metadata(metadata: &MetadataInventory) -> io::Result<()> {
    let supported = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_ARCHIVE
        | FILE_ATTRIBUTE_NORMAL
        | FILE_ATTRIBUTE_TEMPORARY
        | FILE_ATTRIBUTE_SPARSE_FILE
        | FILE_ATTRIBUTE_COMPRESSED
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    if metadata.native_flags() & !u64::from(supported) != 0 {
        return Err(unsupported(
            "source file attributes require a different migration capability",
        ));
    }
    Ok(())
}

struct Backup<'a> {
    file: &'a File,
    context: *mut c_void,
    writing: bool,
}
impl<'a> Backup<'a> {
    fn new(file: &'a File, writing: bool) -> Self {
        Self {
            file,
            context: ptr::null_mut(),
            writing,
        }
    }
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut used = 0u32;
        // SAFETY: file is synchronous, buffer is writable for its stated length,
        // and this owner retains the API context until the abort call in Drop.
        if unsafe {
            BackupRead(
                self.file.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut used,
                0,
                1,
                &mut self.context,
            )
        } == 0
        {
            return Err(native_error("read migration backup stream"));
        }
        if used as usize > buffer.len() {
            return Err(invalid("backup read exceeded buffer"));
        }
        Ok(used as usize)
    }
    fn write(&mut self, buffer: &[u8]) -> io::Result<()> {
        let mut offset = 0usize;
        while offset < buffer.len() {
            let mut written = 0u32;
            // SAFETY: the synchronous destination has data and security write
            // rights; this validated stream fragment remains live for the call.
            if unsafe {
                BackupWrite(
                    self.file.as_raw_handle(),
                    buffer[offset..].as_ptr(),
                    (buffer.len() - offset) as u32,
                    &mut written,
                    0,
                    1,
                    &mut self.context,
                )
            } == 0
            {
                return Err(native_error("restore migration backup stream"));
            }
            if written == 0 || written as usize > buffer.len() - offset {
                return Err(invalid("backup write made invalid progress"));
            }
            offset += written as usize;
        }
        Ok(())
    }
}
impl Drop for Backup<'_> {
    fn drop(&mut self) {
        let mut unused = 0u32;
        // SAFETY: an abort call releases only this unique native context. With
        // bAbort set, all arguments other than lpContext are ignored by the API.
        unsafe {
            if self.writing {
                BackupWrite(
                    self.file.as_raw_handle(),
                    ptr::null(),
                    0,
                    &mut unused,
                    1,
                    1,
                    &mut self.context,
                );
            } else {
                BackupRead(
                    self.file.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    &mut unused,
                    1,
                    1,
                    &mut self.context,
                );
            }
        }
    }
}
struct Writer<'a> {
    backup: Backup<'a>,
    buffer: Vec<u8>,
}
impl<'a> Writer<'a> {
    fn new(file: &'a File) -> Self {
        Self {
            backup: Backup::new(file, true),
            buffer: Vec::with_capacity(65536),
        }
    }
    fn push(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let length = bytes.len().min(65536 - self.buffer.len());
            self.buffer.extend_from_slice(&bytes[..length]);
            bytes = &bytes[length..];
            if self.buffer.len() == 65536 {
                self.backup.write(&self.buffer)?;
                self.buffer.clear();
            }
        }
        Ok(())
    }
    fn finish(mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            self.backup.write(&self.buffer)?;
        }
        Ok(())
    }
}
struct Reader<'a> {
    backup: Backup<'a>,
    buffer: Vec<u8>,
    offset: usize,
    length: usize,
}
impl<'a> Reader<'a> {
    fn new(file: &'a File) -> Self {
        Self {
            backup: Backup::new(file, false),
            buffer: vec![0; 65536],
            offset: 0,
            length: 0,
        }
    }
    fn skip(&mut self, mut length: u64) -> io::Result<()> {
        let buffered = length.min((self.length - self.offset) as u64) as usize;
        self.offset += buffered;
        length -= buffered as u64;
        if length == 0 {
            return Ok(());
        }
        let mut low = 0u32;
        let mut high = 0u32;
        // SAFETY: the synchronous backup context belongs to this reader. All
        // buffered bytes precede the requested remainder of this stream; the
        // skip cannot consume the following stream's header.
        if unsafe {
            BackupSeek(
                self.backup.file.as_raw_handle(),
                length as u32,
                (length >> 32) as u32,
                &mut low,
                &mut high,
                &mut self.backup.context,
            )
        } == 0
        {
            return Err(native_error(
                "skip migration file data during attached-stream verification",
            ));
        }
        if (u64::from(low) | (u64::from(high) << 32)) != length {
            return Err(invalid("backup seek did not cover the recorded stream"));
        }
        Ok(())
    }
}
impl Read for Reader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.length {
            self.length = self.backup.read(&mut self.buffer)?;
            self.offset = 0;
        }
        let amount = output.len().min(self.length - self.offset);
        output[..amount].copy_from_slice(&self.buffer[self.offset..self.offset + amount]);
        self.offset += amount;
        Ok(amount)
    }
}
struct Header {
    raw: [u8; 20],
    kind: u32,
    length: u64,
    name: OsString,
    encoded_name: Vec<u8>,
}
fn header(reader: &mut Reader<'_>) -> io::Result<Option<Header>> {
    // The backup format uses the 20 bytes before cStreamName; Rust/C struct
    // tail alignment is not part of the serialized stream header.
    let mut raw = [0u8; 20];
    if reader.read(&mut raw[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut raw[1..])?;
    let word = |start: usize| {
        u32::from_le_bytes([raw[start], raw[start + 1], raw[start + 2], raw[start + 3]])
    };
    let kind = word(0);
    if !matches!(kind, DATA | EA | SECURITY | ALTERNATE | SPARSE) || word(4) & 1 != 0 {
        return Err(unsupported(
            "backup stream type or read-mutating data cannot be migrated",
        ));
    }
    let length = i64::from_le_bytes(
        raw[8..16]
            .try_into()
            .map_err(|_| invalid("stream size width"))?,
    );
    let length = u64::try_from(length).map_err(|_| invalid("negative backup stream length"))?;
    let name_length = word(16) as usize;
    if !name_length.is_multiple_of(2) || name_length > 65536 {
        return Err(invalid("backup stream name exceeds limit"));
    }
    if matches!(kind, EA | SECURITY) && length > MAX_DESCRIPTOR as u64 {
        return Err(unsupported("backup metadata exceeds limit"));
    }
    let mut encoded_name = vec![0u8; name_length];
    reader.read_exact(&mut encoded_name)?;
    let units = encoded_name
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect::<Vec<_>>();
    if units.iter().any(|v| matches!(*v, 0 | 47 | 92)) {
        return Err(invalid("backup stream name is not a local stream"));
    }
    if kind == ALTERNATE {
        let suffix = [58, 36, 68, 65, 84, 65]; // :$DATA
        if units.len() <= suffix.len() + 1
            || units.first() != Some(&58)
            || !units.ends_with(&suffix)
            || units[1..units.len() - suffix.len()].contains(&58)
        {
            return Err(invalid("alternate stream name invalid"));
        }
    } else if !units.is_empty() {
        return Err(invalid("unexpected name on an unnamed backup stream"));
    }
    Ok(Some(Header {
        raw,
        kind,
        length,
        name: OsString::from_wide(&units),
        encoded_name,
    }))
}

fn control(file: &File, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<()> {
    let mut used = 0u32;
    // SAFETY: both buffers cover their stated lengths and the synchronous live
    // handle is borrowed only for this bounded filesystem control request.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut used,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(native_error("restore migration storage attributes"));
    }
    if used as usize != output.len() {
        return Err(invalid("filesystem control response has invalid length"));
    }
    Ok(())
}
fn restore_access(source: &File, target: &File) -> io::Result<()> {
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this unique descriptor with LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut label = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let information = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    // SAFETY: all output slots are initialized; the descriptor retains SID/ACL
    // storage until after the synchronous restore call below.
    let status = unsafe {
        GetSecurityInfo(
            source.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
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
    let _owned = Descriptor(descriptor);
    let mut storage = Vec::<u64>::new();
    if !dacl.is_null() {
        // SAFETY: dacl points into the live descriptor returned by the API.
        let size = unsafe { (*dacl).AclSize } as usize;
        if size < std::mem::size_of::<ACL>() {
            return Err(invalid("ACL header truncated"));
        }
        storage.resize(size.div_ceil(8), 0);
        // SAFETY: aligned storage covers the complete validated source ACL.
        unsafe {
            ptr::copy_nonoverlapping(dacl.cast::<u8>(), storage.as_mut_ptr().cast::<u8>(), size);
        }
        dacl = storage.as_mut_ptr().cast::<ACL>();
        // SAFETY: the copied header and all ACEs lie in this live owned buffer.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..count {
            let mut entry = ptr::null_mut();
            // SAFETY: GetAce validates the index against this copied ACL.
            if unsafe { GetAce(dacl, u32::from(index), &mut entry) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let address = entry as usize;
            let start = storage.as_ptr() as usize;
            if address < start
                || address
                    .checked_add(std::mem::size_of::<ACE_HEADER>())
                    .is_none_or(|n| n > start + size)
            {
                return Err(invalid("ACE header exceeds copied ACL"));
            }
            // SAFETY: the header is inside owned aligned ACL storage. Only the
            // inherited-origin marker changes; every access rule stays intact.
            unsafe {
                (*entry.cast::<ACE_HEADER>()).AceFlags &= !(INHERITED_ACE as u8);
            }
        }
    }
    // SAFETY: SIDs and label remain in _owned, dacl is null or points to aligned
    // owned storage. The private payload handle has WRITE_DAC/WRITE_OWNER. A
    // protected DACL freezes the restored source rules during publication.
    let status = unsafe {
        SetSecurityInfo(
            target.as_raw_handle(),
            SE_FILE_OBJECT,
            information | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            group,
            dacl,
            label,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}
pub(super) fn copy(
    source: &File,
    target: &mut File,
    metadata: &MetadataInventory,
    check: &(impl Fn() -> io::Result<()> + Sync),
) -> io::Result<()> {
    let mut source = source.try_clone()?;
    source.seek(SeekFrom::Start(0))?;
    target.seek(SeekFrom::Start(0))?;
    let security_target = target.try_clone()?;
    if metadata.native_flags() & u64::from(FILE_ATTRIBUTE_SPARSE_FILE) != 0 {
        control(&security_target, FSCTL_SET_SPARSE, &[], &mut [])?;
    }
    if metadata.native_flags() & u64::from(FILE_ATTRIBUTE_COMPRESSED) != 0 {
        let mut format = [0u8; 2];
        control(&source, FSCTL_GET_COMPRESSION, &[], &mut format)?;
        control(&security_target, FSCTL_SET_COMPRESSION, &format, &mut [])?;
    }
    let mut reader = Reader::new(&source);
    let mut writer = Writer::new(&security_target);
    let mut buffer = [0u8; 65536];
    while let Some(header) = {
        check()?;
        header(&mut reader)?
    } {
        writer.push(&header.raw)?;
        writer.push(&header.encoded_name)?;
        let mut remaining = header.length;
        while remaining > 0 {
            check()?;
            let length = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..length])?;
            writer.push(&buffer[..length])?;
            remaining -= length as u64;
        }
    }
    writer.finish()?;
    drop(reader);
    restore_access(&source, &security_target)?;
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: both live handles are synchronous and basic is an aligned,
    // correctly sized input/output object for these metadata requests.
    if unsafe {
        GetFileInformationByHandleEx(
            source.as_raw_handle(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            std::mem::size_of_val(&basic) as u32,
        )
    } == 0
    {
        return Err(native_error("inspect migration file times"));
    }
    basic.ChangeTime = 0;
    basic.FileAttributes &= !(FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE);
    if basic.FileAttributes == 0 {
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    // SAFETY: the writable payload handle and metadata structure remain live.
    if unsafe {
        SetFileInformationByHandle(
            target.as_raw_handle(),
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of_val(&basic) as u32,
        )
    } == 0
    {
        return Err(native_error("restore migration file times and attributes"));
    }
    check()
}

pub(super) fn visit(
    file: &mut File,
    check: &(impl Fn() -> io::Result<()> + Sync),
    sink: &mut impl FnMut(MigrationData<'_>) -> io::Result<()>,
) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = Reader::new(file);
    let mut buffer = [0u8; 65536];
    while let Some(header) = {
        check()?;
        header(&mut reader)?
    } {
        let attached = matches!(header.kind, EA | ALTERNATE);
        if matches!(header.kind, DATA | SPARSE) {
            reader.skip(header.length)?;
            continue;
        }
        if attached {
            sink(MigrationData::Begin {
                kind: header.kind,
                name: &header.name,
                bytes: header.length,
            })?;
        }
        let mut remaining = header.length;
        while remaining > 0 {
            check()?;
            let length = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..length])?;
            if attached {
                sink(MigrationData::Chunk(&buffer[..length]))?;
            }
            remaining -= length as u64;
        }
        if attached {
            sink(MigrationData::End)?;
        }
    }
    Ok(())
}
