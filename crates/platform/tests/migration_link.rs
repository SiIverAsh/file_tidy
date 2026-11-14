use file_tidy_platform::{
    MigrationData, MigrationDirectory, inspect, metadata_inventory, open_directory_attached_data,
    open_symlink_attached_data, visit_migration_data,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Streams = BTreeMap<(u32, OsString), Vec<u8>>;

#[track_caller]
fn checked<T, E: std::fmt::Display>(value: Result<T, E>) -> Result<T, Box<dyn std::error::Error>> {
    let where_ = std::panic::Location::caller();
    value.map_err(|error| format!("{}:{}: {error}", where_.file(), where_.line()).into())
}

fn collect<'a>(
    streams: &'a mut Streams,
    active: &'a mut Option<(u32, OsString)>,
) -> impl FnMut(MigrationData<'_>) -> std::io::Result<()> + 'a {
    |event| {
        match event {
            MigrationData::Begin { kind, name, .. } => {
                let key = (kind, name.to_owned());
                assert!(streams.insert(key.clone(), Vec::new()).is_none());
                *active = Some(key);
            }
            MigrationData::Chunk(bytes) => streams
                .get_mut(
                    active
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("missing stream"))?,
                )
                .ok_or_else(|| std::io::Error::other("unframed stream"))?
                .extend_from_slice(bytes),
            MigrationData::End => {
                *active = None;
            }
        }
        Ok(())
    }
}

fn symbolic_link(target: &Path, path: &Path, directory: bool) -> TestResult {
    #[cfg(unix)]
    {
        let _ = directory;
        std::os::unix::fs::symlink(target, path)?;
    }
    #[cfg(windows)]
    if directory {
        std::os::windows::fs::symlink_dir(target, path)?;
    } else {
        std::os::windows::fs::symlink_file(target, path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn attach_to_link(path: &Path) -> TestResult {
    use std::io::Write;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    let file = checked(
        std::fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path),
    )?;
    assert_eq!(
        file_tidy_platform::inspect_file(&file)?.kind,
        file_tidy_platform::NodeKind::Symlink
    );
    let parent_path = path.parent().ok_or("link parent missing")?;
    let parent = checked(file_tidy_platform::open_directory_pinned(
        parent_path,
        &inspect(parent_path)?,
    ))?;
    let parent_file = parent.try_clone_file()?;
    let mut name = path
        .file_name()
        .ok_or("link name missing")?
        .encode_wide()
        .collect::<Vec<_>>();
    name.extend(":file_tidy:$DATA".encode_utf16());
    let length = u16::try_from(name.len() * 2)?;
    let native = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent_file.as_raw_handle(),
        ObjectName: &native,
        ..Default::default()
    };
    let mut handle = ptr::null_mut();
    let mut ios = IO_STATUS_BLOCK::default();
    // SAFETY: the relative stream and source no-follow handle stay live; this
    // creates one named stream on the fixture link, without a target pathname.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &attributes,
            &mut ios,
            ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: NTSTATUS conversion is a scalar operation.
        return Err(format!(
            "create fixture link-owned stream: {}",
            std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
        )
        .into());
    }
    // SAFETY: successful NtCreateFile returned this owned live handle.
    let mut stream = unsafe { std::fs::File::from_raw_handle(handle) };
    assert_eq!(
        file_tidy_platform::inspect_file(&stream)?.identity,
        file_tidy_platform::inspect_file(&file)?.identity
    );
    stream.write_all(b"symbolic-link-attached-value")?;
    stream.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn alias_link(source: &Path, alias: &Path) -> TestResult {
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_LINK_INFORMATION, FileLinkInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(source)?;
    let parent = alias.parent().ok_or("alias parent missing")?;
    let parent = file_tidy_platform::open_directory_pinned(parent, &inspect(parent)?)?;
    let name = alias
        .file_name()
        .ok_or("alias name missing")?
        .encode_wide()
        .collect::<Vec<_>>();
    let bytes = size_of::<FILE_LINK_INFORMATION>() + name.len() * 2;
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let information = storage.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    let parent_file = parent.try_clone_file()?;
    // SAFETY: aligned zeroed storage covers the native structure and name. The
    // source link and destination directory remain held; replacement stays false.
    unsafe {
        (*information).RootDirectory = parent_file.as_raw_handle();
        (*information).FileNameLength = (name.len() * 2) as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            information
                .cast::<u8>()
                .add(offset_of!(FILE_LINK_INFORMATION, FileName))
                .cast::<u16>(),
            name.len(),
        );
    }
    let mut ios = IO_STATUS_BLOCK::default();
    // SAFETY: this synchronous handle-relative request uses live buffers and
    // creates an alias of the link object selected by the no-follow source handle.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut ios,
            information.cast(),
            bytes as u32,
            FileLinkInformation,
        )
    };
    if status < 0 {
        // SAFETY: NTSTATUS conversion is a scalar operation.
        return Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32
        )
        .into());
    }
    Ok(())
}

#[test]
fn symbolic_link_migration_preserves_the_link_and_its_values_without_opening_the_target()
-> TestResult {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join("source");
    std::fs::create_dir(&source)?;
    let file_link = source.join(".link");
    let directory_link = source.join("directory-link");
    let file_text = PathBuf::from("..").join("unreachable").join("private-file");
    let directory_text = PathBuf::from("..")
        .join("unreachable")
        .join("private-directory");
    checked(symbolic_link(&file_text, &file_link, false))?;
    checked(symbolic_link(&directory_text, &directory_link, true))?;
    #[cfg(target_os = "macos")]
    rustix::fs::lsetxattr(
        &file_link,
        "com.file-tidy.link",
        b"symbolic-link-attached-value",
        rustix::fs::XattrFlags::empty(),
    )?;
    #[cfg(windows)]
    checked(attach_to_link(&file_link))?;
    let alias = source.join("alias");
    #[cfg(unix)]
    checked(rustix::fs::linkat(
        rustix::fs::CWD,
        &file_link,
        rustix::fs::CWD,
        &alias,
        rustix::fs::AtFlags::empty(),
    ))?;
    #[cfg(windows)]
    checked(alias_link(&file_link, &alias))?;
    assert_eq!(inspect(&alias)?.kind, file_tidy_platform::NodeKind::Symlink);
    assert_eq!(inspect(&alias)?.identity, inspect(&file_link)?.identity);
    let file_info = inspect(&file_link)?;
    let directory_info = inspect(&directory_link)?;
    let source_info = inspect(&source)?;
    let file_metadata = checked(metadata_inventory(&file_link, &file_info))?;
    let directory_metadata = checked(metadata_inventory(&directory_link, &directory_info))?;
    let source_metadata = checked(metadata_inventory(&source, &source_info))?;
    let mut source_file = checked(open_symlink_attached_data(&file_link, &file_info))?;
    let source_directory = checked(open_symlink_attached_data(&directory_link, &directory_info))?;
    let mut source_values = Streams::new();
    checked(visit_migration_data(
        &file_link,
        &mut source_file,
        &file_metadata,
        &|| Ok(()),
        &mut collect(&mut source_values, &mut None),
    ))?;
    #[cfg(any(target_os = "macos", windows))]
    assert!(
        source_values
            .values()
            .any(|bytes| bytes == b"symbolic-link-attached-value")
    );
    let mut payload = checked(MigrationDirectory::create(
        &root,
        &inspect(&root)?,
        ".file-tidy-links.stage".as_ref(),
    ))?;
    let copied = checked(payload.copy_symlink(
        Path::new(".link"),
        &file_link,
        &source_file,
        &file_metadata,
        &|| Ok(()),
    ))?;
    assert_ne!(copied.identity, file_info.identity);
    assert_eq!(copied.kind, file_tidy_platform::NodeKind::Symlink);
    checked(payload.copy_symlink(
        Path::new("directory-link"),
        &directory_link,
        &source_directory,
        &directory_metadata,
        &|| Ok(()),
    ))?;
    let copied_alias = checked(payload.create_hard_link(Path::new(".link"), Path::new("alias")))?;
    assert_eq!(copied_alias.identity, copied.identity);
    assert_eq!(copied_alias.links, 2);
    let source_root = checked(open_directory_attached_data(&source, &source_info))?;
    checked(payload.copy_directory_metadata(
        Path::new(""),
        &source,
        &source_root,
        &source_metadata,
        &|| Ok(()),
    ))?;
    checked(payload.verify_contents(&|| Ok(())))?;
    assert_eq!(
        checked(payload.metadata(Path::new(".link")))?.portable_bytes(),
        file_metadata.portable_bytes()
    );
    let mut copied_values = Streams::new();
    checked(payload.visit_data(
        Path::new(".link"),
        &|| Ok(()),
        &mut collect(&mut copied_values, &mut None),
    ))?;
    assert_eq!(copied_values, source_values);
    checked(payload.publish("target".as_ref()))?;
    checked(payload.verify_contents(&|| Ok(())))?;
    assert_eq!(std::fs::read_link(root.join("target/.link"))?, file_text);
    assert_eq!(std::fs::read_link(root.join("target/alias"))?, file_text);
    assert_eq!(
        std::fs::read_link(root.join("target/directory-link"))?,
        directory_text
    );
    assert_eq!(
        file_tidy_platform::symlink_directory(&root.join("target/directory-link"))?,
        file_tidy_platform::symlink_directory(&directory_link)?
    );
    checked(payload.retire_envelope())?;
    assert_eq!(metadata_inventory(&file_link, &file_info)?, file_metadata);
    assert_eq!(
        metadata_inventory(&directory_link, &directory_info)?,
        directory_metadata
    );
    assert!(!root.join("unreachable").exists());
    assert!(!root.join(".file-tidy-links.stage").exists());
    Ok(())
}
