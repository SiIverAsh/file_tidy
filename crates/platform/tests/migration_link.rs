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
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::*;
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    assert_eq!(
        file_tidy_platform::inspect_file(&file)?.kind,
        file_tidy_platform::NodeKind::Symlink
    );
    let name = ":file_tidy:$DATA"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let body = b"symbolic-link-attached-value";
    let mut stream = Vec::new();
    stream.extend_from_slice(&4u32.to_le_bytes());
    stream.extend_from_slice(&0u32.to_le_bytes());
    stream.extend_from_slice(&(body.len() as i64).to_le_bytes());
    stream.extend_from_slice(&(name.len() as u32).to_le_bytes());
    stream.extend_from_slice(&name);
    stream.extend_from_slice(body);
    struct Backup<'a> {
        file: &'a std::fs::File,
        context: *mut std::ffi::c_void,
    }
    impl Drop for Backup<'_> {
        fn drop(&mut self) {
            let mut unused = 0;
            // SAFETY: abort releases only this fixture's unique backup context.
            unsafe {
                BackupWrite(
                    self.file.as_raw_handle(),
                    ptr::null(),
                    0,
                    &mut unused,
                    1,
                    0,
                    &mut self.context,
                );
            }
        }
    }
    let mut backup = Backup {
        file: &file,
        context: ptr::null_mut(),
    };
    let mut offset = 0;
    while offset < stream.len() {
        let mut written = 0;
        // SAFETY: this no-follow link handle, byte buffer and unique context
        // remain live through the synchronous attached-stream initialization.
        if unsafe {
            BackupWrite(
                file.as_raw_handle(),
                stream[offset..].as_ptr(),
                (stream.len() - offset) as u32,
                &mut written,
                0,
                0,
                &mut backup.context,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if written == 0 {
            return Err("backup fixture made no progress".into());
        }
        offset += written as usize;
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
    let file_text = PathBuf::from("../unreachable/private-file");
    let directory_text = PathBuf::from("../unreachable/private-directory");
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
    checked(std::fs::hard_link(&file_link, &alias))?;
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
