use file_tidy_platform::{
    MigrationData, MigrationFile, inspect, metadata_inventory, open_verified, visit_migration_data,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
type TestResult = Result<(), Box<dyn std::error::Error>>;
type Streams = BTreeMap<(u32, OsString), Vec<u8>>;

fn collect(
    event: MigrationData<'_>,
    current: &mut Option<(u32, OsString)>,
    streams: &mut Streams,
) -> std::io::Result<()> {
    match event {
        MigrationData::Begin { kind, name, .. } => {
            let key = (kind, name.to_owned());
            if current.is_some() || streams.insert(key.clone(), Vec::new()).is_some() {
                return Err(std::io::Error::other("duplicate or nested stream"));
            }
            *current = Some(key);
        }
        MigrationData::Chunk(bytes) => {
            let key = current
                .as_ref()
                .ok_or_else(|| std::io::Error::other("missing stream header"))?;
            streams
                .get_mut(key)
                .ok_or_else(|| std::io::Error::other("missing stream body"))?
                .extend_from_slice(bytes);
        }
        MigrationData::End => {
            current
                .take()
                .ok_or_else(|| std::io::Error::other("missing stream end"))?;
        }
    }
    Ok(())
}
fn read_all(file: &mut File) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn attached(source: &Path, value: &[u8]) -> TestResult {
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let name = "com.file-tidy.migration";
        #[cfg(not(target_os = "macos"))]
        let name = "user.file_tidy.migration";
        rustix::fs::lsetxattr(source, name, value, rustix::fs::XattrFlags::empty())?;
    }
    #[cfg(windows)]
    {
        let mut name = source.as_os_str().to_os_string();
        name.push(":file_tidy");
        std::fs::write(std::path::PathBuf::from(name), value)?;
    }
    Ok(())
}
#[test]
fn migration_preserves_body_permissions_and_attached_data_before_publication() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join(".env");
    let body = [vec![0u8; 65536], vec![41u8; 150000], vec![0u8; 65536]].concat();
    std::fs::write(&source, &body)?;
    attached(&source, b"migration-attached-value")?;
    #[cfg(target_os = "macos")]
    {
        rustix::fs::lsetxattr(
            &source,
            "com.apple.ResourceFork",
            &vec![73u8; 180000],
            rustix::fs::XattrFlags::empty(),
        )?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o440))?;
    }
    let source_before = inspect(&source)?;
    let metadata = metadata_inventory(&source, &source_before)?;
    let parent = inspect(&root)?;
    let mut staged = MigrationFile::create(&root, &parent, ".file-tidy-migration.stage".as_ref())?;
    let envelope_before = staged.envelope_info()?;
    let mut input = open_verified(&source, &source_before)?;
    staged.copy_from(&source, &input, &metadata, &|| Ok(()))?;
    assert!(!root.join("target").exists());
    assert_eq!(read_all(staged.file_mut())?, body);
    let mut source_streams = Streams::new();
    let mut current = None;
    visit_migration_data(&source, &mut input, &metadata, &|| Ok(()), &mut |event| {
        collect(event, &mut current, &mut source_streams)
    })?;
    let mut target_streams = Streams::new();
    staged.visit_data(&|| Ok(()), &mut |event| {
        collect(event, &mut current, &mut target_streams)
    })?;
    assert_eq!(source_streams, target_streams);
    assert!(
        source_streams
            .values()
            .any(|v| v == b"migration-attached-value")
    );
    #[cfg(target_os = "macos")]
    assert!(source_streams.values().any(|v| v == &vec![73u8; 180000]));
    assert_eq!(
        staged.metadata()?.portable_bytes(),
        metadata.portable_bytes()
    );
    let published = staged.publish("target".as_ref())?;
    assert_eq!(published.identity, inspect(&root.join("target"))?.identity);
    assert_eq!(envelope_before.identity, staged.envelope_info()?.identity);
    assert_eq!(read_all(staged.file_mut())?, body);
    staged.retire_envelope()?;
    assert!(!root.join(".file-tidy-migration.stage").exists());
    assert_eq!(std::fs::read(root.join("target"))?, body);
    assert_eq!(metadata_inventory(&source, &source_before)?, metadata);
    Ok(())
}
#[test]
fn migration_conflicts_and_cancellation_keep_the_source_and_existing_target() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join("source");
    let body = vec![17u8; 200000];
    std::fs::write(&source, &body)?;
    std::fs::write(root.join("target"), b"existing")?;
    let info = inspect(&source)?;
    let metadata = metadata_inventory(&source, &info)?;
    let input = open_verified(&source, &info)?;
    let mut staged = MigrationFile::create(
        &root,
        &inspect(&root)?,
        ".file-tidy-conflict.stage".as_ref(),
    )?;
    staged.copy_from(&source, &input, &metadata, &|| Ok(()))?;
    let error = staged
        .publish("target".as_ref())
        .err()
        .ok_or("target was overwritten")?;
    assert!(!error.may_have_moved);
    assert_eq!(std::fs::read(root.join("target"))?, b"existing");
    let mut interrupted =
        MigrationFile::create(&root, &inspect(&root)?, ".file-tidy-cancel.stage".as_ref())?;
    let calls = AtomicUsize::new(0);
    let check = || {
        if calls.fetch_add(1, Ordering::SeqCst) >= 3 {
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        } else {
            Ok(())
        }
    };
    assert!(
        interrupted
            .copy_from(&source, &input, &metadata, &check)
            .is_err()
    );
    assert_eq!(std::fs::read(&source)?, body);
    assert_eq!(metadata_inventory(&source, &info)?, metadata);
    interrupted.verify()?;
    Ok(())
}
#[test]
fn migration_rejects_a_changed_metadata_version_before_copying() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join("source");
    std::fs::write(&source, b"body")?;
    attached(&source, b"first")?;
    let before = inspect(&source)?;
    let expected = metadata_inventory(&source, &before)?;
    attached(&source, b"other")?;
    let current = inspect(&source)?;
    let input = open_verified(&source, &current)?;
    let mut staged =
        MigrationFile::create(&root, &inspect(&root)?, ".file-tidy-changed.stage".as_ref())?;
    assert!(
        staged
            .copy_from(&source, &input, &expected, &|| Ok(()))
            .is_err()
    );
    assert!(read_all(staged.file_mut())?.is_empty());
    assert_eq!(std::fs::read(&source)?, b"body");
    Ok(())
}

#[test]
#[cfg(windows)]
fn migration_preserves_sparse_and_compressed_files() -> TestResult {
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{FSCTL_SET_COMPRESSION, FSCTL_SET_SPARSE};
    for compressed in [false, true] {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let source = root.join("source");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&source)?;
        let format = 1u16;
        let mut returned = 0u32;
        // SAFETY: this owned synchronous fixture file and optional compression
        // format remain live throughout the bounded filesystem-control call.
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                if compressed {
                    FSCTL_SET_COMPRESSION
                } else {
                    FSCTL_SET_SPARSE
                },
                if compressed {
                    (&format as *const u16).cast()
                } else {
                    std::ptr::null()
                },
                if compressed { 2 } else { 0 },
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        file.set_len(2 * 1024 * 1024)?;
        file.seek(SeekFrom::Start(512 * 1024))?;
        file.write_all(&vec![59u8; 90000])?;
        file.sync_all()?;
        drop(file);
        let before = inspect(&source)?;
        let metadata = metadata_inventory(&source, &before)?;
        let mut input = open_verified(&source, &before)?;
        let mut staged =
            MigrationFile::create(&root, &inspect(&root)?, ".file-tidy-storage.stage".as_ref())?;
        staged.copy_from(&source, &input, &metadata, &|| Ok(()))?;
        assert_eq!(read_all(&mut input)?, read_all(staged.file_mut())?);
        assert_eq!(
            metadata.portable_bytes(),
            staged.metadata()?.portable_bytes()
        );
        staged.publish("target".as_ref())?;
        staged.retire_envelope()?;
        assert!(source.exists());
    }
    Ok(())
}
