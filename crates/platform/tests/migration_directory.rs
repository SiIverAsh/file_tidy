use file_tidy_platform::{
    MigrationData, MigrationDirectory, inspect, metadata_inventory, open_directory_attached_data,
    open_verified, visit_migration_data,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Streams = BTreeMap<(u32, OsString), Vec<u8>>;

#[track_caller]
fn checked<T, E: std::fmt::Display>(value: Result<T, E>) -> Result<T, Box<dyn std::error::Error>> {
    let location = std::panic::Location::caller();
    value.map_err(|error| format!("{}:{}: {error}", location.file(), location.line()).into())
}

fn attach(path: &Path, value: &[u8]) -> TestResult {
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let name = "com.file-tidy.directory";
        #[cfg(not(target_os = "macos"))]
        let name = "user.file_tidy.directory";
        rustix::fs::lsetxattr(path, name, value, rustix::fs::XattrFlags::empty())?;
    }
    #[cfg(windows)]
    {
        let mut name = path.as_os_str().to_os_string();
        name.push(":file_tidy");
        std::fs::write(PathBuf::from(name), value)?;
    }
    Ok(())
}

fn sink<'a>(
    streams: &'a mut Streams,
    current: &'a mut Option<(u32, OsString)>,
) -> impl FnMut(MigrationData<'_>) -> std::io::Result<()> + 'a {
    |event| {
        match event {
            MigrationData::Begin { kind, name, .. } => {
                let key = (kind, name.to_owned());
                assert!(streams.insert(key.clone(), Vec::new()).is_none());
                *current = Some(key);
            }
            MigrationData::Chunk(bytes) => streams
                .get_mut(
                    current
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("unframed stream"))?,
                )
                .ok_or_else(|| std::io::Error::other("missing stream"))?
                .extend_from_slice(bytes),
            MigrationData::End => {
                *current = None;
            }
        }
        Ok(())
    }
}

fn source_streams(path: &Path, directory: bool) -> Result<Streams, Box<dyn std::error::Error>> {
    let info = checked(inspect(path))?;
    let metadata = checked(metadata_inventory(path, &info))?;
    let mut file = if directory {
        checked(open_directory_attached_data(path, &info))?
    } else {
        checked(open_verified(path, &info))?
    };
    let mut result = Streams::new();
    checked(visit_migration_data(
        path,
        &mut file,
        &metadata,
        &|| Ok(()),
        &mut sink(&mut result, &mut None),
    ))?;
    Ok(result)
}

struct WritableFixture(Vec<PathBuf>);
impl Drop for WritableFixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in &self.0 {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(windows)]
        #[allow(clippy::permissions_set_readonly_false)]
        // Clears Windows FILE_ATTRIBUTE_READONLY.
        for path in &self.0 {
            if let Ok(metadata) = std::fs::symlink_metadata(path) {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(path, permissions);
            }
        }
    }
}

#[test]
fn directory_payload_preserves_metadata_streams_and_hard_links_before_publication() -> TestResult {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path().canonicalize()?;
    let source = root.join("source");
    let nested = source.join("nested");
    std::fs::create_dir_all(&nested)?;
    let leaf = nested.join(".data");
    let alias = source.join("alias");
    let body = vec![42u8; 180000];
    std::fs::write(&leaf, &body)?;
    std::fs::hard_link(&leaf, &alias)?;
    attach(&source, b"root-directory-attached-data")?;
    attach(&nested, b"nested-directory-attached-data")?;
    attach(&leaf, b"file-attached-data")?;
    let target = root.join("target");
    let stage_path = root.join(".file-tidy-tree.stage");
    let _writable = WritableFixture(vec![
        nested.clone(),
        source.clone(),
        stage_path.join("payload/nested"),
        stage_path.join("payload"),
        target.join("nested"),
        target.clone(),
        leaf.clone(),
        stage_path.join("payload/nested/.data"),
        target.join("nested/.data"),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o440))?;
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555))?;
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o750))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = std::fs::metadata(&leaf)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&leaf, permissions)?;
    }
    let source_info = inspect(&source)?;
    let nested_info = inspect(&nested)?;
    let leaf_info = inspect(&leaf)?;
    let source_metadata = checked(metadata_inventory(&source, &source_info))?;
    let nested_metadata = checked(metadata_inventory(&nested, &nested_info))?;
    let leaf_metadata = checked(metadata_inventory(&leaf, &leaf_info))?;
    let source_values = checked(source_streams(&source, true))?;
    let nested_values = checked(source_streams(&nested, true))?;
    let leaf_values = checked(source_streams(&leaf, false))?;
    let mut payload = checked(MigrationDirectory::create(
        &root,
        &inspect(&root)?,
        ".file-tidy-tree.stage".as_ref(),
    ))?;
    let refused = payload
        .publish("premature".as_ref())
        .err()
        .ok_or("unsealed tree published")?;
    assert!(!refused.may_have_moved);
    assert!(payload.create_directory(Path::new("../escape")).is_err());
    assert!(payload.create_directory(&root.join("escape")).is_err());
    assert!(!root.join("escape").exists());
    checked(payload.create_directory(Path::new("nested")))?;
    let mut input = checked(open_verified(&leaf, &leaf_info))?;
    let mut copied = checked(payload.copy_file(
        Path::new("nested/.data"),
        &leaf,
        &input,
        &leaf_metadata,
        &|| Ok(()),
    ))?;
    let mut copied_body = Vec::new();
    copied.file_mut().seek(SeekFrom::Start(0))?;
    copied.file_mut().read_to_end(&mut copied_body)?;
    assert_eq!(copied_body, body);
    assert_eq!(
        copied.metadata()?.portable_bytes(),
        leaf_metadata.portable_bytes()
    );
    let mut copied_values = Streams::new();
    checked(copied.visit_data(&|| Ok(()), &mut sink(&mut copied_values, &mut None)))?;
    assert_eq!(copied_values, leaf_values);
    drop(copied);
    // A second name shares the copied inode, including its attached data.
    let linked = checked(payload.create_hard_link(Path::new("nested/.data"), Path::new("alias")))?;
    assert_eq!(linked.links, 2);
    assert!(
        payload
            .create_hard_link(Path::new("nested/.data"), Path::new("alias"))
            .is_err()
    );
    let source_directory = checked(open_directory_attached_data(&source, &source_info))?;
    assert!(
        payload
            .copy_directory_metadata(
                Path::new(""),
                &source,
                &source_directory,
                &source_metadata,
                &|| Ok(())
            )
            .is_err()
    );
    let nested_directory = checked(open_directory_attached_data(&nested, &nested_info))?;
    checked(payload.copy_directory_metadata(
        Path::new("nested"),
        &nested,
        &nested_directory,
        &nested_metadata,
        &|| Ok(()),
    ))?;
    assert!(payload.create_directory(Path::new("nested/late")).is_err());
    assert_eq!(
        payload.metadata(Path::new("nested"))?.portable_bytes(),
        nested_metadata.portable_bytes()
    );
    let unexpected = stage_path.join("payload/unexpected");
    std::fs::write(&unexpected, b"unrecorded")?;
    assert!(payload.verify_contents(&|| Ok(())).is_err());
    std::fs::remove_file(unexpected)?;
    checked(payload.copy_directory_metadata(
        Path::new(""),
        &source,
        &source_directory,
        &source_metadata,
        &|| Ok(()),
    ))?;
    assert!(payload.create_directory(Path::new("late")).is_err());
    checked(payload.verify_contents(&|| Ok(())))?;
    let mut root_values = Streams::new();
    checked(payload.visit_data(
        Path::new(""),
        &|| Ok(()),
        &mut sink(&mut root_values, &mut None),
    ))?;
    assert_eq!(root_values, source_values);
    let mut copied_nested_values = Streams::new();
    checked(payload.visit_data(
        Path::new("nested"),
        &|| Ok(()),
        &mut sink(&mut copied_nested_values, &mut None),
    ))?;
    assert_eq!(copied_nested_values, nested_values);
    std::fs::write(root.join("occupied"), b"existing")?;
    assert!(payload.publish("occupied".as_ref()).is_err());
    assert_eq!(std::fs::read(root.join("occupied"))?, b"existing");
    assert!(!target.exists());
    checked(payload.publish("target".as_ref()))?;
    checked(payload.verify_contents(&|| Ok(())))?;
    assert_eq!(
        payload.metadata(Path::new(""))?.portable_bytes(),
        source_metadata.portable_bytes()
    );
    assert_eq!(inspect(&target)?.modified, source_info.modified);
    assert_eq!(
        inspect(&target.join("nested"))?.modified,
        nested_info.modified
    );
    let copied_leaf = inspect(&target.join("nested/.data"))?;
    assert_eq!(
        copied_leaf.identity,
        inspect(&target.join("alias"))?.identity
    );
    assert_ne!(copied_leaf.identity, leaf_info.identity);
    assert_eq!(std::fs::read(target.join("alias"))?, body);
    checked(payload.retire_envelope())?;
    assert!(!stage_path.exists());
    assert_eq!(metadata_inventory(&source, &source_info)?, source_metadata);
    assert_eq!(metadata_inventory(&nested, &nested_info)?, nested_metadata);
    assert_eq!(metadata_inventory(&leaf, &leaf_info)?, leaf_metadata);
    // The source tree and its original hard-link group remain intact.
    input.seek(SeekFrom::Start(0))?;
    let mut original = Vec::new();
    input.read_to_end(&mut original)?;
    assert_eq!(original, body);
    assert_eq!(leaf_info.identity, inspect(&alias)?.identity);
    drop(input);
    drop(source_directory);
    drop(nested_directory);
    Ok(())
}
