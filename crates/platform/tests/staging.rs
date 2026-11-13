use file_tidy_platform::{StagedFile, available_bytes, inspect, open_directory_pinned};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?,
        None => tempfile::tempdir()?,
    })
}
#[test]
fn private_staging_in_public_parent_publishes_the_opened_object() -> TestResult {
    let fixture = fixture()?;
    let root = fixture.path().canonicalize()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    }
    let before = inspect(&root)?;
    let parent = open_directory_pinned(&root, &before)?;
    assert!(available_bytes(&parent)? > 0);
    let mut stage = StagedFile::create(&root, &before, ".stage.part".as_ref())?;
    stage.file_mut().write_all(b"verified bytes")?;
    stage.file_mut().sync_all()?;
    let identity = stage.inspect()?.identity;
    stage.file_mut().seek(SeekFrom::Start(0))?;
    stage.verify()?;
    let published = stage.publish("result".as_ref())?;
    assert_eq!(published.identity, identity);
    assert_eq!(std::fs::read(root.join("result"))?, b"verified bytes");
    assert!(!root.join(".stage.part").exists());
    Ok(())
}
#[test]
fn staging_creation_is_exclusive_and_publication_preserves_occupied_names() -> TestResult {
    let fixture = fixture()?;
    let root = fixture.path().canonicalize()?;
    let before = inspect(&root)?;
    std::fs::write(root.join("occupied"), b"other")?;
    assert!(StagedFile::create(&root, &before, "occupied".as_ref()).is_err());
    assert!(StagedFile::create(&root, &before, "../escape".as_ref()).is_err());
    let mut staged = StagedFile::create(&root, &before, "stage.part".as_ref())?;
    staged.file_mut().write_all(b"source")?;
    staged.file_mut().sync_all()?;
    assert!(staged.publish("occupied".as_ref()).is_err());
    assert_eq!(std::fs::read(root.join("occupied"))?, b"other");
    assert_eq!(std::fs::read(root.join("stage.part"))?, b"source");
    Ok(())
}
