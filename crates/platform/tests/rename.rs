use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use file_tidy_platform::{NodeInfo, RenameError, inspect, rename_noreplace};

fn fixture() -> io::Result<(tempfile::TempDir, PathBuf)> {
    let directory = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(root)?,
        None => tempfile::tempdir()?,
    };
    let path = fs::canonicalize(directory.path())?;
    Ok((directory, path))
}

fn rename(source: &Path, expected: &NodeInfo, destination: &Path) -> Result<(), RenameError> {
    rename_noreplace(
        source,
        expected,
        destination,
        &inspect(
            source
                .parent()
                .ok_or_else(|| io::Error::other("test path has no parent"))?,
        )?,
        &inspect(
            destination
                .parent()
                .ok_or_else(|| io::Error::other("test path has no parent"))?,
        )?,
    )
}

#[test]
fn moves_file_across_directories_preserving_identity_and_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let (_temp, root) = fixture()?;
    let destination_dir = root.join("destination");
    fs::create_dir(&destination_dir)?;
    let source = root.join(".source");
    let target = destination_dir.join("renamed");
    fs::write(&source, b"original data")?;
    let before = inspect(&source)?;
    rename(&source, &before, &target)?;
    assert!(!source.try_exists()?);
    assert_eq!(fs::read(&target)?, b"original data");
    assert!(before.matches(&inspect(&target)?));
    Ok(())
}

#[test]
fn renames_complete_directory_with_nested_data() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, root) = fixture()?;
    let source = root.join("source");
    fs::create_dir_all(source.join("child"))?;
    fs::write(source.join("child/file"), b"nested")?;
    let before = inspect(&source)?;
    let target = root.join("destination");
    rename(&source, &before, &target)?;
    assert!(!source.try_exists()?);
    assert!(before.matches(&inspect(&target)?));
    assert_eq!(fs::read(target.join("child/file"))?, b"nested");
    Ok(())
}

#[test]
fn occupied_destination_and_source_alias_are_preserved() -> io::Result<()> {
    let (_temp, root) = fixture()?;
    let source = root.join("source");
    let target = root.join("target");
    fs::write(&source, b"source")?;
    fs::write(&target, b"target")?;
    let before = inspect(&source)?;
    let error = rename(&source, &before, &target)
        .err()
        .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?;
    assert!(!error.may_have_moved);
    assert!(!error.is_cross_device());
    assert_eq!(error.error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&source)?, b"source");
    assert_eq!(fs::read(&target)?, b"target");
    fs::remove_file(&target)?;
    fs::hard_link(&source, &target)?;
    assert!(
        !rename(&source, &inspect(&source)?, &target)
            .err()
            .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?
            .may_have_moved
    );
    assert!(source.try_exists()? && target.try_exists()?);
    Ok(())
}

#[test]
fn source_replacement_and_changed_content_are_rejected() -> io::Result<()> {
    let (_temp, root) = fixture()?;
    let source = root.join("source");
    let target = root.join("target");
    fs::write(&source, b"original")?;
    let before = inspect(&source)?;
    fs::rename(&source, root.join("original"))?;
    fs::write(&source, b"replacement")?;
    let error = rename(&source, &before, &target)
        .err()
        .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?;
    assert!(!error.may_have_moved);
    let changed = inspect(&source)?;
    fs::write(&source, b"a longer replacement")?;
    assert!(
        !rename(&source, &changed, &target)
            .err()
            .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?
            .may_have_moved
    );
    assert_eq!(fs::read(&source)?, b"a longer replacement");
    assert!(!target.try_exists()?);
    Ok(())
}

#[test]
fn replaced_parent_is_rejected_before_mutation() -> io::Result<()> {
    let (_temp, root) = fixture()?;
    let destination_parent = root.join("destination");
    fs::create_dir(&destination_parent)?;
    let expected_parent = inspect(&destination_parent)?;
    fs::rename(&destination_parent, root.join("old-destination"))?;
    fs::create_dir(&destination_parent)?;
    let source = root.join("source");
    fs::write(&source, b"original")?;
    let error = rename_noreplace(
        &source,
        &inspect(&source)?,
        &destination_parent.join("target"),
        &inspect(&root)?,
        &expected_parent,
    )
    .err()
    .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?;
    assert!(!error.may_have_moved);
    assert_eq!(fs::read(&source)?, b"original");
    assert_eq!(fs::read_dir(&destination_parent)?.count(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn moves_symlink_itself_without_opening_its_target() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;
    let (_temp, root) = fixture()?;
    let source = root.join("link");
    let target = root.join("renamed-link");
    symlink("/absent-file-tidy-test-target", &source)?;
    let before = inspect(&source)?;
    rename(&source, &before, &target)?;
    assert!(before.matches(&inspect(&target)?));
    assert_eq!(
        fs::read_link(&target)?,
        Path::new("/absent-file-tidy-test-target")
    );
    assert!(fs::symlink_metadata(&source).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn renames_file_without_requesting_content_read_permission()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, root) = fixture()?;
    let source = root.join("source");
    let target = root.join("target");
    fs::write(&source, b"metadata-only rename")?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o000))?;
    let before = inspect(&source)?;
    let result = rename(&source, &before, &target);
    // Restore permissions on whichever path exists before asserting the result.
    let actual = if target.try_exists()? {
        &target
    } else {
        &source
    };
    fs::set_permissions(actual, fs::Permissions::from_mode(0o600))?;
    result?;
    assert_eq!(fs::read(&target)?, b"metadata-only rename");
    Ok(())
}

#[cfg(windows)]
#[test]
fn moves_windows_symlink_without_following_target() -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, root) = fixture()?;
    let source = root.join("link");
    let target = root.join("renamed-link");
    let missing = root.join("absent");
    std::os::windows::fs::symlink_file(&missing, &source)?;
    let before = inspect(&source)?;
    assert_eq!(before.kind, file_tidy_platform::NodeKind::Symlink);
    assert!(before.identity.is_some());
    rename(&source, &before, &target)?;
    assert!(before.matches(&inspect(&target)?));
    assert_eq!(fs::read_link(&target)?, missing);
    assert!(fs::symlink_metadata(&source).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_link_parent_and_preserves_dangling_link_destination() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    let (_temp, root) = fixture()?;
    let actual = root.join("actual");
    fs::create_dir(&actual)?;
    let link = root.join("link");
    symlink(&actual, &link)?;
    let source = root.join("source");
    fs::write(&source, b"original")?;
    let before = inspect(&source)?;
    let error = rename_noreplace(
        &source,
        &before,
        &link.join("target"),
        &inspect(&root)?,
        &inspect(&actual)?,
    )
    .err()
    .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?;
    assert!(!error.may_have_moved);
    let target = root.join("target");
    symlink("absent", &target)?;
    assert!(
        !rename(&source, &before, &target)
            .err()
            .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?
            .may_have_moved
    );
    assert_eq!(fs::read_link(&target)?, Path::new("absent"));
    assert_eq!(fs::read(&source)?, b"original");
    Ok(())
}

#[test]
fn rejects_unidentified_nodes_and_parent_traversal() -> io::Result<()> {
    let (_temp, root) = fixture()?;
    let source = root.join("source");
    fs::write(&source, b"original")?;
    let mut unknown = inspect(&source)?;
    unknown.identity = None;
    assert!(
        !rename(&source, &unknown, &root.join("target"))
            .err()
            .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?
            .may_have_moved
    );
    let parent = inspect(&root)?;
    let error = rename_noreplace(
        &source,
        &inspect(&source)?,
        &root.join("../escape"),
        &parent,
        &parent,
    )
    .err()
    .ok_or_else(|| io::Error::other("rename unexpectedly succeeded"))?;
    assert!(!error.may_have_moved);
    assert_eq!(fs::read(&source)?, b"original");
    Ok(())
}
