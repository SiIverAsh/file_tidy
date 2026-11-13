use file_tidy_platform::{inspect, metadata_inventory};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(tempfile::tempdir()?)
}
fn contains(bytes: &[u8], value: &[u8]) -> bool {
    bytes.windows(value.len()).any(|window| window == value)
}

#[test]
fn inventory_is_repeatable_and_contains_no_file_body() -> TestResult {
    let dir = fixture()?;
    let root = dir.path().canonicalize()?;
    let source = root.join("file");
    let body = b"fixture-body-that-must-not-appear-in-metadata-107";
    std::fs::write(&source, body)?;
    let expected = inspect(&source)?;
    let first = metadata_inventory(&source, &expected)?;
    let second = metadata_inventory(&source, &expected)?;
    assert_eq!(first, second);
    assert!(first.owner_is_current());
    assert!(!contains(first.binding_bytes(), body));
    assert!(!contains(first.portable_bytes(), body));
    assert_eq!(std::fs::read(&source)?, body);
    let directory_before = inspect(&root)?;
    let directory_metadata = metadata_inventory(&root, &directory_before)?;
    assert_eq!(
        directory_metadata,
        metadata_inventory(&root, &directory_before)?
    );
    Ok(())
}
#[test]
fn inventory_reports_attached_data_sizes_without_returning_values() -> TestResult {
    let dir = fixture()?;
    let source = dir.path().canonicalize()?.join("file");
    std::fs::write(&source, b"main")?;
    let secret = b"opaque-attribute-value-832748039";
    #[cfg(unix)]
    let expected_name = {
        #[cfg(target_os = "macos")]
        let name = "com.file-tidy.metadata";
        #[cfg(not(target_os = "macos"))]
        let name = "user.file_tidy.metadata";
        rustix::fs::lsetxattr(&source, name, secret, rustix::fs::XattrFlags::empty())?;
        std::ffi::OsString::from(name)
    };
    #[cfg(windows)]
    let expected_name = {
        let mut path = source.as_os_str().to_os_string();
        path.push(":file_tidy");
        std::fs::write(PathBuf::from(path), secret)?;
        std::ffi::OsString::from(":file_tidy:$DATA")
    };
    let inventory = metadata_inventory(&source, &inspect(&source)?)?;
    let attribute = inventory
        .attributes()
        .iter()
        .find(|a| a.name == expected_name)
        .ok_or("attribute not listed")?;
    assert_eq!(attribute.bytes, secret.len() as u64);
    assert!(inventory.opaque_bytes() >= secret.len() as u64);
    assert!(!contains(inventory.binding_bytes(), secret));
    assert!(!contains(inventory.portable_bytes(), secret));
    assert!(!format!("{inventory:?}").contains("file_tidy"));
    Ok(())
}
#[test]
fn inventory_rejects_replaced_files_and_does_not_follow_links() -> TestResult {
    let dir = fixture()?;
    let root = dir.path().canonicalize()?;
    let source = root.join("file");
    std::fs::write(&source, b"original")?;
    let expected = inspect(&source)?;
    std::fs::rename(&source, root.join("kept"))?;
    std::fs::write(&source, b"replacement")?;
    assert!(metadata_inventory(&source, &expected).is_err());
    let link = root.join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink("absent", &link)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("absent", &link)?;
    let inventory = metadata_inventory(&link, &inspect(&link)?)?;
    assert_eq!(std::fs::read_link(&link)?, Path::new("absent"));
    assert!(!root.join("absent").exists());
    assert!(inventory.binding_bytes().len() > 16);
    Ok(())
}
#[test]
#[cfg(unix)]
fn inventory_detects_permissions_and_identifies_privileged_bits_without_content_access()
-> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture()?;
    let source = dir.path().canonicalize()?.join("file");
    std::fs::write(&source, b"fixture")?;
    #[cfg(target_os = "linux")]
    let initial_mode = 0o000;
    #[cfg(not(target_os = "linux"))]
    let initial_mode = 0o400;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(initial_mode))?;
    let before = metadata_inventory(&source, &inspect(&source)?)?;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700))?;
    let after = metadata_inventory(&source, &inspect(&source)?)?;
    assert_ne!(before.binding_bytes(), after.binding_bytes());
    assert_ne!(before.portable_bytes(), after.portable_bytes());
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o4700))?;
    let observed = std::fs::metadata(&source)?.permissions().mode();
    let privileged = metadata_inventory(&source, &inspect(&source)?)?;
    assert_eq!(std::fs::metadata(&source)?.permissions().mode(), observed);
    if observed & 0o6000 != 0 {
        assert!(privileged.privileged_permissions());
    }
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600))?;
    assert_eq!(std::fs::read(source)?, b"fixture");
    Ok(())
}
