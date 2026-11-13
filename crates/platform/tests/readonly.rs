use std::fs;
use std::io::{self, Read};

use file_tidy_platform::{
    MountTable, NodeKind, inspect, inspect_file, open_verified, read_directory_verified,
    read_directory_verified_cancellable,
};

#[test]
fn directory_listing_is_bounded_and_excludes_dot_entries() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = fs::canonicalize(temp.path())?;
    fs::write(root.join("a"), b"a")?;
    fs::write(root.join("b"), b"b")?;
    fs::create_dir(root.join("nested"))?;
    let before = inspect(&root)?;
    let bounded = read_directory_verified(&root, &before, 2)?;
    assert_eq!(bounded.names.len(), 2);
    assert!(bounded.truncated);
    let mut exact = read_directory_verified(&root, &before, 3)?;
    exact.names.sort();
    assert_eq!(exact.names, ["a", "b", "nested"]);
    assert!(!exact.truncated);
    let zero = read_directory_verified(&root, &before, 0)?;
    assert!(zero.names.is_empty());
    assert!(zero.truncated);
    Ok(())
}

#[test]
fn directory_listing_checks_cancellation_between_entries() -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let temp = tempfile::tempdir()?;
    let root = fs::canonicalize(temp.path())?;
    for index in 0..64 {
        fs::write(root.join(format!("entry-{index}")), b"fixture")?;
    }
    let before = inspect(&root)?;
    let checks = AtomicUsize::new(0);
    let result = read_directory_verified_cancellable(&root, &before, 64, &|| {
        checks.fetch_add(1, Ordering::Relaxed) >= 8
    });
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    assert!(checks.load(Ordering::Relaxed) < 64);

    // An already-cancelled request must not even try to open an absent path.
    let result = read_directory_verified_cancellable(&root.join("missing"), &before, 64, &|| true);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    Ok(())
}

#[test]
fn directory_change_invalidates_listing_snapshot() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = fs::canonicalize(temp.path())?;
    let path = root.join("directory");
    fs::create_dir(&path)?;
    let before = inspect(&path)?;
    fs::rename(&path, root.join("previous"))?;
    fs::create_dir(&path)?;
    assert_eq!(
        read_directory_verified(&path, &before, 10)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn reads_only_matching_regular_object() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = fs::canonicalize(temp.path())?;
    let path = root.join("plain.txt");
    fs::write(&path, b"read only")?;
    let before = inspect(&path)?;
    assert_eq!(before.kind, NodeKind::Regular);
    let mut file = open_verified(&path, &before)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    assert_eq!(content, b"read only");
    assert!(before.matches(&inspect_file(&file)?));
    Ok(())
}

#[test]
fn refuses_changed_file_and_replacement_object() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let path = fs::canonicalize(temp.path())?.join("plain.txt");
    fs::write(&path, b"before")?;
    let before = inspect(&path)?;
    fs::write(&path, b"longer content")?;
    assert!(open_verified(&path, &before).is_err());
    let changed = inspect(&path)?;
    let replacement = path.with_extension("replacement");
    fs::write(&replacement, b"longer content")?;
    fs::remove_file(&path)?;
    fs::rename(&replacement, &path)?;
    assert!(open_verified(&path, &changed).is_err());
    Ok(())
}

#[test]
fn native_mount_enumeration_is_nonempty() -> io::Result<()> {
    let table = MountTable::read()?;
    assert!(!table.entries().is_empty());
    assert!(!table.roots().is_empty());
    Ok(())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::time::Duration;

    struct RestorePermissions {
        path: std::path::PathBuf,
        permissions: fs::Permissions,
    }

    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, self.permissions.clone());
        }
    }

    #[test]
    fn reads_files_and_lists_leaf_directory_below_search_only_parent() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let root = fs::canonicalize(temp.path())?;
        let parent = root.join("search-only");
        fs::create_dir(&parent)?;
        let file_path = parent.join("plain.txt");
        fs::write(&file_path, b"searchable file")?;
        let child = parent.join("readable-child");
        fs::create_dir(&child)?;
        fs::write(child.join("entry"), b"child")?;
        let restore = RestorePermissions {
            path: parent.clone(),
            permissions: fs::metadata(&parent)?.permissions(),
        };
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o111))?;
        assert_eq!(fs::read(&file_path)?, b"searchable file");
        let mut content = Vec::new();
        open_verified(&file_path, &inspect(&file_path)?)?.read_to_end(&mut content)?;
        assert_eq!(content, b"searchable file");
        let listing = read_directory_verified(&child, &inspect(&child)?, 10)?;
        assert_eq!(listing.names, ["entry"]);
        assert!(!listing.truncated);
        fs::set_permissions(&parent, restore.permissions.clone())?;
        Ok(())
    }

    #[test]
    fn selected_root_directory_remains_readable() -> io::Result<()> {
        let root = std::path::Path::new("/");
        let listing = read_directory_verified(root, &inspect(root)?, 0)?;
        assert!(listing.names.is_empty());
        assert!(listing.truncated);
        Ok(())
    }

    #[test]
    fn refuses_link_leaf_and_link_parent() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let root = fs::canonicalize(temp.path())?;
        let directory = root.join("actual");
        fs::create_dir(&directory)?;
        fs::write(directory.join("file"), b"original")?;
        symlink(&directory, root.join("linkdir"))?;
        symlink(directory.join("file"), root.join("link"))?;
        let leaf = root.join("link");
        let info = inspect(&leaf)?;
        assert_eq!(info.kind, NodeKind::Symlink);
        assert!(open_verified(&leaf, &info).is_err());
        let through_parent = root.join("linkdir/file");
        let actual_info = inspect(&through_parent)?;
        assert!(open_verified(&through_parent, &actual_info).is_err());
        let actual_directory_info = inspect(&directory)?;
        assert!(
            read_directory_verified(&root.join("linkdir"), &actual_directory_info, 10).is_err()
        );
        fs::create_dir(directory.join("nested"))?;
        let nested_info = inspect(&directory.join("nested"))?;
        assert!(read_directory_verified(&root.join("linkdir/nested"), &nested_info, 10).is_err());
        assert_eq!(fs::read(directory.join("file"))?, b"original");
        Ok(())
    }

    #[test]
    fn fifo_replacement_does_not_block() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let path = fs::canonicalize(temp.path())?.join("file");
        fs::write(&path, b"original")?;
        let before = inspect(&path)?;
        fs::remove_file(&path)?;
        #[cfg(not(target_os = "macos"))]
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            // SAFETY: this is fixture preparation only. name is NUL-terminated
            // and valid for the synchronous call, using a fresh temporary path.
            if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        assert_eq!(inspect(&path)?.kind, NodeKind::Special);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(open_verified(&path, &before).is_err());
        });
        assert!(
            receiver
                .recv_timeout(Duration::from_secs(3))
                .map_err(|error| io::Error::other(error.to_string()))?
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "APFS rejects non-UTF-8 native names; needs Linux filesystem validation"
    )]
    fn preserves_non_utf8_paths() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let root = fs::canonicalize(temp.path())?;
        let path = root.join(OsString::from_vec(b"file-\xff.txt".to_vec()));
        fs::write(&path, b"native path")?;
        let info = inspect(&path)?;
        let mut bytes = Vec::new();
        open_verified(&path, &info)?.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"native path");
        Ok(())
    }

    #[test]
    fn preserves_hardlink_identity() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let root = fs::canonicalize(temp.path())?;
        let path = root.join("file");
        fs::write(&path, b"native path")?;
        let alias = root.join("alias");
        fs::hard_link(&path, &alias)?;
        let info = inspect(&path)?;
        assert_eq!(info.identity, inspect(&alias)?.identity);
        assert!(info.links >= 2);
        Ok(())
    }
}

#[cfg(windows)]
#[test]
fn junction_is_never_followed() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let root = fs::canonicalize(temp.path())?;
    let actual = root.join("actual");
    let junction = root.join("junction");
    fs::create_dir(&actual)?;
    fs::write(actual.join("secret"), b"unchanged")?;
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&actual)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "junction fixture could not be created with ordinary user privileges",
        ));
    }
    let node = inspect(&junction)?;
    // Rust may expose a junction as a directory symlink. Both kinds must
    // still be rejected before content reads, including through descendants.
    assert!(matches!(node.kind, NodeKind::Symlink | NodeKind::Reparse));
    assert!(open_verified(&junction, &node).is_err());
    assert!(open_verified(&junction.join("secret"), &inspect(&actual.join("secret"))?).is_err());
    assert_eq!(fs::read(actual.join("secret"))?, b"unchanged");
    // Remove only the junction itself before tempfile cleans the fixture tree.
    fs::remove_dir(&junction)?;
    Ok(())
}
