use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use file_tidy_core::{
    CancellationToken, EntryKind, ScanOptions, ScanPhase, SkipReason, load_rules, scan,
};

type TestResult = Result<(), Box<dyn Error>>;

fn fixture() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let base = std::env::var_os("FILE_TIDY_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/core-test-fixtures")
        });
    fs::create_dir_all(&base)?;
    Ok(tempfile::tempdir_in(fs::canonicalize(base)?)?)
}

fn options(root: &Path) -> ScanOptions {
    ScanOptions {
        roots: vec![root.to_owned()],
        threads: 2,
        ..ScanOptions::default()
    }
}

#[test]
fn sensitive_files_never_open_content_and_keep_metadata() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join(".env"), b"SECRET=never_read")?;
    fs::create_dir(dir.path().join(".ssh"))?;
    fs::write(dir.path().join(".ssh/config"), b"Host private")?;
    fs::write(dir.path().join("backup.pem"), b"private pem")?;
    let result = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert_eq!(result.summary.files, 3);
    assert_eq!(result.summary.content_open_operations, 0);
    assert_eq!(result.summary.content_bytes_read, 0);
    assert!(
        result
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .all(|e| e.policy.sensitive)
    );
    assert!(result.duplicates.is_empty());
    assert_eq!(
        result
            .skipped
            .iter()
            .filter(|e| e.reason == SkipReason::SensitiveContent)
            .count(),
        3
    );
    assert!(result.summary.complete);
    assert!(!serde_json::to_string(&result)?.contains("never_read"));
    Ok(())
}

#[test]
fn metadata_mode_performs_zero_content_opens_and_preserves_files() -> TestResult {
    let dir = fixture()?;
    let path = dir.path().join("photo.jpg");
    let data = b"\xff\xd8\xff\xe0bytes";
    fs::write(&path, data)?;
    let before = fs::metadata(&path)?;
    let mut opts = options(dir.path());
    opts.metadata_only = true;
    let result = scan(opts, &CancellationToken::default(), |_| {})?;
    assert!(result.summary.complete);
    assert_eq!(result.summary.content_open_operations, 0);
    assert_eq!(result.summary.content_bytes_read, 0);
    assert!(result.duplicates.is_empty());
    assert_eq!(fs::read(&path)?, data);
    let after = fs::metadata(&path)?;
    assert_eq!(before.modified()?, after.modified()?);
    assert_eq!(before.len(), after.len());
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn staged_duplicates_compare_entire_file_and_do_not_count_hardlinks() -> TestResult {
    let dir = fixture()?;
    let a = vec![7_u8; 80 * 1024];
    let mut b = a.clone();
    b[79 * 1024] = 8;
    fs::write(dir.path().join("a.bin"), &a)?;
    fs::write(dir.path().join("b.bin"), &b)?;
    fs::write(dir.path().join("c.bin"), &a)?;
    fs::hard_link(dir.path().join("a.bin"), dir.path().join("hardlink.bin"))?;
    let result = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert!(result.summary.complete);
    assert_eq!(result.summary.files, 4);
    assert_eq!(result.summary.logical_bytes, a.len() as u64 * 4);
    assert_eq!(result.summary.unique_file_logical_bytes, a.len() as u64 * 3);
    assert_eq!(result.duplicates.len(), 1);
    assert_eq!(result.duplicates[0].entry_ids.len(), 2);
    assert_eq!(result.duplicates[0].duplicate_logical_bytes, a.len() as u64);
    let paths: Vec<_> = result.duplicates[0]
        .entry_ids
        .iter()
        .map(|id| &result.entries[(*id - 1) as usize].path)
        .collect();
    assert!(!paths.contains(&&dir.path().join("b.bin")));
    Ok(())
}

#[test]
fn known_sensitive_hardlink_aliases_are_blocked_before_magic() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join("ordinary.txt"), b"same secret inode")?;
    fs::hard_link(dir.path().join("ordinary.txt"), dir.path().join(".env"))?;
    let result = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert_eq!(result.summary.content_open_operations, 0);
    assert!(
        result
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .all(|e| e.policy.sensitive)
    );
    assert!(result.summary.complete);
    Ok(())
}

#[test]
fn missing_roots_do_not_abort_other_roots() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join("ok.txt"), b"ok")?;
    let mut opts = options(dir.path());
    opts.roots.push(dir.path().join("missing"));
    let result = scan(opts, &CancellationToken::default(), |_| {})?;
    assert!(!result.summary.complete);
    assert_eq!(result.summary.files, 1);
    assert!(result.skipped.iter().any(|e| e.incomplete));
    Ok(())
}

#[test]
fn resource_budget_is_reported_as_incomplete() -> TestResult {
    let dir = fixture()?;
    for i in 0..12 {
        fs::write(dir.path().join(format!("{i}.txt")), b"data")?;
    }
    let mut opts = options(dir.path());
    opts.max_entries = 5;
    let result = scan(opts, &CancellationToken::default(), |_| {})?;
    assert!(result.summary.limit_reached);
    assert!(!result.summary.complete);
    assert!(result.summary.entries <= 5);
    Ok(())
}

#[test]
fn cancellation_before_and_during_content_returns_partial_report() -> TestResult {
    let dir = fixture()?;
    let data = vec![19; 256 * 1024];
    fs::write(dir.path().join("a.bin"), &data)?;
    fs::write(dir.path().join("b.bin"), &data)?;
    let cancel = CancellationToken::default();
    cancel.cancel();
    let report = scan(options(dir.path()), &cancel, |_| {})?;
    assert!(report.summary.cancelled);
    assert_eq!(report.summary.content_open_operations, 0);
    let cancel = CancellationToken::default();
    let report = scan(options(dir.path()), &cancel, |progress| {
        if matches!(progress.phase, ScanPhase::FullHash) {
            cancel.cancel();
        }
    })?;
    assert!(report.summary.cancelled);
    assert!(!report.summary.complete);
    assert!(report.duplicates.is_empty());
    Ok(())
}

#[test]
fn mutation_between_magic_and_hash_is_visible_and_not_a_duplicate() -> TestResult {
    let dir = fixture()?;
    let a = dir.path().join("a.bin");
    fs::write(&a, b"same original")?;
    fs::write(dir.path().join("b.bin"), b"same original")?;
    let changed = AtomicBool::new(false);
    let result = scan(
        options(dir.path()),
        &CancellationToken::default(),
        |event| {
            if matches!(event.phase, ScanPhase::PrefixHash)
                && !changed.swap(true, Ordering::Relaxed)
            {
                // Simulate an unrelated writer, never a scanner operation.
                assert!(fs::write(&a, b"different length after preview").is_ok());
            }
        },
    )?;
    assert!(changed.load(Ordering::Relaxed));
    assert!(result.duplicates.is_empty());
    assert!(!result.summary.complete);
    assert!(result.skipped.iter().any(|e| e.incomplete && e.path == a));
    Ok(())
}

#[test]
fn rules_loader_rejects_sensitive_and_oversized_configuration() -> TestResult {
    let dir = fixture()?;
    let path = dir.path().join("rules.toml");
    fs::write(&path, include_bytes!("../../../config/default-rules.toml"))?;
    assert!(load_rules(&path).is_ok());
    let secret = dir.path().join(".env");
    fs::write(
        &secret,
        include_bytes!("../../../config/default-rules.toml"),
    )?;
    assert!(matches!(
        load_rules(&secret),
        Err(file_tidy_core::Error::ConfigurationDenied)
    ));
    fs::write(&path, vec![b'x'; 1_048_577])?;
    assert!(matches!(
        load_rules(&path),
        Err(file_tidy_core::Error::ConfigurationTooLarge)
    ));
    Ok(())
}

#[test]
fn top_usage_and_directory_totals_are_consistent() -> TestResult {
    let dir = fixture()?;
    fs::create_dir(dir.path().join("sub"))?;
    fs::write(dir.path().join("a.txt"), b"123")?;
    fs::write(dir.path().join("sub/b.txt"), b"1234567")?;
    let mut opts = options(dir.path());
    opts.top_n = 1;
    let result = scan(opts, &CancellationToken::default(), |_| {})?;
    assert_eq!(result.summary.logical_bytes, 10);
    assert_eq!(result.top_entry_ids.len(), 1);
    assert!(
        result.entries[(result.top_entry_ids[0] - 1) as usize]
            .path
            .ends_with("b.txt")
    );
    assert!(
        result
            .directory_usage
            .iter()
            .any(|d| d.path == dir.path() && d.logical_bytes == 10 && d.files == 2)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn links_are_not_followed_or_hashed() -> TestResult {
    use std::os::unix::fs::symlink;
    let dir = fixture()?;
    let external = fixture()?;
    fs::write(external.path().join("external.txt"), b"must not read")?;
    symlink(external.path(), dir.path().join("linked-dir"))?;
    symlink(
        external.path().join("external.txt"),
        dir.path().join("linked-file"),
    )?;
    symlink(dir.path().join("absent"), dir.path().join("broken"))?;
    let report = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert_eq!(report.summary.content_open_operations, 0);
    assert_eq!(
        report
            .skipped
            .iter()
            .filter(|e| e.reason == SkipReason::Symlink)
            .count(),
        3
    );
    assert!(load_rules(&dir.path().join("linked-file")).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_socket_is_reported_without_opening_content() -> TestResult {
    use std::os::unix::net::UnixListener;
    #[cfg(target_os = "macos")]
    let base = Path::new("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let base = Path::new("/tmp");
    let dir = tempfile::Builder::new().prefix("ft-").tempdir_in(base)?;
    let _socket = UnixListener::bind(dir.path().join("socket"))?;
    let report = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert!(
        report
            .skipped
            .iter()
            .any(|e| e.reason == SkipReason::SpecialNode)
    );
    assert_eq!(report.summary.content_open_operations, 0);
    Ok(())
}

#[test]
fn magic_conflict_and_old_mtime_remain_reporting_only() -> TestResult {
    use std::time::UNIX_EPOCH;
    let dir = fixture()?;
    let file = dir.path().join("image.txt");
    fs::write(&file, b"\x89PNG\r\n\x1a\nmore bytes")?;
    fs::File::open(&file)?.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH))?;
    let report = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    let entry = report
        .entries
        .iter()
        .find(|e| e.path == file)
        .ok_or("missing image")?;
    let classification = entry
        .classification
        .as_ref()
        .ok_or("missing classification")?;
    assert_eq!(classification.category, file_tidy_core::Category::Image);
    assert_eq!(
        classification.evidence,
        file_tidy_core::TypeEvidence::Conflict
    );
    assert_eq!(classification.year_month.as_deref(), Some("1970-01"));
    assert!(report.stale_entry_ids.contains(&entry.id));
    assert!(file.exists());
    Ok(())
}

#[test]
fn empty_files_are_duplicates_with_zero_claimed_space() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join("a"), [])?;
    fs::write(dir.path().join("b"), [])?;
    let report = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    assert!(report.summary.complete);
    assert_eq!(report.duplicates.len(), 1);
    assert_eq!(report.duplicates[0].duplicate_logical_bytes, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "APFS rejects invalid UTF-8 native filenames; requires a supporting filesystem"
)]
fn non_utf8_names_and_atomic_roots_serialize_losslessly() -> TestResult {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let dir = fixture()?;
    let root = dir
        .path()
        .join(OsString::from_vec(b"project-\xff".to_vec()));
    fs::create_dir(&root)?;
    fs::create_dir(root.join(".git"))?;
    let file = root.join(OsString::from_vec(b"file-\xfe.txt".to_vec()));
    fs::write(&file, b"bytes")?;
    let report = scan(options(&root), &CancellationToken::default(), |_| {})?;
    let json = serde_json::to_value(&report)?;
    let entry = report
        .entries
        .iter()
        .position(|e| e.path == file)
        .ok_or("missing file")?;
    let units = json["entries"][entry]["path"]["units"]
        .as_array()
        .ok_or("missing path units")?;
    let raw: Vec<u8> = units
        .iter()
        .filter_map(|u| u.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect();
    assert_eq!(raw, file.as_os_str().as_bytes());
    assert!(report.entries[entry].policy.atomic_root.is_some());
    Ok(())
}

#[cfg(unix)]
#[test]
fn text_report_escapes_control_and_bidi_characters() -> TestResult {
    use file_tidy_core::render_text;

    let dir = fixture()?;
    fs::write(dir.path().join("name\n\u{1b}[31m\u{202e}.txt"), b"content")?;
    let report = scan(options(dir.path()), &CancellationToken::default(), |_| {})?;
    let text = render_text(&report);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains('\u{202e}'));
    assert!(text.contains("\\u{1b}"));
    assert!(text.contains("\\u{a}"));
    Ok(())
}
