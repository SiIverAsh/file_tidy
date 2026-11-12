use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

fn fixture() -> Result<TempDir, Box<dyn Error>> {
    let parent = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(path) => PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cli-test-fixtures"),
    };
    fs::create_dir_all(&parent)?;
    Ok(tempfile::tempdir_in(parent)?)
}

fn executable() -> Command {
    Command::new(env!("CARGO_BIN_EXE_file-tidy"))
}

fn scan_json(root: &Path, extra: &[&str]) -> Result<Output, Box<dyn Error>> {
    Ok(executable()
        .arg("scan")
        .arg(root)
        .args(["--format", "json", "--quiet", "--threads", "1"])
        .args(extra)
        .output()?)
}

fn snapshot(root: &Path) -> Result<BTreeMap<OsString, Vec<u8>>, Box<dyn Error>> {
    fs::read_dir(root)?
        .map(|entry| {
            let entry = entry?;
            Ok((entry.file_name(), fs::read(entry.path())?))
        })
        .collect()
}

#[test]
fn scan_outputs_json_without_modifying_fixture() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join("a.txt"), b"the same document")?;
    fs::write(dir.path().join("b.txt"), b"the same document")?;
    fs::write(dir.path().join("other.txt"), b"different contents")?;
    let before = snapshot(dir.path())?;

    let output = scan_json(dir.path(), &[])?;
    assert!(
        output.status.success(),
        "unexpected exit status {:?}, stderr {:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["summary"]["cancelled"], false);
    assert_eq!(report["summary"]["complete"], true);
    assert_eq!(before, snapshot(dir.path())?);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn entry_limit_is_visible_and_returns_incomplete_status() -> TestResult {
    let dir = fixture()?;
    for name in ["a.txt", "b.txt", "c.txt"] {
        fs::write(dir.path().join(name), name)?;
    }
    let output = scan_json(dir.path(), &["--max-entries", "1"])?;
    assert_eq!(output.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["summary"]["limit_reached"], true);
    assert_eq!(report["summary"]["complete"], false);
    Ok(())
}

#[test]
fn metadata_only_never_reports_content_duplicates() -> TestResult {
    let dir = fixture()?;
    fs::write(dir.path().join("a.txt"), b"same content")?;
    fs::write(dir.path().join("b.txt"), b"same content")?;
    let output = scan_json(dir.path(), &["--metadata-only"])?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["summary"]["complete"], true);
    assert_eq!(report["summary"]["content_bytes_read"], "0");
    assert_eq!(report["summary"]["content_open_operations"], 0);
    Ok(())
}

#[test]
fn sensitive_rules_file_is_not_loaded_or_logged() -> TestResult {
    let dir = fixture()?;
    let secret = dir.path().join(".env");
    fs::write(&secret, b"PRIVATE_KEY=DO_NOT_PRINT_THIS_SECRET")?;
    let output = executable()
        .arg("scan")
        .arg(dir.path())
        .arg("--rules")
        .arg(&secret)
        .arg("--quiet")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("DO_NOT_PRINT_THIS_SECRET"));
    assert!(!stderr.contains(".env"));
    Ok(())
}

#[test]
fn text_report_escapes_terminal_control_characters() -> TestResult {
    let dir = fixture()?;
    #[cfg(unix)]
    let name = "danger-\x1b[31m\n.txt";
    #[cfg(windows)]
    let name = "danger-\u{202e}.txt";
    fs::write(dir.path().join(name), b"plain")?;
    let output = executable()
        .arg("scan")
        .arg(dir.path())
        .args(["--metadata-only", "--quiet"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(!stdout.contains('\x1b'));
    assert!(!stdout.contains('\u{202e}'));
    assert!(!stdout.contains("31m\n.txt"));
    Ok(())
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "APFS rejects invalid UTF-8 native filenames; run on a supporting filesystem"
)]
fn non_utf8_file_name_does_not_break_json_or_path_processing() -> TestResult {
    use std::os::unix::ffi::OsStringExt;

    let dir = fixture()?;
    let name = OsString::from_vec(b"odd-\xff.txt".to_vec());
    fs::write(dir.path().join(name), b"plain")?;
    let output = scan_json(dir.path(), &["--metadata-only"])?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["summary"]["complete"], true);
    let entries = report["entries"].as_array().ok_or("missing entry array")?;
    assert!(entries.iter().any(|entry| {
        entry["path"]["encoding"] == "unix_bytes"
            && entry["path"]["units"]
                .as_array()
                .is_some_and(|units| units.iter().any(|unit| unit.as_u64() == Some(255)))
    }));
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn help_and_unknown_mutation_command_are_explicit() -> TestResult {
    let help = executable().arg("--help").output()?;
    assert!(help.status.success());
    let stdout = String::from_utf8(help.stdout)?;
    assert!(stdout.contains("只读"));
    assert!(stdout.contains("不移动"));
    let mutation = executable()
        .args(["delete", "--permanent"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    assert_eq!(mutation.status.code(), Some(2));
    assert!(mutation.stdout.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn sigint_cancels_scan_and_returns_a_partial_json_report() -> TestResult {
    use std::io::{BufRead, BufReader, Read};

    let dir = fixture()?;
    // Enough entries that scanning cannot normally finish between the startup
    // handshake and SIGINT. No large file payloads or user files are required.
    for index in 0..1000 {
        fs::write(dir.path().join(format!("file-{index}.txt")), b"small")?;
    }
    let mut child = executable()
        .arg("scan")
        .arg(dir.path())
        .args(["--format", "json", "--progress", "--threads", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("missing child stderr")?;
    let mut reader = BufReader::new(stderr);
    let mut started = String::new();
    reader.read_line(&mut started)?;
    assert!(started.contains("只读扫描已启动"));
    let signal = Command::new("/bin/kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .output()?;
    assert!(signal.status.success());
    let mut stdout = child.stdout.take().ok_or("missing child stdout")?;
    let mut bytes = Vec::new();
    stdout.read_to_end(&mut bytes)?;
    let status = child.wait()?;
    assert_eq!(status.code(), Some(130));
    let report: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(report["summary"]["cancelled"], true);
    assert_eq!(report["summary"]["complete"], false);
    assert_eq!(fs::read_dir(dir.path())?.count(), 1000);
    Ok(())
}
