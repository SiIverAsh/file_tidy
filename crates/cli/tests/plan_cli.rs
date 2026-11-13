use std::path::PathBuf;
use std::process::{Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => Ok(tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?),
        None => Ok(tempfile::tempdir()?),
    }
}
fn executable() -> Command {
    Command::new(env!("CARGO_BIN_EXE_file-tidy"))
}

#[test]
fn commands_require_complete_arguments_and_explicit_execution_state() -> TestResult {
    for args in [
        vec!["plan"],
        vec!["execute"],
        vec!["state"],
        vec!["grant"],
        vec!["history"],
        vec!["recover"],
        vec!["plan", "move", "source", "--to", "target", "--execute"],
        vec![
            "plan",
            "move",
            "source",
            "--to",
            "target",
            "--state",
            "state",
            "--approve",
            "--execute",
        ],
    ] {
        let output = executable().args(args).output()?;
        assert!(!output.status.success());
    }
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn execution_requires_a_terminal_before_saving_or_moving() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = file_tidy_core::authorization::Session::new()?;
    let id = session.grant(root, false)?;
    let plan = session.storage_plan(&id)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    drop(session);
    std::fs::write(root.join("source"), "original")?;
    let output = executable()
        .args(["plan", "move"])
        .arg(root.join("source"))
        .arg("--to")
        .arg(root.join("target"))
        .arg("--state")
        .arg(root)
        .arg("--execute")
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("交互终端"));
    assert_eq!(std::fs::read(root.join("source"))?, b"original");
    assert!(!root.join("target").exists());
    assert!(
        file_tidy_core::authorization::Session::open(root)?
            .history(10)?
            .is_empty()
    );
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn preview_outputs_native_paths_and_does_not_create_state() -> TestResult {
    let dir = fixture()?;
    std::fs::write(dir.path().join("source"), "payload")?;
    let output = executable()
        .args(["plan", "move", "--format", "json"])
        .arg(dir.path().join("source"))
        .arg("--to")
        .arg(dir.path().join("target"))
        .arg("--grant")
        .arg(dir.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["plan"]["confirmation_count"], 1);
    assert_eq!(
        value["plan"]["operations"][0]["source"]["display"],
        file_tidy_core_path_display(dir.path().join("source"))
    );
    assert!(dir.path().join("source").exists());
    assert!(!dir.path().join("target").exists());
    assert!(!dir.path().join(".file-tidy").exists());
    Ok(())
}
fn file_tidy_core_path_display(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn state_initialization_rejects_noninteractive_confirmation_without_writing() -> TestResult {
    let dir = fixture()?;
    let output = executable()
        .args(["state", "init"])
        .arg(dir.path())
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("交互终端"));
    assert!(!dir.path().join(".file-tidy").exists());
    Ok(())
}
