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

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn quarantine_commands_preview_restore_and_reject_noninteractive_execution() -> TestResult {
    use file_tidy_core::{
        CancellationToken,
        approval::Confirmation,
        authorization::Session,
        plan::{OperationKind, OperationRequest, PlanOptions},
    };
    let dir = fixture()?;
    let root = dir.path();
    let mut session = Session::new()?;
    let grant = session.grant(root, false)?;
    let storage = session.storage_plan(&grant)?;
    let digest = storage.digest().to_owned();
    session.initialize_storage(storage, &digest)?;
    std::fs::write(root.join("source"), b"fixture")?;
    drop(session);
    let output = executable()
        .args(["plan", "quarantine"])
        .arg(root.join("source"))
        .arg("--state")
        .arg(root)
        .arg("--format")
        .arg("json")
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(preview["plan"]["operations"][0]["kind"], "quarantine");
    assert!(!root.join(".file-tidy/quarantine").exists());
    let mut session = Session::open_writable(root)?;
    let plan = session.build_plan(
        vec![OperationRequest {
            kind: OperationKind::Quarantine,
            source: root.join("source"),
            destination: None,
        }],
        PlanOptions::default(),
    )?;
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        ..Default::default()
    };
    let approved = session.confirm(plan, confirmation)?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())?
            .completed()
    );
    let id = session.quarantine_items(10, false)?.remove(0).id;
    drop(session);
    let output = executable()
        .args(["quarantine", "list", "--state"])
        .arg(root)
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout)?[0]["id"],
        id.to_string()
    );
    let output = executable()
        .args(["quarantine", "restore", id.as_str(), "--state"])
        .arg(root)
        .args(["--format", "json"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout)?["plan"]["operations"][0]["kind"],
        "restore"
    );
    let output = executable()
        .args(["quarantine", "restore", id.as_str(), "--state"])
        .arg(root)
        .arg("--execute")
        .stdin(Stdio::null())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("交互终端"));
    assert!(!root.join("source").exists());
    let session = Session::open(root)?;
    assert_eq!(session.quarantine_items(10, false)?[0].state, "stored");
    assert_eq!(session.history(10)?.len(), 1);
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_cli_requires_the_explicit_flag_and_an_interactive_review() -> TestResult {
    use file_tidy_core::authorization::Session;
    let directory = fixture()?;
    let root = directory.path();
    let mut session = Session::new()?;
    let grant = session.grant(root, false)?;
    let storage = session.storage_plan(&grant)?;
    let digest = storage.digest().to_owned();
    session.initialize_storage(storage, &digest)?;
    drop(session);
    std::fs::write(root.join("file"), b"keep")?;
    let missing = executable()
        .args(["plan", "permanent-delete"])
        .arg(root.join("file"))
        .arg("--state")
        .arg(root)
        .arg("--execute")
        .stdin(Stdio::null())
        .output()?;
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--permanent"));
    let terminal = executable()
        .args(["plan", "permanent-delete"])
        .arg(root.join("file"))
        .arg("--state")
        .arg(root)
        .args(["--execute", "--permanent"])
        .stdin(Stdio::null())
        .output()?;
    assert!(!terminal.status.success());
    assert!(String::from_utf8_lossy(&terminal.stderr).contains("交互终端"));
    assert_eq!(std::fs::read(root.join("file"))?, b"keep");
    assert!(!root.join(".file-tidy/quarantine").exists());
    assert!(Session::open(root)?.history(10)?.is_empty());
    Ok(())
}
