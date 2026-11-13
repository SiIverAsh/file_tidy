use std::path::{Path, PathBuf};

use file_tidy_core::CancellationToken;
use file_tidy_core::approval::{ApprovedPlan, Confirmation};
use file_tidy_core::authorization::{PlanningError, Session};
use file_tidy_core::execution::ExecutionStatus;
use file_tidy_core::plan::{OperationKind, OperationRequest, PlanOptions};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => Ok(tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?),
        None => Ok(tempfile::tempdir()?),
    }
}
fn initialized(root: &Path) -> Result<Session, Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    let id = session.grant(root, false)?;
    let plan = session.storage_plan(&id)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    Ok(session)
}
fn move_request(source: PathBuf, destination: PathBuf) -> OperationRequest {
    OperationRequest {
        kind: OperationKind::Move,
        source,
        destination: Some(destination),
    }
}
fn approve(
    session: &mut Session,
    requests: Vec<OperationRequest>,
) -> Result<ApprovedPlan, Box<dyn std::error::Error>> {
    let plan = session.build_plan(
        requests,
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    let confirmation = Confirmation {
        digest: plan.digest().to_owned(),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        ..Default::default()
    };
    Ok(session.confirm(plan, confirmation)?)
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn moves_siblings_and_a_complete_tree_with_durable_history() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("a"), "first")?;
    std::fs::write(root.join("b"), "second")?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::create_dir(root.join("tree/empty"))?;
    std::fs::write(root.join("tree/.hidden"), "hidden")?;
    let approved = approve(
        &mut session,
        vec![
            move_request(root.join("a"), root.join("a-new")),
            move_request(root.join("b"), root.join("b-new")),
            move_request(root.join("tree"), root.join("tree-new")),
        ],
    )?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(root.join("a-new"))?, b"first");
    assert_eq!(std::fs::read(root.join("b-new"))?, b"second");
    assert_eq!(std::fs::read(root.join("tree-new/.hidden"))?, b"hidden");
    assert!(root.join("tree-new/empty").is_dir());
    assert!(!root.join("a").exists());
    assert!(!root.join("b").exists());
    assert!(!root.join("tree").exists());
    let detail = session.batch_history(&report.batch_id)?;
    assert_eq!(detail.operations.len(), 3);
    assert_eq!(detail.events.len(), 6);
    drop(session);
    let reader = Session::open(root)?;
    assert_eq!(reader.history(10)?.len(), 1);
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    let invalid: i64 = db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
        r.get(0)
    })?;
    assert_eq!(invalid, 0);
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn occupied_destination_invalidates_approval_and_preserves_both_files() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "original")?;
    let approved = approve(
        &mut session,
        vec![move_request(root.join("source"), root.join("target"))],
    )?;
    std::fs::write(root.join("target"), "other")?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(std::fs::read(root.join("source"))?, b"original");
    assert_eq!(std::fs::read(root.join("target"))?, b"other");
    assert!(session.history(10)?.is_empty());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn replaced_source_parent_is_rejected_even_when_original_inode_is_returned() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(root.join("source-dir"))?;
    std::fs::create_dir(root.join("destination-dir"))?;
    std::fs::write(root.join("source-dir/source"), "original")?;
    let approved = approve(
        &mut session,
        vec![move_request(
            root.join("source-dir/source"),
            root.join("destination-dir/target"),
        )],
    )?;
    std::fs::rename(root.join("source-dir"), root.join("old-dir"))?;
    std::fs::create_dir(root.join("source-dir"))?;
    std::fs::rename(root.join("old-dir/source"), root.join("source-dir/source"))?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(std::fs::read(root.join("source-dir/source"))?, b"original");
    assert!(!root.join("destination-dir/target").exists());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn directory_additions_after_confirmation_prevent_all_moves() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/original"), "original")?;
    let approved = approve(
        &mut session,
        vec![move_request(root.join("tree"), root.join("moved"))],
    )?;
    std::fs::write(root.join("tree/new"), "new")?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert!(root.join("tree/new").is_file());
    assert!(root.join("tree/original").is_file());
    assert!(!root.join("moved").exists());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn cancellation_keeps_every_source_and_records_an_unstarted_batch() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "original")?;
    let approved = approve(
        &mut session,
        vec![move_request(root.join("source"), root.join("target"))],
    )?;
    let token = CancellationToken::new();
    token.cancel();
    let report = session.execute_approved(approved, &token)?;
    assert!(!report.completed());
    assert_eq!(report.operations[0].status, ExecutionStatus::Cancelled);
    assert!(report.journal_error.is_none(), "{report:?}");
    assert!(root.join("source").exists());
    assert!(!root.join("target").exists());
    assert!(session.batch_history(&report.batch_id)?.events.is_empty());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn journal_intent_failure_prevents_file_mutation() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "original")?;
    let approved = approve(
        &mut session,
        vec![move_request(root.join("source"), root.join("target"))],
    )?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON operation_events WHEN NEW.phase='intent' BEGIN SELECT RAISE(ABORT, 'injected intent failure'); END;")?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some());
    assert_eq!(report.operations[0].status, ExecutionStatus::NotStarted);
    assert_eq!(std::fs::read(root.join("source"))?, b"original");
    assert!(!root.join("target").exists());
    assert!(session.batch_history(&report.batch_id)?.events.is_empty());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn journal_result_failure_reports_moved_object_and_stops_following_operations() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("a"), "first")?;
    std::fs::write(root.join("b"), "second")?;
    let approved = approve(
        &mut session,
        vec![
            move_request(root.join("a"), root.join("a-new")),
            move_request(root.join("b"), root.join("b-new")),
        ],
    )?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER fail_result BEFORE INSERT ON operation_events WHEN NEW.phase='result' BEGIN SELECT RAISE(ABORT, 'injected result failure'); END;")?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some());
    assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
    assert_eq!(report.operations[1].status, ExecutionStatus::NotStarted);
    assert_eq!(std::fs::read(root.join("a-new"))?, b"first");
    assert!(!root.join("a").exists());
    assert_eq!(std::fs::read(root.join("b"))?, b"second");
    assert!(!root.join("b-new").exists());
    assert_eq!(session.batch_history(&report.batch_id)?.events.len(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn symlink_to_protected_tree_moves_the_link_without_following_it() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::os::unix::fs::symlink("/usr", root.join("link"))?;
    let approved = approve(
        &mut session,
        vec![move_request(root.join("link"), root.join("new-link"))],
    )?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        std::fs::read_link(root.join("new-link"))?,
        Path::new("/usr")
    );
    assert!(std::fs::symlink_metadata(root.join("link")).is_err());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn all_execution_protocols_are_checked_before_a_batch_starts() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("ordinary"), "first")?;
    std::fs::write(root.join("data.sqlite"), "database")?;
    let approved = approve(
        &mut session,
        vec![
            move_request(root.join("ordinary"), root.join("ordinary-new")),
            move_request(root.join("data.sqlite"), root.join("data-new.sqlite")),
        ],
    )?;
    assert!(matches!(
        session.execute_approved(approved, &CancellationToken::new()),
        Err(PlanningError::ConsistencyRequired)
    ));
    assert!(root.join("ordinary").exists());
    assert!(root.join("data.sqlite").exists());
    assert!(session.history(10)?.is_empty());
    Ok(())
}
