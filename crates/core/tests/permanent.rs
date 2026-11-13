use file_tidy_core::{
    CancellationToken,
    approval::{ApprovedPlan, Confirmation},
    authorization::{PlanningError as E, Session},
    execution::ExecutionStatus,
    plan::{OperationKind as K, OperationRequest, Plan, PlanOptions},
    recovery::RecoveryDisposition as D,
};
use std::path::{Path, PathBuf};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?,
        None => tempfile::tempdir()?,
    })
}
fn setup() -> Result<(tempfile::TempDir, Session), Box<dyn std::error::Error>> {
    let directory = fixture()?;
    let mut session = Session::new()?;
    let grant = session.grant(directory.path(), false)?;
    let plan = session.storage_plan(&grant)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    Ok((directory, session))
}
fn opts() -> PlanOptions {
    PlanOptions {
        include_hidden: true,
        ..Default::default()
    }
}
fn request(kind: K, source: &Path) -> OperationRequest {
    OperationRequest {
        kind,
        source: source.to_owned(),
        destination: None,
    }
}
fn approve(session: &mut Session, plan: Plan) -> Result<ApprovedPlan, E> {
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        item_count: plan
            .preview()
            .requires_count_confirmation
            .then_some(plan.preview().confirmation_count),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        permanent_phrase: plan
            .preview()
            .permanent_challenge
            .as_ref()
            .map(|challenge| {
                format!(
                    "PERMANENT {} {challenge}",
                    plan.preview().confirmation_count
                )
            }),
    };
    session.confirm(plan, confirmation)
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_confirmation_binds_count_sensitive_scope_and_the_complete_manifest() -> TestResult {
    let (directory, mut session) = setup()?;
    let source = directory.path().join("source");
    std::fs::create_dir(&source)?;
    for index in 0..11 {
        std::fs::write(
            source.join(if index == 0 {
                ".env".into()
            } else {
                format!("file-{index}")
            }),
            b"fixture",
        )?;
    }
    let plan = session.build_plan(vec![request(K::PermanentDelete, &source)], opts())?;
    assert!(plan.preview().requires_count_confirmation);
    assert_eq!(plan.preview().confirmation_count, 11);
    assert!(
        plan.preview()
            .sensitive_acknowledgements
            .iter()
            .all(|key| key.ends_with(":write"))
    );
    assert!(!plan.preview().sensitive_acknowledgements.is_empty());
    assert!(plan.review_text()?.contains("删除前暂存"));
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        item_count: Some(10),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        permanent_phrase: plan
            .preview()
            .permanent_challenge
            .as_ref()
            .map(|challenge| format!("PERMANENT 11 {challenge}")),
    };
    assert!(matches!(
        session.confirm(plan, confirmation),
        Err(E::ConfirmationRequired)
    ));
    assert!(!directory.path().join(".file-tidy/quarantine").exists());
    let plan = session.build_plan(vec![request(K::PermanentDelete, &source)], opts())?;
    let approved = approve(&mut session, plan)?;
    std::fs::write(source.join("new"), b"unreviewed")?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(std::fs::read(source.join("new"))?, b"unreviewed");
    assert!(!directory.path().join(".file-tidy/quarantine").exists());
    assert!(session.history(10)?.is_empty());
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_removes_the_reviewed_tree_and_link_without_following_the_target() -> TestResult {
    let (directory, mut session) = setup()?;
    let outside = fixture()?;
    let root = directory.path();
    std::fs::create_dir_all(root.join("tree/nested/empty"))?;
    std::fs::write(root.join("tree/data"), b"data")?;
    std::fs::write(root.join("tree/.env"), b"fixture-secret-value")?;
    std::fs::write(outside.path().join("sentinel"), b"keep")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), root.join("tree/link"))?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), root.join("tree/link"))?;
    let plan = session.build_plan(
        vec![request(K::PermanentDelete, &root.join("tree"))],
        opts(),
    )?;
    let entries = plan.preview().operations[0].manifest.len();
    let operation = plan.preview().operations[0].id.clone();
    let approved = approve(&mut session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert!(!root.join("tree").exists());
    assert_eq!(std::fs::read(outside.path().join("sentinel"))?, b"keep");
    assert_eq!(session.quarantine_items(10, false)?[0].state, "purged");
    let progress = session.permanent_progress(&report.batch_id, &operation)?;
    assert_eq!(progress.confirmed_removed_entries, entries as u64);
    assert!(progress.remaining.is_empty());
    assert!(progress.unconfirmed_entry.is_none());
    assert!(progress.irreversible);
    let history = session.batch_history(&report.batch_id)?;
    assert_eq!(history.operations[0].kind, "permanent_delete");
    assert!(!serde_json::to_string(&history)?.contains("fixture-secret-value"));
    assert!(matches!(
        session.build_undo_plan(&report.batch_id, &[], opts()),
        Err(E::IrreversibleOperation)
    ));
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_purges_a_registered_batch_without_touching_state_or_reusing_old_approval() -> TestResult
{
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("file"), b"data")?;
    std::fs::create_dir_all(root.join("tree/empty"))?;
    let plan = session.build_plan(
        vec![
            request(K::Quarantine, &root.join("file")),
            request(K::Quarantine, &root.join("tree")),
        ],
        opts(),
    )?;
    let approved = approve(&mut session, plan)?;
    let retained = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(retained.completed(), "{retained:?}");
    let plan = session.build_batch_purge_plan(&retained.batch_id, opts())?;
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        ..Default::default()
    };
    assert!(matches!(
        session.confirm(plan, confirmation),
        Err(E::ConfirmationRequired)
    ));
    let plan = session.build_batch_purge_plan(&retained.batch_id, opts())?;
    let approved = approve(&mut session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert!(
        session
            .quarantine_items(10, false)?
            .iter()
            .all(|item| item.state == "purged")
    );
    assert!(root.join(".file-tidy/state.db").is_file());
    assert_eq!(session.history(10)?.len(), 2);
    assert!(
        session
            .build_batch_purge_plan(&retained.batch_id, opts())
            .is_err()
    );
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_partial_journal_failure_lists_and_restores_only_the_remaining_tree() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/a"), b"first")?;
    std::fs::write(root.join("tree/b"), b"remaining")?;
    let plan = session.build_plan(
        vec![request(K::PermanentDelete, &root.join("tree"))],
        opts(),
    )?;
    let operation = plan.preview().operations[0].id.clone();
    let approved = approve(&mut session, plan)?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER stop_second_remove BEFORE INSERT ON operation_events WHEN NEW.step='permanent_remove' AND NEW.phase='intent' AND (SELECT count(*) FROM operation_events WHERE op_id=NEW.op_id AND step='permanent_remove' AND phase='result')=1 BEGIN SELECT RAISE(ABORT,'fixture second removal intent failure'); END;")?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some(), "{report:?}");
    assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
    let progress = session.permanent_progress(&report.batch_id, &operation)?;
    assert_eq!(progress.confirmed_removed_entries, 1);
    assert_eq!(progress.remaining.len(), 2);
    assert!(
        progress
            .remaining
            .iter()
            .any(|entry| entry.path.to_path().is_ok_and(|p| p.ends_with("b")))
    );
    assert!(progress.unconfirmed_entry.is_none());
    let item = session.quarantine_items(10, false)?.remove(0);
    assert_eq!(item.state, "needs_recovery");
    assert!(
        session
            .build_restore_plan(std::slice::from_ref(&item.id), None, opts())
            .is_err()
    );
    let restore = session.build_remaining_restore_plan(&[item.id], None, opts())?;
    assert!(restore.review_text()?.contains("恢复当前保留清单"));
    let approved = approve(&mut session, restore)?;
    let restored = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(restored.completed(), "{restored:?}");
    assert!(!root.join("tree/a").exists());
    assert_eq!(std::fs::read(root.join("tree/b"))?, b"remaining");
    let progress = session.permanent_progress(&report.batch_id, &operation)?;
    assert!(progress.restoration_destination.is_some());
    assert_eq!(progress.confirmed_removed_entries, 1);
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn permanent_result_log_failure_leaves_the_removal_unconfirmed_and_stops_later_items() -> TestResult
{
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("file"), b"data")?;
    std::fs::write(root.join("later"), b"keep")?;
    let plan = session.build_plan(
        vec![
            request(K::PermanentDelete, &root.join("file")),
            request(K::PermanentDelete, &root.join("later")),
        ],
        opts(),
    )?;
    let operation = plan.preview().operations[0].id.clone();
    let approved = approve(&mut session, plan)?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER fail_remove_result BEFORE INSERT ON operation_events WHEN NEW.step='permanent_remove' AND NEW.phase='result' BEGIN SELECT RAISE(ABORT,'fixture removal result failure'); END;")?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some(), "{report:?}");
    assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
    assert_eq!(report.operations[1].status, ExecutionStatus::NotStarted);
    assert_eq!(std::fs::read(root.join("later"))?, b"keep");
    let progress = session.permanent_progress(&report.batch_id, &operation)?;
    assert_eq!(progress.disposition, D::NeedsAttention);
    assert_eq!(progress.confirmed_removed_entries, 0);
    assert!(progress.unconfirmed_entry.is_some());
    assert!(progress.remaining.is_empty());
    let before = serde_json::to_value(session.batch_history(&report.batch_id)?)?;
    let diagnosis = session.recovery_report(Some(&report.batch_id), 10)?;
    assert!(diagnosis.items[0].permanent.is_some());
    assert_eq!(
        serde_json::to_value(session.batch_history(&report.batch_id)?)?,
        before
    );
    Ok(())
}
