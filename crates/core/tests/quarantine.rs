use file_tidy_core::{
    CancellationToken,
    approval::{ApprovedPlan, Confirmation},
    authorization::{PlanningError as E, Session},
    plan::{OperationKind as K, OperationRequest, Plan, PlanOptions},
};
use std::path::{Path, PathBuf};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    Ok(match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?,
        None => tempfile::tempdir()?,
    })
}
fn initialized(root: &Path) -> Result<Session, Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    let grant = session.grant(root, false)?;
    let plan = session.storage_plan(&grant)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    Ok(session)
}
fn options() -> PlanOptions {
    PlanOptions {
        include_hidden: true,
        ..Default::default()
    }
}
fn request(path: &Path) -> OperationRequest {
    OperationRequest {
        kind: K::Quarantine,
        source: path.to_owned(),
        destination: None,
    }
}
fn confirm(session: &mut Session, plan: Plan) -> Result<ApprovedPlan, E> {
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        ..Default::default()
    };
    session.confirm(plan, confirmation)
}
fn quarantine(
    session: &mut Session,
    paths: &[PathBuf],
) -> Result<Vec<file_tidy_core::authorization::Id>, Box<dyn std::error::Error>> {
    let plan = session.build_plan(paths.iter().map(|p| request(p)).collect(), options())?;
    let ids = plan
        .preview()
        .operations
        .iter()
        .map(|op| op.id.clone())
        .collect();
    let approved = confirm(session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    Ok(ids)
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn retains_complete_objects_and_restores_siblings_with_conflict_names() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir_all(root.join("tree/nested/empty"))?;
    std::fs::write(root.join("tree/nested/data"), b"retained-data")?;
    std::fs::write(root.join("tree/.env"), b"retained-sensitive")?;
    std::fs::write(root.join("archive.tar.gz"), b"archive")?;
    let identity = file_tidy_platform::inspect(&root.join("tree"))?.identity;
    let ids = quarantine(
        &mut session,
        &[root.join("tree"), root.join("archive.tar.gz")],
    )?;
    assert!(!root.join("tree").exists());
    let items = session.quarantine_items(10, false)?;
    assert_eq!(items.len(), 2);
    for item in &items {
        assert_eq!(item.expires_at - item.retained_at, 30 * 86400);
        assert!(!item.due);
        assert_eq!(item.state, "stored");
    }
    let tree = items
        .iter()
        .find(|i| i.original_path.to_path().ok() == Some(root.join("tree")))
        .ok_or("missing tree")?;
    assert_eq!(
        file_tidy_platform::inspect(&tree.storage_path.to_path()?)?.identity,
        identity
    );
    assert!(tree.storage_path.to_path()?.join("nested/empty").is_dir());
    std::fs::write(root.join("archive.tar.gz"), b"occupied")?;
    assert!(matches!(
        session.build_restore_plan(&ids, None, PlanOptions::default()),
        Err(E::HiddenEntry)
    ));
    assert_eq!(
        session
            .quarantine_items_in_batch(Some(&items[0].batch_id), 10, false)?
            .len(),
        2
    );
    let plan = session.build_batch_restore_plan(&items[0].batch_id, None, options())?;
    assert!(
        plan.preview()
            .operations
            .iter()
            .any(
                |o| o.destination.as_ref().is_some_and(|d| d.path.to_path().ok()
                    == Some(root.join("archive (1).tar.gz"))
                    && d.renamed_for_conflict)
            )
    );
    let approved = confirm(&mut session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        file_tidy_platform::inspect(&root.join("tree"))?.identity,
        identity
    );
    assert_eq!(
        std::fs::read(root.join("tree/.env"))?,
        b"retained-sensitive"
    );
    assert_eq!(std::fs::read(root.join("archive (1).tar.gz"))?, b"archive");
    assert_eq!(std::fs::read(root.join("archive.tar.gz"))?, b"occupied");
    assert!(
        session
            .quarantine_items(10, false)?
            .iter()
            .all(|i| i.state == "restored")
    );
    assert!(session.build_restore_plan(&ids, None, options()).is_err());
    let history = session.batch_history(&report.batch_id)?;
    assert_eq!(history.events.len(), 4);
    assert!(!serde_json::to_string(&history)?.contains("retained-sensitive"));
    assert!(session.quarantine_items(10, true)?.is_empty());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn preview_and_selection_create_no_directories_and_disclose_retention() -> TestResult {
    let dir = fixture()?;
    let mut session = initialized(dir.path())?;
    for name in ["a", "b"] {
        std::fs::write(dir.path().join(name), name)?;
    }
    let plan = session.build_plan(
        vec![
            request(&dir.path().join("a")),
            request(&dir.path().join("b")),
        ],
        PlanOptions {
            quarantine_retention_days: 7,
            ..options()
        },
    )?;
    assert!(!dir.path().join(".file-tidy/quarantine").exists());
    assert!(plan.review_json()?.contains("retention_days"));
    assert!(plan.review_text()?.contains("保留 7 天"));
    let selected = session.select_operations(&plan, &[plan.preview().operations[1].id.clone()])?;
    let approved = confirm(&mut session, selected)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert!(dir.path().join("a").exists());
    assert!(!dir.path().join("b").exists());
    let items = session.quarantine_items(10, false)?;
    assert_eq!(items[0].expires_at - items[0].retained_at, 7 * 86400);
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn uses_source_grant_storage_and_requires_current_authorization_for_restore() -> TestResult {
    let state = fixture()?;
    let source = fixture()?;
    let mut session = initialized(state.path())?;
    let grant = session.grant(source.path(), true)?;
    std::fs::write(source.path().join("data"), b"data")?;
    let ids = quarantine(&mut session, &[source.path().join("data")])?;
    assert!(!state.path().join(".file-tidy/quarantine").exists());
    assert!(source.path().join(".file-tidy/quarantine").exists());
    assert!(!source.path().join(".file-tidy/state.db").exists());
    session.revoke(&grant)?;
    assert!(session.build_restore_plan(&ids, None, options()).is_err());
    session.grant(source.path(), true)?;
    drop(session);
    let mut session = Session::open_writable(state.path())?;
    let plan = session.build_restore_plan(&ids, None, options())?;
    let approved = confirm(&mut session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(source.path().join("data"))?, b"data");
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn managed_objects_require_registered_restore_and_new_sensitive_confirmation() -> TestResult {
    let dir = fixture()?;
    let mut session = initialized(dir.path())?;
    std::fs::write(dir.path().join(".env"), b"fixture")?;
    let ids = quarantine(&mut session, &[dir.path().join(".env")])?;
    let payload = session.quarantine_items(10, false)?[0]
        .storage_path
        .to_path()?;
    for kind in [K::Move, K::Copy, K::Rename, K::Restore] {
        assert!(
            session
                .build_plan(
                    vec![OperationRequest {
                        kind,
                        source: payload.clone(),
                        destination: Some(dir.path().join("target"))
                    }],
                    options()
                )
                .is_err()
        );
    }
    let plan = session.build_restore_plan(&ids, Some(&dir.path().join("ordinary")), options())?;
    assert!(!plan.preview().sensitive_acknowledgements.is_empty());
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        ..Default::default()
    };
    assert!(session.confirm(plan, confirmation).is_err());
    let plan = session.build_restore_plan(&ids, None, options())?;
    let approved = confirm(&mut session, plan)?;
    std::fs::write(&payload, b"changed content size")?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert!(!dir.path().join(".env").exists());
    assert_eq!(std::fs::read(payload)?, b"changed content size");
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn unknown_managed_directories_and_replaced_owned_directories_are_rejected() -> TestResult {
    let state = fixture()?;
    let source = fixture()?;
    let mut session = initialized(state.path())?;
    session.grant(source.path(), true)?;
    std::fs::write(source.path().join("data"), b"data")?;
    std::fs::create_dir(source.path().join(".file-tidy"))?;
    assert!(
        session
            .build_plan(vec![request(&source.path().join("data"))], options())
            .is_err()
    );
    std::fs::write(state.path().join("data"), b"data")?;
    let ids = quarantine(&mut session, &[state.path().join("data")])?;
    let payload = session.quarantine_items(10, false)?[0]
        .storage_path
        .to_path()?;
    let op_dir = payload.parent().ok_or("parent")?;
    std::fs::rename(op_dir, op_dir.with_extension("old"))?;
    std::fs::create_dir(op_dir)?;
    std::fs::write(payload, b"unregistered")?;
    assert!(session.build_restore_plan(&ids, None, options()).is_err());
    assert!(!state.path().join("data").exists());
    Ok(())
}

#[test]
#[cfg(unix)]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn retains_links_permissions_and_external_targets_without_following_them() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = fixture()?;
    let outside = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/data"), b"linked")?;
    std::fs::set_permissions(
        root.join("tree/data"),
        std::fs::Permissions::from_mode(0o640),
    )?;
    std::fs::hard_link(root.join("tree/data"), root.join("tree/alias"))?;
    std::fs::write(outside.path().join("target"), b"external")?;
    symlink(outside.path(), root.join("tree/link"))?;
    symlink("missing", root.join("tree/dangling"))?;
    let ids = quarantine(&mut session, &[root.join("tree")])?;
    let plan = session.build_restore_plan(&ids, None, options())?;
    let approved = confirm(&mut session, plan)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        std::fs::metadata(root.join("tree/data"))?
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    assert_eq!(
        file_tidy_platform::inspect(&root.join("tree/data"))?.identity,
        file_tidy_platform::inspect(&root.join("tree/alias"))?.identity
    );
    assert_eq!(
        std::fs::read_link(root.join("tree/dangling"))?,
        PathBuf::from("missing")
    );
    assert_eq!(std::fs::read_link(root.join("tree/link"))?, outside.path());
    assert_eq!(std::fs::read(outside.path().join("target"))?, b"external");
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn item_registration_and_completion_are_one_transaction_when_the_journal_fails() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), b"original")?;
    std::fs::write(root.join("later"), b"later")?;
    let plan = session.build_plan(
        vec![request(&root.join("source")), request(&root.join("later"))],
        options(),
    )?;
    let approved = confirm(&mut session, plan)?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER fail_item BEFORE INSERT ON quarantine_items BEGIN SELECT RAISE(ABORT,'fixture item registration failure'); END;")?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some(), "{report:?}");
    assert_eq!(
        report.operations[0].status,
        file_tidy_core::execution::ExecutionStatus::NeedsRecovery
    );
    assert_eq!(
        report.operations[1].status,
        file_tidy_core::execution::ExecutionStatus::NotStarted
    );
    assert_eq!(std::fs::read(root.join("later"))?, b"later");
    assert!(!root.join("source").exists());
    assert!(session.quarantine_items(10, false)?.is_empty());
    let payload = report.operations[0]
        .destination
        .as_ref()
        .ok_or("destination")?
        .to_path()?;
    assert_eq!(std::fs::read(payload)?, b"original");
    let detail = session.batch_history(&report.batch_id)?;
    assert_eq!(detail.events.last().ok_or("event")?.phase, "intent");
    assert_eq!(
        session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
        file_tidy_core::recovery::RecoveryDisposition::RenameObserved
    );
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn restore_result_failure_preserves_original_item_state_and_inverse_audit() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), b"original")?;
    let ids = quarantine(&mut session, &[root.join("source")])?;
    let plan = session.build_restore_plan(&ids, None, options())?;
    let approved = confirm(&mut session, plan)?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER fail_restore BEFORE UPDATE OF state ON quarantine_items BEGIN SELECT RAISE(ABORT,'fixture restore registration failure'); END;")?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some(), "{report:?}");
    assert_eq!(std::fs::read(root.join("source"))?, b"original");
    assert_eq!(session.quarantine_items(10, false)?[0].state, "stored");
    let detail = session.batch_history(&report.batch_id)?;
    assert_eq!(
        detail.operations[0].inverse_of.as_deref(),
        Some(ids[0].as_str())
    );
    assert_eq!(detail.events.last().ok_or("event")?.phase, "intent");
    assert_eq!(
        session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
        file_tidy_core::recovery::RecoveryDisposition::RenameObserved
    );
    Ok(())
}
