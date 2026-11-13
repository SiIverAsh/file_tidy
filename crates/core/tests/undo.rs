use file_tidy_core::{
    CancellationToken,
    approval::Confirmation,
    authorization::{Id, PlanningError as E, Session},
    execution::ExecutionReport,
    plan::{OperationKind as K, OperationRequest, Plan, PlanOptions},
};
use std::path::{Path, PathBuf};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn setup() -> Result<(tempfile::TempDir, Session), Box<dyn std::error::Error>> {
    let directory = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?,
        None => tempfile::tempdir()?,
    };
    let mut session = Session::new()?;
    let grant = session.grant(directory.path(), false)?;
    let storage = session.storage_plan(&grant)?;
    let digest = storage.digest().to_owned();
    session.initialize_storage(storage, &digest)?;
    Ok((directory, session))
}
fn opts() -> PlanOptions {
    PlanOptions {
        include_hidden: true,
        ..Default::default()
    }
}
fn request(kind: K, source: &Path, target: Option<&Path>) -> OperationRequest {
    OperationRequest {
        kind,
        source: source.to_owned(),
        destination: target.map(Path::to_owned),
    }
}
fn execute(
    session: &mut Session,
    plan: Plan,
) -> Result<ExecutionReport, Box<dyn std::error::Error>> {
    let confirmation = Confirmation {
        digest: plan.digest().into(),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        ..Default::default()
    };
    let approved = session.confirm(plan, confirmation)?;
    Ok(session.execute_approved(approved, &CancellationToken::new())?)
}
fn operation(
    session: &mut Session,
    request: OperationRequest,
) -> Result<ExecutionReport, Box<dyn std::error::Error>> {
    let plan = session.build_plan(vec![request], opts())?;
    let report = execute(session, plan)?;
    assert!(report.completed(), "{report:?}");
    Ok(report)
}
fn undo(session: &mut Session, batch: &Id) -> Result<ExecutionReport, Box<dyn std::error::Error>> {
    let plan = session.build_undo_plan(batch, &[], opts())?;
    assert!(plan.review_text()?.contains("撤销操作"));
    let report = execute(session, plan)?;
    assert!(report.completed(), "{report:?}");
    Ok(report)
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn reverses_a_mixed_batch_with_conflicts_and_preserves_original_facts() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("source"), b"move")?;
    std::fs::write(root.join("copy-source"), b"copy")?;
    let plan = session.build_plan(
        vec![
            request(K::Move, &root.join("source"), Some(&root.join("moved"))),
            request(
                K::Copy,
                &root.join("copy-source"),
                Some(&root.join("copied")),
            ),
        ],
        opts(),
    )?;
    let original = execute(&mut session, plan)?;
    assert!(original.completed(), "{original:?}");
    let before = serde_json::to_value(session.batch_history(&original.batch_id)?)?;
    std::fs::write(root.join("source"), b"occupied")?;
    let inverse = session.build_undo_plan(&original.batch_id, &[], opts())?;
    assert_eq!(inverse.preview().operations[0].kind, K::UndoCopy);
    assert_eq!(inverse.preview().operations[1].kind, K::Move);
    let selected =
        session.select_operations(&inverse, &[inverse.preview().operations[0].id.clone()])?;
    let report = execute(&mut session, selected)?;
    assert!(report.completed(), "{report:?}");
    let remaining = session.build_undo_plan(&original.batch_id, &[], opts())?;
    assert_eq!(remaining.preview().operations.len(), 1);
    assert_eq!(remaining.preview().operations[0].kind, K::Move);
    let remaining_report = execute(&mut session, remaining)?;
    assert!(remaining_report.completed(), "{remaining_report:?}");
    assert_eq!(std::fs::read(root.join("source"))?, b"occupied");
    assert_eq!(std::fs::read(root.join("source (1)"))?, b"move");
    assert!(!root.join("moved").exists());
    assert!(!root.join("copied").exists());
    assert_eq!(std::fs::read(root.join("copy-source"))?, b"copy");
    let item = session.quarantine_items(10, false)?.remove(0);
    assert_eq!(std::fs::read(item.storage_path.to_path()?)?, b"copy");
    assert!(
        item.storage_path.to_path()?.starts_with(
            root.join(".file-tidy/quarantine")
                .join(report.batch_id.as_str())
        )
    );
    assert_eq!(
        serde_json::to_value(session.batch_history(&original.batch_id)?)?,
        before
    );
    assert!(matches!(
        session.build_undo_plan(&original.batch_id, &[], opts()),
        Err(E::AlreadyUndone)
    ));
    assert!(
        session
            .batch_history(&report.batch_id)?
            .operations
            .iter()
            .all(|op| op.inverse_of.is_some())
    );
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn undo_copy_verifies_bytes_even_when_length_and_mtime_are_unchanged() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("source"), b"original")?;
    let original = operation(
        &mut session,
        request(K::Copy, &root.join("source"), Some(&root.join("copy"))),
    )?;
    let modified = std::fs::metadata(root.join("copy"))?.modified()?;
    let before = file_tidy_platform::inspect(&root.join("copy"))?;
    std::fs::write(root.join("copy"), b"tampered")?;
    std::fs::File::options()
        .write(true)
        .open(root.join("copy"))?
        .set_times(std::fs::FileTimes::new().set_modified(modified))?;
    assert!(before.matches(&file_tidy_platform::inspect(&root.join("copy"))?));
    let plan = session.build_undo_plan(&original.batch_id, &[], opts())?;
    let report = execute(&mut session, plan)?;
    assert!(!report.completed());
    assert_eq!(std::fs::read(root.join("copy"))?, b"tampered");
    assert_eq!(std::fs::read(root.join("source"))?, b"original");
    assert!(session.quarantine_items(10, false)?.is_empty());
    let history = session.batch_history(&report.batch_id)?;
    assert_eq!(history.events.last().ok_or("event")?.step, "undo_verify");
    assert_eq!(
        session.recovery_report(Some(&report.batch_id), 10)?.items[0].disposition,
        file_tidy_core::recovery::RecoveryDisposition::NotCommitted
    );
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn enforces_dependencies_then_allows_reverse_order_undo_and_restore_of_the_copy() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("source"), b"data")?;
    let moved = operation(
        &mut session,
        request(K::Move, &root.join("source"), Some(&root.join("moved"))),
    )?;
    let copied = operation(
        &mut session,
        request(K::Copy, &root.join("moved"), Some(&root.join("copy"))),
    )?;
    assert!(matches!(
        session.build_undo_plan(&moved.batch_id, &[], opts()),
        Err(E::DependentOperation)
    ));
    let copy_undo = undo(&mut session, &copied.batch_id)?;
    assert!(!root.join("copy").exists());
    undo(&mut session, &moved.batch_id)?;
    assert_eq!(std::fs::read(root.join("source"))?, b"data");
    let plan = session.build_undo_plan(&copy_undo.batch_id, &[], opts())?;
    let report = execute(&mut session, plan)?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(root.join("copy"))?, b"data");
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn directory_undo_requires_the_complete_created_tree_and_sensitive_content_permission() -> TestResult
{
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::create_dir_all(root.join("tree/empty"))?;
    std::fs::write(root.join("tree/.env"), b"fixture-sensitive")?;
    let copied = operation(
        &mut session,
        request(K::Copy, &root.join("tree"), Some(&root.join("copy"))),
    )?;
    std::fs::rename(root.join("tree"), root.join("original-kept"))?;
    std::fs::write(root.join("copy/new"), b"new")?;
    assert!(
        session
            .build_undo_plan(&copied.batch_id, &[], opts())
            .is_err()
    );
    // Quarantine the new item through the normal reviewed operation, then undo
    // that operation so the dependency itself stays active and is diagnosed.
    let q = operation(
        &mut session,
        request(K::Quarantine, &root.join("copy/new"), None),
    )?;
    assert!(matches!(
        session.build_undo_plan(&copied.batch_id, &[], opts()),
        Err(E::DependentOperation)
    ));
    undo(&mut session, &q.batch_id)?;
    assert!(root.join("copy/new").exists());
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn undoing_quarantine_and_restore_keeps_each_retained_item_auditable() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::write(root.join("source"), b"data")?;
    let q = operation(
        &mut session,
        request(K::Quarantine, &root.join("source"), None),
    )?;
    let restored = undo(&mut session, &q.batch_id)?;
    assert_eq!(std::fs::read(root.join("source"))?, b"data");
    let retained = undo(&mut session, &restored.batch_id)?;
    assert!(!root.join("source").exists());
    let items = session.quarantine_items(10, false)?;
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|item| item.state == "restored"));
    assert!(items.iter().any(|item| item.state == "stored"));
    undo(&mut session, &retained.batch_id)?;
    assert_eq!(std::fs::read(root.join("source"))?, b"data");
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn copy_undo_preserves_sensitive_directory_without_access_to_the_original() -> TestResult {
    let (directory, mut session) = setup()?;
    let root = directory.path();
    std::fs::create_dir_all(root.join("tree/empty"))?;
    std::fs::write(root.join("tree/.env"), b"fixture-sensitive")?;
    let copied = operation(
        &mut session,
        request(K::Copy, &root.join("tree"), Some(&root.join("copy"))),
    )?;
    std::fs::rename(root.join("tree"), root.join("kept-original"))?;
    let plan = session.build_undo_plan(&copied.batch_id, &[], opts())?;
    assert!(
        plan.preview()
            .sensitive_acknowledgements
            .iter()
            .any(|key| key.ends_with(":content"))
    );
    let missing = Confirmation {
        digest: plan.digest().into(),
        ..Default::default()
    };
    assert!(session.confirm(plan, missing).is_err());
    let inverse = undo(&mut session, &copied.batch_id)?;
    assert!(!root.join("copy").exists());
    let item = session.quarantine_items(10, false)?.remove(0);
    assert_eq!(
        std::fs::read(item.storage_path.to_path()?.join(".env"))?,
        b"fixture-sensitive"
    );
    assert!(item.storage_path.to_path()?.join("empty").is_dir());
    let history = session.batch_history(&inverse.batch_id)?;
    assert!(!serde_json::to_string(&history)?.contains("fixture-sensitive"));
    Ok(())
}
