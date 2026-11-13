use file_tidy_core::{
    CancellationToken,
    approval::Confirmation,
    authorization::Session,
    execution::ExecutionStatus,
    plan::{OperationKind, OperationRequest, PlanOptions},
    recovery::RecoveryDisposition,
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
fn request(source: &Path, target: &Path) -> OperationRequest {
    OperationRequest {
        kind: OperationKind::Copy,
        source: source.into(),
        destination: Some(target.into()),
    }
}
fn approve(
    session: &mut Session,
    requests: Vec<OperationRequest>,
) -> Result<file_tidy_core::approval::ApprovedPlan, Box<dyn std::error::Error>> {
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
fn copies_private_verified_bytes_and_mtime_from_outside_grants() -> TestResult {
    let directory = fixture()?;
    let source_dir = fixture()?;
    let root = directory.path();
    let source = source_dir.path().join("source");
    let bytes = vec![137u8; 200_123];
    std::fs::write(&source, &bytes)?;
    let before = file_tidy_platform::inspect(&source)?;
    let mut session = initialized(root)?;
    let approved = approve(&mut session, vec![request(&source, &root.join("target"))])?;
    let temporary = approved.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("no destination")?
        .copy_temporary
        .as_ref()
        .ok_or("no temporary")?
        .to_path()?;
    assert!(!temporary.exists());
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(&source)?, bytes);
    assert_eq!(std::fs::read(root.join("target"))?, bytes);
    assert!(before.matches(&file_tidy_platform::inspect(&source)?));
    assert_eq!(
        file_tidy_platform::inspect(&root.join("target"))?.modified,
        before.modified
    );
    assert!(!temporary.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root.join("target"))?.permissions().mode() & 0o777,
            0o600
        );
    }
    let history = session.batch_history(&report.batch_id)?;
    assert_eq!(history.events.len(), 8);
    assert_eq!(
        history.operations[0]
            .after_fingerprint
            .as_ref()
            .ok_or("no fingerprint")?["blake3"],
        blake3::hash(&bytes).to_hex().as_str()
    );
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn multiple_copies_and_empty_file_share_one_destination_parent() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("a"), "first")?;
    std::fs::write(root.join("b"), b"")?;
    let approved = approve(
        &mut session,
        vec![
            request(&root.join("a"), &root.join("a-copy")),
            request(&root.join("b"), &root.join("b-copy")),
        ],
    )?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(root.join("a-copy"))?, b"first");
    assert_eq!(std::fs::metadata(root.join("b-copy"))?.len(), 0);
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn sensitive_copy_requires_each_content_acknowledgement_and_keeps_content_out_of_journal()
-> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    let secret = "fixture-secret-content-34983741";
    std::fs::write(root.join(".env"), secret)?;
    let plan = session.build_plan(
        vec![request(&root.join(".env"), &root.join("copy-env"))],
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    let digest = plan.digest().to_owned();
    assert!(
        session
            .confirm(
                plan,
                Confirmation {
                    digest,
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert!(!root.join("copy-env").exists());
    let approved = approve(
        &mut session,
        vec![request(&root.join(".env"), &root.join("copy-env"))],
    )?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read_to_string(root.join("copy-env"))?, secret);
    let history = serde_json::to_string(&session.batch_history(&report.batch_id)?)?;
    assert!(!history.contains(secret));
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn occupied_destination_rejects_copy_before_creation() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "source")?;
    let approved = approve(
        &mut session,
        vec![request(&root.join("source"), &root.join("target"))],
    )?;
    let temp = approved.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("no destination")?
        .copy_temporary
        .as_ref()
        .ok_or("no temp")?
        .to_path()?;
    std::fs::write(root.join("target"), "other")?;
    assert!(
        session
            .execute_approved(approved, &CancellationToken::new())
            .is_err()
    );
    assert!(!temp.exists());
    assert_eq!(std::fs::read(root.join("target"))?, b"other");
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn publication_result_log_failure_is_diagnosed_without_reading_or_deleting_the_copy() -> TestResult
{
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "source")?;
    let approved = approve(
        &mut session,
        vec![request(&root.join("source"), &root.join("target"))],
    )?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER reject_publish_result BEFORE INSERT ON operation_events WHEN NEW.step='copy_publish' AND NEW.phase='result' BEGIN SELECT RAISE(ABORT,'injected publication result failure'); END;")?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
    assert!(report.journal_error.is_some());
    assert_eq!(std::fs::read(root.join("target"))?, b"source");
    assert_eq!(std::fs::read(root.join("source"))?, b"source");
    let recovery = session.recovery_report(None, 10)?;
    assert_eq!(recovery.items.len(), 1);
    assert_eq!(
        recovery.items[0].disposition,
        RecoveryDisposition::CopyPublishedObserved
    );
    drop(session);
    let reader = Session::open(root)?;
    assert_eq!(
        reader.recovery_report(None, 10)?.items[0].disposition,
        RecoveryDisposition::CopyPublishedObserved
    );
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn publish_intent_failure_leaves_a_verified_staging_object_for_read_only_diagnosis() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "source")?;
    let approved = approve(
        &mut session,
        vec![request(&root.join("source"), &root.join("target"))],
    )?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER reject_publish_intent BEFORE INSERT ON operation_events WHEN NEW.step='copy_publish' AND NEW.phase='intent' BEGIN SELECT RAISE(ABORT,'injected publication intent failure'); END;")?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some());
    assert!(!root.join("target").exists());
    let temporary = report.operations[0]
        .temporary
        .as_ref()
        .ok_or("no temp")?
        .to_path()?;
    assert_eq!(std::fs::read(temporary)?, b"source");
    assert_eq!(
        session.recovery_report(None, 10)?.items[0].disposition,
        RecoveryDisposition::VerifiedCopyObserved
    );
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn failed_creation_result_never_attributes_an_unrecorded_temporary_to_the_tool() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "source")?;
    let approved = approve(
        &mut session,
        vec![request(&root.join("source"), &root.join("target"))],
    )?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch("CREATE TRIGGER reject_created BEFORE INSERT ON operation_events WHEN NEW.step='copy_create' AND NEW.phase='result' BEGIN SELECT RAISE(ABORT,'injected creation result failure'); END;")?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.journal_error.is_some());
    assert!(!root.join("target").exists());
    assert_eq!(
        session.recovery_report(None, 10)?.items[0].disposition,
        RecoveryDisposition::NeedsAttention
    );
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires independent FILE_TIDY_TEST_ROOT and distinct native volumes in CI"]
fn copies_between_distinct_windows_volumes_with_sensitive_source_permission() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let private_dirs = directories::BaseDirs::new().ok_or("private directory unavailable")?;
    let source_directory = tempfile::tempdir_in(private_dirs.cache_dir())?;
    let source = source_directory
        .path()
        .canonicalize()?
        .join("cross-volume-source");
    std::fs::write(&source, vec![53u8; 91_003])?;
    let source_volume = file_tidy_platform::inspect(&source)?
        .identity
        .ok_or("source identity unavailable")?
        .volume;
    let destination_volume = file_tidy_platform::inspect(root)?
        .identity
        .ok_or("destination identity unavailable")?
        .volume;
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert_ne!(
            source_volume, destination_volume,
            "CI needs distinct source and destination volumes"
        );
    } else if source_volume == destination_volume {
        return Ok(());
    }
    let mut session = initialized(root)?;
    let approved = approve(
        &mut session,
        vec![request(&source, &root.join("cross-volume-copy"))],
    )?;
    assert!(!approved.preview().sensitive_acknowledgements.is_empty());
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        std::fs::read(&source)?,
        std::fs::read(root.join("cross-volume-copy"))?
    );
    assert_ne!(
        file_tidy_platform::inspect(&source)?.identity,
        file_tidy_platform::inspect(&root.join("cross-volume-copy"))?.identity
    );
    Ok(())
}
