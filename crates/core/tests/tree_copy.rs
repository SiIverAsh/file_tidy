use file_tidy_core::{
    CancellationToken,
    approval::Confirmation,
    authorization::Session,
    execution::ExecutionStatus,
    plan::{OperationKind, OperationRequest, PlanOptions},
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
fn initialized(root: &Path) -> Result<Session, Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    let grant = session.grant(root, false)?;
    let plan = session.storage_plan(&grant)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    Ok(session)
}
fn approve(
    session: &mut Session,
    source: &Path,
    target: &Path,
) -> Result<file_tidy_core::approval::ApprovedPlan, Box<dyn std::error::Error>> {
    let plan = session.build_plan(
        vec![OperationRequest {
            kind: OperationKind::Copy,
            source: source.into(),
            destination: Some(target.into()),
        }],
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
fn tree(root: &Path) -> TestResult {
    std::fs::create_dir_all(root.join("nested/empty"))?;
    std::fs::write(root.join("nested/data"), vec![71u8; 140_137])?;
    std::fs::write(root.join(".env"), "fixture-sensitive-data")?;
    std::fs::write(root.join("zero"), b"")?;
    Ok(())
}
fn request(source: &Path, target: &Path) -> OperationRequest {
    OperationRequest {
        kind: OperationKind::Copy,
        source: source.into(),
        destination: Some(target.into()),
    }
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn publishes_a_complete_private_tree_with_empty_hidden_and_sensitive_entries() -> TestResult {
    let dir = fixture()?;
    let source_dir = fixture()?;
    let root = dir.path();
    let source = source_dir.path().join("source");
    tree(&source)?;
    let mut session = initialized(root)?;
    let before = file_tidy_platform::inspect(&source)?;
    let approved = approve(&mut session, &source, &root.join("target"))?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        std::fs::read(root.join("target/nested/data"))?,
        vec![71u8; 140_137]
    );
    assert_eq!(
        std::fs::read(root.join("target/.env"))?,
        b"fixture-sensitive-data"
    );
    assert!(root.join("target/nested/empty").is_dir());
    assert_eq!(std::fs::metadata(root.join("target/zero"))?.len(), 0);
    assert_eq!(
        file_tidy_platform::inspect(&root.join("target"))?.modified,
        before.modified
    );
    assert!(before.matches(&file_tidy_platform::inspect(&source)?));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root.join("target"))?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join("target/.env"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let history = serde_json::to_string(&session.batch_history(&report.batch_id)?)?;
    assert!(!history.contains("fixture-sensitive-data"));
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn copies_an_empty_directory_and_multiple_siblings_in_one_batch() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(root.join("empty"))?;
    tree(&root.join("tree"))?;
    std::fs::write(root.join("file"), "file")?;
    let plan = session.build_plan(
        vec![
            request(&root.join("empty"), &root.join("empty-copy")),
            request(&root.join("tree"), &root.join("tree-copy")),
            request(&root.join("file"), &root.join("file-copy")),
        ],
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    let input = Confirmation {
        digest: plan.digest().to_owned(),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        ..Default::default()
    };
    let approved = session.confirm(plan, input)?;
    let result = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(result.completed(), "{result:?}");
    assert_eq!(std::fs::read_dir(root.join("empty-copy"))?.count(), 0);
    assert!(root.join("tree-copy/nested/empty").is_dir());
    assert_eq!(std::fs::read(root.join("file-copy"))?, b"file");
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn reconstructs_relative_dangling_and_directory_links_without_following_them() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    tree(&root.join("source"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink("nested/data", root.join("source/link"))?;
        symlink("nested", root.join("source/dir-link"))?;
        symlink("absent", root.join("source/dangling"))?;
        symlink("/usr", root.join("source/protected-link"))?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        symlink_file("nested\\data", root.join("source/link"))?;
        symlink_dir("nested", root.join("source/dir-link"))?;
        symlink_file("absent", root.join("source/dangling"))?;
    }
    let approved = approve(&mut session, &root.join("source"), &root.join("target"))?;
    let result = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(result.completed(), "{result:?}");
    for name in ["link", "dir-link", "dangling"] {
        assert_eq!(
            std::fs::read_link(root.join("target").join(name))?,
            std::fs::read_link(root.join("source").join(name))?
        );
        assert_eq!(
            file_tidy_platform::inspect(&root.join("target").join(name))?.modified,
            file_tidy_platform::inspect(&root.join("source").join(name))?.modified
        );
        assert_eq!(
            file_tidy_platform::symlink_directory(&root.join("target").join(name))?,
            file_tidy_platform::symlink_directory(&root.join("source").join(name))?
        );
    }
    assert_eq!(
        std::fs::read(root.join("target/nested/data"))?,
        vec![71u8; 140_137]
    );
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn creation_result_failure_leaves_unattributed_tree_and_preserves_the_source() -> TestResult {
    failure("tree_create", "result", D::NeedsAttention)
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn publication_intent_failure_leaves_verified_tree_for_read_only_inspection() -> TestResult {
    failure("tree_publish", "intent", D::VerifiedCopyObserved)
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn publication_result_failure_is_observed_without_repeating_the_copy() -> TestResult {
    failure("tree_publish", "result", D::CopyPublishedObserved)
}
fn failure(step: &str, phase: &str, expected: D) -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    tree(&root.join("source"))?;
    let approved = approve(&mut session, &root.join("source"), &root.join("target"))?;
    let db = rusqlite::Connection::open(root.join(".file-tidy/state.db"))?;
    db.execute_batch(&format!("CREATE TRIGGER reject_step BEFORE INSERT ON operation_events WHEN NEW.step='{step}' AND NEW.phase='{phase}' BEGIN SELECT RAISE(ABORT,'injected tree fault'); END;"))?;
    drop(db);
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(!report.completed());
    assert_eq!(report.operations[0].status, ExecutionStatus::NeedsRecovery);
    assert!(report.journal_error.is_some());
    assert_eq!(
        std::fs::read(root.join("source/nested/data"))?,
        vec![71u8; 140_137]
    );
    let items = session.recovery_report(None, 10)?.items;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].disposition, expected, "{items:?}");
    drop(session);
    let reader = Session::open(root)?;
    assert_eq!(
        reader.recovery_report(None, 10)?.items[0].disposition,
        expected
    );
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "requires independent FILE_TIDY_TEST_ROOT and distinct native volumes in CI"]
fn copies_a_complete_directory_between_distinct_windows_volumes() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let private = directories::BaseDirs::new().ok_or("private directory unavailable")?;
    let source_dir = tempfile::tempdir_in(private.cache_dir())?;
    let source = source_dir.path().canonicalize()?.join("source");
    tree(&source)?;
    let source_volume = file_tidy_platform::inspect(&source)?
        .identity
        .ok_or("source volume unavailable")?
        .volume;
    let target_volume = file_tidy_platform::inspect(root)?
        .identity
        .ok_or("target volume unavailable")?
        .volume;
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        assert_ne!(source_volume, target_volume, "CI needs distinct volumes");
    } else if source_volume == target_volume {
        return Ok(());
    }
    let mut session = initialized(root)?;
    let approved = approve(&mut session, &source, &root.join("target"))?;
    assert!(!approved.preview().sensitive_acknowledgements.is_empty());
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(
        std::fs::read(root.join("target/nested/data"))?,
        std::fs::read(source.join("nested/data"))?
    );
    assert!(root.join("target/nested/empty").is_dir());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn sensitive_destination_children_require_their_own_write_scopes() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    tree(&root.join("source"))?;
    let make = |target: &str| request(&root.join("source"), &root.join(target));
    let plan = session.build_plan(
        vec![make("target")],
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    let keys = plan.preview().sensitive_acknowledgements.clone();
    assert_eq!(
        keys.iter().filter(|key| key.ends_with(":content")).count(),
        1
    );
    assert_eq!(keys.iter().filter(|key| key.ends_with(":write")).count(), 1);
    let write = keys
        .iter()
        .find(|key| key.ends_with(":write"))
        .ok_or("write scope missing")?;
    assert!(plan.acknowledgement_description(write)?.contains("target"));
    let input = Confirmation {
        digest: plan.digest().to_owned(),
        sensitive_acknowledgements: keys
            .into_iter()
            .filter(|key| key.ends_with(":content"))
            .collect(),
        ..Default::default()
    };
    assert!(session.confirm(plan, input).is_err());
    assert!(!root.join("target").exists());
    let plan = session.build_plan(
        vec![make(".aws")],
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    assert_eq!(
        plan.preview()
            .sensitive_acknowledgements
            .iter()
            .filter(|key| key.ends_with(":write"))
            .count(),
        plan.preview().operations[0].manifest.len()
    );
    for key in &plan.preview().sensitive_acknowledgements {
        assert!(!plan.acknowledgement_description(key)?.is_empty());
    }
    let input = Confirmation {
        digest: plan.digest().to_owned(),
        sensitive_acknowledgements: plan.preview().sensitive_acknowledgements.clone(),
        ..Default::default()
    };
    let approved = session.confirm(plan, input)?;
    let result = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(result.completed(), "{result:?}");
    Ok(())
}
#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn copying_an_empty_sensitive_directory_does_not_request_content_permission() -> TestResult {
    let dir = fixture()?;
    let source = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(source.path().join(".aws"))?;
    let plan = session.build_plan(
        vec![request(
            &source.path().join(".aws"),
            &root.join("empty-copy"),
        )],
        PlanOptions {
            include_hidden: true,
            ..Default::default()
        },
    )?;
    assert!(plan.preview().sensitive_acknowledgements.is_empty());
    let input = Confirmation {
        digest: plan.digest().to_owned(),
        ..Default::default()
    };
    let approved = session.confirm(plan, input)?;
    let result = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(result.completed(), "{result:?}");
    assert!(root.join("empty-copy").is_dir());
    Ok(())
}
