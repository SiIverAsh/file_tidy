use std::path::{Path, PathBuf};

use file_tidy_core::approval::Confirmation;
use file_tidy_core::authorization::{PlanningError, Session};
use file_tidy_core::plan::{OperationKind, OperationRequest, PlanOptions};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => Ok(tempfile::tempdir_in(PathBuf::from(root).canonicalize()?)?),
        None => Ok(tempfile::tempdir()?),
    }
}
fn request(kind: OperationKind, source: &Path, destination: Option<&Path>) -> OperationRequest {
    OperationRequest {
        kind,
        source: source.into(),
        destination: destination.map(Path::to_path_buf),
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

#[test]
fn protected_roots_and_parent_traversal_are_rejected() -> TestResult {
    let mut session = Session::new()?;
    #[cfg(unix)]
    assert!(matches!(
        session.grant(Path::new("/usr"), false),
        Err(PlanningError::ProtectedZone)
    ));
    assert!(matches!(
        session.grant(Path::new("somewhere/../elsewhere"), false),
        Err(PlanningError::InvalidPath)
    ));
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires FILE_TIDY_TEST_ROOT outside protected, sensitive and project trees"
)]
fn dry_run_is_read_only_and_keeps_compound_extensions() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    std::fs::write(root.join("source.tar.gz"), "payload")?;
    std::fs::write(root.join("result.tar.gz"), "existing")?;
    let before: Vec<_> = std::fs::read_dir(root)?.collect::<Result<_, _>>()?;
    let mut session = Session::new()?;
    session.grant(root, false)?;
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("source.tar.gz"),
            Some(&root.join("result.tar.gz")),
        )],
        PlanOptions::default(),
    )?;
    let destination = plan.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("missing destination")?;
    assert_eq!(destination.path.to_path()?, root.join("result (1).tar.gz"));
    assert!(destination.renamed_for_conflict);
    assert_eq!(plan.preview().files_and_links, 1);
    assert_eq!(std::fs::read(root.join("source.tar.gz"))?, b"payload");
    assert_eq!(std::fs::read(root.join("result.tar.gz"))?, b"existing");
    assert_eq!(std::fs::read_dir(root)?.count(), before.len());
    assert!(!root.join(".file-tidy").exists());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn initialization_requires_exact_review_and_persists_only_durable_grants() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = Session::new()?;
    let id = session.grant(root, false)?;
    let plan = session.storage_plan(&id)?;
    assert!(matches!(
        session.initialize_storage(plan, "wrong"),
        Err(PlanningError::ConfirmationRequired)
    ));
    assert!(!root.join(".file-tidy").exists());
    let plan = session.storage_plan(&id)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    let other = fixture()?;
    session.grant(other.path(), false)?;
    assert_eq!(session.grants().count(), 2);
    drop(session);
    let loaded = Session::open(root)?;
    assert_eq!(loaded.grants().count(), 1);
    assert!(
        loaded
            .grants()
            .next()
            .ok_or("missing grant")?
            .is_persistent()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(root.join(".file-tidy"))?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join(".file-tidy/state.db"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn stale_plan_cannot_be_confirmed_after_source_or_directory_changes() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let session = initialized(root)?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/a"), "old")?;
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("tree"),
            Some(&root.join("target")),
        )],
        PlanOptions::default(),
    )?;
    assert_eq!(plan.preview().operations[0].manifest.len(), 2);
    std::fs::write(root.join("tree/b"), "new")?;
    assert!(session.validate_plan(&plan).is_err());
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("tree/a"),
            Some(&root.join("target-a")),
        )],
        PlanOptions::default(),
    )?;
    std::fs::write(root.join("tree/a"), "changed")?;
    assert!(session.validate_plan(&plan).is_err());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn hidden_children_and_incomplete_manifests_are_rejected() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = Session::new()?;
    session.grant(root, false)?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/.hidden"), "payload")?;
    let make_request = || {
        vec![request(
            OperationKind::Move,
            &root.join("tree"),
            Some(&root.join("target")),
        )]
    };
    assert!(matches!(
        session.build_plan(make_request(), PlanOptions::default()),
        Err(PlanningError::HiddenEntry)
    ));
    assert!(matches!(
        session.build_plan(
            make_request(),
            PlanOptions {
                include_hidden: true,
                max_entries: 1,
                ..PlanOptions::default()
            }
        ),
        Err(PlanningError::IncompleteManifest)
    ));
    let plan = session.build_plan(
        make_request(),
        PlanOptions {
            include_hidden: true,
            ..PlanOptions::default()
        },
    )?;
    assert_eq!(plan.preview().operations[0].manifest.len(), 2);
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn grant_revocation_invalidates_plan_and_persists() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join("source"), "payload")?;
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("source"),
            Some(&root.join("target")),
        )],
        PlanOptions::default(),
    )?;
    let id = session.grants().next().ok_or("missing grant")?.id().clone();
    session.revoke(&id)?;
    assert!(session.validate_plan(&plan).is_err());
    drop(session);
    assert!(
        Session::open(root)?
            .grants()
            .next()
            .ok_or("missing grant")?
            .is_revoked()
    );
    assert!(Session::open_writable(root).is_err());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn destination_races_and_overlapping_sources_are_rejected() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = Session::new()?;
    session.grant(root, false)?;
    std::fs::create_dir(root.join("tree"))?;
    std::fs::write(root.join("tree/a"), "payload")?;
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("tree/a"),
            Some(&root.join("target")),
        )],
        PlanOptions::default(),
    )?;
    std::fs::write(root.join("target"), "concurrent")?;
    assert!(session.validate_plan(&plan).is_err());
    assert!(matches!(
        session.build_plan(
            vec![
                request(
                    OperationKind::Move,
                    &root.join("tree"),
                    Some(&root.join("other"))
                ),
                request(
                    OperationKind::Copy,
                    &root.join("tree/a"),
                    Some(&root.join("copy"))
                )
            ],
            PlanOptions::default()
        ),
        Err(PlanningError::OverlappingOperations)
    ));
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn selection_changes_digest_and_sensitive_items_require_separate_acknowledgements() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::write(root.join(".env"), "secret")?;
    std::fs::write(root.join("ordinary"), "payload")?;
    let plan = session.build_plan(
        vec![
            request(
                OperationKind::Copy,
                &root.join(".env"),
                Some(&root.join("copy-env")),
            ),
            request(
                OperationKind::Move,
                &root.join("ordinary"),
                Some(&root.join("renamed")),
            ),
        ],
        PlanOptions {
            include_hidden: true,
            ..PlanOptions::default()
        },
    )?;
    assert_eq!(plan.preview().sensitive_acknowledgements.len(), 1);
    let selected = session.select_operations(&plan, &[plan.preview().operations[1].id.clone()])?;
    assert_ne!(plan.digest(), selected.digest());
    let digest = plan.digest().to_owned();
    assert!(matches!(
        session.confirm(
            plan,
            Confirmation {
                digest,
                ..Confirmation::default()
            }
        ),
        Err(PlanningError::ConfirmationRequired)
    ));
    let digest = selected.digest().to_owned();
    let approved = session.confirm(
        selected,
        Confirmation {
            digest,
            ..Confirmation::default()
        },
    )?;
    session.validate_approval(&approved)?;
    assert!(root.join("ordinary").exists());
    assert!(!root.join("renamed").exists());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn private_state_lock_excludes_concurrent_writers() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let session = initialized(root)?;
    assert!(Session::open(root).is_err());
    assert!(Session::open_writable(root).is_err());
    drop(session);
    let reader = Session::open(root)?;
    assert!(Session::open_writable(root).is_err());
    drop(reader);
    let _writer = Session::open_writable(root)?;
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn read_only_open_can_preview_then_upgrade_for_confirmation() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    drop(initialized(root)?);
    std::fs::write(root.join("source"), "payload")?;
    let mut reader = Session::open(root)?;
    let other = fixture()?;
    reader.grant(other.path(), false)?;
    let plan = reader.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("source"),
            Some(&root.join("destination")),
        )],
        PlanOptions::default(),
    )?;
    let digest = plan.digest().to_owned();
    reader.enable_persistence()?;
    reader.confirm(
        plan,
        Confirmation {
            digest,
            ..Confirmation::default()
        },
    )?;
    assert!(root.join("source").exists());
    assert!(!root.join("destination").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn links_are_not_followed_and_non_private_storage_is_rejected() -> TestResult {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = fixture()?;
    let root = dir.path();
    std::fs::create_dir(root.join("tree"))?;
    symlink("/usr", root.join("tree/link"))?;
    let mut session = initialized(root)?;
    assert!(session.grant(&root.join("tree/link"), false).is_err());
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("tree"),
            Some(&root.join("target")),
        )],
        PlanOptions::default(),
    )?;
    assert_eq!(plan.preview().operations[0].manifest.len(), 2);
    assert!(
        plan.preview().operations[0]
            .manifest
            .iter()
            .any(|entry| entry.kind == "Symlink")
    );
    drop(session);
    std::fs::set_permissions(
        root.join(".file-tidy"),
        std::fs::Permissions::from_mode(0o755),
    )?;
    assert!(Session::open(root).is_err());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn empty_directories_are_counted_and_permanent_confirmation_is_bound() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let mut session = initialized(root)?;
    std::fs::create_dir(root.join("empty"))?;
    let options = PlanOptions {
        permanent_item_count: 0,
        ..PlanOptions::default()
    };
    let plan = session.build_plan(
        vec![request(
            OperationKind::PermanentDelete,
            &root.join("empty"),
            None,
        )],
        options.clone(),
    )?;
    assert_eq!(plan.preview().empty_directories, 1);
    assert_eq!(plan.preview().confirmation_count, 1);
    assert!(plan.preview().requires_count_confirmation);
    let digest = plan.digest().to_owned();
    assert!(matches!(
        session.confirm(
            plan,
            Confirmation {
                digest,
                item_count: Some(1),
                ..Confirmation::default()
            }
        ),
        Err(PlanningError::ConfirmationRequired)
    ));
    let plan = session.build_plan(
        vec![request(
            OperationKind::PermanentDelete,
            &root.join("empty"),
            None,
        )],
        options,
    )?;
    let challenge = plan
        .preview()
        .permanent_challenge
        .as_ref()
        .ok_or("missing challenge")?;
    let input = Confirmation {
        digest: plan.digest().to_owned(),
        item_count: Some(1),
        permanent_phrase: Some(format!("PERMANENT 1 {challenge}")),
        ..Confirmation::default()
    };
    session.confirm(plan, input)?;
    assert!(root.join("empty").is_dir());
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn grant_root_replacement_is_rejected_but_stale_grants_can_be_revoked() -> TestResult {
    let dir = fixture()?;
    let mut session = initialized(dir.path())?;
    let other = fixture()?;
    let source_root = other.path().join("authorized");
    std::fs::create_dir(&source_root)?;
    let reviewed = Session::preview_grant(&source_root)?;
    let id = session.grant_reviewed(&reviewed, true)?;
    std::fs::rename(&source_root, other.path().join("old"))?;
    std::fs::create_dir(&source_root)?;
    std::fs::write(source_root.join("new"), "payload")?;
    assert!(
        session
            .build_plan(
                vec![request(
                    OperationKind::Move,
                    &source_root.join("new"),
                    Some(&dir.path().join("new"))
                )],
                PlanOptions::default()
            )
            .is_err()
    );
    drop(session);
    let mut loaded = Session::open_writable(dir.path())?;
    loaded.revoke(&id)?;
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn unrelated_sessions_and_expired_plans_cannot_confirm() -> TestResult {
    let dir = fixture()?;
    let root = dir.path();
    let session = initialized(root)?;
    std::fs::write(root.join("source"), "payload")?;
    let plan = session.build_plan(
        vec![request(
            OperationKind::Move,
            &root.join("source"),
            Some(&root.join("target")),
        )],
        PlanOptions {
            expires_after_seconds: 1,
            ..PlanOptions::default()
        },
    )?;
    assert!(Session::new()?.validate_plan(&plan).is_err());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(matches!(
        session.validate_plan(&plan),
        Err(PlanningError::InvalidPlan)
    ));
    Ok(())
}
