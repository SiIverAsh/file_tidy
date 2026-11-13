use file_tidy_core::CancellationToken;
use file_tidy_core::approval::Confirmation;
use file_tidy_core::authorization::{PlanningError, Session};
use file_tidy_core::plan::{OperationKind, OperationRequest, PlanOptions};
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
    let id = session.grant(root, false)?;
    let plan = session.storage_plan(&id)?;
    let digest = plan.digest().to_owned();
    session.initialize_storage(plan, &digest)?;
    Ok(session)
}
fn request(source: &Path, target: &Path) -> OperationRequest {
    OperationRequest {
        kind: OperationKind::Rename,
        source: source.into(),
        destination: Some(target.into()),
    }
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn spelling_change_previews_both_steps_and_preserves_complete_tree() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let mut session = initialized(root)?;
    let source = root.join("Example");
    let target = root.join("EXAMPLE");
    std::fs::create_dir(&source)?;
    std::fs::write(source.join("child"), b"data")?;
    let aliases = target.try_exists()?;
    let plan = session.build_plan(vec![request(&source, &target)], PlanOptions::default())?;
    let destination = plan.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("missing destination")?;
    assert_eq!(destination.path.to_path()?, target);
    assert_eq!(destination.spelling_temporary.is_some(), aliases);
    let temporary = destination
        .spelling_temporary
        .as_ref()
        .map(|path| path.to_path())
        .transpose()?;
    if let Some(path) = &temporary {
        assert!(!path.try_exists()?);
        assert!(
            plan.review_text()?
                .contains(&path.to_string_lossy().to_string())
        );
    }
    let confirmation = Confirmation {
        digest: plan.digest().to_owned(),
        ..Default::default()
    };
    let approved = session.confirm(plan, confirmation)?;
    let report = session.execute_approved(approved, &CancellationToken::new())?;
    assert!(report.completed(), "{report:?}");
    assert_eq!(std::fs::read(target.join("child"))?, b"data");
    let names = std::fs::read_dir(root)?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(names.iter().any(|name| name == "EXAMPLE"));
    assert!(!names.iter().any(|name| name == "Example"));
    if let Some(path) = &temporary {
        assert!(!path.try_exists()?);
    }
    let history = session.batch_history(&report.batch_id)?;
    assert_eq!(history.events.len(), if aliases { 4 } else { 2 });
    if aliases {
        assert_eq!(history.events[0].step, "rename_to_temporary");
        assert_eq!(history.events[2].step, "rename_from_temporary");
    }
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn real_hardlink_destination_is_a_conflict_not_a_spelling_alias() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let session = initialized(root)?;
    let source = root.join("source");
    let target = root.join("other-name");
    std::fs::write(&source, b"data")?;
    std::fs::hard_link(&source, &target)?;
    let plan = session.build_plan(vec![request(&source, &target)], PlanOptions::default())?;
    let destination = plan.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("missing destination")?;
    assert!(destination.spelling_temporary.is_none());
    assert!(destination.renamed_for_conflict);
    assert_eq!(destination.path.to_path()?, root.join("other-name (1)"));
    assert_eq!(std::fs::read(&source)?, b"data");
    assert_eq!(std::fs::read(&target)?, b"data");
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn occupied_reviewed_temporary_invalidates_the_plan() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let session = initialized(root)?;
    let source = root.join("Example");
    let target = root.join("EXAMPLE");
    std::fs::write(&source, b"data")?;
    let plan = session.build_plan(vec![request(&source, &target)], PlanOptions::default())?;
    let destination = plan.preview().operations[0]
        .destination
        .as_ref()
        .ok_or("missing destination")?;
    let occupied = destination
        .spelling_temporary
        .as_ref()
        .unwrap_or(&destination.path)
        .to_path()?;
    std::fs::write(&occupied, b"racing entry")?;
    assert!(session.validate_plan(&plan).is_err());
    assert_eq!(std::fs::read(&source)?, b"data");
    assert_eq!(std::fs::read(&occupied)?, b"racing entry");
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn spelling_alias_requires_complete_bounded_parent_enumeration() -> TestResult {
    let directory = fixture()?;
    let root = directory.path();
    let session = initialized(root)?;
    let source = root.join("Example");
    let target = root.join("EXAMPLE");
    std::fs::write(&source, b"data")?;
    std::fs::write(root.join("sibling"), b"data")?;
    let aliases = target.try_exists()?;
    let result = session.build_plan(
        vec![request(&source, &target)],
        PlanOptions {
            max_entries: 1,
            ..Default::default()
        },
    );
    if aliases {
        assert!(matches!(result, Err(PlanningError::IncompleteManifest)));
    } else {
        assert!(result.is_ok());
    }
    Ok(())
}
