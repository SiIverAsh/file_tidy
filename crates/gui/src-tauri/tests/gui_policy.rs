use std::path::PathBuf;
use std::sync::atomic::Ordering;

use file_tidy_core::authorization::Session;
use file_tidy_core::plan::{OperationKind, OperationRequest, PlanOptions};
use file_tidy_gui::commands::{
    StartScanRequest, build_plan_from_selection_inner, confirm_and_execute_inner,
    get_treemap_nodes_inner, query_scan_entries_inner, request_permanent_challenge_inner,
    start_scan_inner,
};
use file_tidy_gui::dto::{
    BuildPlanRequest, ConfirmAndExecuteInput, PlanActionKindDto, QueryScanEntriesRequest,
    ScanFilter, ScanTab, SelectionSpec, SortField, to_plan_preview_dto,
};
use file_tidy_gui::error::GuiError;
use file_tidy_gui::state::{AppState, PERMANENT_CHALLENGE_TTL_SECS, generate_challenge_code};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn stale_scan_generation_is_rejected() -> TestResult {
    let state = AppState::new()?;
    let err = state
        .snapshot_scan("999")
        .err()
        .ok_or("expected stale generation error")?;
    assert!(matches!(err, GuiError::StaleScanGeneration { .. }));
    Ok(())
}

#[test]
fn permanent_challenge_ttl_and_code_format() -> TestResult {
    assert_eq!(PERMANENT_CHALLENGE_TTL_SECS, 180);
    let c1 = generate_challenge_code()?;
    let c2 = generate_challenge_code()?;
    assert_eq!(c1.len(), 12);
    assert!(c1.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_ne!(c1, c2);
    Ok(())
}

#[test]
fn tauri_csp_forbids_inline_styles_and_unsafe_directives() -> TestResult {
    let conf_str = include_str!("../tauri.conf.json");
    let conf: serde_json::Value = serde_json::from_str(conf_str)?;
    let csp = conf["app"]["security"]["csp"]
        .as_str()
        .ok_or("csp string missing in tauri.conf.json")?;
    assert!(csp.contains("style-src 'self'"));
    assert!(csp.contains("style-src-attr 'none'"));
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("unsafe-eval"));
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn b_zone_copy_out_exposes_content_ack_while_b_write_is_blocked() -> TestResult {
    let tmp_root = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => PathBuf::from(root),
        None => std::env::temp_dir(),
    };
    let base_raw = tmp_root
        .join("file-tidy-gui-test")
        .join(format!("run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base_raw);
    std::fs::create_dir_all(&base_raw)?;
    let base = std::fs::canonicalize(&base_raw)?;
    let src_dir = base.join("src");
    let dst_dir = base.join("dst");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::create_dir_all(&dst_dir)?;

    let secret = src_dir.join(".env");
    std::fs::write(&secret, b"SECRET=1")?;
    let public = src_dir.join("public.txt");
    std::fs::write(&public, b"ordinary file")?;

    let mut session = Session::new()?;
    session.grant(&dst_dir, false)?;
    session.grant(&src_dir, false)?;

    // 1) Copy out from B -> non-B C: exposes :content ack and zero blocked_b_write_reasons
    let copy_plan = session.build_plan(
        vec![OperationRequest {
            kind: OperationKind::Copy,
            source: secret.clone(),
            destination: Some(dst_dir.join("exported.txt")),
        }],
        PlanOptions {
            include_hidden: true,
            ..PlanOptions::default()
        },
    )?;
    let copy_dto = to_plan_preview_dto(&copy_plan, &session);
    assert!(copy_dto.blocked_b_write_reasons.is_empty());
    assert_eq!(copy_dto.sensitive_acknowledgements.len(), 1);
    assert_eq!(
        copy_dto.sensitive_acknowledgements[0].kind,
        "copy_out_content"
    );

    // 2) Move touching B: core allows inside C with :write, GUI policy MUST block it
    let move_plan = session.build_plan(
        vec![OperationRequest {
            kind: OperationKind::Move,
            source: secret,
            destination: Some(dst_dir.join(".env-moved")),
        }],
        PlanOptions {
            include_hidden: true,
            ..PlanOptions::default()
        },
    )?;
    let move_dto = to_plan_preview_dto(&move_plan, &session);
    assert!(
        !move_dto.blocked_b_write_reasons.is_empty(),
        "B-zone write must be blocked in GUI policy"
    );

    // 3) An ordinary source still cannot be copied to a new sensitive target name.
    let sensitive_target = dst_dir.join("credentials.json");
    assert!(!sensitive_target.exists());
    let sensitive_target_plan = session.build_plan(
        vec![OperationRequest {
            kind: OperationKind::Copy,
            source: public,
            destination: Some(sensitive_target),
        }],
        PlanOptions::default(),
    )?;
    let sensitive_target_dto = to_plan_preview_dto(&sensitive_target_plan, &session);
    assert!(
        !sensitive_target_dto.blocked_b_write_reasons.is_empty(),
        "a missing sensitive destination must remain blocked"
    );
    assert!(
        sensitive_target_dto.operations[0]
            .destination_policy
            .as_ref()
            .is_some_and(|policy| policy.sensitive)
    );

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}

#[test]
fn app_manifest_and_capabilities_stay_in_sync() -> TestResult {
    let build_rs = include_str!("../build.rs");
    let cap_json = include_str!("../capabilities/default.json");
    let cap: serde_json::Value = serde_json::from_str(cap_json)?;
    let perms = cap["permissions"]
        .as_array()
        .ok_or("permissions must be an array")?;

    for line in build_rs.lines() {
        let trimmed = line.trim();
        if let Some(cmd) = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix("\","))
        {
            let expected_perm = format!("allow-{}", cmd.replace('_', "-"));
            assert!(
                perms.iter().any(|p| p.as_str() == Some(&expected_perm)),
                "missing capability permission {expected_perm}"
            );
        }
    }
    Ok(())
}

#[test]
fn confirm_and_execute_rejects_write_acknowledgements_directly() -> TestResult {
    let state = AppState::new()?;
    let input = ConfirmAndExecuteInput {
        plan_id: "01".to_owned(),
        plan_digest: "deadbeef".to_owned(),
        item_count: None,
        sensitive_acknowledgements: vec!["grant-1:/secret:write".to_owned()],
        permanent_challenge_input: None,
    };
    let res = tauri::async_runtime::block_on(confirm_and_execute_inner(&state, input, None));
    assert!(matches!(res, Err(GuiError::Rejected(_))));
    assert!(
        !state.exec_in_flight.load(Ordering::SeqCst),
        "exec_in_flight slot guard must reset on rejection"
    );
    Ok(())
}

#[test]
fn query_and_treemap_reject_stale_scan_generation() -> TestResult {
    let state = AppState::new()?;
    let filter = ScanFilter {
        tab: ScanTab::Browse,
        parent_entry_id: None,
        search_text: String::new(),
        zone_filter: "all".to_owned(),
        category_filter: String::new(),
        hide_hidden: false,
        duplicate_group_id: None,
        skip_reason_filter: String::new(),
    };
    let q_res = tauri::async_runtime::block_on(query_scan_entries_inner(
        &state,
        QueryScanEntriesRequest {
            scan_generation: "42".to_owned(),
            filter,
            sort: SortField::SizeDesc,
            offset: 0,
            limit: 50,
            tree_roots_only: false,
        },
    ));
    assert!(matches!(q_res, Err(GuiError::StaleScanGeneration { .. })));

    let t_res = tauri::async_runtime::block_on(get_treemap_nodes_inner(
        &state,
        "42".to_owned(),
        None,
        Some(40),
    ));
    assert!(matches!(t_res, Err(GuiError::StaleScanGeneration { .. })));
    Ok(())
}

#[test]
fn tree_queries_page_roots_and_expand_children_without_changing_flat_queries() -> TestResult {
    let base_raw = std::env::current_dir()?
        .join("target")
        .join("tree-query-fixtures")
        .join(format!(
            "run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
    let nested_raw = base_raw.join("alpha").join("nested");
    std::fs::create_dir_all(&nested_raw)?;
    std::fs::create_dir_all(base_raw.join("beta"))?;
    std::fs::write(nested_raw.join("nested.txt"), b"nested")?;
    std::fs::write(base_raw.join("alpha").join("direct.txt"), b"direct")?;
    std::fs::write(base_raw.join("beta").join("other.txt"), b"other")?;
    let base = std::fs::canonicalize(&base_raw)?;
    let state = AppState::new()?;
    *state.pending_roots.lock().map_err(|_| "lock poisoned")? = vec![
        base.join("alpha"),
        base.join("alpha").join("nested"),
        base.join("beta"),
    ];
    let summary = tauri::async_runtime::block_on(start_scan_inner(
        &state,
        StartScanRequest {
            all_volumes: false,
            metadata_only: true,
            no_duplicates: true,
            stale_days: 30,
            max_entries: 100,
        },
        None,
    ))?;
    let request_json = serde_json::json!({
        "scan_generation": summary.scan_generation,
        "filter": {
            "tab": "browse",
            "parent_entry_id": null,
            "search_text": "",
            "zone_filter": "all",
            "category_filter": "all",
            "hide_hidden": false,
            "duplicate_group_id": null,
            "skip_reason_filter": ""
        },
        "sort": "name_asc",
        "offset": 0,
        "limit": 100
    });
    let flat_request: QueryScanEntriesRequest = serde_json::from_value(request_json.clone())?;
    assert!(!flat_request.tree_roots_only, "legacy requests remain flat");
    let flat = tauri::async_runtime::block_on(query_scan_entries_inner(&state, flat_request))?;
    assert_eq!(
        flat.total_count, 6,
        "all scanned entries stay in flat queries"
    );

    let mut root_request: QueryScanEntriesRequest = serde_json::from_value(request_json.clone())?;
    root_request.tree_roots_only = true;
    root_request.limit = 1;
    let first_page =
        tauri::async_runtime::block_on(query_scan_entries_inner(&state, root_request))?;
    assert_eq!(first_page.total_count, 2);
    assert_eq!(first_page.entries.len(), 1);
    assert_eq!(first_page.entries[0].name_display, "alpha");

    let mut second_request: QueryScanEntriesRequest = serde_json::from_value(request_json.clone())?;
    second_request.tree_roots_only = true;
    second_request.offset = 1;
    second_request.limit = 1;
    let second_page =
        tauri::async_runtime::block_on(query_scan_entries_inner(&state, second_request))?;
    assert_eq!(second_page.total_count, 2);
    assert_eq!(second_page.entries[0].name_display, "beta");

    let mut child_request: QueryScanEntriesRequest = serde_json::from_value(request_json)?;
    child_request.tree_roots_only = true;
    child_request.filter.parent_entry_id = Some(first_page.entries[0].id.clone());
    let children = tauri::async_runtime::block_on(query_scan_entries_inner(&state, child_request))?;
    assert_eq!(children.total_count, 2);
    assert_eq!(
        children
            .entries
            .iter()
            .map(|entry| entry.name_display.as_str())
            .collect::<Vec<_>>(),
        vec!["direct.txt", "nested"]
    );
    let treemap = tauri::async_runtime::block_on(get_treemap_nodes_inner(
        &state,
        summary.scan_generation,
        None,
        Some(40),
    ))?;
    let mut treemap_root_ids = treemap
        .nodes
        .iter()
        .filter_map(|node| node.entry_id.as_deref())
        .collect::<Vec<_>>();
    treemap_root_ids.sort_unstable();
    let mut query_root_ids = vec![
        first_page.entries[0].id.as_str(),
        second_page.entries[0].id.as_str(),
    ];
    query_root_ids.sort_unstable();
    assert_eq!(query_root_ids, treemap_root_ids);
    std::fs::remove_dir_all(base)?;
    Ok(())
}

#[test]
fn hidden_directory_descendants_are_excluded_from_flat_and_child_queries() -> TestResult {
    let base_raw = std::env::current_dir()?
        .join("target")
        .join("tree-query-fixtures")
        .join(format!("hidden-{}", generate_challenge_code()?));
    std::fs::create_dir_all(base_raw.join("hidden-folder").join("nested"))?;
    std::fs::write(base_raw.join("visible.txt"), b"visible")?;
    std::fs::write(base_raw.join("hidden-folder").join("direct.txt"), b"direct")?;
    std::fs::write(
        base_raw
            .join("hidden-folder")
            .join("nested")
            .join("report.txt"),
        b"nested",
    )?;
    let base = std::fs::canonicalize(base_raw)?;
    let state = AppState::new()?;
    *state.pending_roots.lock().map_err(|_| "lock poisoned")? = vec![base.clone()];
    let summary = tauri::async_runtime::block_on(start_scan_inner(
        &state,
        StartScanRequest {
            all_volumes: false,
            metadata_only: true,
            no_duplicates: true,
            stale_days: 30,
            max_entries: 100,
        },
        None,
    ))?;
    let (hidden_id, nested_id) = {
        let mut slot = state.scan.write().map_err(|_| "lock poisoned")?;
        let report = std::sync::Arc::make_mut(slot.report.as_mut().ok_or("scan missing")?);
        // Exercise the platform-independent metadata flag, including Windows and
        // macOS hidden attributes on directories whose names do not start with '.'.
        let hidden = report
            .entries
            .iter_mut()
            .find(|entry| entry.path == base.join("hidden-folder"))
            .ok_or("hidden directory missing")?;
        hidden.hidden = true;
        let hidden_id = hidden.id.to_string();
        let nested_id = report
            .entries
            .iter()
            .find(|entry| entry.path == base.join("hidden-folder").join("nested"))
            .ok_or("nested directory missing")?
            .id
            .to_string();
        (hidden_id, nested_id)
    };
    let query = |parent_entry_id: Option<String>, hide_hidden| {
        tauri::async_runtime::block_on(query_scan_entries_inner(
            &state,
            QueryScanEntriesRequest {
                scan_generation: summary.scan_generation.clone(),
                filter: ScanFilter {
                    tab: ScanTab::Browse,
                    parent_entry_id,
                    search_text: String::new(),
                    zone_filter: "all".to_owned(),
                    category_filter: "all".to_owned(),
                    hide_hidden,
                    duplicate_group_id: None,
                    skip_reason_filter: "all".to_owned(),
                },
                sort: SortField::NameAsc,
                offset: 0,
                limit: 100,
                tree_roots_only: false,
            },
        ))
    };
    let visible = query(None, true)?;
    assert_eq!(
        visible.total_count, 2,
        "only the root and visible.txt remain"
    );
    assert!(
        visible
            .entries
            .iter()
            .any(|entry| entry.name_display == "visible.txt")
    );
    assert_eq!(query(Some(hidden_id.clone()), true)?.total_count, 0);
    assert_eq!(query(Some(nested_id.clone()), true)?.total_count, 0);
    assert_eq!(query(None, false)?.total_count, 6);
    assert_eq!(query(Some(hidden_id), false)?.total_count, 2);
    assert_eq!(query(Some(nested_id), false)?.total_count, 1);
    std::fs::remove_dir_all(base)?;
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn multi_selection_copy_and_move_keep_names_inside_selected_destination() -> TestResult {
    let tmp_root = std::env::var_os("FILE_TIDY_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let base_raw = tmp_root
        .join("file-tidy-gui-multi-selection")
        .join(format!("run-{}", std::process::id()));
    std::fs::create_dir_all(&base_raw)?;
    let base = std::fs::canonicalize(&base_raw)?;

    for (case, kind) in [
        ("copy", PlanActionKindDto::Copy),
        ("move", PlanActionKindDto::Move),
    ] {
        let case_root = base.join(case);
        let scan_root = case_root.join("source");
        let dst_root = case_root.join("destination");
        let state_root = case_root.join("state");
        std::fs::create_dir_all(&scan_root)?;
        std::fs::create_dir_all(&dst_root)?;
        std::fs::create_dir_all(&state_root)?;
        std::fs::write(scan_root.join("first.txt"), b"first file")?;
        std::fs::write(scan_root.join("second.txt"), b"second file")?;

        let state = AppState::new()?;
        let dst_grant_id = tauri::async_runtime::block_on(async {
            let mut session = state.session.lock().await;
            let state_gid = session.grant(&state_root, false)?;
            let storage_plan = session.storage_plan(&state_gid)?;
            let digest = storage_plan.digest().to_owned();
            session.initialize_storage(storage_plan, &digest)?;
            session.grant(&scan_root, false)?;
            let dst_gid = session.grant(&dst_root, false)?;
            Ok::<String, GuiError>(dst_gid.to_string())
        })?;
        *state.pending_roots.lock().map_err(|_| "lock poisoned")? = vec![scan_root.clone()];
        state
            .picked_destinations
            .lock()
            .map_err(|_| "lock poisoned")?
            .insert(dst_grant_id.clone(), dst_root.clone());

        let summary = tauri::async_runtime::block_on(start_scan_inner(
            &state,
            StartScanRequest {
                all_volumes: false,
                metadata_only: true,
                no_duplicates: true,
                stale_days: 30,
                max_entries: 100,
            },
            None,
        ))?;
        let (_, report) = state.snapshot_scan(&summary.scan_generation)?;
        let ids = report
            .entries
            .iter()
            .filter(|entry| {
                entry.path == scan_root.join("first.txt")
                    || entry.path == scan_root.join("second.txt")
            })
            .map(|entry| entry.id.to_string())
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);

        let preview = tauri::async_runtime::block_on(build_plan_from_selection_inner(
            &state,
            BuildPlanRequest {
                kind,
                selection: SelectionSpec::Ids {
                    scan_generation: summary.scan_generation,
                    ids,
                },
                destination_grant_id: Some(dst_grant_id),
                destination_relative_name: None,
                include_hidden: false,
                quarantine_retention_days: 30,
            },
        ))?;
        assert_eq!(preview.operations.len(), 2);
        for operation in &preview.operations {
            let destination = operation
                .destination
                .as_ref()
                .ok_or("destination missing")?;
            assert!(
                ["first.txt", "second.txt"]
                    .iter()
                    .any(|name| destination.path_display
                        == file_tidy_core::display_path(&dst_root.join(name))),
                "{case} must keep each filename inside the selected directory"
            );
            assert!(!destination.renamed_for_conflict);
        }

        let executed = tauri::async_runtime::block_on(confirm_and_execute_inner(
            &state,
            ConfirmAndExecuteInput {
                plan_id: preview.plan_id,
                plan_digest: preview.plan_digest,
                item_count: None,
                sensitive_acknowledgements: Vec::new(),
                permanent_challenge_input: None,
            },
            None,
        ))?;
        assert!(
            executed.completed,
            "{case} must succeed without a grant on the destination parent"
        );
        assert_eq!(std::fs::read(dst_root.join("first.txt"))?, b"first file");
        assert_eq!(std::fs::read(dst_root.join("second.txt"))?, b"second file");
        assert_eq!(scan_root.join("first.txt").exists(), case == "copy");
        assert_eq!(scan_root.join("second.txt").exists(), case == "copy");
    }

    std::fs::remove_dir_all(&base)?;
    Ok(())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", windows),
    ignore = "requires independent FILE_TIDY_TEST_ROOT"
)]
fn end_to_end_scan_selection_copy_out_and_permanent_challenge_lifecycle() -> TestResult {
    let tmp_root = match std::env::var_os("FILE_TIDY_TEST_ROOT") {
        Some(root) => PathBuf::from(root),
        None => std::env::temp_dir(),
    };
    let base_raw = tmp_root
        .join("file-tidy-gui-e2e")
        .join(format!("run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base_raw);
    std::fs::create_dir_all(&base_raw)?;
    let base = std::fs::canonicalize(&base_raw)?;

    let scan_root = base.join("scan-root");
    let dst_root = base.join("dst-root");
    let state_root = base.join("state-root");
    std::fs::create_dir_all(&scan_root)?;
    std::fs::create_dir_all(&dst_root)?;
    std::fs::create_dir_all(&state_root)?;

    // A file under a sensitive directory can be copied to a non-sensitive destination.
    let sensitive_dir = scan_root.join(".ssh");
    std::fs::create_dir_all(&sensitive_dir)?;
    let secret_file = sensitive_dir.join("secret.txt");
    let keep_file = scan_root.join("notes.txt");
    let purge_file = scan_root.join("trash.tmp");
    std::fs::write(&secret_file, b"PRIVATE-KEY-BYTES")?;
    std::fs::write(&keep_file, b"keep me")?;
    std::fs::write(&purge_file, b"delete me permanently")?;

    let state = AppState::new()?;
    let dst_grant_id = tauri::async_runtime::block_on(async {
        let mut session = state.session.lock().await;
        let state_gid = session.grant(&state_root, false)?;
        let sp = session.storage_plan(&state_gid)?;
        let digest = sp.digest().to_owned();
        session.initialize_storage(sp, &digest)?;
        session.grant(&scan_root, false)?;
        let dst_gid = session.grant(&dst_root, false)?;
        Ok::<String, GuiError>(dst_gid.to_string())
    })?;

    {
        let mut roots = state.pending_roots.lock().map_err(|_| "lock poisoned")?;
        *roots = vec![scan_root.clone()];
    }
    {
        let mut picked = state
            .picked_destinations
            .lock()
            .map_err(|_| "lock poisoned")?;
        picked.insert(dst_grant_id.clone(), dst_root.clone());
    }

    // 1) Start read-only scan and inspect query + treemap
    let summary = tauri::async_runtime::block_on(start_scan_inner(
        &state,
        StartScanRequest {
            all_volumes: false,
            metadata_only: false,
            no_duplicates: false,
            stale_days: 30,
            max_entries: 10_000,
        },
        None,
    ))?;
    assert_eq!(summary.scan_generation, "1");

    let browse_filter = ScanFilter {
        tab: ScanTab::Browse,
        parent_entry_id: None,
        search_text: String::new(),
        zone_filter: "all".to_owned(),
        category_filter: "all".to_owned(),
        hide_hidden: false,
        duplicate_group_id: None,
        skip_reason_filter: String::new(),
    };
    let entries_res = tauri::async_runtime::block_on(query_scan_entries_inner(
        &state,
        QueryScanEntriesRequest {
            scan_generation: summary.scan_generation.clone(),
            filter: browse_filter.clone(),
            sort: SortField::SizeDesc,
            offset: 0,
            limit: 50,
            tree_roots_only: false,
        },
    ))?;
    let treemap = tauri::async_runtime::block_on(get_treemap_nodes_inner(
        &state,
        summary.scan_generation.clone(),
        None,
        Some(40),
    ))?;
    assert!(!treemap.nodes.is_empty());

    let secret_entry = entries_res
        .entries
        .iter()
        .find(|e| e.name_display == "secret.txt")
        .ok_or("secret.txt entry missing")?;
    let keep_entry = entries_res
        .entries
        .iter()
        .find(|e| e.name_display == "notes.txt")
        .ok_or("notes.txt entry missing")?;
    let purge_entry = entries_res
        .entries
        .iter()
        .find(|e| e.name_display == "trash.tmp")
        .ok_or("trash.tmp entry missing")?;

    // Verify B-zone exposure in DTO
    assert!(secret_entry.policy.sensitive);
    assert!(secret_entry.policy.blocked_reason.is_some());

    // 2) Copy out B-zone file (`.ssh/secret.txt` -> `dst_root/secret.txt`) succeeds with :content ack
    let copy_preview = tauri::async_runtime::block_on(build_plan_from_selection_inner(
        &state,
        BuildPlanRequest {
            kind: PlanActionKindDto::Copy,
            selection: SelectionSpec::Ids {
                scan_generation: summary.scan_generation.clone(),
                ids: vec![secret_entry.id.clone()],
            },
            destination_grant_id: Some(dst_grant_id.clone()),
            destination_relative_name: None,
            include_hidden: true,
            quarantine_retention_days: 30,
        },
    ))?;
    assert!(copy_preview.blocked_b_write_reasons.is_empty());
    assert_eq!(copy_preview.sensitive_acknowledgements.len(), 1);
    let ack_keys: Vec<String> = copy_preview
        .sensitive_acknowledgements
        .iter()
        .map(|a| a.key.clone())
        .collect();
    let copy_report = tauri::async_runtime::block_on(confirm_and_execute_inner(
        &state,
        ConfirmAndExecuteInput {
            plan_id: copy_preview.plan_id,
            plan_digest: copy_preview.plan_digest,
            item_count: None,
            sensitive_acknowledgements: ack_keys,
            permanent_challenge_input: None,
        },
        None,
    ))?;
    assert!(copy_report.completed);
    assert_eq!(
        std::fs::read(dst_root.join("secret.txt"))?,
        b"PRIVATE-KEY-BYTES"
    );

    // 3) Move touching Zone B (`.ssh/secret.txt`) is rejected both in preview AND on confirm_and_execute
    let move_preview = tauri::async_runtime::block_on(build_plan_from_selection_inner(
        &state,
        BuildPlanRequest {
            kind: PlanActionKindDto::Move,
            selection: SelectionSpec::Ids {
                scan_generation: summary.scan_generation.clone(),
                ids: vec![secret_entry.id.clone()],
            },
            destination_grant_id: Some(dst_grant_id),
            destination_relative_name: None,
            include_hidden: true,
            quarantine_retention_days: 30,
        },
    ))?;
    assert!(!move_preview.blocked_b_write_reasons.is_empty());
    let move_exec = tauri::async_runtime::block_on(confirm_and_execute_inner(
        &state,
        ConfirmAndExecuteInput {
            plan_id: move_preview.plan_id,
            plan_digest: move_preview.plan_digest,
            item_count: None,
            sensitive_acknowledgements: Vec::new(),
            permanent_challenge_input: None,
        },
        None,
    ));
    assert!(matches!(move_exec, Err(GuiError::Rejected(_))));
    assert!(secret_file.exists());

    // 4) SelectionSpec::Filtered with excludes targeting only C-zone `trash.tmp`
    let purge_filter = ScanFilter {
        search_text: ".tmp".to_owned(),
        ..browse_filter
    };
    let perm_preview = tauri::async_runtime::block_on(build_plan_from_selection_inner(
        &state,
        BuildPlanRequest {
            kind: PlanActionKindDto::PermanentDelete,
            selection: SelectionSpec::Filtered {
                scan_generation: summary.scan_generation,
                filter: purge_filter,
                excludes: vec![keep_entry.id.clone(), secret_entry.id.clone()],
            },
            destination_grant_id: None,
            destination_relative_name: None,
            include_hidden: false,
            quarantine_retention_days: 30,
        },
    ))?;
    assert!(perm_preview.blocked_b_write_reasons.is_empty());
    assert_eq!(perm_preview.operations.len(), 1);
    assert_eq!(
        perm_preview.operations[0].source_display,
        file_tidy_core::display_path(&purge_file)
    );
    let _ = purge_entry;

    let ch = tauri::async_runtime::block_on(request_permanent_challenge_inner(
        &state,
        perm_preview.plan_id.clone(),
        perm_preview.plan_digest.clone(),
    ))?;

    // Wrong phrase preserves active plan & challenge so user can fix typo and retry
    let bad_phrase = tauri::async_runtime::block_on(confirm_and_execute_inner(
        &state,
        ConfirmAndExecuteInput {
            plan_id: perm_preview.plan_id.clone(),
            plan_digest: perm_preview.plan_digest.clone(),
            item_count: None,
            sensitive_acknowledgements: Vec::new(),
            permanent_challenge_input: Some("WRONG PHRASE".to_owned()),
        },
        None,
    ));
    assert!(matches!(bad_phrase, Err(GuiError::Rejected(_))));
    {
        let guard = state.plan.lock().map_err(|_| "lock poisoned")?;
        assert!(guard.active.is_some());
        assert!(guard.permanent_challenge.is_some());
    }

    // Expired challenge clears only challenge while preserving active plan
    {
        let mut guard = state.plan.lock().map_err(|_| "lock poisoned")?;
        if let Some(pending) = guard.permanent_challenge.as_mut() {
            pending.expires_at = 0;
        }
    }
    let expired_res = tauri::async_runtime::block_on(confirm_and_execute_inner(
        &state,
        ConfirmAndExecuteInput {
            plan_id: perm_preview.plan_id.clone(),
            plan_digest: perm_preview.plan_digest.clone(),
            item_count: None,
            sensitive_acknowledgements: Vec::new(),
            permanent_challenge_input: Some(format!(
                "{} {} {}",
                ch.expected_prefix, ch.confirmation_count, ch.challenge_code
            )),
        },
        None,
    ));
    assert!(matches!(expired_res, Err(GuiError::ChallengeExpired)));

    // Re-issue challenge cleanly and execute permanent delete
    let ch2 = tauri::async_runtime::block_on(request_permanent_challenge_inner(
        &state,
        perm_preview.plan_id.clone(),
        perm_preview.plan_digest.clone(),
    ))?;
    let perm_report = tauri::async_runtime::block_on(confirm_and_execute_inner(
        &state,
        ConfirmAndExecuteInput {
            plan_id: perm_preview.plan_id,
            plan_digest: perm_preview.plan_digest,
            item_count: None,
            sensitive_acknowledgements: Vec::new(),
            permanent_challenge_input: Some(format!(
                "{} {} {}",
                ch2.expected_prefix, ch2.confirmation_count, ch2.challenge_code
            )),
        },
        None,
    ))?;
    assert!(perm_report.completed);
    assert!(!purge_file.exists());
    assert!(keep_file.exists());

    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
