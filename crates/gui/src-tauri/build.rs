fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "pick_scan_roots",
        "pick_rules_file",
        "start_scan",
        "cancel_scan",
        "query_scan_entries",
        "get_treemap_nodes",
        "get_workspace_status",
        "get_suggested_directories",
        "pick_and_preview_grant",
        "confirm_grant",
        "revoke_grant",
        "pick_and_preview_storage_init",
        "confirm_storage_init",
        "open_existing_storage",
        "pick_destination_directory",
        "build_plan_from_selection",
        "filter_plan_operations",
        "request_permanent_challenge",
        "confirm_and_execute",
        "cancel_execution",
        "list_quarantine",
        "build_restore_plan",
        "build_purge_plan",
        "list_history",
        "get_batch_detail",
        "build_undo_plan",
        "get_recovery_report",
    ]);

    if let Err(error) =
        tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
    {
        eprintln!("failed to run tauri-build: {error}");
        std::process::exit(1);
    }
}
