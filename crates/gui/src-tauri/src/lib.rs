pub mod commands;
pub mod dto;
pub mod error;
pub mod state;

use crate::state::AppState;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let app_state = AppState::new()?;
    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::pick_scan_roots,
            commands::pick_rules_file,
            commands::start_scan,
            commands::cancel_scan,
            commands::query_scan_entries,
            commands::get_treemap_nodes,
            commands::get_workspace_status,
            commands::get_suggested_directories,
            commands::pick_and_preview_grant,
            commands::confirm_grant,
            commands::revoke_grant,
            commands::pick_and_preview_storage_init,
            commands::confirm_storage_init,
            commands::open_existing_storage,
            commands::pick_destination_directory,
            commands::build_plan_from_selection,
            commands::filter_plan_operations,
            commands::request_permanent_challenge,
            commands::confirm_and_execute,
            commands::cancel_execution,
            commands::list_quarantine,
            commands::build_restore_plan,
            commands::build_purge_plan,
            commands::list_history,
            commands::get_batch_detail,
            commands::build_undo_plan,
            commands::get_recovery_report,
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}
