use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use file_tidy_core::approval::Confirmation;
use file_tidy_core::authorization::{Grant, Id, Session};
use file_tidy_core::plan::{OperationKind, OperationRequest, Plan, PlanOptions};
use file_tidy_core::policy::Policy;
use file_tidy_core::{
    CancellationToken, EntryKind, Rules, ScanOptions, ScanReport, display_path, load_rules, scan,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::dto::{
    BatchHistoryDetailDto, BatchHistoryDto, BreadcrumbDto, BuildPlanRequest,
    ConfirmAndExecuteInput, ExecutionReportDto, GrantDto, PermanentChallengeDto,
    PickedDestinationDto, PickedRulesFileDto, PickedScanRootsDto, PlanActionKindDto,
    PlanPreviewDto, QuarantineItemDto, QueryScanEntriesRequest, QueryScanEntriesResponse,
    RecoveryReportDto, ScanSummaryDto, SelectionSpec, SortField, StorageInitPreviewDto,
    SuggestedDirectoriesResponse, SuggestedDirectoryDto, TreemapNodeDto, TreemapResponse,
    WorkspaceStatusDto, build_policy_view, compute_sensitive_parent_dirs, entry_name_display,
    filter_entries, policy_view_for_path, to_batch_detail_dto, to_batch_dto,
    to_execution_report_dto, to_file_entry_dto, to_plan_preview_dto, to_quarantine_dto,
    to_recovery_dto, to_scan_summary_dto, to_skipped_dto,
};
use crate::error::{GuiError, GuiResult};
use crate::state::{
    ActivePlanRecord, AppState, PERMANENT_CHALLENGE_TTL_SECS, PendingPermanentChallenge,
    generate_challenge_code, now_unix_secs,
};

struct ExecSlotGuard {
    in_flight: Arc<AtomicBool>,
    cancel_slot: Arc<Mutex<Option<CancellationToken>>>,
}

impl Drop for ExecSlotGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.cancel_slot.lock() {
            *slot = None;
        }
        self.in_flight.store(false, Ordering::SeqCst);
    }
}

#[derive(Clone, Serialize)]
struct ScanProgressPayload {
    scan_generation: String,
    phase: String,
    discovered: String,
    processed: String,
    content_bytes_read: String,
    errors: String,
}

#[derive(Clone, Serialize)]
struct ExecutionProgressPayload {
    batch_id: String,
    completed_operations: usize,
    total_operations: usize,
    current_op_id: Option<String>,
    status: String,
}

fn scan_phase_label(phase: file_tidy_core::ScanPhase) -> &'static str {
    match phase {
        file_tidy_core::ScanPhase::Discover => "discovering",
        file_tidy_core::ScanPhase::Magic => "metadata",
        file_tidy_core::ScanPhase::PrefixHash => "content",
        file_tidy_core::ScanPhase::FullHash => "duplicates",
        file_tidy_core::ScanPhase::Complete => "complete",
    }
}

#[derive(Deserialize)]
pub struct StartScanRequest {
    pub all_volumes: bool,
    pub metadata_only: bool,
    pub no_duplicates: bool,
    pub stale_days: u64,
    pub max_entries: usize,
}

#[tauri::command]
pub async fn pick_scan_roots(state: State<'_, AppState>) -> GuiResult<PickedScanRootsDto> {
    let folders = rfd::AsyncFileDialog::new()
        .set_title("选择要扫描的目录")
        .pick_folders()
        .await
        .unwrap_or_default();

    let paths: Vec<PathBuf> = folders
        .into_iter()
        .map(|h| h.path().to_path_buf())
        .collect();
    if paths.is_empty() {
        let existing = state
            .pending_roots
            .lock()
            .map_err(|_| GuiError::Rejected("目录选择锁不可用".to_owned()))?
            .clone();
        return build_picked_roots_dto(&existing, &state.session).await;
    }

    {
        let mut guard = state
            .pending_roots
            .lock()
            .map_err(|_| GuiError::Rejected("目录选择锁不可用".to_owned()))?;
        *guard = paths.clone();
    }

    build_picked_roots_dto(&paths, &state.session).await
}

async fn build_picked_roots_dto(
    paths: &[PathBuf],
    session_lock: &Arc<tokio::sync::Mutex<Session>>,
) -> GuiResult<PickedScanRootsDto> {
    let paths_owned = paths.to_vec();
    let policy = tauri::async_runtime::spawn_blocking(Policy::new)
        .await
        .map_err(|_| GuiError::Rejected("策略检查任务失败".to_owned()))?;
    let session = session_lock.lock().await;
    let policies = paths_owned
        .iter()
        .map(|p| policy_view_for_path(p, &policy, &session))
        .collect();
    let roots_display = paths_owned.iter().map(|p| display_path(p)).collect();
    Ok(PickedScanRootsDto {
        roots_display,
        policies,
    })
}

#[tauri::command]
pub async fn pick_rules_file(state: State<'_, AppState>) -> GuiResult<PickedRulesFileDto> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("选择分类规则 TOML 文件")
        .add_filter("TOML", &["toml"])
        .pick_file()
        .await;

    let Some(handle) = file else {
        return Ok(PickedRulesFileDto {
            path_display: None,
            rule_count: 0,
        });
    };
    let path = handle.path().to_path_buf();
    let path_for_load = path.clone();
    let rules = tauri::async_runtime::spawn_blocking(move || load_rules(&path_for_load))
        .await
        .map_err(|_| GuiError::Rejected("规则加载任务中断".to_owned()))??;

    let disp = display_path(&path);
    let mut guard = state
        .pending_rules
        .lock()
        .map_err(|_| GuiError::Rejected("规则状态锁不可用".to_owned()))?;
    *guard = Some((disp.clone(), rules));

    Ok(PickedRulesFileDto {
        path_display: Some(disp),
        rule_count: 1,
    })
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    request: StartScanRequest,
) -> GuiResult<ScanSummaryDto> {
    start_scan_inner(&state, request, Some(&app)).await
}

pub async fn start_scan_inner(
    state: &AppState,
    request: StartScanRequest,
    app: Option<&AppHandle>,
) -> GuiResult<ScanSummaryDto> {
    let roots = if request.all_volumes {
        Vec::new()
    } else {
        let guard = state
            .pending_roots
            .lock()
            .map_err(|_| GuiError::Rejected("扫描根目录锁不可用".to_owned()))?;
        if guard.is_empty() {
            return Err(GuiError::Rejected(
                "请先选择至少一个扫描目录或启用全盘本地卷".to_owned(),
            ));
        }
        guard.clone()
    };

    let rules = state
        .pending_rules
        .lock()
        .map_err(|_| GuiError::Rejected("规则锁不可用".to_owned()))?
        .as_ref()
        .map(|(_, r)| r.clone())
        .unwrap_or_else(Rules::default);

    let token = CancellationToken::new();
    let generation = {
        let mut guard = state
            .scan
            .write()
            .map_err(|_| GuiError::Rejected("扫描状态锁不可用".to_owned()))?;
        if guard.running {
            return Err(GuiError::Rejected(
                "已有扫描正在进行中，请先停止".to_owned(),
            ));
        }
        guard.generation = guard.generation.saturating_add(1);
        guard.running = true;
        guard.cancel = Some(token.clone());
        guard.generation
    };

    let root_displays: Vec<String> = if request.all_volumes {
        vec!["全部本地卷".to_owned()]
    } else {
        roots.iter().map(|p| display_path(p)).collect()
    };

    let options = ScanOptions {
        roots,
        all_volumes: request.all_volumes,
        metadata_only: request.metadata_only,
        detect_duplicates: !request.no_duplicates,
        stale_days: request.stale_days.max(1),
        max_entries: request.max_entries.clamp(1, 1_000_000),
        rules,
        ..ScanOptions::default()
    };

    let gen_str = generation.to_string();
    let app_clone = app.cloned();
    let gen_for_emit = gen_str.clone();
    let last_emit = Arc::new(Mutex::new(Instant::now()));

    let scan_result = tauri::async_runtime::spawn_blocking(move || {
        scan(options, &token, |progress| {
            let Some(app_handle) = app_clone.as_ref() else {
                return;
            };
            let should_emit = if let Ok(mut prev) = last_emit.lock() {
                if prev.elapsed().as_millis() >= 120 {
                    *prev = Instant::now();
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if should_emit {
                let phase = scan_phase_label(progress.phase).to_owned();
                let _ = app_handle.emit(
                    "scan://progress",
                    ScanProgressPayload {
                        scan_generation: gen_for_emit.clone(),
                        phase,
                        discovered: progress.discovered.to_string(),
                        processed: progress.processed.to_string(),
                        content_bytes_read: progress.bytes_read.to_string(),
                        errors: "0".to_owned(),
                    },
                );
            }
        })
    })
    .await;

    let report = match scan_result {
        Ok(Ok(report)) => Arc::new(report),
        Ok(Err(err)) => {
            if let Ok(mut guard) = state.scan.write() {
                guard.running = false;
                guard.cancel = None;
            }
            return Err(GuiError::CoreScan(err));
        }
        Err(_) => {
            if let Ok(mut guard) = state.scan.write() {
                guard.running = false;
                guard.cancel = None;
            }
            return Err(GuiError::Rejected("扫描任务意外终止".to_owned()));
        }
    };

    {
        let mut guard = state
            .scan
            .write()
            .map_err(|_| GuiError::Rejected("扫描状态锁不可用".to_owned()))?;
        guard.report = Some(report.clone());
        guard.running = false;
        guard.cancel = None;
    }

    Ok(to_scan_summary_dto(generation, &report, root_displays))
}

#[tauri::command]
pub async fn cancel_scan(state: State<'_, AppState>) -> GuiResult<()> {
    let guard = state
        .scan
        .read()
        .map_err(|_| GuiError::Rejected("扫描状态锁不可用".to_owned()))?;
    if let Some(cancel) = &guard.cancel {
        cancel.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn query_scan_entries(
    state: State<'_, AppState>,
    request: QueryScanEntriesRequest,
) -> GuiResult<QueryScanEntriesResponse> {
    query_scan_entries_inner(&state, request).await
}

pub async fn query_scan_entries_inner(
    state: &AppState,
    request: QueryScanEntriesRequest,
) -> GuiResult<QueryScanEntriesResponse> {
    let (generation, report) = state.snapshot_scan(&request.scan_generation)?;

    // Snapshot grants briefly without holding session lock across filtering/sorting.
    let grants_owned: Vec<Grant> = {
        let session = state.session.lock().await;
        session.grants().cloned().collect()
    };

    tauri::async_runtime::spawn_blocking(move || {
        let grant_refs: Vec<&Grant> = grants_owned.iter().collect();
        let sensitive_dirs = compute_sensitive_parent_dirs(&report);
        let stale_set: BTreeSet<u64> = report.stale_entry_ids.iter().copied().collect();

        let skipped: Vec<_> = report
            .skipped
            .iter()
            .take(500)
            .map(to_skipped_dto)
            .collect();

        let mut filtered = filter_entries(&report, &request.filter, &grant_refs, &sensitive_dirs)?;
        match request.sort {
            SortField::SizeDesc => {
                filtered.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes).then(a.id.cmp(&b.id)));
            }
            SortField::NameAsc => {
                filtered.sort_by(|a, b| a.path.cmp(&b.path));
            }
            SortField::ModifiedAsc => {
                filtered.sort_by(|a, b| {
                    let am = a.modified.as_ref().map(|t| t.unix_seconds.as_str());
                    let bm = b.modified.as_ref().map(|t| t.unix_seconds.as_str());
                    am.cmp(&bm).then(a.id.cmp(&b.id))
                });
            }
        }

        let total_count = filtered.len();
        let limit = request.limit.min(500);
        let entries = filtered
            .into_iter()
            .skip(request.offset)
            .take(limit)
            .map(|e| to_file_entry_dto(e, &grant_refs, &stale_set, &sensitive_dirs))
            .collect();

        Ok(QueryScanEntriesResponse {
            scan_generation: generation.to_string(),
            total_count,
            offset: request.offset,
            entries,
            skipped,
        })
    })
    .await
    .map_err(|_| GuiError::Rejected("查询扫描条目失败".to_owned()))?
}

#[tauri::command]
pub async fn get_treemap_nodes(
    state: State<'_, AppState>,
    scan_generation: String,
    parent_entry_id: Option<String>,
    max_nodes: Option<usize>,
) -> GuiResult<TreemapResponse> {
    get_treemap_nodes_inner(&state, scan_generation, parent_entry_id, max_nodes).await
}

pub async fn get_treemap_nodes_inner(
    state: &AppState,
    scan_generation: String,
    parent_entry_id: Option<String>,
    max_nodes: Option<usize>,
) -> GuiResult<TreemapResponse> {
    let (generation, report) = state.snapshot_scan(&scan_generation)?;
    let grants_owned: Vec<Grant> = {
        let session = state.session.lock().await;
        session.grants().cloned().collect()
    };

    tauri::async_runtime::spawn_blocking(move || {
        let cap = max_nodes.unwrap_or(40).clamp(1, 40);
        let grant_refs: Vec<&Grant> = grants_owned.iter().collect();
        let sensitive_dirs = compute_sensitive_parent_dirs(&report);

        let parent_path: Option<PathBuf> = if let Some(pid) = &parent_entry_id {
            let id = pid
                .parse::<u64>()
                .map_err(|_| GuiError::Rejected("无效目录 ID".to_owned()))?;
            let found = report
                .entries
                .iter()
                .find(|e| e.id == id && e.kind == EntryKind::Directory)
                .ok_or_else(|| GuiError::Rejected("找不到目标目录".to_owned()))?;
            Some(found.path.clone())
        } else {
            None
        };

        let mut breadcrumbs = vec![BreadcrumbDto {
            entry_id: None,
            label_display: "扫描根".to_owned(),
        }];
        if let Some(p) = &parent_path {
            let dir_by_path: BTreeMap<&Path, u64> = report
                .entries
                .iter()
                .filter(|e| e.kind == EntryKind::Directory)
                .map(|e| (e.path.as_path(), e.id))
                .collect();
            let mut chain = Vec::new();
            for anc in p.ancestors() {
                if let Some(&id) = dir_by_path.get(anc) {
                    chain.push(BreadcrumbDto {
                        entry_id: Some(id.to_string()),
                        label_display: entry_name_display(anc),
                    });
                }
            }
            chain.reverse();
            breadcrumbs.extend(chain);
        }

        // Aggregate direct children (directories use directory_usage; direct files use entry size).
        let dir_usage_map: BTreeMap<&Path, (u64, u64)> = report
            .directory_usage
            .iter()
            .map(|u| (u.path.as_path(), (u.logical_bytes, u.files)))
            .collect();

        let mut candidates: Vec<(TreemapNodeDto, u64)> = Vec::new();
        for entry in &report.entries {
            let is_direct_child = match &parent_path {
                Some(parent) => entry.path.parent() == Some(parent.as_path()),
                None => {
                    // Top-level directories / entries that have no ancestor in report.entries
                    entry
                        .path
                        .parent()
                        .is_none_or(|p| !dir_usage_map.contains_key(p))
                }
            };
            if !is_direct_child {
                continue;
            }
            let (bytes, files) = if entry.kind == EntryKind::Directory {
                dir_usage_map
                    .get(entry.path.as_path())
                    .copied()
                    .unwrap_or((entry.size_bytes, 0))
            } else {
                (entry.size_bytes, 1)
            };
            let has_sens =
                entry.kind == EntryKind::Directory && sensitive_dirs.contains(&entry.path);
            let policy = build_policy_view(&entry.path, &entry.policy, &grant_refs, has_sens);
            candidates.push((
                TreemapNodeDto {
                    id: format!("tm-{}", entry.id),
                    entry_id: Some(entry.id.to_string()),
                    label_display: entry_name_display(&entry.path),
                    path_display: display_path(&entry.path),
                    logical_bytes: bytes.to_string(),
                    file_count: files.to_string(),
                    is_other_rollup: false,
                    drillable: entry.kind == EntryKind::Directory,
                    policy: Some(policy),
                },
                bytes,
            ));
        }

        candidates.sort_by_key(|a| std::cmp::Reverse(a.1));
        let total_bytes: u64 = candidates
            .iter()
            .map(|(_, b)| *b)
            .fold(0u64, u64::saturating_add);

        let mut nodes = Vec::new();
        if candidates.len() > cap {
            let (head, tail) = candidates.split_at(cap - 1);
            nodes.extend(head.iter().map(|(n, _)| clone_treemap_node(n)));
            let other_bytes: u64 = tail.iter().map(|(_, b)| *b).fold(0u64, u64::saturating_add);
            let other_count = tail.len();
            nodes.push(TreemapNodeDto {
                id: "tm-other".to_owned(),
                entry_id: None,
                label_display: format!("其他 {other_count} 项"),
                path_display: format!("其余 {other_count} 个较小子项聚合"),
                logical_bytes: other_bytes.to_string(),
                file_count: other_count.to_string(),
                is_other_rollup: true,
                drillable: false,
                policy: None,
            });
        } else {
            nodes.extend(candidates.into_iter().map(|(n, _)| n));
        }

        Ok(TreemapResponse {
            scan_generation: generation.to_string(),
            parent_entry_id,
            breadcrumbs,
            total_bytes: total_bytes.to_string(),
            nodes,
        })
    })
    .await
    .map_err(|_| GuiError::Rejected("计算树图节点失败".to_owned()))?
}

fn clone_treemap_node(n: &TreemapNodeDto) -> TreemapNodeDto {
    TreemapNodeDto {
        id: n.id.clone(),
        entry_id: n.entry_id.clone(),
        label_display: n.label_display.clone(),
        path_display: n.path_display.clone(),
        logical_bytes: n.logical_bytes.clone(),
        file_count: n.file_count.clone(),
        is_other_rollup: n.is_other_rollup,
        drillable: n.drillable,
        policy: n.policy.clone(),
    }
}

#[tauri::command]
pub async fn get_workspace_status(state: State<'_, AppState>) -> GuiResult<WorkspaceStatusDto> {
    build_workspace_status(&state).await
}

async fn build_workspace_status(state: &AppState) -> GuiResult<WorkspaceStatusDto> {
    let storage_root_display = state
        .storage_root_display
        .lock()
        .map_err(|_| GuiError::Rejected("状态锁不可用".to_owned()))?
        .clone();

    let session = state.session.lock().await;
    let grants: Vec<GrantDto> = session
        .grants()
        .map(|g| GrantDto {
            id: g.id().to_string(),
            root_display: g.root().display.clone(),
            persistent: g.is_persistent(),
            revoked: g.is_revoked(),
        })
        .collect();

    let (storage_initialized, pending_recovery_count, due_quarantine_count) =
        match session.quarantine_items(1000, true) {
            Ok(due_items) => {
                let pending = session
                    .recovery_report(None, 200)
                    .map(|r| r.items.len())
                    .unwrap_or(0);
                (true, pending, due_items.len())
            }
            Err(_) => (false, 0, 0),
        };

    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "other"
    };

    Ok(WorkspaceStatusDto {
        storage_initialized,
        storage_root_display,
        authorization_epoch: state.known_epoch.load(Ordering::SeqCst).to_string(),
        grants,
        pending_recovery_count,
        due_quarantine_count,
        platform,
    })
}

#[tauri::command]
pub async fn get_suggested_directories(
    state: State<'_, AppState>,
    allow_private_config: bool,
) -> GuiResult<SuggestedDirectoriesResponse> {
    if cfg!(target_os = "linux") && !allow_private_config {
        return Ok(SuggestedDirectoriesResponse {
            requires_private_config_consent: true,
            consent_reason: Some(
                "在 Linux 上发现常见个人目录需单次只读读取 ~/.config/user-dirs.dirs（该文件位于 B 敏感保护区）。未经明确同意不会自动读取。".to_owned(),
            ),
            items: Vec::new(),
        });
    }

    let (raw, policy) = tauri::async_runtime::spawn_blocking(move || {
        let dirs = file_tidy_core::suggested_directories(allow_private_config)?;
        let policy = Policy::new();
        Ok::<_, GuiError>((dirs, policy))
    })
    .await
    .map_err(|_| GuiError::Rejected("读取建议目录任务失败".to_owned()))??;

    let session = state.session.lock().await;
    let items = raw
        .into_iter()
        .map(|s| SuggestedDirectoryDto {
            purpose: s.purpose,
            path_display: display_path(&s.path),
            policy: policy_view_for_path(&s.path, &policy, &session),
        })
        .collect();

    Ok(SuggestedDirectoriesResponse {
        requires_private_config_consent: false,
        consent_reason: None,
        items,
    })
}

#[tauri::command]
pub async fn pick_and_preview_grant(state: State<'_, AppState>) -> GuiResult<Option<GrantDto>> {
    let folder = rfd::AsyncFileDialog::new()
        .set_title("选择要授权整理的本地目录")
        .pick_folder()
        .await;
    let Some(handle) = folder else {
        return Ok(None);
    };
    let path = handle.path().to_path_buf();
    let grant = tauri::async_runtime::spawn_blocking(move || Session::preview_grant(&path))
        .await
        .map_err(|_| GuiError::Rejected("授权检查任务失败".to_owned()))??;

    let dto = GrantDto {
        id: grant.id().to_string(),
        root_display: grant.root().display.clone(),
        persistent: false,
        revoked: false,
    };

    state
        .pending_grants
        .lock()
        .map_err(|_| GuiError::Rejected("授权缓存锁不可用".to_owned()))?
        .insert(dto.id.clone(), grant);

    Ok(Some(dto))
}

#[tauri::command]
pub async fn confirm_grant(
    state: State<'_, AppState>,
    grant_id: String,
    persistent: bool,
) -> GuiResult<WorkspaceStatusDto> {
    let grant = state
        .pending_grants
        .lock()
        .map_err(|_| GuiError::Rejected("授权缓存锁不可用".to_owned()))?
        .remove(&grant_id)
        .ok_or_else(|| GuiError::Rejected("找不到待确认的授权预览".to_owned()))?;

    {
        let mut session = state.session.lock().await;
        session.grant_reviewed(&grant, persistent)?;
        state.known_epoch.fetch_add(1, Ordering::SeqCst);
    }

    build_workspace_status(&state).await
}

#[tauri::command]
pub async fn revoke_grant(
    state: State<'_, AppState>,
    grant_id: String,
) -> GuiResult<WorkspaceStatusDto> {
    if state.exec_in_flight.load(Ordering::SeqCst) {
        if let Ok(slot) = state.exec_cancel.lock()
            && let Some(cancel) = slot.as_ref()
        {
            cancel.cancel();
        }
        return Err(GuiError::ExecutionInFlight);
    }

    let id: Id = grant_id.parse()?;
    {
        let mut session = state.session.lock().await;
        session.revoke(&id)?;
        state.known_epoch.fetch_add(1, Ordering::SeqCst);
    }

    build_workspace_status(&state).await
}

#[tauri::command]
pub async fn pick_and_preview_storage_init(
    state: State<'_, AppState>,
) -> GuiResult<Option<StorageInitPreviewDto>> {
    let folder = rfd::AsyncFileDialog::new()
        .set_title("选择非敏感本地目录以初始化 .file-tidy 状态存储")
        .pick_folder()
        .await;
    let Some(handle) = folder else {
        return Ok(None);
    };
    let path = handle.path().to_path_buf();
    let policy = tauri::async_runtime::spawn_blocking(Policy::new)
        .await
        .map_err(|_| GuiError::Rejected("策略检查失败".to_owned()))?;
    let labels = policy.labels(&path);
    if labels.protected || labels.sensitive {
        return Err(GuiError::Rejected(
            "不能在系统保护区（A）或敏感区（B）初始化内部状态存储，请选择普通用户目录。".to_owned(),
        ));
    }

    let (plan, root_disp) = {
        let mut session = state.session.lock().await;
        let grant_id = session.grant(&path, false)?;
        let plan = session.storage_plan(&grant_id)?;
        (plan, display_path(&path))
    };

    let preview = plan.preview();
    let digest = plan.digest().to_owned();
    let grant_id_str = preview.grant.to_string();
    let dto = StorageInitPreviewDto {
        grant_id: grant_id_str.clone(),
        directory_display: preview.directory.display.clone(),
        objects: preview.objects.clone(),
        expires_at_unix: preview.expires_at.to_string(),
        digest: digest.clone(),
    };

    state
        .pending_storage_plans
        .lock()
        .map_err(|_| GuiError::Rejected("存储计划缓存锁不可用".to_owned()))?
        .insert(grant_id_str, (plan, root_disp));

    Ok(Some(dto))
}

#[tauri::command]
pub async fn confirm_storage_init(
    state: State<'_, AppState>,
    grant_id: String,
    digest: String,
) -> GuiResult<WorkspaceStatusDto> {
    let (plan, root_disp) = state
        .pending_storage_plans
        .lock()
        .map_err(|_| GuiError::Rejected("存储计划缓存锁不可用".to_owned()))?
        .remove(&grant_id)
        .ok_or_else(|| GuiError::Rejected("找不到待确认的初始化计划".to_owned()))?;

    {
        let mut session = state.session.lock().await;
        session.initialize_storage(plan, &digest)?;
        state.known_epoch.fetch_add(1, Ordering::SeqCst);
    }

    if let Ok(mut root_guard) = state.storage_root_display.lock() {
        *root_guard = Some(root_disp);
    }

    build_workspace_status(&state).await
}

#[tauri::command]
pub async fn open_existing_storage(state: State<'_, AppState>) -> GuiResult<WorkspaceStatusDto> {
    if state.exec_in_flight.load(Ordering::SeqCst) {
        return Err(GuiError::ExecutionInFlight);
    }
    let folder = rfd::AsyncFileDialog::new()
        .set_title("选择已包含 .file-tidy 状态目录的工作区")
        .pick_folder()
        .await;
    let Some(handle) = folder else {
        return build_workspace_status(&state).await;
    };
    let path = handle.path().to_path_buf();
    let disp = display_path(&path);

    let opened = tauri::async_runtime::spawn_blocking(move || Session::open_writable(&path))
        .await
        .map_err(|_| GuiError::Rejected("打开状态库失败".to_owned()))??;

    {
        let mut session = state.session.lock().await;
        *session = opened;
        state.known_epoch.fetch_add(1, Ordering::SeqCst);
    }
    if let Ok(mut root_guard) = state.storage_root_display.lock() {
        *root_guard = Some(disp);
    }

    build_workspace_status(&state).await
}

#[tauri::command]
pub async fn pick_destination_directory(
    state: State<'_, AppState>,
) -> GuiResult<Option<PickedDestinationDto>> {
    let folder = rfd::AsyncFileDialog::new()
        .set_title("选择目标目录（需在已授权的 C 区内）")
        .pick_folder()
        .await;
    let Some(handle) = folder else {
        return Ok(None);
    };
    let path = handle.path().to_path_buf();
    let path_for_policy = path.clone();
    let policy = tauri::async_runtime::spawn_blocking(Policy::new)
        .await
        .map_err(|_| GuiError::Rejected("策略检查失败".to_owned()))?;

    let session = state.session.lock().await;
    let pv = policy_view_for_path(&path_for_policy, &policy, &session);
    let matching_grant = session
        .grants()
        .find(|g| {
            !g.is_revoked()
                && g.root()
                    .to_path()
                    .map(|r| path_for_policy.starts_with(&r))
                    .unwrap_or(false)
        })
        .map(|g| g.id().to_string());

    if let Some(ref gid) = matching_grant
        && let Ok(mut map) = state.picked_destinations.lock()
    {
        map.insert(gid.clone(), path.clone());
    }

    Ok(Some(PickedDestinationDto {
        grant_id: matching_grant.clone(),
        path_display: display_path(&path),
        needs_grant: matching_grant.is_none()
            || matches!(
                pv.zone,
                crate::dto::ZoneKind::AProtected | crate::dto::ZoneKind::BSensitive
            ),
        policy: pv,
    }))
}

#[tauri::command]
pub async fn build_plan_from_selection(
    state: State<'_, AppState>,
    request: BuildPlanRequest,
) -> GuiResult<PlanPreviewDto> {
    build_plan_from_selection_inner(&state, request).await
}

pub async fn build_plan_from_selection_inner(
    state: &AppState,
    request: BuildPlanRequest,
) -> GuiResult<PlanPreviewDto> {
    let scan_gen = match &request.selection {
        SelectionSpec::Ids {
            scan_generation, ..
        } => scan_generation.as_str(),
        SelectionSpec::Filtered {
            scan_generation, ..
        } => scan_generation.as_str(),
    };
    let (_, report) = state.snapshot_scan(scan_gen)?;

    let grants_owned: Vec<Grant> = {
        let session = state.session.lock().await;
        session.grants().cloned().collect()
    };

    let picked_dest_path: Option<PathBuf> = match &request.destination_grant_id {
        Some(gid) => state
            .picked_destinations
            .lock()
            .ok()
            .and_then(|map| map.get(gid).cloned()),
        None => None,
    };

    let selected_paths = tauri::async_runtime::spawn_blocking(move || {
        resolve_selection_paths(&report, &request.selection, &grants_owned)
    })
    .await
    .map_err(|_| GuiError::Rejected("解析选择项失败".to_owned()))??;

    if selected_paths.is_empty() {
        return Err(GuiError::Rejected("没有选中的文件或目录".to_owned()));
    }

    let op_kind = match request.kind {
        PlanActionKindDto::Copy => OperationKind::Copy,
        PlanActionKindDto::Move => OperationKind::Move,
        PlanActionKindDto::Rename => OperationKind::Rename,
        PlanActionKindDto::Quarantine => OperationKind::Quarantine,
        PlanActionKindDto::PermanentDelete => OperationKind::PermanentDelete,
    };

    let multi = selected_paths.len() > 1;
    let mut requests = Vec::with_capacity(selected_paths.len());
    for source in selected_paths {
        let destination = match op_kind {
            OperationKind::Copy | OperationKind::Move => {
                let base_dir = picked_dest_path.as_ref().ok_or_else(|| {
                    GuiError::Rejected("请先通过原生选择器选择已授权目标目录".to_owned())
                })?;
                let leaf = source
                    .file_name()
                    .ok_or_else(|| GuiError::Rejected("源路径缺少文件名".to_owned()))?;
                Some(base_dir.join(leaf))
            }
            OperationKind::Rename => {
                if multi {
                    return Err(GuiError::Rejected("重命名一次只支持单个对象".to_owned()));
                }
                let new_name = request
                    .destination_relative_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains('\\'))
                    .ok_or_else(|| {
                        GuiError::Rejected("请输入合法的新名称（不含路径分隔符）".to_owned())
                    })?;
                let parent = source
                    .parent()
                    .ok_or_else(|| GuiError::Rejected("无法定位父目录".to_owned()))?;
                Some(parent.join(new_name))
            }
            OperationKind::Quarantine | OperationKind::PermanentDelete => None,
            _ => None,
        };
        requests.push(OperationRequest {
            kind: op_kind,
            source,
            destination,
        });
    }

    let options = PlanOptions {
        include_hidden: request.include_hidden,
        quarantine_retention_days: request.quarantine_retention_days.clamp(1, 36500),
        ..PlanOptions::default()
    };

    let session = state.session.lock().await;
    let plan = session.build_plan(requests, options)?;
    let dto = to_plan_preview_dto(&plan, &session);
    store_active_plan(state, plan, &dto)?;
    Ok(dto)
}

fn resolve_selection_paths(
    report: &ScanReport,
    selection: &SelectionSpec,
    grants_owned: &[Grant],
) -> GuiResult<Vec<PathBuf>> {
    match selection {
        SelectionSpec::Ids { ids, .. } => {
            let wanted: BTreeSet<u64> = ids
                .iter()
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|_| GuiError::Rejected("无效的 entry_id".to_owned()))
                })
                .collect::<GuiResult<_>>()?;
            Ok(report
                .entries
                .iter()
                .filter(|e| wanted.contains(&e.id))
                .map(|e| e.path.clone())
                .collect())
        }
        SelectionSpec::Filtered {
            filter, excludes, ..
        } => {
            let excluded: BTreeSet<u64> = excludes
                .iter()
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|_| GuiError::Rejected("无效的排除 entry_id".to_owned()))
                })
                .collect::<GuiResult<_>>()?;
            let grant_refs: Vec<&Grant> = grants_owned.iter().collect();
            let sens_dirs = compute_sensitive_parent_dirs(report);
            let entries = filter_entries(report, filter, &grant_refs, &sens_dirs)?;
            Ok(entries
                .into_iter()
                .filter(|e| !excluded.contains(&e.id))
                .map(|e| e.path.clone())
                .collect())
        }
    }
}

fn store_active_plan(state: &AppState, plan: Plan, dto: &PlanPreviewDto) -> GuiResult<()> {
    let mut guard = state
        .plan
        .lock()
        .map_err(|_| GuiError::Rejected("计划缓存锁不可用".to_owned()))?;
    guard.active = Some(ActivePlanRecord {
        plan,
        plan_id: dto.plan_id.clone(),
        plan_digest: dto.plan_digest.clone(),
    });
    // Replacing the active plan immediately invalidates any prior permanent challenge.
    guard.permanent_challenge = None;
    Ok(())
}

#[tauri::command]
pub async fn filter_plan_operations(
    state: State<'_, AppState>,
    plan_id: String,
    selected_op_ids: Vec<String>,
) -> GuiResult<PlanPreviewDto> {
    filter_plan_operations_inner(&state, plan_id, selected_op_ids).await
}

pub async fn filter_plan_operations_inner(
    state: &AppState,
    plan_id: String,
    selected_op_ids: Vec<String>,
) -> GuiResult<PlanPreviewDto> {
    let existing = {
        let mut guard = state
            .plan
            .lock()
            .map_err(|_| GuiError::Rejected("计划缓存锁不可用".to_owned()))?;
        let active = guard
            .active
            .take()
            .filter(|a| a.plan_id == plan_id)
            .ok_or(GuiError::PlanMismatch)?;
        guard.permanent_challenge = None;
        active.plan
    };

    let parsed_ids: Vec<Id> = selected_op_ids
        .iter()
        .map(|s| s.parse::<Id>().map_err(GuiError::from))
        .collect::<GuiResult<_>>()?;

    let session = state.session.lock().await;
    let narrowed = session.select_operations(&existing, &parsed_ids)?;
    let dto = to_plan_preview_dto(&narrowed, &session);
    store_active_plan(state, narrowed, &dto)?;
    Ok(dto)
}

#[tauri::command]
pub async fn request_permanent_challenge(
    state: State<'_, AppState>,
    plan_id: String,
    plan_digest: String,
) -> GuiResult<PermanentChallengeDto> {
    request_permanent_challenge_inner(&state, plan_id, plan_digest).await
}

pub async fn request_permanent_challenge_inner(
    state: &AppState,
    plan_id: String,
    plan_digest: String,
) -> GuiResult<PermanentChallengeDto> {
    let now = now_unix_secs()?;
    let challenge_code = generate_challenge_code()?;

    let mut guard = state
        .plan
        .lock()
        .map_err(|_| GuiError::Rejected("计划缓存锁不可用".to_owned()))?;
    let active = guard.active.as_ref().ok_or(GuiError::PlanMismatch)?;
    if active.plan_id != plan_id || active.plan_digest != plan_digest {
        return Err(GuiError::PlanMismatch);
    }
    let preview = active.plan.preview();
    if !preview
        .operations
        .iter()
        .any(|op| op.kind == OperationKind::PermanentDelete)
    {
        return Err(GuiError::Rejected("当前计划不是永久删除计划".to_owned()));
    }
    let expires_at = now
        .saturating_add(PERMANENT_CHALLENGE_TTL_SECS)
        .min(preview.expires_at);
    if expires_at <= now {
        return Err(GuiError::PlanMismatch);
    }
    let confirmation_count = preview.confirmation_count;
    guard.permanent_challenge = Some(PendingPermanentChallenge {
        plan_id: plan_id.clone(),
        plan_digest: plan_digest.clone(),
        challenge_code: challenge_code.clone(),
        confirmation_count,
        expires_at,
    });

    Ok(PermanentChallengeDto {
        plan_id,
        plan_digest,
        challenge_code,
        expected_prefix: "PERMANENT",
        confirmation_count: confirmation_count.to_string(),
        expires_at_unix: expires_at.to_string(),
    })
}

#[tauri::command]
pub async fn confirm_and_execute(
    app: AppHandle,
    state: State<'_, AppState>,
    input: ConfirmAndExecuteInput,
) -> GuiResult<ExecutionReportDto> {
    confirm_and_execute_inner(&state, input, Some(&app)).await
}

pub async fn confirm_and_execute_inner(
    state: &AppState,
    input: ConfirmAndExecuteInput,
    app: Option<&AppHandle>,
) -> GuiResult<ExecutionReportDto> {
    if state
        .exec_in_flight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(GuiError::ExecutionInFlight);
    }
    let _exec_guard = ExecSlotGuard {
        in_flight: state.exec_in_flight.clone(),
        cancel_slot: state.exec_cancel.clone(),
    };

    // Strict B-zone rule: confirm_and_execute only permits `:content` acknowledgements for copying out of B.
    if input
        .sensitive_acknowledgements
        .iter()
        .any(|k| !k.ends_with(":content"))
    {
        return Err(GuiError::Rejected(
            "安全拒绝：sensitive_acknowledgements 仅用于 B 区文件复制出（:content），触及 B 区的任何写操作不可确认放行。".to_owned(),
        ));
    }

    let item_count = match &input.item_count {
        Some(s) => Some(
            s.parse::<u64>()
                .map_err(|_| GuiError::Rejected("核对数量格式无效".to_owned()))?,
        ),
        None => None,
    };

    let (plan, permanent_phrase) = {
        let mut guard = state
            .plan
            .lock()
            .map_err(|_| GuiError::Rejected("计划缓存锁不可用".to_owned()))?;
        let active = guard.active.as_ref().ok_or(GuiError::PlanMismatch)?;
        if active.plan_id != input.plan_id || active.plan_digest != input.plan_digest {
            return Err(GuiError::PlanMismatch);
        }

        let core_preview = active.plan.preview();
        let phrase = if let Some(core_challenge) = &core_preview.permanent_challenge {
            let ch = guard
                .permanent_challenge
                .as_ref()
                .ok_or(GuiError::ChallengeExpired)?;
            let now = now_unix_secs()?;
            if ch.plan_id != input.plan_id
                || ch.plan_digest != input.plan_digest
                || now > ch.expires_at
            {
                guard.permanent_challenge = None;
                return Err(GuiError::ChallengeExpired);
            }
            let expected_gui_phrase =
                format!("PERMANENT {} {}", ch.confirmation_count, ch.challenge_code);
            let supplied = input
                .permanent_challenge_input
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            if supplied != expected_gui_phrase {
                return Err(GuiError::Rejected("永久删除确认短语不匹配".to_owned()));
            }
            Some(format!(
                "PERMANENT {} {core_challenge}",
                core_preview.confirmation_count
            ))
        } else {
            None
        };

        let active = guard.active.take().ok_or(GuiError::PlanMismatch)?;
        guard.permanent_challenge = None;
        (active.plan, phrase)
    };

    let preview_dto = {
        let session = state.session.lock().await;
        to_plan_preview_dto(&plan, &session)
    };

    if !preview_dto.blocked_b_write_reasons.is_empty() {
        return Err(GuiError::Rejected(
            preview_dto.blocked_b_write_reasons.join("；"),
        ));
    }
    if let Some(err) = preview_dto.executable_error {
        return Err(GuiError::Rejected(err));
    }

    let confirmation = Confirmation {
        digest: input.plan_digest,
        item_count,
        sensitive_acknowledgements: input.sensitive_acknowledgements,
        permanent_phrase,
    };

    let cancel = CancellationToken::new();
    if let Ok(mut slot) = state.exec_cancel.lock() {
        *slot = Some(cancel.clone());
    }

    let total_operations = preview_dto.operations.len();
    let batch_id_preview = preview_dto.plan_id.clone();
    let first_op_id = preview_dto.operations.first().map(|op| op.id.clone());
    if let Some(app_handle) = app {
        let _ = app_handle.emit(
            "exec://progress",
            ExecutionProgressPayload {
                batch_id: batch_id_preview,
                completed_operations: 0,
                total_operations,
                current_op_id: first_op_id,
                status: "running".to_owned(),
            },
        );
    }

    let session_arc = state.session.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut session = session_arc.blocking_lock();
        let approved = session.confirm(plan, confirmation)?;
        session.execute_approved(approved, &cancel)
    })
    .await
    .map_err(|_| GuiError::Rejected("执行任务意外终止".to_owned()))??;

    let dto = to_execution_report_dto(&report);
    if let Some(app_handle) = app {
        let _ = app_handle.emit(
            "exec://progress",
            ExecutionProgressPayload {
                batch_id: dto.batch_id.clone(),
                completed_operations: dto.operations.len(),
                total_operations,
                current_op_id: None,
                status: if dto.completed {
                    "completed".to_owned()
                } else {
                    "stopped".to_owned()
                },
            },
        );
    }

    Ok(dto)
}

#[tauri::command]
pub async fn cancel_execution(state: State<'_, AppState>) -> GuiResult<()> {
    if let Ok(slot) = state.exec_cancel.lock()
        && let Some(cancel) = slot.as_ref()
    {
        cancel.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn list_quarantine(
    state: State<'_, AppState>,
    due_only: bool,
) -> GuiResult<Vec<QuarantineItemDto>> {
    let session_arc = state.session.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = session_arc.blocking_lock();
        let items = session.quarantine_items(1000, due_only)?;
        Ok(items.iter().map(to_quarantine_dto).collect())
    })
    .await
    .map_err(|_| GuiError::Rejected("查询隔离区失败".to_owned()))?
}

#[tauri::command]
pub async fn build_restore_plan(
    state: State<'_, AppState>,
    item_ids: Vec<String>,
    destination_grant_id: Option<String>,
    include_hidden: bool,
) -> GuiResult<PlanPreviewDto> {
    let ids: Vec<Id> = item_ids
        .iter()
        .map(|s| s.parse::<Id>().map_err(GuiError::from))
        .collect::<GuiResult<_>>()?;
    let dest_path: Option<PathBuf> = match destination_grant_id {
        Some(gid) => state
            .picked_destinations
            .lock()
            .ok()
            .and_then(|map| map.get(&gid).cloned()),
        None => None,
    };
    let options = PlanOptions {
        include_hidden,
        ..PlanOptions::default()
    };
    let session = state.session.lock().await;
    let plan = session.build_restore_plan(&ids, dest_path.as_deref(), options)?;
    let dto = to_plan_preview_dto(&plan, &session);
    store_active_plan(&state, plan, &dto)?;
    Ok(dto)
}

#[tauri::command]
pub async fn build_purge_plan(
    state: State<'_, AppState>,
    item_ids: Vec<String>,
    include_hidden: bool,
) -> GuiResult<PlanPreviewDto> {
    let ids: Vec<Id> = item_ids
        .iter()
        .map(|s| s.parse::<Id>().map_err(GuiError::from))
        .collect::<GuiResult<_>>()?;
    let options = PlanOptions {
        include_hidden,
        ..PlanOptions::default()
    };
    let session = state.session.lock().await;
    let plan = session.build_purge_plan(&ids, options)?;
    let dto = to_plan_preview_dto(&plan, &session);
    store_active_plan(&state, plan, &dto)?;
    Ok(dto)
}

#[tauri::command]
pub async fn list_history(
    state: State<'_, AppState>,
    limit: usize,
) -> GuiResult<Vec<BatchHistoryDto>> {
    let session_arc = state.session.clone();
    let bounded = limit.clamp(1, 1000);
    tauri::async_runtime::spawn_blocking(move || {
        let session = session_arc.blocking_lock();
        let list = session.history(bounded)?;
        Ok(list.iter().map(to_batch_dto).collect())
    })
    .await
    .map_err(|_| GuiError::Rejected("读取执行历史失败".to_owned()))?
}

#[tauri::command]
pub async fn get_batch_detail(
    state: State<'_, AppState>,
    batch_id: String,
) -> GuiResult<BatchHistoryDetailDto> {
    let id: Id = batch_id.parse()?;
    let session_arc = state.session.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = session_arc.blocking_lock();
        let detail = session.batch_history(&id)?;
        Ok(to_batch_detail_dto(&detail))
    })
    .await
    .map_err(|_| GuiError::Rejected("读取批次详情失败".to_owned()))?
}

#[tauri::command]
pub async fn build_undo_plan(
    state: State<'_, AppState>,
    batch_id: String,
    operation_ids: Vec<String>,
    include_hidden: bool,
    retain_days: u64,
) -> GuiResult<PlanPreviewDto> {
    let batch: Id = batch_id.parse()?;
    let ops: Vec<Id> = operation_ids
        .iter()
        .map(|s| s.parse::<Id>().map_err(GuiError::from))
        .collect::<GuiResult<_>>()?;
    let options = PlanOptions {
        include_hidden,
        quarantine_retention_days: retain_days.clamp(1, 36500),
        ..PlanOptions::default()
    };
    let session = state.session.lock().await;
    let plan = session.build_undo_plan(&batch, &ops, options)?;
    let dto = to_plan_preview_dto(&plan, &session);
    store_active_plan(&state, plan, &dto)?;
    Ok(dto)
}

#[tauri::command]
pub async fn get_recovery_report(state: State<'_, AppState>) -> GuiResult<RecoveryReportDto> {
    let session_arc = state.session.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let session = session_arc.blocking_lock();
        let report = session.recovery_report(None, 200)?;
        Ok(to_recovery_dto(&report))
    })
    .await
    .map_err(|_| GuiError::Rejected("运行恢复诊断失败".to_owned()))?
}
