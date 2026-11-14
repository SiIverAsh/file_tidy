use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use file_tidy_core::authorization::{Grant, Session};
use file_tidy_core::execution::ExecutionReport;
use file_tidy_core::journal::{BatchHistory, BatchHistoryDetail};
use file_tidy_core::plan::{OperationKind, Plan, PlannedOperation};
use file_tidy_core::policy::{Policy, PolicyLabels};
use file_tidy_core::quarantine::QuarantineItem;
use file_tidy_core::recovery::RecoveryReport;
use file_tidy_core::{
    Category, EntryKind, FileEntry, ScanReport, SkipReason, SkippedEntry, display_path,
};
use serde::{Deserialize, Serialize};

use crate::error::{GuiError, GuiResult};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZoneKind {
    #[serde(rename = "A_Protected")]
    AProtected,
    #[serde(rename = "B_Sensitive")]
    BSensitive,
    #[serde(rename = "C_GrantedSession")]
    CGrantedSession,
    #[serde(rename = "C_GrantedPersistent")]
    CGrantedPersistent,
    Unauthenticated,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityReason {
    SensitiveRootAncestor,
    SensitiveFilename,
    HardlinkAliasPropagated,
    ContainsSensitiveChild,
    ConservativeUnknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryPolicyView {
    pub zone: ZoneKind,
    pub protected: bool,
    pub sensitive: bool,
    pub atomic_root_display: Option<String>,
    pub sensitivity_reason: Option<SensitivityReason>,
    pub allowed_actions: Vec<&'static str>,
    pub blocked_reason: Option<String>,
}

pub fn infer_sensitivity_reason(path: &Path, has_sensitive_child: bool) -> SensitivityReason {
    if has_sensitive_child {
        return SensitivityReason::ContainsSensitiveChild;
    }
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        let lower = name.to_ascii_lowercase();
        if lower == ".env"
            || lower.starts_with(".env.")
            || lower.starts_with("id_rsa")
            || lower.starts_with("id_ed25519")
            || lower.starts_with("id_dsa")
            || lower.starts_with("id_ecdsa")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower == "credentials.json"
            || lower == "secrets.json"
        {
            return SensitivityReason::SensitiveFilename;
        }
    }
    SensitivityReason::SensitiveRootAncestor
}

pub fn build_policy_view(
    path: &Path,
    labels: &PolicyLabels,
    grants: &[&Grant],
    has_sensitive_child: bool,
) -> EntryPolicyView {
    let grant_match = grants.iter().find(|g| {
        !g.is_revoked()
            && g.root()
                .to_path()
                .map(|root| path.starts_with(&root))
                .unwrap_or(false)
    });

    let zone = if labels.protected {
        ZoneKind::AProtected
    } else if labels.sensitive || has_sensitive_child {
        ZoneKind::BSensitive
    } else if let Some(grant) = grant_match {
        if grant.is_persistent() {
            ZoneKind::CGrantedPersistent
        } else {
            ZoneKind::CGrantedSession
        }
    } else {
        ZoneKind::Unauthenticated
    };

    let sensitivity_reason = if labels.sensitive || has_sensitive_child {
        Some(infer_sensitivity_reason(path, has_sensitive_child))
    } else {
        None
    };

    let mut allowed_actions = Vec::new();
    let blocked_reason = match zone {
        ZoneKind::AProtected => {
            allowed_actions.push("copy_out");
            Some(
                "位于系统核心保护区（A 区）：禁止一切写入、移动或删除，仅允许复制到已授权 C 区。"
                    .to_owned(),
            )
        }
        ZoneKind::BSensitive => {
            allowed_actions.push("copy_out");
            Some("触及敏感隐私区（B 区）：禁止移动、重命名、隔离或删除；仅支持逐项内容许可后复制到非 B 的 C 区。".to_owned())
        }
        ZoneKind::Unauthenticated => {
            allowed_actions.push("copy_out");
            Some("尚未授予目录写入权限：当前仅支持只读查看或作为复制来源，请先在“授权与设置”授权该目录。".to_owned())
        }
        ZoneKind::CGrantedPersistent | ZoneKind::CGrantedSession => {
            if labels.atomic_root.is_some() {
                Some("属于项目/依赖/应用包受保护整体，不能单独拆开内部文件操作。".to_owned())
            } else {
                None
            }
        }
    };

    EntryPolicyView {
        zone,
        protected: labels.protected,
        sensitive: labels.sensitive || has_sensitive_child,
        atomic_root_display: labels.atomic_root.as_deref().map(display_path),
        sensitivity_reason,
        allowed_actions,
        blocked_reason,
    }
}

pub fn policy_view_for_path(path: &Path, policy: &Policy, session: &Session) -> EntryPolicyView {
    let labels = policy.labels(path);
    let grants: Vec<&Grant> = session.grants().collect();
    build_policy_view(path, &labels, &grants, false)
}

#[derive(Serialize)]
pub struct DuplicateGroupDto {
    pub group_id: String,
    pub entry_ids: Vec<String>,
    pub size_bytes: String,
    pub duplicate_logical_bytes: String,
    pub blake3_prefix: String,
}

#[derive(Serialize)]
pub struct ScanSummaryDto {
    pub scan_generation: String,
    pub scanned_at_unix: String,
    pub entries: String,
    pub files: String,
    pub directories: String,
    pub skipped: String,
    pub logical_bytes: String,
    pub unique_file_logical_bytes: String,
    pub unique_allocated_bytes: Option<String>,
    pub content_bytes_read: String,
    pub content_open_operations: String,
    pub complete: bool,
    pub cancelled: bool,
    pub limit_reached: bool,
    pub top_entry_ids: Vec<String>,
    pub stale_entry_ids: Vec<String>,
    pub duplicates: Vec<DuplicateGroupDto>,
    pub notices: Vec<String>,
    pub root_displays: Vec<String>,
}

pub fn to_scan_summary_dto(
    generation: u64,
    report: &ScanReport,
    root_displays: Vec<String>,
) -> ScanSummaryDto {
    ScanSummaryDto {
        scan_generation: generation.to_string(),
        scanned_at_unix: report.scanned_at.unix_seconds.clone(),
        entries: report.summary.entries.to_string(),
        files: report.summary.files.to_string(),
        directories: report.summary.directories.to_string(),
        skipped: report.summary.skipped.to_string(),
        logical_bytes: report.summary.logical_bytes.to_string(),
        unique_file_logical_bytes: report.summary.unique_file_logical_bytes.to_string(),
        unique_allocated_bytes: report.summary.unique_allocated_bytes.map(|n| n.to_string()),
        content_bytes_read: report.summary.content_bytes_read.to_string(),
        content_open_operations: report.summary.content_open_operations.to_string(),
        complete: report.summary.complete,
        cancelled: report.summary.cancelled,
        limit_reached: report.summary.limit_reached,
        top_entry_ids: report.top_entry_ids.iter().map(u64::to_string).collect(),
        stale_entry_ids: report.stale_entry_ids.iter().map(u64::to_string).collect(),
        duplicates: report
            .duplicates
            .iter()
            .enumerate()
            .map(|(idx, g)| DuplicateGroupDto {
                group_id: format!("dup-{idx}"),
                entry_ids: g.entry_ids.iter().map(u64::to_string).collect(),
                size_bytes: g.size_bytes.to_string(),
                duplicate_logical_bytes: g.duplicate_logical_bytes.to_string(),
                blake3_prefix: g.blake3.chars().take(12).collect(),
            })
            .collect(),
        notices: report.notices.clone(),
        root_displays,
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTab {
    Browse,
    Top,
    Duplicates,
    Stale,
    Skipped,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortField {
    SizeDesc,
    NameAsc,
    ModifiedAsc,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScanFilter {
    pub tab: ScanTab,
    pub parent_entry_id: Option<String>,
    pub search_text: String,
    pub zone_filter: String,
    pub category_filter: String,
    pub hide_hidden: bool,
    pub duplicate_group_id: Option<String>,
    pub skip_reason_filter: String,
}

#[derive(Deserialize)]
pub struct QueryScanEntriesRequest {
    pub scan_generation: String,
    pub filter: ScanFilter,
    pub sort: SortField,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Serialize)]
pub struct FileEntryDto {
    pub id: String,
    pub path_display: String,
    pub name_display: String,
    pub kind: &'static str,
    pub size_bytes: String,
    pub allocated_bytes: Option<String>,
    pub modified_unix: Option<String>,
    pub hidden: bool,
    pub category: Option<&'static str>,
    pub type_evidence: Option<String>,
    pub content_inspected: bool,
    pub is_stale: bool,
    pub policy: EntryPolicyView,
}

#[derive(Serialize)]
pub struct SkippedEntryDto {
    pub path_display: String,
    pub reason: String,
    pub detail: String,
    pub os_error: Option<i32>,
    pub incomplete: bool,
}

#[derive(Serialize)]
pub struct QueryScanEntriesResponse {
    pub scan_generation: String,
    pub total_count: usize,
    pub offset: usize,
    pub entries: Vec<FileEntryDto>,
    pub skipped: Vec<SkippedEntryDto>,
}

pub fn entry_name_display(path: &Path) -> String {
    path.file_name()
        .map(|s| file_tidy_core::escape_text(&s.to_string_lossy()))
        .unwrap_or_else(|| display_path(path))
}

pub fn to_file_entry_dto(
    entry: &FileEntry,
    grants: &[&Grant],
    stale_set: &BTreeSet<u64>,
    sensitive_dirs: &BTreeSet<std::path::PathBuf>,
) -> FileEntryDto {
    let has_sensitive_child =
        entry.kind == EntryKind::Directory && sensitive_dirs.contains(&entry.path);
    let policy = build_policy_view(&entry.path, &entry.policy, grants, has_sensitive_child);
    FileEntryDto {
        id: entry.id.to_string(),
        path_display: display_path(&entry.path),
        name_display: entry_name_display(&entry.path),
        kind: match entry.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
        },
        size_bytes: entry.size_bytes.to_string(),
        allocated_bytes: entry.allocated_bytes.map(|n| n.to_string()),
        modified_unix: entry.modified.as_ref().map(|m| m.unix_seconds.clone()),
        hidden: entry.hidden,
        category: entry.classification.as_ref().map(|c| c.category.as_str()),
        type_evidence: entry
            .classification
            .as_ref()
            .map(|c| format!("{:?}", c.evidence)),
        content_inspected: entry.content_inspected,
        is_stale: stale_set.contains(&entry.id),
        policy,
    }
}

pub fn skip_reason_label(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::PermissionDenied => "permission_denied",
        SkipReason::Io => "io",
        SkipReason::Symlink => "symlink",
        SkipReason::ReparsePoint => "reparse_point",
        SkipReason::SpecialNode => "special_node",
        SkipReason::MountBoundary => "mount_boundary",
        SkipReason::RemoteFilesystem => "remote_filesystem",
        SkipReason::VirtualFilesystem => "virtual_filesystem",
        SkipReason::UnknownFilesystem => "unknown_filesystem",
        SkipReason::SensitiveContent => "sensitive_content",
        SkipReason::MetadataOnly => "metadata_only",
        SkipReason::ChangedDuringRead => "changed_during_read",
        SkipReason::IdentityUnavailable => "identity_unavailable",
        SkipReason::InvalidRoot => "invalid_root",
        SkipReason::PathAlias => "path_alias",
    }
}

pub fn to_skipped_dto(entry: &SkippedEntry) -> SkippedEntryDto {
    SkippedEntryDto {
        path_display: display_path(&entry.path),
        reason: skip_reason_label(entry.reason).to_owned(),
        detail: file_tidy_core::escape_text(&entry.detail),
        os_error: entry.os_error,
        incomplete: entry.incomplete,
    }
}

pub fn compute_sensitive_parent_dirs(report: &ScanReport) -> BTreeSet<std::path::PathBuf> {
    let mut dirs = BTreeSet::new();
    for entry in &report.entries {
        if entry.policy.sensitive {
            for anc in entry.path.ancestors().skip(1) {
                if !dirs.insert(anc.to_path_buf()) {
                    break;
                }
            }
        }
    }
    dirs
}

pub fn filter_entries<'a>(
    report: &'a ScanReport,
    filter: &ScanFilter,
    grants: &[&Grant],
    sensitive_dirs: &BTreeSet<std::path::PathBuf>,
) -> GuiResult<Vec<&'a FileEntry>> {
    let mut base: Vec<&FileEntry> = match filter.tab {
        ScanTab::Top => {
            let map: BTreeMap<u64, &FileEntry> = report.entries.iter().map(|e| (e.id, e)).collect();
            report
                .top_entry_ids
                .iter()
                .filter_map(|id| map.get(id).copied())
                .collect()
        }
        ScanTab::Stale => {
            let stale_ids: BTreeSet<u64> = report.stale_entry_ids.iter().copied().collect();
            report
                .entries
                .iter()
                .filter(|e| stale_ids.contains(&e.id))
                .collect()
        }
        ScanTab::Duplicates => {
            let mut ids = BTreeSet::new();
            if let Some(grp_id) = &filter.duplicate_group_id {
                if let Some(idx) = grp_id
                    .strip_prefix("dup-")
                    .and_then(|s| s.parse::<usize>().ok())
                    && let Some(group) = report.duplicates.get(idx)
                {
                    ids.extend(group.entry_ids.iter().copied());
                }
            } else {
                for g in &report.duplicates {
                    ids.extend(g.entry_ids.iter().copied());
                }
            }
            report
                .entries
                .iter()
                .filter(|e| ids.contains(&e.id))
                .collect()
        }
        ScanTab::Browse => {
            if let Some(parent_id_str) = &filter.parent_entry_id {
                let parent_id = parent_id_str
                    .parse::<u64>()
                    .map_err(|_| GuiError::Rejected("无效的父目录 entry_id".to_owned()))?;
                let parent_path = report
                    .entries
                    .iter()
                    .find(|e| e.id == parent_id)
                    .map(|e| e.path.as_path())
                    .ok_or_else(|| GuiError::Rejected("找不到父目录条目".to_owned()))?;
                report
                    .entries
                    .iter()
                    .filter(|e| e.path.parent() == Some(parent_path))
                    .collect()
            } else {
                report.entries.iter().collect()
            }
        }
        ScanTab::Skipped => Vec::new(),
    };

    let search = filter.search_text.trim().to_ascii_lowercase();
    base.retain(|entry| {
        if filter.hide_hidden && entry.hidden {
            return false;
        }
        if !search.is_empty() {
            let disp = display_path(&entry.path).to_ascii_lowercase();
            if !disp.contains(&search) {
                return false;
            }
        }
        if filter.category_filter != "all" {
            let cat = entry
                .classification
                .as_ref()
                .map(|c| c.category.as_str())
                .unwrap_or("other");
            if cat != filter.category_filter {
                return false;
            }
        }
        if filter.zone_filter != "all" {
            let has_sens =
                entry.kind == EntryKind::Directory && sensitive_dirs.contains(&entry.path);
            let pv = build_policy_view(&entry.path, &entry.policy, grants, has_sens);
            let zone_str = match pv.zone {
                ZoneKind::AProtected => "A_Protected",
                ZoneKind::BSensitive => "B_Sensitive",
                ZoneKind::CGrantedSession => "C_GrantedSession",
                ZoneKind::CGrantedPersistent => "C_GrantedPersistent",
                ZoneKind::Unauthenticated => "Unauthenticated",
            };
            if zone_str != filter.zone_filter {
                return false;
            }
        }
        true
    });

    Ok(base)
}

#[derive(Serialize)]
pub struct TreemapNodeDto {
    pub id: String,
    pub entry_id: Option<String>,
    pub label_display: String,
    pub path_display: String,
    pub logical_bytes: String,
    pub file_count: String,
    pub is_other_rollup: bool,
    pub drillable: bool,
    pub policy: Option<EntryPolicyView>,
}

#[derive(Serialize)]
pub struct BreadcrumbDto {
    pub entry_id: Option<String>,
    pub label_display: String,
}

#[derive(Serialize)]
pub struct TreemapResponse {
    pub scan_generation: String,
    pub parent_entry_id: Option<String>,
    pub breadcrumbs: Vec<BreadcrumbDto>,
    pub total_bytes: String,
    pub nodes: Vec<TreemapNodeDto>,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SelectionSpec {
    Ids {
        scan_generation: String,
        ids: Vec<String>,
    },
    Filtered {
        scan_generation: String,
        filter: ScanFilter,
        excludes: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanActionKindDto {
    Copy,
    Move,
    Rename,
    Quarantine,
    PermanentDelete,
}

#[derive(Deserialize)]
pub struct BuildPlanRequest {
    pub kind: PlanActionKindDto,
    pub selection: SelectionSpec,
    pub destination_grant_id: Option<String>,
    pub destination_relative_name: Option<String>,
    pub include_hidden: bool,
    pub quarantine_retention_days: u64,
}

#[derive(Serialize)]
pub struct ManifestEntryDto {
    pub path_display: String,
    pub kind: String,
    pub size_bytes: String,
    pub hidden: bool,
    pub sensitive: bool,
    pub sensitivity_reason: Option<SensitivityReason>,
    pub link_target_display: Option<String>,
}

#[derive(Serialize)]
pub struct DestinationDto {
    pub path_display: String,
    pub existing_parent_display: String,
    pub create_directories_display: Vec<String>,
    pub renamed_for_conflict: bool,
    pub spelling_temporary_display: Option<String>,
    pub copy_temporary_display: Option<String>,
    pub copy_metadata: Option<&'static str>,
}

#[derive(Serialize)]
pub struct PlannedOperationDto {
    pub id: String,
    pub kind: OperationKind,
    pub source_display: String,
    pub source_policy: EntryPolicyView,
    pub destination: Option<DestinationDto>,
    pub destination_policy: Option<EntryPolicyView>,
    pub manifest: Vec<ManifestEntryDto>,
    pub source_grant_id: Option<String>,
    pub destination_grant_id: Option<String>,
    pub irreversible: bool,
}

#[derive(Serialize)]
pub struct SensitiveAckDto {
    pub key: String,
    pub description: String,
    pub kind: &'static str,
}

#[derive(Serialize)]
pub struct PlanPreviewDto {
    pub plan_id: String,
    pub plan_digest: String,
    pub created_at_unix: String,
    pub expires_at_unix: String,
    pub authorization_epoch: String,
    pub operations: Vec<PlannedOperationDto>,
    pub files_and_links: String,
    pub directories: String,
    pub empty_directories: String,
    pub confirmation_count: String,
    pub total_bytes: String,
    pub requires_count_confirmation: bool,
    pub sensitive_acknowledgements: Vec<SensitiveAckDto>,
    pub has_permanent_delete: bool,
    pub executable_error: Option<String>,
    pub blocked_b_write_reasons: Vec<String>,
}

/// Evaluates strict GUI B-zone policy:
/// - Any `:write` acknowledgement or non-copy-out B-zone operation is rejected and listed in `blocked_b_write_reasons`.
/// - Only `:content` acknowledgements on `Copy` / `UndoCopy` (copying out of B into non-B C) are surfaced as confirmable.
pub fn to_plan_preview_dto(plan: &Plan, session: &Session) -> PlanPreviewDto {
    let preview = plan.preview();
    let policy = Policy::new();
    let grants: Vec<&Grant> = session.grants().collect();

    let mut blocked_b_write_reasons = Vec::new();
    let mut sensitive_acknowledgements = Vec::new();

    for key in &preview.sensitive_acknowledgements {
        if key.ends_with(":write") {
            let desc = plan
                .acknowledgement_description(key)
                .unwrap_or_else(|_| key.clone());
            blocked_b_write_reasons.push(format!(
                "拒绝写入或修改 B 区敏感对象（仅允许从 B 复制出到非 B 的 C 目录）：{desc}"
            ));
        } else if key.ends_with(":content") {
            let desc = plan
                .acknowledgement_description(key)
                .unwrap_or_else(|_| key.clone());
            sensitive_acknowledgements.push(SensitiveAckDto {
                key: key.clone(),
                description: desc,
                kind: "copy_out_content",
            });
        }
    }

    let operations: Vec<PlannedOperationDto> = preview
        .operations
        .iter()
        .map(|op| {
            let destination_prefix = format!("{}:destination", op.id);
            let destination_sensitive = preview
                .sensitive_acknowledgements
                .iter()
                .any(|key| key.starts_with(&destination_prefix) && key.ends_with(":write"));
            to_planned_op_dto(
                op,
                &policy,
                &grants,
                destination_sensitive,
                &mut blocked_b_write_reasons,
            )
        })
        .collect();

    let executable_error = session
        .validate_executable(plan)
        .err()
        .map(|e| e.to_string());

    PlanPreviewDto {
        plan_id: preview.id.to_string(),
        plan_digest: plan.digest().to_owned(),
        created_at_unix: preview.created_at.to_string(),
        expires_at_unix: preview.expires_at.to_string(),
        authorization_epoch: preview.authorization_epoch.to_string(),
        operations,
        files_and_links: preview.files_and_links.to_string(),
        directories: preview.directories.to_string(),
        empty_directories: preview.empty_directories.to_string(),
        confirmation_count: preview.confirmation_count.to_string(),
        total_bytes: preview.total_bytes.clone(),
        requires_count_confirmation: preview.requires_count_confirmation,
        sensitive_acknowledgements,
        has_permanent_delete: preview
            .operations
            .iter()
            .any(|op| op.kind == OperationKind::PermanentDelete),
        executable_error,
        blocked_b_write_reasons,
    }
}

fn to_planned_op_dto(
    op: &PlannedOperation,
    policy: &Policy,
    grants: &[&Grant],
    destination_sensitive: bool,
    blocked_b_write_reasons: &mut Vec<String>,
) -> PlannedOperationDto {
    let source_path = op.source.to_path().ok();
    let source_labels = source_path
        .as_deref()
        .map(|p| policy.labels(p))
        .unwrap_or_default();
    let has_sensitive_child = op.manifest.iter().any(|m| m.sensitive);

    if has_sensitive_child && !matches!(op.kind, OperationKind::Copy | OperationKind::UndoCopy) {
        blocked_b_write_reasons.push(format!(
            "操作 {:?} 涉及 B 区敏感项（{}），核心策略禁止对 B 区执行写/移动/隔离/永久删除。",
            op.kind, op.source.display
        ));
    }

    let source_policy = match source_path.as_deref() {
        Some(p) => build_policy_view(p, &source_labels, grants, has_sensitive_child),
        None => EntryPolicyView {
            zone: ZoneKind::Unauthenticated,
            protected: false,
            sensitive: has_sensitive_child,
            atomic_root_display: None,
            sensitivity_reason: has_sensitive_child
                .then_some(SensitivityReason::ContainsSensitiveChild),
            allowed_actions: Vec::new(),
            blocked_reason: Some("无法解析源路径".to_owned()),
        },
    };

    let (destination, destination_policy) = match &op.destination {
        Some(d) => {
            let dest_path = d.path.to_path().ok();
            let dest_pol = dest_path.as_deref().map(|p| {
                // New destinations do not exist yet. Inspect the reviewed parent;
                // core acknowledgements retain sensitivity of new target names.
                let mut lbl = d
                    .existing_parent
                    .to_path()
                    .map(|parent| policy.labels(&parent))
                    .unwrap_or_else(|_| policy.labels(p));
                lbl.sensitive |= destination_sensitive;
                if lbl.sensitive {
                    blocked_b_write_reasons.push(format!(
                        "目标路径位于 B 敏感区，禁止写入：{}",
                        d.path.display
                    ));
                }
                build_policy_view(p, &lbl, grants, false)
            });
            let dto = DestinationDto {
                path_display: d.path.display.clone(),
                existing_parent_display: d.existing_parent.display.clone(),
                create_directories_display: d
                    .create_directories
                    .iter()
                    .map(|p| p.display.clone())
                    .collect(),
                renamed_for_conflict: d.renamed_for_conflict,
                spelling_temporary_display: d
                    .spelling_temporary
                    .as_ref()
                    .map(|p| p.display.clone()),
                copy_temporary_display: d.copy_temporary.as_ref().map(|p| p.display.clone()),
                copy_metadata: d.copy_metadata.map(|_| "private_data_stream_and_mtime"),
            };
            (Some(dto), dest_pol)
        }
        None => (None, None),
    };

    let manifest = op
        .manifest
        .iter()
        .map(|m| {
            let reason = if m.sensitive {
                m.path
                    .to_path()
                    .ok()
                    .map(|p| infer_sensitivity_reason(&p, false))
                    .or(Some(SensitivityReason::SensitiveRootAncestor))
            } else {
                None
            };
            ManifestEntryDto {
                path_display: m.path.display.clone(),
                kind: m.kind.clone(),
                size_bytes: m.size_bytes.clone(),
                hidden: m.hidden,
                sensitive: m.sensitive,
                sensitivity_reason: reason,
                link_target_display: m.link_target.as_ref().map(|t| t.display.clone()),
            }
        })
        .collect();

    PlannedOperationDto {
        id: op.id.to_string(),
        kind: op.kind,
        source_display: op.source.display.clone(),
        source_policy,
        destination,
        destination_policy,
        manifest,
        source_grant_id: op.source_grant.as_ref().map(ToString::to_string),
        destination_grant_id: op.destination_grant.as_ref().map(ToString::to_string),
        irreversible: op.kind == OperationKind::PermanentDelete,
    }
}

#[derive(Serialize)]
pub struct PermanentChallengeDto {
    pub plan_id: String,
    pub plan_digest: String,
    pub challenge_code: String,
    pub expected_prefix: &'static str,
    pub confirmation_count: String,
    pub expires_at_unix: String,
}

#[derive(Deserialize)]
pub struct ConfirmAndExecuteInput {
    pub plan_id: String,
    pub plan_digest: String,
    pub item_count: Option<String>,
    pub sensitive_acknowledgements: Vec<String>,
    pub permanent_challenge_input: Option<String>,
}

#[derive(Serialize)]
pub struct OperationResultDto {
    pub id: String,
    pub source_display: String,
    pub destination_display: Option<String>,
    pub temporary_display: Option<String>,
    pub status: file_tidy_core::execution::ExecutionStatus,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct ExecutionReportDto {
    pub batch_id: String,
    pub operations: Vec<OperationResultDto>,
    pub journal_error: Option<String>,
    pub completed: bool,
}

pub fn to_execution_report_dto(report: &ExecutionReport) -> ExecutionReportDto {
    ExecutionReportDto {
        batch_id: report.batch_id.to_string(),
        completed: report.completed(),
        journal_error: report.journal_error.clone(),
        operations: report
            .operations
            .iter()
            .map(|op| OperationResultDto {
                id: op.id.to_string(),
                source_display: op.source.display.clone(),
                destination_display: op.destination.as_ref().map(|d| d.display.clone()),
                temporary_display: op.temporary.as_ref().map(|t| t.display.clone()),
                status: op.status,
                reason: op.reason.clone(),
            })
            .collect(),
    }
}

#[derive(Serialize)]
pub struct GrantDto {
    pub id: String,
    pub root_display: String,
    pub persistent: bool,
    pub revoked: bool,
}

#[derive(Serialize)]
pub struct WorkspaceStatusDto {
    pub storage_initialized: bool,
    pub storage_root_display: Option<String>,
    pub authorization_epoch: String,
    pub grants: Vec<GrantDto>,
    pub pending_recovery_count: usize,
    pub due_quarantine_count: usize,
    pub platform: &'static str,
}

#[derive(Serialize)]
pub struct SuggestedDirectoryDto {
    pub purpose: &'static str,
    pub path_display: String,
    pub policy: EntryPolicyView,
}

#[derive(Serialize)]
pub struct SuggestedDirectoriesResponse {
    pub requires_private_config_consent: bool,
    pub consent_reason: Option<String>,
    pub items: Vec<SuggestedDirectoryDto>,
}

#[derive(Serialize)]
pub struct StorageInitPreviewDto {
    pub grant_id: String,
    pub directory_display: String,
    pub objects: Vec<&'static str>,
    pub expires_at_unix: String,
    pub digest: String,
}

#[derive(Serialize)]
pub struct QuarantineItemDto {
    pub id: String,
    pub batch_id: String,
    pub original_path_display: String,
    pub storage_path_display: String,
    pub retained_at_unix: String,
    pub expires_at_unix: String,
    pub due: bool,
    pub state: String,
}

pub fn to_quarantine_dto(item: &QuarantineItem) -> QuarantineItemDto {
    QuarantineItemDto {
        id: item.id.to_string(),
        batch_id: item.batch_id.to_string(),
        original_path_display: item.original_path.display.clone(),
        storage_path_display: item.storage_path.display.clone(),
        retained_at_unix: item.retained_at.to_string(),
        expires_at_unix: item.expires_at.to_string(),
        due: item.due,
        state: item.state.clone(),
    }
}

#[derive(Serialize)]
pub struct BatchHistoryDto {
    pub id: String,
    pub digest: String,
    pub state: file_tidy_core::journal::BatchState,
    pub item_count: String,
    pub total_bytes: String,
    pub created_at_unix: String,
    pub completed_at_unix: Option<String>,
}

pub fn to_batch_dto(b: &BatchHistory) -> BatchHistoryDto {
    BatchHistoryDto {
        id: b.id.clone(),
        digest: b.digest.clone(),
        state: b.state,
        item_count: b.item_count.to_string(),
        total_bytes: b.total_bytes.clone(),
        created_at_unix: b.created_at.to_string(),
        completed_at_unix: b.completed_at.map(|n| n.to_string()),
    }
}

#[derive(Serialize)]
pub struct OperationHistoryDto {
    pub id: String,
    pub ordinal: String,
    pub kind: String,
    pub inverse_of: Option<String>,
    pub source_display: String,
    pub destination_display: Option<String>,
    pub state: String,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct JournalEventDto {
    pub id: String,
    pub operation_id: String,
    pub step: String,
    pub phase: String,
    pub created_at_unix: String,
}

#[derive(Serialize)]
pub struct BatchHistoryDetailDto {
    pub batch: BatchHistoryDto,
    pub operations: Vec<OperationHistoryDto>,
    pub events: Vec<JournalEventDto>,
    pub events_truncated: bool,
}

pub fn to_batch_detail_dto(d: &BatchHistoryDetail) -> BatchHistoryDetailDto {
    BatchHistoryDetailDto {
        batch: to_batch_dto(&d.batch),
        operations: d
            .operations
            .iter()
            .map(|op| OperationHistoryDto {
                id: op.id.clone(),
                ordinal: op.ordinal.to_string(),
                kind: op.kind.clone(),
                inverse_of: op.inverse_of.clone(),
                source_display: op.source.display.clone(),
                destination_display: op.destination.as_ref().map(|dst| dst.display.clone()),
                state: format!("{:?}", op.state).to_ascii_lowercase(),
                reason: op.reason.clone(),
            })
            .collect(),
        events: d
            .events
            .iter()
            .map(|ev| JournalEventDto {
                id: ev.id.to_string(),
                operation_id: ev.operation_id.clone(),
                step: ev.step.clone(),
                phase: ev.phase.clone(),
                created_at_unix: ev.created_at.to_string(),
            })
            .collect(),
        events_truncated: d.events_truncated,
    }
}

#[derive(Serialize)]
pub struct RecoveryItemDto {
    pub batch_id: String,
    pub operation_id: String,
    pub source_display: String,
    pub destination_display: Option<String>,
    pub temporary_display: Option<String>,
    pub journal_state: String,
    pub policy_changed: bool,
    pub disposition: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct RecoveryReportDto {
    pub items: Vec<RecoveryItemDto>,
}

pub fn to_recovery_dto(report: &RecoveryReport) -> RecoveryReportDto {
    RecoveryReportDto {
        items: report
            .items
            .iter()
            .map(|item| RecoveryItemDto {
                batch_id: item.batch_id.clone(),
                operation_id: item.operation_id.clone(),
                source_display: item.source.display.clone(),
                destination_display: item.destination.as_ref().map(|d| d.display.clone()),
                temporary_display: item.temporary.as_ref().map(|t| t.display.clone()),
                journal_state: format!("{:?}", item.journal_state),
                policy_changed: item.policy_changed,
                disposition: format!("{:?}", item.disposition),
                reason: item.reason.clone(),
            })
            .collect(),
    }
}

#[derive(Serialize)]
pub struct PickedScanRootsDto {
    pub roots_display: Vec<String>,
    pub policies: Vec<EntryPolicyView>,
}

#[derive(Serialize)]
pub struct PickedRulesFileDto {
    pub path_display: Option<String>,
    pub rule_count: usize,
}

#[derive(Serialize)]
pub struct PickedDestinationDto {
    pub grant_id: Option<String>,
    pub path_display: String,
    pub needs_grant: bool,
    pub policy: EntryPolicyView,
}

pub fn category_str_matches(_cat: Category) -> bool {
    true
}
