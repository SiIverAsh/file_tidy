export type EntryId = string;
export type ScanGeneration = string;

export type ZoneKind =
  | "A_Protected"
  | "B_Sensitive"
  | "C_GrantedSession"
  | "C_GrantedPersistent"
  | "Unauthenticated";

export type SensitivityReason =
  | "sensitive_root_ancestor"
  | "sensitive_filename"
  | "hardlink_alias_propagated"
  | "contains_sensitive_child"
  | "conservative_unknown";

export type AllowedAction = "copy_out";

export interface EntryPolicyView {
  zone: ZoneKind;
  protected: boolean;
  sensitive: boolean;
  atomic_root_display: string | null;
  sensitivity_reason: SensitivityReason | null;
  allowed_actions: AllowedAction[];
  blocked_reason: string | null;
}

export type ScanPhase =
  | "discovering"
  | "metadata"
  | "content"
  | "duplicates"
  | "complete";

export interface ScanProgressEvent {
  scan_generation: ScanGeneration;
  phase: ScanPhase;
  discovered: string;
  processed: string;
  content_bytes_read: string;
  errors: string;
}

export interface ExecutionProgressEvent {
  batch_id: string;
  completed_operations: number;
  total_operations: number;
  current_op_id: string | null;
  status: string;
}

export interface ScanSummaryDto {
  scan_generation: ScanGeneration;
  scanned_at_unix: string;
  entries: string;
  files: string;
  directories: string;
  skipped: string;
  logical_bytes: string;
  unique_file_logical_bytes: string;
  unique_allocated_bytes: string | null;
  content_bytes_read: string;
  content_open_operations: string;
  complete: boolean;
  cancelled: boolean;
  limit_reached: boolean;
  top_entry_ids: EntryId[];
  stale_entry_ids: EntryId[];
  duplicates: DuplicateGroupDto[];
  notices: string[];
  root_displays: string[];
}

export interface DuplicateGroupDto {
  group_id: string;
  entry_ids: EntryId[];
  size_bytes: string;
  duplicate_logical_bytes: string;
  blake3_prefix: string;
}

export interface FileEntryDto {
  id: EntryId;
  path_display: string;
  name_display: string;
  kind: "file" | "directory";
  size_bytes: string;
  allocated_bytes: string | null;
  modified_unix: string | null;
  hidden: boolean;
  category: string | null;
  type_evidence: string | null;
  content_inspected: boolean;
  is_stale: boolean;
  policy: EntryPolicyView;
}

export interface SkippedEntryDto {
  path_display: string;
  reason: string;
  detail: string;
  os_error: number | null;
  incomplete: boolean;
}

export type ScanTab = "browse" | "top" | "duplicates" | "stale" | "skipped";

export type SortField = "size_desc" | "name_asc" | "modified_asc";

export interface ScanFilter {
  tab: ScanTab;
  parent_entry_id: EntryId | null;
  search_text: string;
  zone_filter: ZoneKind | "all";
  category_filter: string;
  hide_hidden: boolean;
  duplicate_group_id: string | null;
  skip_reason_filter: string;
}

export interface QueryScanEntriesRequest {
  scan_generation: ScanGeneration;
  filter: ScanFilter;
  sort: SortField;
  offset: number;
  limit: number;
  tree_roots_only?: boolean;
}

export interface QueryScanEntriesResponse {
  scan_generation: ScanGeneration;
  total_count: number;
  offset: number;
  entries: FileEntryDto[];
  skipped: SkippedEntryDto[];
}

export interface TreemapNodeDto {
  id: string;
  entry_id: EntryId | null;
  label_display: string;
  path_display: string;
  logical_bytes: string;
  file_count: string;
  is_other_rollup: boolean;
  drillable: boolean;
  policy: EntryPolicyView | null;
}

export interface TreemapResponse {
  scan_generation: ScanGeneration;
  parent_entry_id: EntryId | null;
  breadcrumbs: Array<{ entry_id: EntryId | null; label_display: string }>;
  total_bytes: string;
  nodes: TreemapNodeDto[];
}

export type SelectionSpec =
  | {
      mode: "ids";
      scan_generation: ScanGeneration;
      ids: EntryId[];
    }
  | {
      mode: "filtered";
      scan_generation: ScanGeneration;
      filter: ScanFilter;
      excludes: EntryId[];
    };

export type OperationKindDto =
  | "copy"
  | "move"
  | "rename"
  | "quarantine"
  | "restore"
  | "undo_copy"
  | "permanent_delete";

export interface ManifestEntryDto {
  path_display: string;
  kind: string;
  size_bytes: string;
  hidden: boolean;
  sensitive: boolean;
  sensitivity_reason: SensitivityReason | null;
  link_target_display: string | null;
}

export interface DestinationDto {
  path_display: string;
  existing_parent_display: string;
  create_directories_display: string[];
  renamed_for_conflict: boolean;
  spelling_temporary_display: string | null;
  copy_temporary_display: string | null;
  copy_metadata: string | null;
}

export interface PlannedOperationDto {
  id: string;
  kind: OperationKindDto;
  source_display: string;
  source_policy: EntryPolicyView;
  destination: DestinationDto | null;
  destination_policy: EntryPolicyView | null;
  manifest: ManifestEntryDto[];
  source_grant_id: string | null;
  destination_grant_id: string | null;
  irreversible: boolean;
}

export interface SensitiveAckDto {
  key: string;
  description: string;
  kind: "copy_out_content";
}

export interface PlanPreviewDto {
  plan_id: string;
  plan_digest: string;
  created_at_unix: string;
  expires_at_unix: string;
  authorization_epoch: string;
  operations: PlannedOperationDto[];
  files_and_links: string;
  directories: string;
  empty_directories: string;
  confirmation_count: string;
  total_bytes: string;
  requires_count_confirmation: boolean;
  sensitive_acknowledgements: SensitiveAckDto[];
  has_permanent_delete: boolean;
  executable_error: string | null;
  blocked_b_write_reasons: string[];
}

export interface BuildPlanRequest {
  kind: "copy" | "move" | "rename" | "quarantine" | "permanent_delete";
  selection: SelectionSpec;
  destination_grant_id: string | null;
  destination_relative_name: string | null;
  include_hidden: boolean;
  quarantine_retention_days: number;
}

export interface PermanentChallengeDto {
  plan_id: string;
  plan_digest: string;
  challenge_code: string;
  expected_prefix: string;
  confirmation_count: string;
  expires_at_unix: string;
}

export interface ConfirmAndExecuteInput {
  plan_id: string;
  plan_digest: string;
  item_count?: string;
  sensitive_acknowledgements: string[];
  permanent_challenge_input?: string;
}

export interface OperationResultDto {
  id: string;
  source_display: string;
  destination_display: string | null;
  temporary_display: string | null;
  status: "done" | "failed" | "needs_recovery" | "not_started" | "cancelled";
  reason: string | null;
}

export interface ExecutionReportDto {
  batch_id: string;
  operations: OperationResultDto[];
  journal_error: string | null;
  completed: boolean;
}

export interface GrantDto {
  id: string;
  root_display: string;
  persistent: boolean;
  revoked: boolean;
}

export interface WorkspaceStatusDto {
  storage_initialized: boolean;
  storage_root_display: string | null;
  authorization_epoch: string;
  grants: GrantDto[];
  pending_recovery_count: number;
  due_quarantine_count: number;
  platform: "linux" | "macos" | "windows" | "other";
}

export interface SuggestedDirectoryDto {
  purpose: string;
  path_display: string;
  policy: EntryPolicyView;
}

export interface SuggestedDirectoriesResponse {
  requires_private_config_consent: boolean;
  consent_reason: string | null;
  items: SuggestedDirectoryDto[];
}

export interface StorageInitPreviewDto {
  grant_id: string;
  directory_display: string;
  objects: string[];
  expires_at_unix: string;
  digest: string;
}

export interface QuarantineItemDto {
  id: string;
  batch_id: string;
  original_path_display: string;
  storage_path_display: string;
  retained_at_unix: string;
  expires_at_unix: string;
  due: boolean;
  state: string;
}

export interface BatchHistoryDto {
  id: string;
  digest: string;
  state: "running" | "completed" | "partial" | "cancelled" | "needs_recovery";
  item_count: string;
  total_bytes: string;
  created_at_unix: string;
  completed_at_unix: string | null;
}

export interface JournalEventDto {
  id: string;
  operation_id: string;
  step: string;
  phase: string;
  created_at_unix: string;
}

export interface OperationHistoryDto {
  id: string;
  ordinal: string;
  kind: string;
  inverse_of: string | null;
  source_display: string;
  destination_display: string | null;
  state: string;
  reason: string | null;
}

export interface BatchHistoryDetailDto {
  batch: BatchHistoryDto;
  operations: OperationHistoryDto[];
  events: JournalEventDto[];
  events_truncated: boolean;
}

export interface RecoveryItemDto {
  batch_id: string;
  operation_id: string;
  source_display: string;
  destination_display: string | null;
  temporary_display: string | null;
  journal_state: string;
  policy_changed: boolean;
  disposition: string;
  reason: string;
}

export interface RecoveryReportDto {
  items: RecoveryItemDto[];
}

export interface PickedScanRootsDto {
  roots_display: string[];
  policies: EntryPolicyView[];
}

export interface PickedRulesFileDto {
  path_display: string | null;
  rule_count: number;
}

export interface PickedDestinationDto {
  grant_id: string | null;
  path_display: string;
  needs_grant: boolean;
  policy: EntryPolicyView;
}
