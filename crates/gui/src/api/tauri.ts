import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  BatchHistoryDetailDto,
  BatchHistoryDto,
  BuildPlanRequest,
  ConfirmAndExecuteInput,
  ExecutionProgressEvent,
  ExecutionReportDto,
  GrantDto,
  PermanentChallengeDto,
  PickedDestinationDto,
  PickedRulesFileDto,
  PickedScanRootsDto,
  PlanPreviewDto,
  QuarantineItemDto,
  QueryScanEntriesRequest,
  QueryScanEntriesResponse,
  RecoveryReportDto,
  ScanGeneration,
  ScanProgressEvent,
  ScanSummaryDto,
  StorageInitPreviewDto,
  SuggestedDirectoriesResponse,
  TreemapResponse,
  WorkspaceStatusDto,
} from "./types.ts";

export interface StartScanRequest {
  all_volumes: boolean;
  metadata_only: boolean;
  no_duplicates: boolean;
  stale_days: number;
  max_entries: number;
}

export interface ApiClient {
  pickScanRoots(): Promise<PickedScanRootsDto>;
  pickRulesFile(): Promise<PickedRulesFileDto>;
  startScan(req: StartScanRequest): Promise<ScanSummaryDto>;
  cancelScan(): Promise<void>;
  queryScanEntries(req: QueryScanEntriesRequest): Promise<QueryScanEntriesResponse>;
  getTreemapNodes(
    scanGeneration: ScanGeneration,
    parentEntryId: string | null,
    maxNodes?: number,
  ): Promise<TreemapResponse>;

  getWorkspaceStatus(): Promise<WorkspaceStatusDto>;
  getSuggestedDirectories(allowPrivateConfig: boolean): Promise<SuggestedDirectoriesResponse>;
  pickAndPreviewGrant(): Promise<GrantDto | null>;
  confirmGrant(grantId: string, persistent: boolean): Promise<WorkspaceStatusDto>;
  revokeGrant(grantId: string): Promise<WorkspaceStatusDto>;
  pickAndPreviewStorageInit(): Promise<StorageInitPreviewDto | null>;
  confirmStorageInit(grantId: string, digest: string): Promise<WorkspaceStatusDto>;
  openExistingStorage(): Promise<WorkspaceStatusDto>;
  pickDestinationDirectory(): Promise<PickedDestinationDto | null>;

  buildPlanFromSelection(req: BuildPlanRequest): Promise<PlanPreviewDto>;
  filterPlanOperations(planId: string, selectedOpIds: string[]): Promise<PlanPreviewDto>;
  requestPermanentChallenge(
    planId: string,
    planDigest: string,
  ): Promise<PermanentChallengeDto>;
  confirmAndExecute(input: ConfirmAndExecuteInput): Promise<ExecutionReportDto>;
  cancelExecution(): Promise<void>;

  listQuarantine(dueOnly: boolean): Promise<QuarantineItemDto[]>;
  buildRestorePlan(
    itemIds: string[],
    destinationGrantId: string | null,
    includeHidden: boolean,
  ): Promise<PlanPreviewDto>;
  buildPurgePlan(itemIds: string[], includeHidden: boolean): Promise<PlanPreviewDto>;
  listHistory(limit: number): Promise<BatchHistoryDto[]>;
  getBatchDetail(batchId: string): Promise<BatchHistoryDetailDto>;
  buildUndoPlan(
    batchId: string,
    operationIds: string[],
    includeHidden: boolean,
    retainDays: number,
  ): Promise<PlanPreviewDto>;
  getRecoveryReport(): Promise<RecoveryReportDto>;

  onScanProgress(cb: (ev: ScanProgressEvent) => void): Promise<UnlistenFn>;
  onExecutionProgress(cb: (ev: ExecutionProgressEvent) => void): Promise<UnlistenFn>;
}

export const tauriApi: ApiClient = {
  pickScanRoots: () => invoke("pick_scan_roots"),
  pickRulesFile: () => invoke("pick_rules_file"),
  startScan: (req) => invoke("start_scan", { request: req }),
  cancelScan: () => invoke("cancel_scan"),
  queryScanEntries: (req) => invoke("query_scan_entries", { request: req }),
  getTreemapNodes: (scanGeneration, parentEntryId, maxNodes = 40) =>
    invoke("get_treemap_nodes", {
      scanGeneration,
      parentEntryId,
      maxNodes,
    }),

  getWorkspaceStatus: () => invoke("get_workspace_status"),
  getSuggestedDirectories: (allowPrivateConfig) =>
    invoke("get_suggested_directories", { allowPrivateConfig }),
  pickAndPreviewGrant: () => invoke("pick_and_preview_grant"),
  confirmGrant: (grantId, persistent) =>
    invoke("confirm_grant", { grantId, persistent }),
  revokeGrant: (grantId) => invoke("revoke_grant", { grantId }),
  pickAndPreviewStorageInit: () => invoke("pick_and_preview_storage_init"),
  confirmStorageInit: (grantId, digest) =>
    invoke("confirm_storage_init", { grantId, digest }),
  openExistingStorage: () => invoke("open_existing_storage"),
  pickDestinationDirectory: () => invoke("pick_destination_directory"),

  buildPlanFromSelection: (req) => invoke("build_plan_from_selection", { request: req }),
  filterPlanOperations: (planId, selectedOpIds) =>
    invoke("filter_plan_operations", { planId, selectedOpIds }),
  requestPermanentChallenge: (planId, planDigest) =>
    invoke("request_permanent_challenge", { planId, planDigest }),
  confirmAndExecute: (input) => invoke("confirm_and_execute", { input }),
  cancelExecution: () => invoke("cancel_execution"),

  listQuarantine: (dueOnly) => invoke("list_quarantine", { dueOnly }),
  buildRestorePlan: (itemIds, destinationGrantId, includeHidden) =>
    invoke("build_restore_plan", {
      itemIds,
      destinationGrantId,
      includeHidden,
    }),
  buildPurgePlan: (itemIds, includeHidden) =>
    invoke("build_purge_plan", { itemIds, includeHidden }),
  listHistory: (limit) => invoke("list_history", { limit }),
  getBatchDetail: (batchId) => invoke("get_batch_detail", { batchId }),
  buildUndoPlan: (batchId, operationIds, includeHidden, retainDays) =>
    invoke("build_undo_plan", {
      batchId,
      operationIds,
      includeHidden,
      retainDays,
    }),
  getRecoveryReport: () => invoke("get_recovery_report"),

  onScanProgress: (cb) => listen<ScanProgressEvent>("scan://progress", (e) => cb(e.payload)),
  onExecutionProgress: (cb) =>
    listen<ExecutionProgressEvent>("exec://progress", (e) => cb(e.payload)),
};
