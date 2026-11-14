import type {
  BatchHistoryDetailDto,
  BatchHistoryDto,
  EntryId,
  ExecutionProgressEvent,
  ExecutionReportDto,
  FileEntryDto,
  PermanentChallengeDto,
  PickedRulesFileDto,
  PickedScanRootsDto,
  PlanPreviewDto,
  QuarantineItemDto,
  RecoveryReportDto,
  ScanFilter,
  ScanProgressEvent,
  ScanSummaryDto,
  SelectionSpec,
  SortField,
  StorageInitPreviewDto,
  SuggestedDirectoriesResponse,
  TreemapResponse,
  WorkspaceStatusDto,
} from "../api/types.ts";

export type MainView = "explore" | "safety" | "access";
export type SafetySubTab = "quarantine" | "history" | "recovery";

export interface AppStateModel {
  view: MainView;
  globalError: string | null;
  workspace: WorkspaceStatusDto | null;

  pendingRoots: PickedScanRootsDto | null;
  rulesFile: PickedRulesFileDto | null;
  scanOptions: {
    all_volumes: boolean;
    metadata_only: boolean;
    no_duplicates: boolean;
    stale_days: number;
    max_entries: number;
  };
  scanning: boolean;
  scanProgress: ScanProgressEvent | null;
  scanSummary: ScanSummaryDto | null;
  scanFilter: ScanFilter;
  scanSort: SortField;
  selection: SelectionSpec;
  totalFilteredCount: number;
  treemap: TreemapResponse | null;
  hoveredTreemapEntryId: EntryId | null;
  inspectedEntry: FileEntryDto | null;

  planDrawer: {
    open: boolean;
    loading: boolean;
    preview: PlanPreviewDto | null;
    selectedOpIds: Set<string>;
    itemCountInput: string;
    acknowledgedContentKeys: Set<string>;
    executing: boolean;
    execProgress: ExecutionProgressEvent | null;
    executionReport: ExecutionReportDto | null;
    error: string | null;
  };

  permanentModal: {
    open: boolean;
    loading: boolean;
    preview: PlanPreviewDto | null;
    challenge: PermanentChallengeDto | null;
    phraseInput: string;
    countInput: string;
    executing: boolean;
    executionReport: ExecutionReportDto | null;
    error: string | null;
  };

  safety: {
    tab: SafetySubTab;
    dueOnly: boolean;
    quarantineItems: QuarantineItemDto[];
    selectedQuarantineIds: Set<string>;
    historyBatches: BatchHistoryDto[];
    selectedBatchDetail: BatchHistoryDetailDto | null;
    recoveryReport: RecoveryReportDto | null;
  };

  access: {
    suggested: SuggestedDirectoriesResponse | null;
    allowPrivateConfig: boolean;
    pendingGrant: { id: string; root_display: string } | null;
    pendingStorageInit: StorageInitPreviewDto | null;
  };
}

export function defaultFilter(): ScanFilter {
  return {
    tab: "browse",
    parent_entry_id: null,
    search_text: "",
    zone_filter: "all",
    category_filter: "all",
    hide_hidden: true,
    duplicate_group_id: null,
    skip_reason_filter: "all",
  };
}

export function createInitialState(): AppStateModel {
  return {
    view: "explore",
    globalError: null,
    workspace: null,

    pendingRoots: null,
    rulesFile: null,
    scanOptions: {
      all_volumes: false,
      metadata_only: false,
      no_duplicates: false,
      stale_days: 365,
      max_entries: 250_000,
    },
    scanning: false,
    scanProgress: null,
    scanSummary: null,
    scanFilter: defaultFilter(),
    scanSort: "size_desc",
    selection: { mode: "ids", scan_generation: "0", ids: [] },
    totalFilteredCount: 0,
    treemap: null,
    hoveredTreemapEntryId: null,
    inspectedEntry: null,

    planDrawer: {
      open: false,
      loading: false,
      preview: null,
      selectedOpIds: new Set(),
      itemCountInput: "",
      acknowledgedContentKeys: new Set(),
      executing: false,
      execProgress: null,
      executionReport: null,
      error: null,
    },

    permanentModal: {
      open: false,
      loading: false,
      preview: null,
      challenge: null,
      phraseInput: "",
      countInput: "",
      executing: false,
      executionReport: null,
      error: null,
    },

    safety: {
      tab: "quarantine",
      dueOnly: false,
      quarantineItems: [],
      selectedQuarantineIds: new Set(),
      historyBatches: [],
      selectedBatchDetail: null,
      recoveryReport: null,
    },

    access: {
      suggested: null,
      allowPrivateConfig: false,
      pendingGrant: null,
      pendingStorageInit: null,
    },
  };
}

export function isEntrySelected(
  selection: SelectionSpec,
  entryId: EntryId,
  currentGeneration: string,
): boolean {
  if (selection.scan_generation !== currentGeneration) {
    return false;
  }
  if (selection.mode === "ids") {
    return selection.ids.includes(entryId);
  }
  return !selection.excludes.includes(entryId);
}

export function toggleEntrySelection(
  selection: SelectionSpec,
  entryId: EntryId,
  currentGeneration: string,
): SelectionSpec {
  if (selection.scan_generation !== currentGeneration) {
    return { mode: "ids", scan_generation: currentGeneration, ids: [entryId] };
  }
  if (selection.mode === "ids") {
    const exists = selection.ids.includes(entryId);
    return {
      mode: "ids",
      scan_generation: currentGeneration,
      ids: exists
        ? selection.ids.filter((id) => id !== entryId)
        : [...selection.ids, entryId],
    };
  }
  const excluded = selection.excludes.includes(entryId);
  return {
    mode: "filtered",
    scan_generation: currentGeneration,
    filter: selection.filter,
    excludes: excluded
      ? selection.excludes.filter((id) => id !== entryId)
      : [...selection.excludes, entryId],
  };
}

export function selectAllCurrentFilter(
  scanGeneration: string,
  filter: ScanFilter,
): SelectionSpec {
  return {
    mode: "filtered",
    scan_generation: scanGeneration,
    filter: { ...filter },
    excludes: [],
  };
}

export function clearSelection(scanGeneration: string): SelectionSpec {
  return {
    mode: "ids",
    scan_generation: scanGeneration,
    ids: [],
  };
}

export function selectedCountEstimate(
  selection: SelectionSpec,
  totalFilteredCount: number,
  currentGeneration: string,
): number {
  if (selection.scan_generation !== currentGeneration) {
    return 0;
  }
  if (selection.mode === "ids") {
    return selection.ids.length;
  }
  return Math.max(0, totalFilteredCount - selection.excludes.length);
}

export type Listener = () => void;

export class AppStore {
  readonly state: AppStateModel;
  private listeners = new Set<Listener>();

  constructor() {
    this.state = createInitialState();
  }

  updateScanFilter(patch: Partial<ScanFilter>): void {
    Object.assign(this.state.scanFilter, patch);
    const generation =
      this.state.scanSummary?.scan_generation ?? this.state.selection.scan_generation;
    this.state.selection = clearSelection(generation);
    this.notify();
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  notify(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }
}
