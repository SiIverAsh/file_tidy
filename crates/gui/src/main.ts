import "./styles/main.css";
import { tauriApi, type ApiClient } from "./api/tauri.ts";
import type { BuildPlanRequest, PlanPreviewDto, ScanFilter, SortField } from "./api/types.ts";
import { PermanentDeleteModal } from "./components/permanent-modal.ts";
import { ReviewDrawer } from "./components/review-drawer.ts";
import { clearChildren, el } from "./components/safe-text.ts";
import { isTreeBrowseFilter } from "./components/entry-tree.ts";
import {
  AppStore,
  clearSelection,
  defaultFilter,
  type MainView,
} from "./state/store.ts";
import { AccessRulesView } from "./views/access-rules.ts";
import { ExploreView } from "./views/explore.ts";
import { SafetyHistoryView } from "./views/safety-history.ts";

function extractErrorMessage(err: unknown): string {
  if (typeof err === "string") {
    return err;
  }
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return "操作失败，请检查日志或重试";
}

export class FileTidyApp {
  private readonly store = new AppStore();
  private readonly api: ApiClient;
  private readonly root: HTMLElement;

  private readonly statusBar = el("header", "topbar");
  private readonly navEl = el("nav", "sidebar");
  private readonly mainSlot = el("main", "main-canvas");
  private readonly renameOverlay = el("div", "modal-backdrop");

  private readonly exploreView: ExploreView;
  private readonly safetyView: SafetyHistoryView;
  private readonly accessView: AccessRulesView;
  private readonly reviewDrawer: ReviewDrawer;
  private readonly permanentModal: PermanentDeleteModal;

  private renameResolver: ((name: string | null) => void) | null = null;
  private activeViewMounted: MainView | null = null;
  private exploreReloadSeq = 0;

  constructor(root: HTMLElement, api: ApiClient = tauriApi) {
    this.root = root;
    this.api = api;

    this.exploreView = new ExploreView({
      onPickRoots: async () => {
        try {
          this.store.state.globalError = null;
          this.store.state.pendingRoots = await this.api.pickScanRoots();
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onPickRules: async () => {
        try {
          this.store.state.globalError = null;
          this.store.state.rulesFile = await this.api.pickRulesFile();
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onStartScan: async () => {
        await this.startScan();
      },
      onCancelScan: async () => {
        try {
          await this.api.cancelScan();
        } catch (err) {
          this.reportError(err);
        }
      },
      onUpdateOptions: (patch) => {
        Object.assign(this.store.state.scanOptions, patch);
        this.store.notify();
      },
      onFilterChange: async (patch, reloadTreemap = false) => {
        this.store.updateScanFilter(patch);
        await this.reloadExploreData(reloadTreemap);
      },
      onSortChange: async (sort) => {
        this.store.state.scanSort = sort;
        await this.reloadExploreData(false);
      },
      onFetchWindow: async (offset, limit) => {
        const gen = this.store.state.scanSummary?.scan_generation;
        if (!gen) {
          return { totalCount: 0, entries: [] };
        }
        const filter = { ...this.store.state.scanFilter };
        const sort = this.store.state.scanSort;
        const res = await this.api.queryScanEntries({
          scan_generation: gen,
          filter,
          sort,
          offset,
          limit,
        });
        if (this.isCurrentExploreQuery(gen, filter, sort)) {
          this.store.state.totalFilteredCount = res.total_count;
          this.store.notify();
        }
        return { totalCount: res.total_count, entries: res.entries };
      },
      onFetchChildren: async (parentId, offset, limit) => {
        const gen = this.store.state.scanSummary?.scan_generation;
        if (!gen) return { totalCount: 0, entries: [] };
        const filter = { ...this.store.state.scanFilter };
        const sort = this.store.state.scanSort;
        const request = { scan_generation: gen, filter, sort, offset, limit };
        const [children, all] = await Promise.all([
          this.api.queryScanEntries({
            ...request,
            filter: { ...filter, parent_entry_id: parentId },
            tree_roots_only: parentId === null,
          }),
          // The selection count still covers the full filter, including descendants.
          parentId === null && offset === 0
            ? this.api.queryScanEntries({ ...request, offset: 0, limit: 0 })
            : Promise.resolve(null),
        ]);
        if (all && this.isCurrentExploreQuery(gen, filter, sort)) {
          this.store.state.totalFilteredCount = all.total_count;
          this.store.notify();
        }
        return { totalCount: children.total_count, entries: children.entries };
      },
      onFetchSkipped: async () => {
        const gen = this.store.state.scanSummary?.scan_generation;
        if (!gen) {
          return [];
        }
        const res = await this.api.queryScanEntries({
          scan_generation: gen,
          filter: { ...this.store.state.scanFilter, tab: "skipped" },
          sort: this.store.state.scanSort,
          offset: 0,
          limit: 500,
        });
        return res.skipped;
      },
      onSelectionChange: (next) => {
        this.store.state.selection = next;
        this.store.notify();
      },
      onInspectEntry: (entry) => {
        this.store.state.inspectedEntry = entry;
        this.store.notify();
      },
      onDrillDirectory: async (entryId) => {
        this.store.updateScanFilter({ tab: "browse", parent_entry_id: entryId });
        await this.reloadExploreData(true);
      },
      onTriggerAction: async (kind, pickDestination) => {
        await this.openPlanForAction(kind, pickDestination);
      },
      onQuickAuthorizeSelected: async () => {
        this.store.state.view = "access";
        this.store.notify();
        await this.refreshAccessData();
      },
    });

    this.safetyView = new SafetyHistoryView({
      onSwitchTab: async (tab) => {
        this.store.state.safety.tab = tab;
        this.store.notify();
        await this.refreshSafetyData();
      },
      onToggleDueOnly: async (dueOnly) => {
        this.store.state.safety.dueOnly = dueOnly;
        await this.refreshSafetyData();
      },
      onToggleQuarantineItem: (itemId) => {
        const set = this.store.state.safety.selectedQuarantineIds;
        if (set.has(itemId)) {
          set.delete(itemId);
        } else {
          set.add(itemId);
        }
        this.store.notify();
      },
      onRestoreSelected: async (pickNewTarget) => {
        await this.buildRestorePlan(pickNewTarget);
      },
      onPurgeSelected: async () => {
        await this.buildPurgePlan();
      },
      onSelectBatch: async (batchId) => {
        try {
          this.store.state.safety.selectedBatchDetail =
            await this.api.getBatchDetail(batchId);
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onUndoBatch: async (batchId, opIds) => {
        await this.openDrawerWithLoader(async () =>
          this.api.buildUndoPlan(batchId, opIds, false, 30),
        );
      },
      onRefreshRecovery: async () => {
        await this.refreshSafetyData();
      },
    });

    this.accessView = new AccessRulesView({
      onOpenExistingStorage: async () => {
        try {
          this.store.state.globalError = null;
          this.store.state.workspace = await this.api.openExistingStorage();
          this.store.notify();
          await this.refreshWorkspaceAndRecovery();
        } catch (err) {
          this.reportError(err);
        }
      },
      onPickStorageInit: async () => {
        try {
          this.store.state.globalError = null;
          this.store.state.access.pendingStorageInit =
            await this.api.pickAndPreviewStorageInit();
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onConfirmStorageInit: async (grantId, digest) => {
        try {
          this.store.state.globalError = null;
          this.store.state.workspace = await this.api.confirmStorageInit(
            grantId,
            digest,
          );
          this.store.state.access.pendingStorageInit = null;
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onCancelPendingStorageInit: () => {
        this.store.state.access.pendingStorageInit = null;
        this.store.notify();
      },
      onPickAndPreviewGrant: async () => {
        try {
          this.store.state.globalError = null;
          const preview = await this.api.pickAndPreviewGrant();
          if (preview) {
            this.store.state.access.pendingGrant = {
              id: preview.id,
              root_display: preview.root_display,
            };
            this.store.notify();
          }
        } catch (err) {
          this.reportError(err);
        }
      },
      onConfirmGrant: async (grantId, persistent) => {
        try {
          this.store.state.globalError = null;
          this.store.state.workspace = await this.api.confirmGrant(
            grantId,
            persistent,
          );
          this.store.state.access.pendingGrant = null;
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onCancelPendingGrant: () => {
        this.store.state.access.pendingGrant = null;
        this.store.notify();
      },
      onRevokeGrant: async (grantId) => {
        try {
          this.store.state.globalError = null;
          this.store.state.workspace = await this.api.revokeGrant(grantId);
          this.store.notify();
        } catch (err) {
          this.reportError(err);
        }
      },
      onRequestSuggested: async (allowPrivateConfig) => {
        this.store.state.access.allowPrivateConfig = allowPrivateConfig;
        await this.refreshAccessData();
      },
    });

    this.reviewDrawer = new ReviewDrawer({
      onClose: () => {
        this.store.state.planDrawer.open = false;
        this.store.state.planDrawer.preview = null;
        this.store.state.planDrawer.executionReport = null;
        this.store.state.planDrawer.error = null;
        this.store.notify();
      },
      onFilterOperations: async (planId, selectedOpIds) => {
        try {
          this.store.state.planDrawer.loading = true;
          this.store.state.planDrawer.error = null;
          this.store.notify();
          const next = await this.api.filterPlanOperations(planId, selectedOpIds);
          this.applyPreviewToDrawer(next);
        } catch (err) {
          this.store.state.planDrawer.loading = false;
          this.store.state.planDrawer.error = extractErrorMessage(err);
          this.store.notify();
        }
      },
      onToggleAckKey: (key) => {
        const set = this.store.state.planDrawer.acknowledgedContentKeys;
        if (set.has(key)) {
          set.delete(key);
        } else {
          set.add(key);
        }
        this.store.notify();
      },
      onItemCountInput: (val) => {
        this.store.state.planDrawer.itemCountInput = val;
        this.store.notify();
      },
      onExecute: async (preview) => {
        await this.executeDrawerPlan(preview);
      },
      onCancelExecution: async () => {
        try {
          await this.api.cancelExecution();
        } catch (err) {
          this.reportError(err);
        }
      },
      onJumpToRecovery: () => {
        this.store.state.planDrawer.open = false;
        this.store.state.view = "safety";
        this.store.state.safety.tab = "recovery";
        this.store.notify();
        void this.refreshSafetyData();
      },
    });

    this.permanentModal = new PermanentDeleteModal({
      onClose: () => {
        this.store.state.permanentModal.open = false;
        this.store.state.permanentModal.preview = null;
        this.store.state.permanentModal.challenge = null;
        this.store.state.permanentModal.executionReport = null;
        this.store.state.permanentModal.error = null;
        this.store.notify();
      },
      onRequestChallenge: async (planId, planDigest) => {
        try {
          this.store.state.permanentModal.error = null;
          this.store.state.permanentModal.challenge =
            await this.api.requestPermanentChallenge(planId, planDigest);
          this.store.notify();
        } catch (err) {
          this.store.state.permanentModal.error = extractErrorMessage(err);
          this.store.notify();
        }
      },
      onPhraseInput: (value) => {
        this.store.state.permanentModal.phraseInput = value;
        this.store.notify();
      },
      onCountInput: (value) => {
        this.store.state.permanentModal.countInput = value;
        this.store.notify();
      },
      onExecutePermanent: async (preview) => {
        await this.executePermanentPlan(preview);
      },
    });
  }

  async mount(): Promise<void> {
    this.buildShell();
    this.store.subscribe(() => this.render());

    await this.api.onScanProgress((ev) => {
      if (this.store.state.scanning) {
        this.store.state.scanProgress = ev;
        this.store.notify();
      }
    });
    await this.api.onExecutionProgress((ev) => {
      if (this.store.state.planDrawer.executing) {
        this.store.state.planDrawer.execProgress = ev;
        this.store.notify();
      }
    });

    await this.refreshWorkspaceAndRecovery();
    this.render();
  }

  private buildShell(): void {
    clearChildren(this.root);
    const app = el("div", "app-shell");
    app.appendChild(this.statusBar);

    const body = el("div", "app-body");
    body.appendChild(this.navEl);
    body.appendChild(this.mainSlot);
    app.appendChild(body);
    app.appendChild(this.reviewDrawer.root);
    app.appendChild(this.permanentModal.root);
    app.appendChild(this.renameOverlay);

    this.root.appendChild(app);
  }

  private render(): void {
    const model = this.store.state;
    this.renderTopbar(model);
    this.renderSidebar(model);

    if (this.activeViewMounted !== model.view) {
      clearChildren(this.mainSlot);
      if (model.view === "explore") {
        this.mainSlot.appendChild(this.exploreView.root);
      } else if (model.view === "safety") {
        this.mainSlot.appendChild(this.safetyView.root);
      } else {
        this.mainSlot.appendChild(this.accessView.root);
      }
      this.activeViewMounted = model.view;
    }

    if (model.view === "explore") {
      this.exploreView.render(model);
    } else if (model.view === "safety") {
      this.safetyView.render(model);
    } else {
      this.accessView.render(model);
    }

    this.reviewDrawer.render(model);
    this.permanentModal.render(model);
  }

  private renderTopbar(model: typeof this.store.state): void {
    clearChildren(this.statusBar);
    const brand = el("div", "topbar__brand");
    brand.appendChild(el("span", "topbar__title", "File Tidy"));
    const ws = model.workspace;
    const modeText = ws?.storage_initialized
      ? `已就绪 · ${ws.grants.filter((g) => !g.revoked).length} 目录`
      : "只读";
    brand.appendChild(el("span", "topbar__mode", modeText));
    this.statusBar.appendChild(brand);

    const alerts = el("div", "topbar__alerts");
    if (model.globalError) {
      const errPill = el("div", "alert-pill alert-pill--error", model.globalError);
      const dismiss = el("button", "alert-pill__close", "×");
      dismiss.type = "button";
      dismiss.addEventListener("click", () => {
        this.store.state.globalError = null;
        this.store.notify();
      });
      errPill.appendChild(dismiss);
      alerts.appendChild(errPill);
    }
    if (ws && ws.pending_recovery_count > 0) {
      const recBtn = el(
        "button",
        "alert-pill alert-pill--warn",
        `${ws.pending_recovery_count} 项待核对`,
      );
      recBtn.type = "button";
      recBtn.addEventListener("click", () => {
        this.store.state.view = "safety";
        this.store.state.safety.tab = "recovery";
        this.store.notify();
        void this.refreshSafetyData();
      });
      alerts.appendChild(recBtn);
    }
    if (ws && ws.due_quarantine_count > 0) {
      const dueBtn = el(
        "button",
        "alert-pill",
        `${ws.due_quarantine_count} 项到期`,
      );
      dueBtn.type = "button";
      dueBtn.addEventListener("click", () => {
        this.store.state.view = "safety";
        this.store.state.safety.tab = "quarantine";
        this.store.state.safety.dueOnly = true;
        this.store.notify();
        void this.refreshSafetyData();
      });
      alerts.appendChild(dueBtn);
    }
    this.statusBar.appendChild(alerts);
  }

  private renderSidebar(model: typeof this.store.state): void {
    clearChildren(this.navEl);
    this.navEl.appendChild(el("div", "sidebar__section", "位置"));
    const items: Array<{ id: MainView; label: string }> = [
      { id: "explore", label: "文件与空间" },
      { id: "safety", label: "废纸篓与历史" },
      { id: "access", label: "授权与规则" },
    ];
    for (const item of items) {
      const btn = el("button", "nav-btn", item.label);
      btn.type = "button";
      if (model.view === item.id) {
        btn.classList.add("nav-btn--active");
      }
      btn.addEventListener("click", () => {
        this.store.state.view = item.id;
        this.store.notify();
        if (item.id === "safety") {
          void this.refreshSafetyData();
        } else if (item.id === "access") {
          void this.refreshAccessData();
        }
      });
      this.navEl.appendChild(btn);
    }
  }

  private async refreshWorkspaceAndRecovery(): Promise<void> {
    try {
      this.store.state.workspace = await this.api.getWorkspaceStatus();
      this.store.notify();
    } catch (err) {
      this.reportError(err);
    }
  }

  private async refreshAccessData(): Promise<void> {
    try {
      this.store.state.workspace = await this.api.getWorkspaceStatus();
      this.store.state.access.suggested =
        await this.api.getSuggestedDirectories(
          this.store.state.access.allowPrivateConfig,
        );
      this.store.notify();
    } catch (err) {
      this.reportError(err);
    }
  }

  private async refreshSafetyData(): Promise<void> {
    if (!this.store.state.workspace?.storage_initialized) {
      this.store.notify();
      return;
    }
    try {
      const [quarantine, history, recovery] = await Promise.all([
        this.api.listQuarantine(this.store.state.safety.dueOnly),
        this.api.listHistory(50),
        this.api.getRecoveryReport(),
      ]);
      this.store.state.safety.quarantineItems = quarantine;
      this.store.state.safety.historyBatches = history;
      this.store.state.safety.recoveryReport = recovery;
      this.store.notify();
    } catch (err) {
      this.reportError(err);
    }
  }

  private async startScan(): Promise<void> {
    try {
      this.store.state.globalError = null;
      this.store.state.scanning = true;
      this.store.state.scanProgress = null;
      this.store.notify();

      const summary = await this.api.startScan(this.store.state.scanOptions);
      this.store.state.scanning = false;
      this.store.state.scanSummary = summary;
      this.store.state.scanFilter = defaultFilter();
      this.store.state.selection = clearSelection(summary.scan_generation);
      this.store.state.inspectedEntry = null;
      this.store.notify();

      await this.reloadExploreData(true);
    } catch (err) {
      this.store.state.scanning = false;
      this.reportError(err);
    }
  }

  private async reloadExploreData(reloadTreemap: boolean): Promise<void> {
    const seq = ++this.exploreReloadSeq;
    const gen = this.store.state.scanSummary?.scan_generation;
    if (!gen) {
      return;
    }
    try {
      const filter = { ...this.store.state.scanFilter };
      // Invalidate the old list immediately, before any treemap request can yield.
      const listLoad = this.exploreView.virtualList.resetAndLoad(
        gen,
        this.store.state.selection,
        isTreeBrowseFilter(filter),
      );
      const [, treemap] = await Promise.all([
        listLoad,
        reloadTreemap && filter.tab === "browse"
          ? this.api.getTreemapNodes(gen, filter.parent_entry_id, 40)
          : Promise.resolve(null),
      ]);
      if (seq !== this.exploreReloadSeq || this.store.state.scanSummary?.scan_generation !== gen) return;
      if (treemap) this.store.state.treemap = treemap;
      this.store.notify();
    } catch (err) {
      if (seq === this.exploreReloadSeq) this.reportError(err);
    }
  }

  private isCurrentExploreQuery(
    generation: string,
    filter: ScanFilter,
    sort: SortField,
  ): boolean {
    return this.store.state.scanSummary?.scan_generation === generation &&
      this.store.state.scanSort === sort &&
      JSON.stringify(this.store.state.scanFilter) === JSON.stringify(filter);
  }

  private async openPlanForAction(
    kind: BuildPlanRequest["kind"],
    pickDestination: boolean,
  ): Promise<void> {
    let destinationGrantId: string | null = null;
    let relativeName: string | null = null;

    if (pickDestination) {
      try {
        const picked = await this.api.pickDestinationDirectory();
        if (!picked) {
          return;
        }
        if (picked.needs_grant || !picked.grant_id) {
          this.store.state.globalError = `目标目录尚未获得授权（${picked.path_display}）。请先在“授权与设置”中授予目录写入权限。`;
          this.store.state.view = "access";
          this.store.notify();
          await this.refreshAccessData();
          return;
        }
        destinationGrantId = picked.grant_id;
      } catch (err) {
        this.reportError(err);
        return;
      }
    }

    if (kind === "rename") {
      const nextName = await this.promptNewFilename();
      if (!nextName) {
        return;
      }
      relativeName = nextName;
    }

    const req: BuildPlanRequest = {
      kind,
      selection: this.store.state.selection,
      destination_grant_id: destinationGrantId,
      destination_relative_name: relativeName,
      include_hidden: !this.store.state.scanFilter.hide_hidden,
      quarantine_retention_days: 30,
    };

    if (kind === "permanent_delete") {
      await this.openPermanentModalWithLoader(() =>
        this.api.buildPlanFromSelection(req),
      );
    } else {
      await this.openDrawerWithLoader(() =>
        this.api.buildPlanFromSelection(req),
      );
    }
  }

  private async buildRestorePlan(pickNewTarget: boolean): Promise<void> {
    const ids = [...this.store.state.safety.selectedQuarantineIds];
    if (ids.length === 0) {
      return;
    }
    let grantId: string | null = null;
    if (pickNewTarget) {
      const picked = await this.api.pickDestinationDirectory();
      if (!picked) {
        return;
      }
      if (!picked.grant_id || picked.needs_grant) {
        this.reportError("目标目录尚未获得写入授权，请先在“授权与设置”授权该目录。");
        return;
      }
      grantId = picked.grant_id;
    }
    await this.openDrawerWithLoader(() =>
      this.api.buildRestorePlan(ids, grantId, true),
    );
  }

  private async buildPurgePlan(): Promise<void> {
    const ids = [...this.store.state.safety.selectedQuarantineIds];
    if (ids.length === 0) {
      return;
    }
    await this.openPermanentModalWithLoader(() =>
      this.api.buildPurgePlan(ids, true),
    );
  }

  private async openDrawerWithLoader(
    loader: () => Promise<PlanPreviewDto>,
  ): Promise<void> {
    const d = this.store.state.planDrawer;
    d.open = true;
    d.loading = true;
    d.preview = null;
    d.executionReport = null;
    d.error = null;
    d.itemCountInput = "";
    d.acknowledgedContentKeys.clear();
    this.store.notify();

    try {
      const preview = await loader();
      this.applyPreviewToDrawer(preview);
    } catch (err) {
      d.loading = false;
      d.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private applyPreviewToDrawer(preview: PlanPreviewDto): void {
    const d = this.store.state.planDrawer;
    d.loading = false;
    d.preview = preview;
    d.selectedOpIds = new Set(preview.operations.map((o) => o.id));
    d.itemCountInput = "";
    d.acknowledgedContentKeys.clear();
    this.store.notify();
  }

  private async executeDrawerPlan(preview: PlanPreviewDto): Promise<void> {
    const d = this.store.state.planDrawer;
    d.executing = true;
    d.error = null;
    d.execProgress = null;
    this.store.notify();

    try {
      const report = await this.api.confirmAndExecute({
        plan_id: preview.plan_id,
        plan_digest: preview.plan_digest,
        ...(preview.requires_count_confirmation
          ? { item_count: d.itemCountInput.trim() }
          : {}),
        sensitive_acknowledgements: [...d.acknowledgedContentKeys],
      });
      d.executing = false;
      d.executionReport = report;
      this.store.state.safety.selectedQuarantineIds.clear();
      this.store.notify();
      await this.refreshWorkspaceAndRecovery();
      await this.refreshSafetyData();
    } catch (err) {
      d.executing = false;
      d.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private async openPermanentModalWithLoader(
    loader: () => Promise<PlanPreviewDto>,
  ): Promise<void> {
    const m = this.store.state.permanentModal;
    m.open = true;
    m.loading = true;
    m.preview = null;
    m.challenge = null;
    m.phraseInput = "";
    m.countInput = "";
    m.executionReport = null;
    m.error = null;
    this.store.notify();

    try {
      m.preview = await loader();
      m.loading = false;
      this.store.notify();
    } catch (err) {
      m.loading = false;
      m.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private async executePermanentPlan(preview: PlanPreviewDto): Promise<void> {
    const m = this.store.state.permanentModal;
    m.executing = true;
    m.error = null;
    this.store.notify();

    try {
      const report = await this.api.confirmAndExecute({
        plan_id: preview.plan_id,
        plan_digest: preview.plan_digest,
        ...(preview.requires_count_confirmation
          ? { item_count: m.countInput.trim() }
          : {}),
        // Permanent delete never accepts B-zone sensitive acknowledgements.
        sensitive_acknowledgements: [],
        permanent_challenge_input: m.phraseInput.trim(),
      });
      m.executing = false;
      m.executionReport = report;
      this.store.notify();
      await this.refreshWorkspaceAndRecovery();
      await this.refreshSafetyData();
    } catch (err) {
      m.executing = false;
      m.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private promptNewFilename(): Promise<string | null> {
    return new Promise((resolve) => {
      this.renameResolver = resolve;
      clearChildren(this.renameOverlay);
      this.renameOverlay.classList.add("modal-backdrop--open");

      const card = el("div", "dialog-card");
      card.appendChild(el("h3", "dialog-card__title", "输入新名称（仅单个文件名）"));
      const input = el("input", "input");
      input.type = "text";
      input.placeholder = "例如：archive-2026.tar.gz";
      input.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") {
          const val = input.value.trim();
          this.closeRenamePrompt(val || null);
        } else if (ev.key === "Escape") {
          this.closeRenamePrompt(null);
        }
      });
      card.appendChild(input);

      const actions = el("div", "panel-toolbar");
      const ok = el("button", "btn btn--primary", "生成重命名预览");
      ok.type = "button";
      ok.addEventListener("click", () => {
        const val = input.value.trim();
        this.closeRenamePrompt(val || null);
      });
      const cancel = el("button", "btn btn--ghost", "取消");
      cancel.type = "button";
      cancel.addEventListener("click", () => this.closeRenamePrompt(null));
      actions.appendChild(ok);
      actions.appendChild(cancel);
      card.appendChild(actions);

      this.renameOverlay.appendChild(card);
      input.focus();
    });
  }

  private closeRenamePrompt(value: string | null): void {
    this.renameOverlay.classList.remove("modal-backdrop--open");
    clearChildren(this.renameOverlay);
    const r = this.renameResolver;
    this.renameResolver = null;
    if (r) {
      r(value);
    }
  }

  private reportError(err: unknown): void {
    this.store.state.globalError = extractErrorMessage(err);
    this.store.notify();
  }
}

const mountPoint = document.getElementById("app");
if (mountPoint) {
  const app = new FileTidyApp(mountPoint);
  void app.mount();
}
