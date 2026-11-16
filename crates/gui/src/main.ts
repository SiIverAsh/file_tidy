import "./styles/main.css";
import "./styles/themes.css";
import "./styles/appearance.css";
import "./styles/scan-options.css";
import { tauriApi, type ApiClient } from "./api/tauri.ts";
import type { BuildPlanRequest, PlanPreviewDto, ScanFilter, SortField, WorkspaceStatusDto } from "./api/types.ts";
import { PermanentDeleteModal } from "./components/permanent-modal.ts";
import { ReviewDrawer } from "./components/review-drawer.ts";
import { clearChildren, el } from "./components/safe-text.ts";
import { isTreeBrowseFilter } from "./components/entry-tree.ts";
import { MotionPresence } from "./components/motion.ts";
import { OverlayFocus } from "./components/overlay-focus.ts";
import {
  AppStore,
  clearSelection,
  createInitialState,
  defaultFilter,
  type MainView,
} from "./state/store.ts";
import { AccessRulesView } from "./views/access-rules.ts";
import { ExploreView } from "./views/explore.ts";
import { SafetyHistoryView } from "./views/safety-history.ts";
import { AppearanceView } from "./views/appearance.ts";
import { AppearanceController, DEFAULT_APPEARANCE } from "./state/appearance.ts";

function extractErrorMessage(err: unknown): string {
  if (typeof err === "string") {
    return err;
  }
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return "操作失败，请重试";
}

export class FileTidyApp {
  private readonly store = new AppStore();
  private readonly appearance = new AppearanceController();
  private readonly api: ApiClient;
  private readonly root: HTMLElement;

  private readonly noticesEl = el("div", "app-notices");
  private readonly errorToast = el("div", "error-toast");
  private readonly errorPresence = new MotionPresence(this.errorToast, "error-toast--open");
  private readonly navDockEl = el("div", "topbar-dock");
  private readonly navEl = el("nav", "sidebar topbar");
  private readonly mainSlot = el("main", "main-canvas");
  private readonly bodyEl = el("div", "app-body");
  private readonly renameOverlay = el("div", "modal-backdrop");

  private readonly exploreView: ExploreView;
  private readonly safetyView: SafetyHistoryView;
  private readonly accessView: AccessRulesView;
  private readonly appearanceView: AppearanceView;
  private readonly reviewDrawer: ReviewDrawer;
  private readonly permanentModal: PermanentDeleteModal;
  private readonly drawerFocus: OverlayFocus;
  private readonly permanentFocus: OverlayFocus;
  private readonly renameFocus: OverlayFocus;
  private activeOverlayFocus: OverlayFocus | null = null;

  private renameResolver: ((name: string | null) => void) | null = null;
  private activeViewMounted: MainView | null = null;
  private sidebarViewRendered: MainView | null = null;
  private exploreReloadSeq = 0;
  private renderedError: string | null = null;
  private appearancePersisted = true;
  private drawerRequestSeq = 0;
  private permanentRequestSeq = 0;
  private challengeRequestSeq = 0;
  private safetyRefreshSeq = 0;
  private batchDetailSeq = 0;
  private workspaceSeq = 0;
  private scanContextSeq = 0;
  private scanRequestSeq = 0;
  private activeScanContextSeq: number | null = null;
  private pickingRoots = false;

  constructor(root: HTMLElement, api: ApiClient = tauriApi) {
    this.root = root;
    this.api = api;

    this.appearanceView = new AppearanceView({
      onChange: (patch) => {
        this.appearancePersisted = this.appearance.setPreference(patch);
        this.appearanceView.render(this.appearance.preference, this.appearancePersisted);
      },
      onReset: () => {
        this.appearancePersisted = this.appearance.setPreference(DEFAULT_APPEARANCE);
        this.appearanceView.render(this.appearance.preference, this.appearancePersisted);
      },
    });

    this.exploreView = new ExploreView({
      onPickRoots: async () => {
        if (this.pickingRoots || this.store.state.planDrawer.executing || this.store.state.permanentModal.executing) return;
        this.pickingRoots = true;
        const workspaceSeq = this.workspaceSeq;
        try {
          this.store.state.globalError = null;
          const picked = await this.api.pickScanRoots();
          if (workspaceSeq !== this.workspaceSeq || picked.cancelled || picked.roots_display.length === 0) return;
          const previous = this.store.state.pendingRoots?.roots_display ?? this.store.state.scanSummary?.root_displays ?? [];
          const changed = this.store.state.scanOptions.all_volumes ||
            JSON.stringify([...previous].sort()) !== JSON.stringify([...picked.roots_display].sort());
          this.store.state.pendingRoots = picked;
          this.store.state.scanOptions.all_volumes = false;
          if (changed) this.invalidateScanResults();
          this.store.notify();
          if (changed && this.store.state.scanning) await this.api.cancelScan();
        } catch (err) {
          if (workspaceSeq === this.workspaceSeq) this.reportError(err);
        } finally {
          this.pickingRoots = false;
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
        const scopeChanged = patch.all_volumes !== undefined && patch.all_volumes !== this.store.state.scanOptions.all_volumes;
        Object.assign(this.store.state.scanOptions, patch);
        if (scopeChanged) {
          this.invalidateScanResults();
          if (this.store.state.scanning) void this.api.cancelScan().catch((err: unknown) => this.reportError(err));
        }
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
        this.store.state.safety.selectedQuarantineIds.clear();
        this.store.notify();
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
        const seq = ++this.batchDetailSeq;
        const workspaceSeq = this.workspaceSeq;
        this.store.state.safety.selectedBatchDetail = null;
        this.store.notify();
        try {
          const detail = await this.api.getBatchDetail(batchId);
          if (seq !== this.batchDetailSeq || workspaceSeq !== this.workspaceSeq) return;
          this.store.state.safety.selectedBatchDetail = detail;
          this.store.notify();
        } catch (err) {
          if (seq === this.batchDetailSeq && workspaceSeq === this.workspaceSeq) this.reportError(err);
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
          const previous = this.store.state.workspace;
          const workspace = await this.api.openExistingStorage();
          // The native picker returns the current status when the user cancels.
          if (previous && workspace.authorization_epoch === previous.authorization_epoch &&
            workspace.storage_root_display === previous.storage_root_display) {
            this.store.state.workspace = workspace;
            this.store.notify();
            return;
          }
          this.replaceWorkspace(workspace);
          await Promise.all([this.refreshAccessData(), this.refreshSafetyData()]);
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
          const workspace = await this.api.confirmStorageInit(
            grantId,
            digest,
          );
          this.replaceWorkspace(workspace);
          await Promise.all([this.refreshAccessData(), this.refreshSafetyData()]);
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
      onClose: () => this.closeDrawer(),
      onFilterOperations: async (planId, selectedOpIds) => {
        const drawer = this.store.state.planDrawer;
        if (!drawer.open || drawer.executing || drawer.preview?.plan_id !== planId) return;
        const seq = ++this.drawerRequestSeq;
        try {
          this.store.state.planDrawer.loading = true;
          this.store.state.planDrawer.error = null;
          this.store.notify();
          const next = await this.api.filterPlanOperations(planId, selectedOpIds);
          if (seq !== this.drawerRequestSeq || !drawer.open) return;
          this.applyPreviewToDrawer(next);
        } catch (err) {
          if (seq !== this.drawerRequestSeq || !drawer.open) return;
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
        this.closeDrawer();
        this.store.state.view = "safety";
        this.store.state.safety.tab = "recovery";
        this.store.notify();
        void this.refreshSafetyData();
      },
    });

    this.permanentModal = new PermanentDeleteModal({
      onClose: () => this.closePermanentModal(),
      onRequestChallenge: async (planId, planDigest) => {
        const modal = this.store.state.permanentModal;
        if (!modal.open || modal.executing || modal.preview?.plan_id !== planId || modal.preview.plan_digest !== planDigest) return;
        const seq = ++this.challengeRequestSeq;
        try {
          modal.error = null;
          const challenge = await this.api.requestPermanentChallenge(planId, planDigest);
          if (seq !== this.challengeRequestSeq || !modal.open || modal.preview?.plan_id !== planId) return;
          modal.challenge = challenge;
          modal.phraseInput = "";
          modal.countInput = "";
          this.store.notify();
        } catch (err) {
          if (seq !== this.challengeRequestSeq || !modal.open) return;
          modal.error = extractErrorMessage(err);
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
    this.drawerFocus = new OverlayFocus(this.reviewDrawer.root, () => this.closeDrawer(),
      () => !this.store.state.planDrawer.executing);
    this.permanentFocus = new OverlayFocus(this.permanentModal.root, () => this.closePermanentModal(),
      () => !this.store.state.permanentModal.executing);
    this.renameFocus = new OverlayFocus(this.renameOverlay, () => this.closeRenamePrompt(null));
    this.renameOverlay.setAttribute("role", "dialog");
    this.renameOverlay.setAttribute("aria-modal", "true");
    this.renameOverlay.setAttribute("aria-label", "重命名文件");
  }

  async mount(): Promise<void> {
    this.buildShell();
    this.store.subscribe(() => this.render());
    this.appearance.subscribe(() => {
      this.appearanceView.render(this.appearance.preference, this.appearancePersisted);
    });

    await this.api.onScanProgress((ev) => {
      if (this.store.state.scanning && this.activeScanContextSeq === this.scanContextSeq) {
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
    this.navEl.setAttribute("aria-label", "主导航");
    this.mainSlot.id = "main-content";
    this.noticesEl.setAttribute("aria-live", "polite");
    this.errorToast.setAttribute("role", "alert");
    this.errorToast.setAttribute("aria-atomic", "true");

    clearChildren(this.navDockEl);
    const handle = el("div", "topbar-dock__handle");
    handle.setAttribute("aria-hidden", "true");
    handle.appendChild(el("span", "topbar-dock__pill"));
    this.navDockEl.appendChild(handle);
    this.navDockEl.appendChild(this.navEl);

    const body = this.bodyEl;
    body.appendChild(this.navDockEl);
    body.appendChild(this.mainSlot);
    app.appendChild(body);
    app.appendChild(this.reviewDrawer.root);
    app.appendChild(this.permanentModal.root);
    app.appendChild(this.renameOverlay);
    app.appendChild(this.errorToast);

    this.root.appendChild(app);
  }

  private render(): void {
    const model = this.store.state;
    this.renderErrorToast(model.globalError);
    this.renderNotices(model);
    this.renderSidebar(model);

    if (this.activeViewMounted !== model.view) {
      model.inspectedEntry = null;
      this.exploreView.closeFloatingPanels(false);
      clearChildren(this.mainSlot);
      this.mainSlot.appendChild(this.noticesEl);
      if (model.view === "explore") {
        this.mainSlot.appendChild(this.exploreView.root);
      } else if (model.view === "safety") {
        this.mainSlot.appendChild(this.safetyView.root);
      } else if (model.view === "access") {
        this.mainSlot.appendChild(this.accessView.root);
      } else {
        this.mainSlot.appendChild(this.appearanceView.root);
      }
      this.activeViewMounted = model.view;
    }

    if (model.view === "explore") {
      this.exploreView.render(model);
    } else if (model.view === "safety") {
      this.safetyView.render(model);
    } else if (model.view === "access") {
      this.accessView.render(model);
    } else {
      this.appearanceView.render(this.appearance.preference, this.appearancePersisted);
    }

    this.reviewDrawer.render(model);
    this.permanentModal.render(model);
    this.syncOverlayFocus();
  }

  private syncOverlayFocus(): void {
    const next = this.renameResolver ? this.renameFocus : this.store.state.permanentModal.open
      ? this.permanentFocus : this.store.state.planDrawer.open ? this.drawerFocus : null;
    if (next === null) this.bodyEl.inert = false;
    if (next === this.drawerFocus) this.reviewDrawer.root.inert = false;
    if (next === this.permanentFocus) this.permanentModal.root.inert = false;
    if (next === this.renameFocus) this.renameOverlay.inert = false;
    if (this.activeOverlayFocus !== next) {
      this.activeOverlayFocus?.deactivate(next === null);
      this.activeOverlayFocus = next;
    }
    next?.activate();
    this.bodyEl.inert = next !== null;
    this.reviewDrawer.root.inert = next !== this.drawerFocus;
    this.permanentModal.root.inert = next !== this.permanentFocus;
    this.renameOverlay.inert = next !== this.renameFocus;
  }

  private closeDrawer(): void {
    const drawer = this.store.state.planDrawer;
    if (drawer.executing) return;
    this.drawerRequestSeq += 1;
    drawer.open = false;
    drawer.loading = false;
    drawer.preview = null;
    drawer.executionReport = null;
    drawer.error = null;
    this.store.notify();
  }

  private closePermanentModal(): void {
    const modal = this.store.state.permanentModal;
    if (modal.executing) return;
    this.permanentRequestSeq += 1;
    this.challengeRequestSeq += 1;
    modal.open = false;
    modal.loading = false;
    modal.preview = null;
    modal.challenge = null;
    modal.executionReport = null;
    modal.error = null;
    this.store.notify();
  }

  private replaceWorkspace(workspace: WorkspaceStatusDto): void {
    this.workspaceSeq += 1;
    this.safetyRefreshSeq += 1;
    this.batchDetailSeq += 1;
    this.drawerRequestSeq += 1;
    this.permanentRequestSeq += 1;
    this.challengeRequestSeq += 1;
    this.store.state.workspace = workspace;
    const safety = this.store.state.safety;
    safety.quarantineItems = [];
    safety.historyBatches = [];
    safety.recoveryReport = null;
    safety.selectedBatchDetail = null;
    safety.selectedQuarantineIds.clear();
    this.store.state.access.pendingGrant = null;
    this.store.state.access.pendingStorageInit = null;
    this.store.state.access.suggested = null;
    const initial = createInitialState();
    this.store.state.planDrawer = initial.planDrawer;
    this.store.state.permanentModal = initial.permanentModal;
    this.scanRequestSeq += 1;
    this.activeScanContextSeq = null;
    this.invalidateScanResults();
    this.store.state.scanning = false;
    this.store.notify();
  }

  private renderErrorToast(message: string | null): void {
    if (!message) {
      this.renderedError = null;
      this.errorPresence.hide(() => clearChildren(this.errorToast));
      return;
    }
    if (message === this.renderedError) return;
    this.renderedError = message;
    clearChildren(this.errorToast);
    this.errorToast.appendChild(el("span", "error-toast__message", message));
    const dismiss = el("button", "error-toast__close", "×");
    dismiss.type = "button";
    dismiss.setAttribute("aria-label", "关闭错误提示");
    dismiss.addEventListener("click", () => {
      this.store.state.globalError = null;
      this.store.notify();
    });
    this.errorToast.appendChild(dismiss);
    this.errorPresence.show();
  }

  private renderNotices(model: typeof this.store.state): void {
    clearChildren(this.noticesEl);
    const ws = model.workspace;
    this.noticesEl.hidden = !ws?.pending_recovery_count && !ws?.due_quarantine_count;
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
      this.noticesEl.appendChild(recBtn);
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
        this.store.state.safety.selectedQuarantineIds.clear();
        this.store.notify();
        void this.refreshSafetyData();
      });
      this.noticesEl.appendChild(dueBtn);
    }
  }

  private renderSidebar(model: typeof this.store.state): void {
    if (this.sidebarViewRendered === model.view) return;
    this.sidebarViewRendered = model.view;
    clearChildren(this.navEl);
    const items: Array<{ id: MainView; label: string; icon: string }> = [
      { id: "explore", label: "文件与空间", icon: "folder" },
      { id: "safety", label: "隔离与历史", icon: "archive" },
      { id: "access", label: "授权与规则", icon: "shield" },
      { id: "appearance", label: "外观", icon: "palette" },
    ];
    for (const item of items) {
      const btn = el("button", "nav-btn");
      const icon = el("span", `ui-icon ui-icon--${item.icon}`);
      icon.setAttribute("aria-hidden", "true");
      btn.appendChild(icon);
      btn.appendChild(el("span", "nav-btn__label", item.label));
      btn.type = "button";
      btn.setAttribute("aria-label", item.label);
      btn.setAttribute("aria-controls", "main-content");
      if (model.view === item.id) {
        btn.classList.add("nav-btn--active");
        btn.setAttribute("aria-current", "page");
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
    const seq = this.workspaceSeq;
    try {
      const workspace = await this.api.getWorkspaceStatus();
      if (seq !== this.workspaceSeq) return;
      this.store.state.workspace = workspace;
      this.store.notify();
    } catch (err) {
      if (seq === this.workspaceSeq) this.reportError(err);
    }
  }

  private async refreshAccessData(): Promise<void> {
    const seq = this.workspaceSeq;
    try {
      const [workspace, suggested] = await Promise.all([
        this.api.getWorkspaceStatus(),
        this.api.getSuggestedDirectories(this.store.state.access.allowPrivateConfig),
      ]);
      if (seq !== this.workspaceSeq) return;
      this.store.state.workspace = workspace;
      this.store.state.access.suggested = suggested;
      this.store.notify();
    } catch (err) {
      if (seq === this.workspaceSeq) this.reportError(err);
    }
  }

  private async refreshSafetyData(): Promise<void> {
    const seq = ++this.safetyRefreshSeq;
    const workspaceSeq = this.workspaceSeq;
    const dueOnly = this.store.state.safety.dueOnly;
    if (!this.store.state.workspace?.storage_initialized) {
      this.store.notify();
      return;
    }
    try {
      const [quarantine, history, recovery] = await Promise.all([
        this.api.listQuarantine(dueOnly),
        this.api.listHistory(50),
        this.api.getRecoveryReport(),
      ]);
      if (seq !== this.safetyRefreshSeq || workspaceSeq !== this.workspaceSeq ||
        dueOnly !== this.store.state.safety.dueOnly) return;
      this.store.state.safety.quarantineItems = quarantine;
      this.store.state.safety.historyBatches = history;
      this.store.state.safety.recoveryReport = recovery;
      const visibleStored = new Set(quarantine.filter((item) => item.state === "stored").map((item) => item.id));
      for (const id of this.store.state.safety.selectedQuarantineIds) {
        if (!visibleStored.has(id)) this.store.state.safety.selectedQuarantineIds.delete(id);
      }
      const detail = this.store.state.safety.selectedBatchDetail;
      if (detail && !history.some((batch) => batch.id === detail.batch.id)) {
        this.batchDetailSeq += 1;
        this.store.state.safety.selectedBatchDetail = null;
      }
      this.store.notify();
    } catch (err) {
      if (seq === this.safetyRefreshSeq && workspaceSeq === this.workspaceSeq) this.reportError(err);
    }
  }

  private async startScan(): Promise<void> {
    if (this.store.state.scanning || this.pickingRoots) return;
    const workspaceSeq = this.workspaceSeq;
    const requestSeq = ++this.scanRequestSeq;
    this.invalidateScanResults();
    const contextSeq = this.scanContextSeq;
    this.activeScanContextSeq = contextSeq;
    try {
      this.store.state.globalError = null;
      this.store.state.scanning = true;
      this.store.state.scanProgress = null;
      this.store.notify();

      const summary = await this.api.startScan({ ...this.store.state.scanOptions });
      if (workspaceSeq !== this.workspaceSeq || contextSeq !== this.scanContextSeq) return;
      this.store.state.scanning = false;
      this.store.state.scanSummary = summary;
      this.store.state.scanFilter = defaultFilter();
      this.store.state.selection = clearSelection(summary.scan_generation);
      this.store.state.inspectedEntry = null;
      this.store.notify();

      await this.reloadExploreData(true);
    } catch (err) {
      if (workspaceSeq !== this.workspaceSeq || contextSeq !== this.scanContextSeq) return;
      this.reportError(err);
    } finally {
      if (workspaceSeq === this.workspaceSeq && requestSeq === this.scanRequestSeq) {
        this.store.state.scanning = false;
        this.activeScanContextSeq = null;
        this.store.notify();
      }
    }
  }

  private invalidateScanResults(): void {
    this.scanContextSeq += 1;
    this.exploreReloadSeq += 1;
    this.drawerRequestSeq += 1;
    this.permanentRequestSeq += 1;
    this.challengeRequestSeq += 1;
    this.store.clearScanResults();
    const initial = createInitialState();
    if (!this.store.state.planDrawer.executing) this.store.state.planDrawer = initial.planDrawer;
    if (!this.store.state.permanentModal.executing) this.store.state.permanentModal = initial.permanentModal;
    if (this.renameResolver) this.closeRenamePrompt(null);
  }

  private async reloadExploreData(_reloadTreemap = false): Promise<void> {
    const seq = ++this.exploreReloadSeq;
    const gen = this.store.state.scanSummary?.scan_generation;
    if (!gen) {
      return;
    }
    try {
      const filter = { ...this.store.state.scanFilter };
      await this.exploreView.virtualList.resetAndLoad(
        gen,
        this.store.state.selection,
        isTreeBrowseFilter(filter),
      );
      if (seq !== this.exploreReloadSeq || this.store.state.scanSummary?.scan_generation !== gen) return;
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
    this.store.state.inspectedEntry = null;
    this.exploreView.closeFloatingPanels();
    const workspaceSeq = this.workspaceSeq;
    let destinationGrantId: string | null = null;
    let relativeName: string | null = null;

    if (pickDestination) {
      try {
        const picked = await this.api.pickDestinationDirectory();
        if (workspaceSeq !== this.workspaceSeq) return;
        if (!picked) {
          return;
        }
        if (picked.needs_grant || !picked.grant_id) {
          this.store.state.globalError = picked.policy.blocked_reason ?? `目标目录无法用于写入（${picked.path_display}），请选择其他本地目录。`;
          this.store.notify();
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
      if (workspaceSeq !== this.workspaceSeq) return;
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
    const workspaceSeq = this.workspaceSeq;
    const ids = [...this.store.state.safety.selectedQuarantineIds];
    if (ids.length === 0) {
      return;
    }
    let grantId: string | null = null;
    if (pickNewTarget) {
      let picked;
      try {
        picked = await this.api.pickDestinationDirectory();
        if (workspaceSeq !== this.workspaceSeq) return;
      } catch (err) {
        this.reportError(err);
        return;
      }
      if (!picked) {
        return;
      }
      if (!picked.grant_id || picked.needs_grant) {
        this.reportError(picked.policy.blocked_reason ?? "目标目录无法用于恢复，请选择其他本地目录。");
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
    if (d.executing || this.store.state.permanentModal.executing) return;
    this.store.state.inspectedEntry = null;
    this.exploreView.closeFloatingPanels();
    const seq = ++this.drawerRequestSeq;
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
      if (seq !== this.drawerRequestSeq || !d.open) return;
      this.applyPreviewToDrawer(preview);
    } catch (err) {
      if (seq !== this.drawerRequestSeq || !d.open) return;
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
    if (d.executing || d.loading || !d.open || d.preview?.plan_id !== preview.plan_id) return;
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
      if (d !== this.store.state.planDrawer) return;
      d.executing = false;
      d.executionReport = report;
      this.store.state.safety.selectedQuarantineIds.clear();
      this.store.notify();
      await this.refreshWorkspaceAndRecovery();
      await this.refreshSafetyData();
    } catch (err) {
      if (d !== this.store.state.planDrawer) return;
      d.executing = false;
      d.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private async openPermanentModalWithLoader(
    loader: () => Promise<PlanPreviewDto>,
  ): Promise<void> {
    const m = this.store.state.permanentModal;
    if (m.executing || this.store.state.planDrawer.executing) return;
    this.store.state.inspectedEntry = null;
    this.exploreView.closeFloatingPanels();
    const seq = ++this.permanentRequestSeq;
    this.challengeRequestSeq += 1;
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
      const preview = await loader();
      if (seq !== this.permanentRequestSeq || !m.open) return;
      m.preview = preview;
      m.loading = false;
      this.store.notify();
    } catch (err) {
      if (seq !== this.permanentRequestSeq || !m.open) return;
      m.loading = false;
      m.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private async executePermanentPlan(preview: PlanPreviewDto): Promise<void> {
    const m = this.store.state.permanentModal;
    if (m.executing || m.loading || !m.open || m.preview?.plan_id !== preview.plan_id) return;
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
        sensitive_acknowledgements: [],
        permanent_challenge_input: m.phraseInput.trim(),
      });
      if (m !== this.store.state.permanentModal) return;
      m.executing = false;
      m.executionReport = report;
      this.store.state.safety.selectedQuarantineIds.clear();
      this.store.notify();
      await this.refreshWorkspaceAndRecovery();
      await this.refreshSafetyData();
    } catch (err) {
      if (m !== this.store.state.permanentModal) return;
      m.executing = false;
      m.error = extractErrorMessage(err);
      this.store.notify();
    }
  }

  private promptNewFilename(): Promise<string | null> {
    this.store.state.inspectedEntry = null;
    this.exploreView.closeFloatingPanels();
    if (this.renameResolver) this.closeRenamePrompt(null);
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
      this.syncOverlayFocus();
    });
  }

  private closeRenamePrompt(value: string | null): void {
    this.renameOverlay.classList.remove("modal-backdrop--open");
    clearChildren(this.renameOverlay);
    const r = this.renameResolver;
    this.renameResolver = null;
    this.syncOverlayFocus();
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
