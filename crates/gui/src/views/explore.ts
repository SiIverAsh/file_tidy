import type {
  BuildPlanRequest,
  EntryId,
  FileEntryDto,
  ScanFilter,
  ScanTab,
  SkippedEntryDto,
  SortField,
  ZoneKind,
} from "../api/types.ts";
import {
  clearChildren,
  createSizeLabel,
  el,
  formatBytes,
  setText,
} from "../components/safe-text.ts";
import { VirtualEntryList } from "../components/virtual-list.ts";
import { createPolicyExplanationBox, createZoneBadge } from "../components/zone-badge.ts";
import { containsNode } from "../components/overlay-focus.ts";
import { categoryLabel } from "../components/display-labels.ts";
import {
  clearSelection,
  selectAllCurrentFilter,
  selectedCountEstimate,
  toggleEntrySelection,
  type AppStateModel,
} from "../state/store.ts";

function extensionDisplayLabel(extension: string): string {
  return extension === "" || extension === "__none__" ? "无后缀" : `.${extension}`;
}

export interface ExploreViewCallbacks {
  onPickRoots(): Promise<void>;
  onPickRules(): Promise<void>;
  onStartScan(): Promise<void>;
  onCancelScan(): Promise<void>;
  onUpdateOptions(patch: Partial<AppStateModel["scanOptions"]>): void;
  onFilterChange(patch: Partial<ScanFilter>, reloadTreemap?: boolean): Promise<void>;
  onSortChange(sort: SortField): Promise<void>;
  onFetchWindow(offset: number, limit: number): Promise<{
    totalCount: number;
    entries: FileEntryDto[];
  }>;
  onFetchChildren?(parentId: EntryId | null, offset: number, limit: number): Promise<{
    totalCount: number;
    entries: FileEntryDto[];
  }>;
  onFetchSkipped(): Promise<SkippedEntryDto[]>;
  onSelectionChange(next: AppStateModel["selection"]): void;
  onInspectEntry(entry: FileEntryDto | null): void;
  onDrillDirectory(entryId: EntryId | null): Promise<void>;
  onTriggerAction(
    kind: BuildPlanRequest["kind"],
    pickDestination: boolean,
  ): Promise<void>;
  onQuickAuthorizeSelected(): Promise<void>;
}

function bindFloatingDisclosure(
  container: HTMLElement,
  trigger: HTMLElement,
  panel: HTMLElement,
  initialOpen = false,
  onToggle?: (open: boolean) => void,
): { isOpen(): boolean; setOpen(next: boolean): void; close(restoreFocus?: boolean): void; dispose(): void } {
  const doc = document;
  const win = typeof window !== "undefined" &&
    typeof (window as unknown as { addEventListener?: unknown }).addEventListener === "function" &&
    typeof (window as unknown as { removeEventListener?: unknown }).removeEventListener === "function" &&
    (window as unknown) !== (doc as unknown)
    ? window
    : null;
  let openState = initialOpen;
  let listening = false;
  const canListen = typeof doc.addEventListener === "function" &&
    typeof doc.removeEventListener === "function";

  const isTargetInside = (event: Event): boolean => {
    const withPath = event as { composedPath?: () => EventTarget[] };
    if (typeof withPath.composedPath === "function" && withPath.composedPath().includes(container)) {
      return true;
    }
    let target = event.target as Node | null;
    while (target) {
      if (target === container) return true;
      target = target.parentNode;
    }
    return false;
  };

  const onOutsidePointer = (event: Event): void => {
    if (!openState) {
      stopListening();
      return;
    }
    if (isTargetInside(event)) return;
    close();
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !openState) return;
    if (container.isConnected === false) {
      close();
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    close(true);
  };

  const startListening = (): void => {
    if (!canListen || listening) return;
    win?.addEventListener("pointerdown", onOutsidePointer, true);
    win?.addEventListener("mousedown", onOutsidePointer, true);
    win?.addEventListener("click", onOutsidePointer, true);
    win?.addEventListener("keydown", onKeyDown, true);
    doc.addEventListener("pointerdown", onOutsidePointer, true);
    doc.addEventListener("mousedown", onOutsidePointer, true);
    doc.addEventListener("click", onOutsidePointer, true);
    doc.addEventListener("keydown", onKeyDown, true);
    listening = true;
  };

  const stopListening = (): void => {
    if (!listening) return;
    win?.removeEventListener("pointerdown", onOutsidePointer, true);
    win?.removeEventListener("mousedown", onOutsidePointer, true);
    win?.removeEventListener("click", onOutsidePointer, true);
    win?.removeEventListener("keydown", onKeyDown, true);
    doc.removeEventListener("pointerdown", onOutsidePointer, true);
    doc.removeEventListener("mousedown", onOutsidePointer, true);
    doc.removeEventListener("click", onOutsidePointer, true);
    doc.removeEventListener("keydown", onKeyDown, true);
    listening = false;
  };

  const applyState = (): void => {
    panel.hidden = !openState;
    trigger.setAttribute("aria-expanded", String(openState));
    if (openState) {
      container.setAttribute("data-open", "true");
      container.classList.add("disclosure--open");
      startListening();
    } else {
      container.removeAttribute("data-open");
      container.classList.remove("disclosure--open");
      stopListening();
    }
  };

  const close = (restoreFocus = false): void => {
    const wasOpen = openState;
    openState = false;
    applyState();
    if (wasOpen) onToggle?.(false);
    if (wasOpen && restoreFocus) trigger.focus();
  };

  const setOpen = (next: boolean): void => {
    if (openState === next) return;
    openState = next;
    applyState();
    onToggle?.(openState);
  };

  trigger.addEventListener("click", (event) => {
    event.preventDefault();
    setOpen(!openState);
  });
  container.addEventListener("keydown", onKeyDown);
  applyState();
  return { isOpen: () => openState, setOpen, close, dispose: () => stopListening() };
}

export class ExploreView {
  readonly root: HTMLElement;
  readonly virtualList: VirtualEntryList;

  private readonly callbacks: ExploreViewCallbacks;
  private readonly splitEl: HTMLElement;
  private readonly inspectorEl: HTMLElement;
  private readonly progressSlot: HTMLElement;
  private readonly progressText: HTMLElement;
  private readonly sideDockEl: HTMLElement;
  private readonly sideHandleEl: HTMLButtonElement;
  private readonly summarySlot: HTMLElement;
  private readonly contentSlot: HTMLElement;
  private readonly actionBar: HTMLElement;
  private readonly filterBar: HTMLElement;

  constructor(callbacks: ExploreViewCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--explore");

    this.progressSlot = el("div", "slot");
    this.progressSlot.hidden = true;
    const progressBar = el("div", "scan-progress");
    this.progressText = el("span", "scan-progress__text");
    progressBar.appendChild(this.progressText);
    const cancelBtn = el("button", "btn btn--danger-outline btn--compact", "停止扫描");
    cancelBtn.type = "button";
    cancelBtn.addEventListener("click", () => {
      void this.callbacks.onCancelScan();
    });
    progressBar.appendChild(cancelBtn);
    this.progressSlot.appendChild(progressBar);
    this.sideDockEl = el("div", "explore-side-dock");
    this.sideDockEl.hidden = true;
    this.sideHandleEl = el("button", "explore-side-dock__handle");
    this.sideHandleEl.type = "button";
    this.sideHandleEl.setAttribute("aria-label", "展开文件类型与后缀筛选");
    this.sideHandleEl.appendChild(el("span", "explore-side-dock__dot"));
    this.sideHandleEl.appendChild(el("span", "explore-side-dock__label", "类型"));
    this.summarySlot = el("section", "explore-side");
    this.summarySlot.hidden = true;
    this.summarySlot.setAttribute("aria-label", "文件类型分布");
    this.sideDockEl.appendChild(this.sideHandleEl);
    this.sideDockEl.appendChild(this.summarySlot);
    this.filterBar = el("div", "filter-bar");
    this.contentSlot = el("div", "explore-content");
    this.inspectorEl = el("aside", "inspector inspector--hidden");
    this.inspectorEl.setAttribute("role", "dialog");
    this.inspectorEl.setAttribute("aria-label", "文件夹与项目详情");
    this.splitEl = el("div", "explore-split explore-split--single");
    this.actionBar = el("div", "action-bar");

    this.virtualList = new VirtualEntryList({
      onFetchWindow: (offset, limit) => this.callbacks.onFetchWindow(offset, limit),
      ...(callbacks.onFetchChildren ? {
        onFetchChildren: (parentId: EntryId | null, offset: number, limit: number) =>
          callbacks.onFetchChildren!(parentId, offset, limit),
      } : {}),
      onToggleSelect: (entryId) => {
        // Store handles toggle in main coordinator
        const current = this.lastModel;
        if (!current) {
          return;
        }
        const gen = current.scanSummary?.scan_generation ?? "0";
        this.callbacks.onSelectionChange(
          toggleEntrySelection(current.selection, entryId, gen),
        );
      },
      onInspectEntry: (entry) => this.callbacks.onInspectEntry(entry),
      onDrillDirectory: (entry) => {
        void this.callbacks.onDrillDirectory(entry.id);
      },
    });
  }

  private lastModel: AppStateModel | null = null;
  private lastGenRendered: string | null = null;
  private lastTabRendered: ScanTab | null = null;
  private lastDupGroupRendered: string | null = null;
  private searchInputEl: HTMLInputElement | null = null;
  private selectAllBtnEl: HTMLButtonElement | null = null;
  private toolbarBuilt = false;
  private rootsSummaryEl: HTMLElement | null = null;
  private rulesBtnEl: HTMLButtonElement | null = null;
  private scanBtnEl: HTMLButtonElement | null = null;
  private allVolInput: HTMLInputElement | null = null;
  private metaInput: HTMLInputElement | null = null;
  private noDupInput: HTMLInputElement | null = null;
  private staleInput: HTMLInputElement | null = null;
  private emptyStateKey: string | null = null;
  private summaryRendered: AppStateModel["scanSummary"] = null;
  private summaryCategoryRendered: string | null = null;
  private summaryExtensionRendered: string | null = null;
  private summaryExpandedVersion = 0;
  private summaryRenderedExpandedVersion = -1;
  private readonly expandedCategories = new Set<string>();
  private renderedInspectorKey: string | null = null;
  private inspectorListening = false;
  private filterDisclosureOpen = false;
  private renderedFilterKey: string | null = null;
  private renderedActionKey: string | null = null;
  private scanOptionsDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private scanOptionsEl: HTMLElement | null = null;
  private filterDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private actionDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private filterDisclosureEl: HTMLElement | null = null;
  private actionDisclosureEl: HTMLElement | null = null;

  private readonly onInspectorKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !this.lastModel?.inspectedEntry) return;
    event.preventDefault();
    event.stopPropagation();
    this.callbacks.onInspectEntry(null);
  };

  private readonly onInspectorPointerDown = (event: Event): void => {
    if (!this.lastModel?.inspectedEntry) return;
    let target = event.target as HTMLElement | null;
    while (target) {
      if (
        target === this.inspectorEl ||
        target.classList?.contains("vlist__row") ||
        target.classList?.contains("action-bar") ||
        target.classList?.contains("drawer") ||
        target.classList?.contains("modal-backdrop")
      ) {
        return;
      }
      target = target.parentNode as HTMLElement | null;
    }
    this.callbacks.onInspectEntry(null);
  };

  private setInspectorListeners(active: boolean): void {
    const canListen = typeof document.addEventListener === "function" &&
      typeof document.removeEventListener === "function";
    if (!canListen) return;
    if (active && !this.inspectorListening) {
      document.addEventListener("keydown", this.onInspectorKeyDown, true);
      document.addEventListener("pointerdown", this.onInspectorPointerDown, true);
      document.addEventListener("mousedown", this.onInspectorPointerDown, true);
      this.inspectorListening = true;
    } else if (!active && this.inspectorListening) {
      document.removeEventListener("keydown", this.onInspectorKeyDown, true);
      document.removeEventListener("pointerdown", this.onInspectorPointerDown, true);
      document.removeEventListener("mousedown", this.onInspectorPointerDown, true);
      this.inspectorListening = false;
    }
  }

  closeFloatingPanels(restoreFocus = true): void {
    const active = document.activeElement;
    this.scanOptionsDismissal?.close(restoreFocus && containsNode(this.scanOptionsEl ?? this.root, active));
    this.filterDismissal?.close(restoreFocus && containsNode(this.filterDisclosureEl ?? this.filterBar, active));
    this.actionDismissal?.close(restoreFocus && containsNode(this.actionDisclosureEl ?? this.actionBar, active));
    this.filterDisclosureOpen = false;
    this.setInspectorListeners(false);
    this.renderedInspectorKey = null;
    clearChildren(this.inspectorEl);
    this.inspectorEl.classList.add("inspector--hidden");
    this.inspectorEl.classList.remove("inspector--open");
  }

  render(model: AppStateModel): void {
    this.lastModel = model;
    if (!this.toolbarBuilt) {
      this.buildSkeleton(model);
      this.toolbarBuilt = true;
    }

    this.syncToolbar(model);
    this.renderProgress(model);
    this.renderSummary(model);
    this.renderFilterBar(model);
    this.renderContent(model);
    this.renderInspector(model.inspectedEntry);
    this.renderActionBar(model);
  }

  private buildSkeleton(model: AppStateModel): void {
    clearChildren(this.root);

    const heading = el("header", "page-header");
    heading.appendChild(el("h1", "page-header__title", "文件与空间"));
    this.root.appendChild(heading);

    const toolbar = el("div", "scan-toolbar");
    const primaryRow = el("div", "scan-toolbar__primary");

    const directory = el("div", "scan-directory");
    const directoryIcon = el("span", "scan-directory__icon ui-icon ui-icon--folder");
    directoryIcon.setAttribute("aria-hidden", "true");
    directory.appendChild(directoryIcon);
    const directoryInfo = el("div", "scan-directory__info");
    directoryInfo.appendChild(el("span", "scan-directory__label", "扫描位置"));
    this.rootsSummaryEl = el("span", "scan-toolbar__roots", "选择要整理的文件夹");
    directoryInfo.appendChild(this.rootsSummaryEl);
    directory.appendChild(directoryInfo);
    primaryRow.appendChild(directory);

    const actions = el("div", "scan-toolbar__actions");
    const pickBtn = el("button", "btn btn--secondary", "选择文件夹");
    pickBtn.type = "button";
    pickBtn.addEventListener("click", () => {
      void this.callbacks.onPickRoots();
    });
    const scanBtn = el("button", "btn btn--primary", "开始扫描");
    scanBtn.type = "button";
    scanBtn.addEventListener("click", () => {
      void this.callbacks.onStartScan();
    });
    this.scanBtnEl = scanBtn;

    const optionsDisclosure = el("div", "scan-options");
    this.scanOptionsEl = optionsDisclosure;
    const optionsTrigger = el("button", "scan-options__summary", "扫描选项");
    optionsTrigger.type = "button";
    optionsTrigger.setAttribute("aria-haspopup", "true");
    optionsTrigger.setAttribute("aria-controls", "scan-options-panel");
    optionsDisclosure.appendChild(optionsTrigger);
    const optRow = el("div", "scan-toolbar__options");
    optRow.id = "scan-options-panel";
    optRow.setAttribute("role", "group");
    optRow.setAttribute("aria-label", "扫描选项");
    this.scanOptionsDismissal = bindFloatingDisclosure(optionsDisclosure, optionsTrigger, optRow);

    const allLabel = el("label", "switch scan-option");
    const allCb = el("input");
    allCb.type = "checkbox";
    allCb.checked = model.scanOptions.all_volumes;
    allCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ all_volumes: allCb.checked }),
    );
    this.allVolInput = allCb;
    allLabel.appendChild(allCb);
    allLabel.appendChild(el("span", "", "扫描所有本地磁盘"));
    optRow.appendChild(allLabel);

    const metaLabel = el("label", "switch scan-option");
    const metaCb = el("input");
    metaCb.type = "checkbox";
    metaCb.checked = model.scanOptions.metadata_only;
    metaCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ metadata_only: metaCb.checked }),
    );
    this.metaInput = metaCb;
    metaLabel.appendChild(metaCb);
    metaLabel.appendChild(el("span", "", "仅读取文件信息"));
    optRow.appendChild(metaLabel);

    const dupLabel = el("label", "switch scan-option");
    const dupCb = el("input");
    dupCb.type = "checkbox";
    dupCb.checked = model.scanOptions.no_duplicates;
    dupCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ no_duplicates: dupCb.checked }),
    );
    this.noDupInput = dupCb;
    dupLabel.appendChild(dupCb);
    dupLabel.appendChild(el("span", "", "不查找重复文件"));
    optRow.appendChild(dupLabel);

    const staleLabel = el("label", "inline-field scan-option scan-option--number");
    staleLabel.appendChild(el("span", "", "未修改天数"));
    const staleIn = el("input", "input input--sm");
    staleIn.type = "number";
    staleIn.min = "1";
    staleIn.max = "36500";
    staleIn.value = String(model.scanOptions.stale_days);
    staleIn.addEventListener("change", () => {
      const n = Number.parseInt(staleIn.value, 10);
      if (Number.isFinite(n) && n >= 1) {
        this.callbacks.onUpdateOptions({ stale_days: n });
      }
    });
    this.staleInput = staleIn;
    staleLabel.appendChild(staleIn);
    optRow.appendChild(staleLabel);

    const rulesBtn = el("button", "btn btn--ghost scan-options__rules", "自定义规则");
    rulesBtn.type = "button";
    rulesBtn.addEventListener("click", () => {
      void this.callbacks.onPickRules();
    });
    this.rulesBtnEl = rulesBtn;
    optRow.appendChild(rulesBtn);

    optionsDisclosure.appendChild(optRow);
    actions.appendChild(optionsDisclosure);
    actions.appendChild(pickBtn);
    actions.appendChild(scanBtn);
    primaryRow.appendChild(actions);
    toolbar.appendChild(primaryRow);

    this.root.appendChild(toolbar);
    this.root.appendChild(this.progressSlot);

    const mainColumn = el("div", "explore-main");
    mainColumn.appendChild(this.filterBar);
    mainColumn.appendChild(this.contentSlot);
    this.splitEl.appendChild(mainColumn);
    this.splitEl.appendChild(this.sideDockEl);
    this.root.appendChild(this.splitEl);
    this.root.appendChild(this.inspectorEl);
    this.root.appendChild(this.actionBar);
  }

  private syncToolbar(model: AppStateModel): void {
    if (this.rootsSummaryEl) {
      if (model.scanOptions.all_volumes) {
        this.rootsSummaryEl.textContent = "全部本地卷";
      } else if (model.pendingRoots && model.pendingRoots.roots_display.length > 0) {
        this.rootsSummaryEl.textContent = model.pendingRoots.roots_display.join(" , ");
      } else {
        this.rootsSummaryEl.textContent = "选择要整理的文件夹";
      }
      this.rootsSummaryEl.title = this.rootsSummaryEl.textContent ?? "";
    }
    if (this.rulesBtnEl) {
      this.rulesBtnEl.textContent = model.rulesFile?.path_display
        ? `规则：${model.rulesFile.path_display} (${model.rulesFile.rule_count})`
        : "自定义规则 (TOML)";
    }
    if (this.scanBtnEl) {
      this.scanBtnEl.textContent = model.scanning ? "正在扫描…" : model.scanSummary ? "重新扫描" : "开始扫描";
      this.scanBtnEl.disabled =
        model.scanning ||
        (!model.scanOptions.all_volumes &&
          (!model.pendingRoots || model.pendingRoots.roots_display.length === 0));
    }
    if (this.allVolInput) {
      this.allVolInput.checked = model.scanOptions.all_volumes;
    }
    if (this.metaInput) {
      this.metaInput.checked = model.scanOptions.metadata_only;
    }
    if (this.noDupInput) {
      this.noDupInput.checked = model.scanOptions.no_duplicates;
    }
    if (this.staleInput) {
      this.staleInput.value = String(model.scanOptions.stale_days);
    }
  }

  private renderProgress(model: AppStateModel): void {
    this.progressSlot.hidden = !model.scanning;
    if (!model.scanning) {
      return;
    }
    const phaseLabel = (phase: string): string => {
      switch (phase) {
        case "discovering":
          return "扫描文件夹";
        case "metadata":
          return "识别文件类型";
        case "content":
          return "读取文件内容";
        case "duplicates":
          return "查找重复文件";
        case "complete":
          return "整理结果";
        default:
          return phase;
      }
    };
    const p = model.scanProgress;
    const counts = p?.phase === "discovering"
      ? `发现 ${p.discovered} 项 · 已处理 ${p.processed} 项`
      : p
        ? `${p.phase === "content" || p.phase === "duplicates" ? "当前组" : "已完成"} ${p.phase_processed}/${p.phase_total} 项`
        : "";
    setText(
      this.progressText,
      p
        ? `${phaseLabel(p.phase)} · ${counts} · 已读 ${formatBytes(p.content_bytes_read)}`
        : "正在扫描…",
    );
  }

  private renderSummary(model: AppStateModel): void {
    const activeCategory = model.scanFilter.category_filter;
    const activeExtension = model.scanFilter.extension_filter;
    if (
      this.summaryRendered === model.scanSummary &&
      this.summaryCategoryRendered === activeCategory &&
      this.summaryExtensionRendered === activeExtension &&
      this.summaryRenderedExpandedVersion === this.summaryExpandedVersion
    ) {
      return;
    }
    if (this.summaryRendered !== model.scanSummary) {
      this.expandedCategories.clear();
    }
    this.summaryRendered = model.scanSummary;
    this.summaryCategoryRendered = activeCategory;
    this.summaryExtensionRendered = activeExtension;
    this.summaryRenderedExpandedVersion = this.summaryExpandedVersion;
    clearChildren(this.summarySlot);
    const summary = model.scanSummary;
    if (!summary) {
      this.sideDockEl.hidden = true;
      this.sideDockEl.classList.remove("explore-side-dock--filtered");
      this.summarySlot.hidden = true;
      this.splitEl.classList.add("explore-split--single");
      return;
    }
    const isFiltered = activeCategory !== "all" || activeExtension !== "all";
    this.sideDockEl.hidden = false;
    if (isFiltered) {
      this.sideDockEl.classList.add("explore-side-dock--filtered");
    } else {
      this.sideDockEl.classList.remove("explore-side-dock--filtered");
    }
    this.summarySlot.hidden = false;
    this.splitEl.classList.remove("explore-split--single");

    if (!summary.complete) {
      const reasons: string[] = [];
      if (summary.cancelled) {
        reasons.push("已停止");
      }
      if (summary.limit_reached) {
        reasons.push("已达条目上限");
      }
      if (Number(summary.skipped) > 0) {
        reasons.push(`${summary.skipped} 项跳过`);
      }
      this.summarySlot.appendChild(
        el(
          "div",
          "alert alert--warn",
          `不完整扫描（${reasons.join(" · ") || "部分未完成"}）：未扫描区域标为未知。`,
        ),
      );
    }

    const strip = el("section", "category-strip");
    strip.setAttribute("aria-label", "文件类型统计");
    const head = el("div", "category-strip__head");
    head.appendChild(el("span", "category-strip__title", "文件类型与后缀"));
    if (isFiltered) {
      const resetBtn = el("button", "btn btn--ghost btn--compact category-strip__reset", "显示全部类型");
      resetBtn.type = "button";
      resetBtn.addEventListener("click", () => {
        void this.callbacks.onFilterChange({
          category_filter: "all",
          extension_filter: "all",
        });
      });
      head.appendChild(resetBtn);
    } else {
      head.appendChild(el("span", "category-strip__hint", "点击类型或展开后缀筛选"));
    }
    strip.appendChild(head);

    const categories = summary.category_counts ?? [];
    if (categories.length === 0) {
      strip.appendChild(el("div", "category-strip__empty", "本次扫描未发现可分类的常规文件"));
    } else {
      const totalFiles = categories.reduce((sum, item) => sum + item.count, 0);
      const grid = el("div", "category-strip__list");
      const knownCategories = new Set([
        "document", "image", "video", "audio", "archive", "code", "installer", "other",
      ]);
      for (const item of categories) {
        const safeCategory = knownCategories.has(item.category) ? item.category : "other";
        const isCategoryActive = activeCategory === item.category;
        const isCategoryOnlyActive = isCategoryActive && activeExtension === "all";
        const extensions = item.extensions ?? [];
        const isExpanded = this.expandedCategories.has(item.category);

        const group = el(
          "div",
          `category-group category-chip--${safeCategory}${isCategoryActive ? " category-group--active" : ""}`,
        );

        const chip = el(
          "button",
          `category-chip category-chip--${safeCategory}${isCategoryOnlyActive ? " category-chip--active" : ""}`,
        );
        chip.type = "button";
        chip.setAttribute("aria-pressed", String(isCategoryOnlyActive));

        const top = el("div", "category-chip__top");
        const nameGroup = el("span", "category-chip__name-group");
        const dot = el("span", "category-chip__dot");
        dot.setAttribute("aria-hidden", "true");
        nameGroup.appendChild(dot);
        nameGroup.appendChild(el("span", "category-chip__name", categoryLabel(item.category)));
        top.appendChild(nameGroup);
        top.appendChild(el("strong", "category-chip__count", `${item.count} 个`));
        chip.appendChild(top);

        const meta = el("div", "category-chip__meta");
        meta.appendChild(el("span", "", formatBytes(item.logical_bytes)));
        if (totalFiles > 0) {
          const share = Math.max(1, Math.round((item.count / totalFiles) * 100));
          meta.appendChild(el("span", "", `${share}%`));
        }
        chip.appendChild(meta);

        chip.addEventListener("click", () => {
          void this.callbacks.onFilterChange({
            ...(model.scanFilter.tab === "skipped" ? { tab: "browse" as const } : {}),
            category_filter: isCategoryOnlyActive ? "all" : item.category,
            extension_filter: "all",
          });
        });
        group.appendChild(chip);

        if (extensions.length > 0) {
          const toggleBtn = el(
            "button",
            "category-group__toggle",
            `${extensions.length} 种后缀`,
          );
          toggleBtn.type = "button";
          toggleBtn.setAttribute("aria-expanded", String(isExpanded));
          toggleBtn.addEventListener("click", () => {
            if (this.expandedCategories.has(item.category)) {
              this.expandedCategories.delete(item.category);
            } else {
              this.expandedCategories.add(item.category);
            }
            this.summaryExpandedVersion += 1;
            this.renderSummary(model);
          });
          group.appendChild(toggleBtn);

          if (isExpanded) {
            const extList = el("div", "category-ext-list");
            for (const ext of extensions) {
              const extKey = ext.extension === "" ? "__none__" : ext.extension;
              const extLabel = extensionDisplayLabel(ext.extension);
              const isExtActive = isCategoryActive && activeExtension === extKey;
              const extBtn = el(
                "button",
                `ext-chip${isExtActive ? " ext-chip--active" : ""}`,
              );
              extBtn.type = "button";
              extBtn.setAttribute("aria-pressed", String(isExtActive));
              extBtn.title = `${extLabel} · ${ext.count} 个 · ${formatBytes(ext.logical_bytes)}`;
              extBtn.appendChild(el("span", "ext-chip__name", extLabel));
              extBtn.appendChild(el("span", "ext-chip__count", String(ext.count)));
              extBtn.addEventListener("click", () => {
                void this.callbacks.onFilterChange({
                  ...(model.scanFilter.tab === "skipped" ? { tab: "browse" as const } : {}),
                  category_filter: item.category,
                  extension_filter: isExtActive ? "all" : extKey,
                });
              });
              extList.appendChild(extBtn);
            }
            group.appendChild(extList);
          }
        }

        grid.appendChild(group);
      }
      strip.appendChild(grid);
    }
    this.summarySlot.appendChild(strip);

    if (summary.notices.length > 0) {
      this.summarySlot.appendChild(el("div", "notice-strip", summary.notices.join(" · ")));
    }
  }

  private renderFilterBar(model: AppStateModel): void {
    if (!model.scanSummary) {
      this.filterDisclosureEl = null;
      this.filterDismissal?.dispose();
      this.filterDismissal = null;
      this.renderedFilterKey = null;
      this.searchInputEl = null;
      this.selectAllBtnEl = null;
      clearChildren(this.filterBar);
      return;
    }

    const filterKey = JSON.stringify([model.scanSummary.scan_generation, model.scanFilter, model.scanSort]);
    if (filterKey === this.renderedFilterKey) {
      if (this.selectAllBtnEl) {
        this.selectAllBtnEl.textContent = `全选 (${model.totalFilteredCount})`;
        this.selectAllBtnEl.disabled = model.totalFilteredCount === 0;
      }
      return;
    }

    if (
      this.searchInputEl !== null &&
      document.activeElement === this.searchInputEl &&
      this.lastTabRendered === model.scanFilter.tab
    ) {
      if (this.selectAllBtnEl) {
        this.selectAllBtnEl.textContent = `全选 (${model.totalFilteredCount})`;
        this.selectAllBtnEl.disabled = model.totalFilteredCount === 0;
      }
      return;
    }

    this.searchInputEl = null;
    this.selectAllBtnEl = null;
    this.renderedFilterKey = filterKey;
    this.filterDisclosureEl = null;
    this.filterDismissal?.dispose();
    this.filterDismissal = null;
    clearChildren(this.filterBar);

    const tabs: Array<{ id: ScanTab; label: string }> = [
      { id: "browse", label: "浏览" },
      { id: "top", label: `大文件 (${model.scanSummary.top_entry_ids.length})` },
      { id: "duplicates", label: `重复 (${model.scanSummary.duplicates.length})` },
      { id: "stale", label: `久未修改 (${model.scanSummary.stale_entry_ids.length})` },
      { id: "skipped", label: `跳过 (${model.scanSummary.skipped})` },
    ];

    const barRow = el("div", "filter-bar__row");

    if (
      model.scanFilter.tab === "browse" &&
      model.scanFilter.parent_entry_id !== null
    ) {
      const backBtn = el("button", "btn btn--ghost btn--compact", "← 根目录");
      backBtn.type = "button";
      backBtn.title = "返回扫描根目录";
      backBtn.addEventListener("click", () => {
        void this.callbacks.onDrillDirectory(null);
      });
      barRow.appendChild(backBtn);
    }

    const tabRow = el("div", "subtabs");
    for (const t of tabs) {
      const btn = el("button", "subtab", t.label);
      btn.type = "button";
      if (model.scanFilter.tab === t.id) {
        btn.classList.add("subtab--active");
      }
      btn.setAttribute("aria-pressed", String(model.scanFilter.tab === t.id));
      btn.addEventListener("click", () => {
        void this.callbacks.onFilterChange({
          tab: t.id,
          duplicate_group_id: null,
        });
      });
      tabRow.appendChild(btn);
    }
    barRow.appendChild(tabRow);
    this.filterBar.appendChild(barRow);

    if (model.scanFilter.tab !== "skipped") {
      const controls = el("div", "filter-controls");

      const search = el("input", "input input--search");
      search.type = "search";
      search.placeholder = "搜索文件或文件夹";
      search.setAttribute("aria-label", "搜索文件或文件夹");
      search.value = model.scanFilter.search_text;
      search.addEventListener("change", () => {
        void this.callbacks.onFilterChange({ search_text: search.value });
      });
      this.searchInputEl = search;
      controls.appendChild(search);

      const showHidden = el("label", "switch");
      showHidden.title = "目录大小包含隐藏文件；此开关只控制列表显示。";
      const hiddenCb = el("input");
      hiddenCb.type = "checkbox";
      hiddenCb.setAttribute("aria-label", "显示隐藏文件");
      hiddenCb.checked = !model.scanFilter.hide_hidden;
      hiddenCb.addEventListener("change", () => {
        void this.callbacks.onFilterChange({ hide_hidden: !hiddenCb.checked });
      });
      showHidden.appendChild(hiddenCb);
      showHidden.appendChild(el("span", "", "显示隐藏文件"));
      controls.appendChild(showHidden);
      if (model.scanFilter.hide_hidden) {
        controls.appendChild(el("span", "item-card__sub", "目录大小包含隐藏文件"));
      }
      if (model.scanFilter.category_filter !== "all" || model.scanFilter.extension_filter !== "all") {
        const parts: string[] = [];
        if (model.scanFilter.category_filter !== "all") {
          parts.push(categoryLabel(model.scanFilter.category_filter));
        }
        if (model.scanFilter.extension_filter !== "all") {
          parts.push(extensionDisplayLabel(model.scanFilter.extension_filter));
        }
        const typePill = el("button", "active-type-pill", `${parts.join(" · ")} ×`);
        typePill.type = "button";
        typePill.title = "点击清除文件类型/后缀筛选";
        typePill.setAttribute("aria-label", `清除筛选：${parts.join(" ")}`);
        typePill.addEventListener("click", () => {
          void this.callbacks.onFilterChange({
            category_filter: "all",
            extension_filter: "all",
          });
        });
        controls.appendChild(typePill);
      }

      const filterDisclosure = el("div", "filter-disclosure");
      this.filterDisclosureEl = filterDisclosure;
      if (this.filterDisclosureOpen) filterDisclosure.classList.add("filter-disclosure--restored");
      const filterLabel = model.scanFilter.zone_filter !== "all" ? "筛选 · 已调整" : "筛选";
      const filterTrigger = el("button", "scan-options__summary", filterLabel);
      filterTrigger.type = "button";
      filterTrigger.setAttribute("aria-haspopup", "true");
      filterDisclosure.appendChild(filterTrigger);
      const filterPanel = el("div", "filter-disclosure__panel");
      this.filterDismissal = bindFloatingDisclosure(
        filterDisclosure,
        filterTrigger,
        filterPanel,
        this.filterDisclosureOpen,
        (open) => {
          if (this.filterDisclosureEl !== filterDisclosure) return;
          this.filterDisclosureOpen = open;
          if (!open) filterDisclosure.classList.remove("filter-disclosure--restored");
        },
      );
      const zoneSel = el("select", "select");
      zoneSel.setAttribute("aria-label", "按访问状态筛选");
      const zones: Array<{ value: ZoneKind | "all"; label: string }> = [
        { value: "all", label: "全部区域" },
        { value: "C_DefaultAllowed", label: "默认允许" },
        { value: "C_GrantedPersistent", label: "持久授权" },
        { value: "C_GrantedSession", label: "本次授权" },
        { value: "B_Sensitive", label: "敏感提示" },
        { value: "A_Protected", label: "系统保护" },
        { value: "Unauthenticated", label: "访问受限" },
      ];
      for (const z of zones) {
        const opt = el("option", "", z.label);
        opt.value = z.value;
        opt.selected = model.scanFilter.zone_filter === z.value;
        zoneSel.appendChild(opt);
      }
      zoneSel.addEventListener("change", () => {
        void this.callbacks.onFilterChange({
          zone_filter: zoneSel.value as ZoneKind | "all",
        });
      });
      const zoneLabel = el("label", "inline-field");
      zoneLabel.appendChild(el("span", "", "访问状态"));
      zoneLabel.appendChild(zoneSel);
      filterPanel.appendChild(zoneLabel);

      const sortSel = el("select", "select");
      sortSel.setAttribute("aria-label", "排序方式");
      const sorts: Array<{ value: SortField; label: string }> = [
        { value: "size_desc", label: "按大小" },
        { value: "name_asc", label: "按名称" },
        { value: "modified_asc", label: "按最早修改" },
      ];
      for (const s of sorts) {
        const opt = el("option", "", s.label);
        opt.value = s.value;
        opt.selected = model.scanSort === s.value;
        sortSel.appendChild(opt);
      }
      sortSel.addEventListener("change", () => {
        void this.callbacks.onSortChange(sortSel.value as SortField);
      });

      filterDisclosure.appendChild(filterPanel);
      controls.appendChild(filterDisclosure);
      controls.appendChild(sortSel);

      const selectAllBtn = el(
        "button",
        "btn btn--ghost btn--compact",
        `全选 (${model.totalFilteredCount})`,
      );
      selectAllBtn.type = "button";
      selectAllBtn.disabled = model.totalFilteredCount === 0;
      selectAllBtn.addEventListener("click", () => {
        const gen = model.scanSummary?.scan_generation ?? "0";
        this.callbacks.onSelectionChange(selectAllCurrentFilter(gen, model.scanFilter));
      });
      this.selectAllBtnEl = selectAllBtn;
      controls.appendChild(selectAllBtn);

      this.filterBar.appendChild(controls);
    }
  }

  private renderContent(model: AppStateModel): void {
    const gen = model.scanSummary?.scan_generation ?? null;
    if (!model.scanSummary) {
      this.lastGenRendered = null;
      this.lastTabRendered = null;
      this.lastDupGroupRendered = null;
      const emptyKey = model.scanning ? "scanning" : "ready";
      if (this.emptyStateKey === emptyKey) return;
      this.emptyStateKey = emptyKey;
      clearChildren(this.contentSlot);
      const hero = el("div", model.scanning ? "empty-hero empty-hero--scanning" : "empty-hero");
      const illustration = el("div", "empty-hero__illustration");
      illustration.setAttribute("aria-hidden", "true");
      illustration.appendChild(el("span", "empty-hero__paper empty-hero__paper--back"));
      illustration.appendChild(el("span", "empty-hero__paper"));
      illustration.appendChild(el("span", "empty-hero__folder"));
      hero.appendChild(illustration);
      hero.appendChild(el("h2", "empty-hero__title", model.scanning ? "正在了解你的文件" : "给文件一个整洁的空间"));
      hero.appendChild(el("p", "empty-hero__sub", model.scanning ? "扫描完成后，空间分布和整理建议会显示在这里。" : "选择文件夹并开始扫描，先了解，再整理。"));
      this.contentSlot.appendChild(hero);
      return;
    }
    this.emptyStateKey = null;

    const tab = model.scanFilter.tab;
    const dupGroupChanged =
      tab === "duplicates" &&
      this.lastDupGroupRendered !== model.scanFilter.duplicate_group_id;
    const structureChanged =
      this.lastGenRendered !== gen || this.lastTabRendered !== tab || dupGroupChanged;
    this.lastGenRendered = gen;
    this.lastTabRendered = tab;
    this.lastDupGroupRendered = model.scanFilter.duplicate_group_id;

    if (structureChanged) {
      clearChildren(this.contentSlot);
      if (tab === "browse" || tab === "top") {
        this.contentSlot.appendChild(this.virtualList.root);
      } else if (tab === "duplicates") {
        this.renderDuplicatesPanel(model);
        this.contentSlot.appendChild(this.virtualList.root);
      } else if (tab === "stale") {
        this.contentSlot.appendChild(
          el(
            "div",
            "alert alert--info",
            `超过 ${model.scanOptions.stale_days} 天未修改`,
          ),
        );
        this.contentSlot.appendChild(this.virtualList.root);
      } else if (tab === "skipped") {
        this.renderSkippedNotice(model);
      }
    }

    if (tab !== "skipped") {
      this.virtualList.updateSelection(model.selection, model.scanSummary.scan_generation);
    }
  }

  private renderDuplicatesPanel(model: AppStateModel): void {
    const summary = model.scanSummary;
    if (!summary) {
      return;
    }
    const wrap = el("div", "dup-groups");
    if (summary.duplicates.length === 0) {
      wrap.appendChild(el("div", "empty-state", "未发现重复文件"));
      this.contentSlot.appendChild(wrap);
      return;
    }
    const list = el("div", "dup-group-list");
    for (const [index, grp] of summary.duplicates.entries()) {
      const btn = el("button", "dup-group-btn");
      btn.type = "button";
      if (model.scanFilter.duplicate_group_id === grp.group_id) {
        btn.classList.add("dup-group-btn--active");
      }
      btn.appendChild(el("span", "", `重复组 ${index + 1} · ${grp.entry_ids.length} 份 · 单份 ${formatBytes(grp.size_bytes)} · 可节省 ${formatBytes(grp.duplicate_logical_bytes)}`));
      btn.appendChild(el("span", "technical-detail", ` · ${grp.blake3_prefix}…`));
      btn.addEventListener("click", () => {
        void this.callbacks.onFilterChange({ duplicate_group_id: grp.group_id });
      });
      list.appendChild(btn);
    }
    wrap.appendChild(list);
    this.contentSlot.appendChild(wrap);
  }

  private renderSkippedNotice(model: AppStateModel): void {
    const box = el("div", "skipped-panel");
    box.appendChild(
      el(
        "p",
        "skipped-panel__lead",
        `已跳过 ${model.scanSummary?.skipped ?? "0"} 项`,
      ),
    );
    // Skipped items are queried from backend via query_scan_entries with tab='skipped'
    const listEl = el("div", "skipped-list");
    box.appendChild(listEl);
    this.contentSlot.appendChild(box);
    void this.loadSkippedInto(listEl);
  }

  private async loadSkippedInto(container: HTMLElement): Promise<void> {
    const gen = this.lastModel?.scanSummary?.scan_generation;
    if (!gen) {
      return;
    }
    const items = await this.callbacks.onFetchSkipped();
    if (this.lastModel?.scanSummary?.scan_generation !== gen) {
      return;
    }
    clearChildren(container);
    if (items.length === 0) {
      container.appendChild(el("div", "empty-state", "没有跳过条目"));
      return;
    }
    for (const item of items) {
      const row = el("div", "item-card");
      const top = el("div", "item-card__top");
      const skipLabels: Record<string, string> = {
        permission_denied: "无访问权限", io: "读取失败", symlink: "符号链接",
        reparse_point: "链接或系统重定向", special_node: "特殊文件", mount_boundary: "其他磁盘",
        remote_filesystem: "网络磁盘", virtual_filesystem: "虚拟文件系统", unknown_filesystem: "无法识别的文件系统",
        sensitive_content: "敏感文件", metadata_only: "仅查看文件信息", changed_during_read: "文件已发生变化",
        identity_unavailable: "无法验证文件", invalid_root: "目录不可用", path_alias: "重复路径",
      };
      const reason = el("span", "tag tag--warn", skipLabels[item.reason] ?? "已跳过");
      reason.appendChild(el("span", "technical-detail", ` (${item.reason})`));
      top.appendChild(reason);
      if (item.incomplete) {
        top.appendChild(el("span", "tag tag--danger", "未能完整扫描"));
      }
      top.appendChild(el("span", "item-card__title", item.path_display));
      row.appendChild(top);
      row.appendChild(el("div", "item-card__sub technical-detail", item.detail));
      container.appendChild(row);
    }
  }

  private renderInspector(entry: FileEntryDto | null): void {
    if (!entry) {
      this.renderedInspectorKey = null;
      this.setInspectorListeners(false);
      clearChildren(this.inspectorEl);
      this.inspectorEl.classList.add("inspector--hidden");
      this.inspectorEl.classList.remove("inspector--open");
      return;
    }
    const key = `${entry.id}:${this.lastModel?.scanFilter.tab ?? ""}`;
    this.setInspectorListeners(true);
    if (this.renderedInspectorKey === key) {
      return;
    }
    this.renderedInspectorKey = key;
    clearChildren(this.inspectorEl);
    this.inspectorEl.classList.remove("inspector--hidden");
    this.inspectorEl.classList.add("inspector--open");

    const head = el("div", "inspector__head");
    const glyphWrap = el("span", "inspector__glyph-wrap");
    glyphWrap.setAttribute("aria-hidden", "true");
    glyphWrap.appendChild(
      el("span", `inspector__glyph ui-icon ui-icon--${entry.kind === "directory" ? "folder" : "file"}`),
    );
    head.appendChild(glyphWrap);
    head.appendChild(el("h3", "inspector__title", entry.name_display));
    const closeBtn = el("button", "inspector__close", "×");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "关闭详情");
    closeBtn.addEventListener("click", () => this.callbacks.onInspectEntry(null));
    head.appendChild(closeBtn);
    this.inspectorEl.appendChild(head);

    const badges = el("div", "inspector__badges");
    badges.appendChild(el("span", "tag", entry.kind === "directory" ? "文件夹" : "文件"));
    badges.appendChild(createZoneBadge(entry.policy));
    this.inspectorEl.appendChild(badges);

    this.inspectorEl.appendChild(el("div", "inspector__path", entry.path_display));

    const meta = el("dl", "inspector__kv");
    const addKv = (label: string, val: string | HTMLElement): void => {
      const row = el("div", "inspector__kv-row");
      row.appendChild(el("dt", "inspector__dt", label));
      const value = el("dd", "inspector__dd");
      if (typeof val === "string") value.textContent = val;
      else value.appendChild(val);
      row.appendChild(value);
      meta.appendChild(row);
    };
    addKv("大小", createSizeLabel(entry.size_bytes));
    if (entry.allocated_bytes !== null) {
      addKv("实际占用", createSizeLabel(entry.allocated_bytes));
    }
    if (entry.category) {
      const category = el("span", "", categoryLabel(entry.category));
      category.appendChild(el("span", "technical-detail", ` (${entry.category}${entry.type_evidence ? ` · ${entry.type_evidence}` : ""})`));
      addKv("类型", category);
    }
    this.inspectorEl.appendChild(meta);

    const explanation = createPolicyExplanationBox(entry.policy);
    if (explanation) {
      this.inspectorEl.appendChild(explanation);
    }

    if (entry.kind === "directory" && this.lastModel?.scanFilter.tab === "browse") {
      const actions = el("div", "inspector__actions");
      const drillBtn = el("button", "btn btn--primary", "进入此文件夹");
      drillBtn.type = "button";
      drillBtn.addEventListener("click", () => {
        this.callbacks.onInspectEntry(null);
        void this.callbacks.onDrillDirectory(entry.id);
      });
      actions.appendChild(drillBtn);
      this.inspectorEl.appendChild(actions);
    }
  }

  private renderActionBar(model: AppStateModel): void {
    const gen = model.scanSummary?.scan_generation ?? "0";
    const count = selectedCountEstimate(
      model.selection,
      model.totalFilteredCount,
      gen,
    );
    if (count === 0) {
      this.actionDismissal?.close();
      this.renderedActionKey = null;
      this.actionBar.classList.remove("action-bar--visible");
      return;
    }
    const actionKey = JSON.stringify([model.selection, count]);
    if (this.renderedActionKey === actionKey) return;
    this.renderedActionKey = actionKey;
    this.actionDismissal?.dispose();
    this.actionDismissal = null;
    clearChildren(this.actionBar);
    this.actionBar.classList.add("action-bar--visible");

    const modeLabel =
      model.selection.mode === "filtered"
        ? `已按筛选选中约 ${count} 项（排除 ${model.selection.excludes.length} 项）`
        : `已选择 ${count} 项`;
    this.actionBar.appendChild(el("span", "action-bar__count", modeLabel));

    const clearBtn = el("button", "btn btn--ghost btn--compact", "清空");
    clearBtn.type = "button";
    clearBtn.addEventListener("click", () => {
      this.callbacks.onSelectionChange(clearSelection(gen));
    });
    this.actionBar.appendChild(clearBtn);

    const actions = el("div", "action-bar__buttons");

    const quarantineBtn = el("button", "btn btn--primary", "移入隔离区");
    quarantineBtn.type = "button";
    quarantineBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("quarantine", false);
    });
    actions.appendChild(quarantineBtn);

    const moveBtn = el("button", "btn btn--secondary", "移动到…");
    moveBtn.type = "button";
    moveBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("move", true);
    });
    actions.appendChild(moveBtn);

    const copyBtn = el("button", "btn btn--secondary", "复制到…");
    copyBtn.type = "button";
    copyBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("copy", true);
    });
    actions.appendChild(copyBtn);

    const more = el("div", "action-more");
    this.actionDisclosureEl = more;
    const moreTrigger = el("button", "btn btn--secondary", "更多操作");
    moreTrigger.type = "button";
    moreTrigger.setAttribute("aria-haspopup", "true");
    more.appendChild(moreTrigger);
    const menu = el("div", "action-more__menu");
    this.actionDismissal = bindFloatingDisclosure(more, moreTrigger, menu);

    const renameBtn = el("button", "btn btn--secondary", "重命名…");
    renameBtn.type = "button";
    renameBtn.disabled = count !== 1;
    renameBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("rename", false);
    });
    menu.appendChild(renameBtn);

    const permBtn = el("button", "btn btn--danger-outline", "永久删除…");
    permBtn.type = "button";
    permBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("permanent_delete", false);
    });
    menu.appendChild(permBtn);
    more.appendChild(menu);
    actions.appendChild(more);

    this.actionBar.appendChild(actions);
  }
}
