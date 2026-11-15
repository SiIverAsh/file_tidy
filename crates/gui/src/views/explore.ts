import type {
  BuildPlanRequest,
  EntryId,
  FileEntryDto,
  ScanFilter,
  ScanTab,
  SkippedEntryDto,
  SortField,
  TreemapNodeDto,
  ZoneKind,
} from "../api/types.ts";
import {
  clearChildren,
  createSizeLabel,
  el,
  formatBytes,
  setText,
} from "../components/safe-text.ts";
import { TreemapPanel } from "../components/treemap.ts";
import { VirtualEntryList } from "../components/virtual-list.ts";
import { createPolicyExplanationBox, createZoneBadge } from "../components/zone-badge.ts";
import { containsNode } from "../components/overlay-focus.ts";
import {
  clearSelection,
  selectAllCurrentFilter,
  selectedCountEstimate,
  toggleEntrySelection,
  type AppStateModel,
} from "../state/store.ts";

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
  disclosure: HTMLDetailsElement,
  trigger: HTMLElement,
): { close(restoreFocus?: boolean): void; dispose(): void } {
  const doc = document;
  let listening = false;
  const canListen = typeof doc.addEventListener === "function" &&
    typeof doc.removeEventListener === "function";

  const stopListening = (): void => {
    if (!listening) return;
    doc.removeEventListener("pointerdown", onPointerDown, true);
    doc.removeEventListener("keydown", onKeyDown, true);
    listening = false;
  };

  const close = (restoreFocus = false): void => {
    const wasOpen = disclosure.open;
    disclosure.open = false;
    trigger.setAttribute("aria-expanded", "false");
    stopListening();
    if (wasOpen && restoreFocus) trigger.focus();
  };

  const onPointerDown = (event: PointerEvent): void => {
    let target = event.target as Node | null;
    while (target) {
      if (target === disclosure) return;
      target = target.parentNode;
    }
    close();
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== "Escape" || !disclosure.open) return;
    if (disclosure.isConnected === false) {
      close();
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    close(true);
  };

  trigger.setAttribute("aria-expanded", "false");
  disclosure.addEventListener("keydown", onKeyDown);
  disclosure.addEventListener("toggle", () => {
    trigger.setAttribute("aria-expanded", String(disclosure.open));
    if (!disclosure.open) {
      stopListening();
    } else if (canListen && !listening) {
      doc.addEventListener("pointerdown", onPointerDown, true);
      doc.addEventListener("keydown", onKeyDown, true);
      listening = true;
    }
  });
  return { close, dispose: () => close() };
}

export class ExploreView {
  readonly root: HTMLElement;
  readonly virtualList: VirtualEntryList;
  readonly treemap: TreemapPanel;

  private readonly callbacks: ExploreViewCallbacks;
  private readonly splitEl: HTMLElement;
  private readonly inspectorEl: HTMLElement;
  private readonly progressSlot: HTMLElement;
  private readonly progressText: HTMLElement;
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
    this.summarySlot = el("div", "slot");
    this.filterBar = el("div", "filter-bar");
    this.contentSlot = el("div", "explore-content");
    this.inspectorEl = el("div", "inspector inspector--hidden");
    this.splitEl = el("div", "explore-split explore-split--single");
    this.actionBar = el("div", "action-bar");

    this.treemap = new TreemapPanel({
      onDrillDown: (parentId) => {
        void this.callbacks.onDrillDirectory(parentId);
      },
      onHighlightNode: (node) => {
        this.renderTreemapInspector(node);
      },
    });

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
  private filterDisclosureOpen = false;
  private renderedFilterKey: string | null = null;
  private renderedActionKey: string | null = null;
  private scanOptionsDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private scanOptionsEl: HTMLDetailsElement | null = null;
  private filterDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private actionDismissal: ReturnType<typeof bindFloatingDisclosure> | null = null;
  private filterDisclosureEl: HTMLDetailsElement | null = null;
  private actionDisclosureEl: HTMLDetailsElement | null = null;

  closeFloatingPanels(restoreFocus = true): void {
    const active = document.activeElement;
    this.scanOptionsDismissal?.close(restoreFocus && containsNode(this.scanOptionsEl ?? this.root, active));
    this.filterDismissal?.close(restoreFocus && containsNode(this.filterDisclosureEl ?? this.filterBar, active));
    this.actionDismissal?.close(restoreFocus && containsNode(this.actionDisclosureEl ?? this.actionBar, active));
    this.filterDisclosureOpen = false;
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

    const optionsDisclosure = el("details", "scan-options");
    this.scanOptionsEl = optionsDisclosure;
    const optionsTrigger = el("summary", "scan-options__summary", "扫描选项");
    optionsTrigger.setAttribute("aria-controls", "scan-options-panel");
    optionsDisclosure.appendChild(optionsTrigger);
    this.scanOptionsDismissal = bindFloatingDisclosure(optionsDisclosure, optionsTrigger);
    const optRow = el("div", "scan-toolbar__options");
    optRow.id = "scan-options-panel";
    optRow.setAttribute("role", "group");
    optRow.setAttribute("aria-label", "扫描选项");

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
    this.root.appendChild(this.summarySlot);
    this.root.appendChild(this.filterBar);

    this.splitEl.appendChild(this.contentSlot);
    this.splitEl.appendChild(this.inspectorEl);
    this.root.appendChild(this.splitEl);
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
    if (this.summaryRendered === model.scanSummary) return;
    this.summaryRendered = model.scanSummary;
    clearChildren(this.summarySlot);
    const summary = model.scanSummary;
    if (!summary) {
      return;
    }

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

    const alloc =
      summary.unique_allocated_bytes === null
        ? "未知"
        : formatBytes(summary.unique_allocated_bytes);
    const strip = el("div", "summary-strip");
    const metrics = [
      ["文件", summary.files, `${summary.directories} 个目录`],
      ["文件总大小", formatBytes(summary.logical_bytes), `去重后 ${formatBytes(summary.unique_file_logical_bytes)}`],
      ["实际占用", alloc, `已读取 ${formatBytes(summary.content_bytes_read)}`],
      ["重复文件组", String(summary.duplicates.length), "相同内容，集中查看"],
    ];
    for (const [label, value, detail] of metrics) {
      const metric = el("div", "summary-metric");
      metric.appendChild(el("span", "summary-metric__label", label));
      metric.appendChild(el("strong", "summary-metric__value", value));
      metric.appendChild(el("span", "summary-metric__detail", detail));
      strip.appendChild(metric);
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

      const filterDisclosure = el("details", "filter-disclosure");
      this.filterDisclosureEl = filterDisclosure;
      filterDisclosure.open = this.filterDisclosureOpen;
      if (this.filterDisclosureOpen) filterDisclosure.classList.add("filter-disclosure--restored");
      filterDisclosure.addEventListener("toggle", () => {
        if (this.filterDisclosureEl !== filterDisclosure) return;
        this.filterDisclosureOpen = filterDisclosure.open;
        if (!filterDisclosure.open) filterDisclosure.classList.remove("filter-disclosure--restored");
      });
      const filterLabel = model.scanFilter.zone_filter !== "all" || !model.scanFilter.hide_hidden ? "筛选 · 已调整" : "筛选";
      const filterTrigger = el("summary", "scan-options__summary", filterLabel);
      filterDisclosure.appendChild(filterTrigger);
      this.filterDismissal = bindFloatingDisclosure(filterDisclosure, filterTrigger);
      const filterPanel = el("div", "filter-disclosure__panel");
      const zoneSel = el("select", "select");
      zoneSel.setAttribute("aria-label", "按授权区域筛选");
      const zones: Array<{ value: ZoneKind | "all"; label: string }> = [
        { value: "all", label: "全部区域" },
        { value: "C_GrantedPersistent", label: "持久授权" },
        { value: "C_GrantedSession", label: "本次授权" },
        { value: "B_Sensitive", label: "敏感文件" },
        { value: "A_Protected", label: "系统保护" },
        { value: "Unauthenticated", label: "未授权" },
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
      zoneLabel.appendChild(el("span", "", "授权区域"));
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

      const hideHidden = el("label", "switch");
      const hhCb = el("input");
      hhCb.type = "checkbox";
      hhCb.checked = model.scanFilter.hide_hidden;
      hhCb.addEventListener("change", () => {
        void this.callbacks.onFilterChange({ hide_hidden: hhCb.checked });
      });
      hideHidden.appendChild(hhCb);
      hideHidden.appendChild(el("span", "", "隐藏点文件"));
      filterPanel.appendChild(hideHidden);
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
      if (tab === "browse") {
        const treeDisclosure = el("details", "treemap-disclosure");
        treeDisclosure.appendChild(
          el("summary", "treemap-disclosure__summary", "空间分布（前 40 个目录）"),
        );
        treeDisclosure.appendChild(this.treemap.root);
        this.contentSlot.appendChild(treeDisclosure);
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
      } else if (tab === "top") {
        this.contentSlot.appendChild(this.virtualList.root);
      } else if (tab === "skipped") {
        this.renderSkippedNotice(model);
      }
    }

    if (tab === "browse") {
      this.treemap.setData(model.treemap);
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
    clearChildren(this.inspectorEl);
    if (!entry) {
      this.inspectorEl.classList.add("inspector--hidden");
      this.splitEl.classList.add("explore-split--single");
      return;
    }
    this.inspectorEl.classList.remove("inspector--hidden");
    this.splitEl.classList.remove("explore-split--single");

    const head = el("div", "inspector__head");
    head.appendChild(
      el("span", `inspector__glyph ui-icon ui-icon--${entry.kind === "directory" ? "folder" : "file"}`),
    );
    head.appendChild(el("h3", "inspector__title", entry.name_display));
    const closeBtn = el("button", "inspector__close", "×");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "关闭详情");
    closeBtn.addEventListener("click", () => this.callbacks.onInspectEntry(null));
    head.appendChild(closeBtn);
    this.inspectorEl.appendChild(head);
    this.inspectorEl.appendChild(el("div", "inspector__path", entry.path_display));
    this.inspectorEl.appendChild(createZoneBadge(entry.policy));

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
      const names: Record<string, string> = {
        document: "文档", image: "图片", video: "视频", audio: "音频",
        archive: "压缩文件", code: "代码", installer: "安装程序", other: "其他",
      };
      const category = el("span", "", names[entry.category] ?? "其他");
      category.appendChild(el("span", "technical-detail", ` (${entry.category}${entry.type_evidence ? ` · ${entry.type_evidence}` : ""})`));
      addKv("类型", category);
    }
    this.inspectorEl.appendChild(meta);

    const explanation = createPolicyExplanationBox(entry.policy);
    if (explanation) {
      this.inspectorEl.appendChild(explanation);
    }

    if (entry.policy.zone === "Unauthenticated") {
      const authBtn = el("button", "btn btn--secondary", "前往授权目录");
      authBtn.type = "button";
      authBtn.addEventListener("click", () => {
        void this.callbacks.onQuickAuthorizeSelected();
      });
      this.inspectorEl.appendChild(authBtn);
    }
  }

  private renderTreemapInspector(node: TreemapNodeDto | null): void {
    if (!node || !node.policy) {
      return;
    }
    clearChildren(this.inspectorEl);
    this.inspectorEl.classList.remove("inspector--hidden");
    this.splitEl.classList.remove("explore-split--single");

    const head = el("div", "inspector__head");
    head.appendChild(el("h3", "inspector__title", node.label_display));
    const closeBtn = el("button", "inspector__close", "×");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "关闭详情");
    closeBtn.addEventListener("click", () => this.callbacks.onInspectEntry(null));
    head.appendChild(closeBtn);
    this.inspectorEl.appendChild(head);
    this.inspectorEl.appendChild(el("div", "inspector__path", node.path_display));
    this.inspectorEl.appendChild(createZoneBadge(node.policy));
    const total = el("div", "inspector__meta", "目录大小：");
    total.appendChild(createSizeLabel(node.logical_bytes));
    this.inspectorEl.appendChild(total);
    const explanation = createPolicyExplanationBox(node.policy);
    if (explanation) {
      this.inspectorEl.appendChild(explanation);
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

    const more = el("details", "action-more");
    this.actionDisclosureEl = more;
    const moreTrigger = el("summary", "btn btn--secondary", "更多操作");
    more.appendChild(moreTrigger);
    this.actionDismissal = bindFloatingDisclosure(more, moreTrigger);
    const menu = el("div", "action-more__menu");

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
