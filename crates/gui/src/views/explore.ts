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
  el,
  formatBytes,
  formatBytesWithExact,
} from "../components/safe-text.ts";
import { TreemapPanel } from "../components/treemap.ts";
import { VirtualEntryList } from "../components/virtual-list.ts";
import { createPolicyExplanationBox, createZoneBadge } from "../components/zone-badge.ts";
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

export class ExploreView {
  readonly root: HTMLElement;
  readonly virtualList: VirtualEntryList;
  readonly treemap: TreemapPanel;

  private readonly callbacks: ExploreViewCallbacks;
  private readonly splitEl: HTMLElement;
  private readonly inspectorEl: HTMLElement;
  private readonly progressSlot: HTMLElement;
  private readonly summarySlot: HTMLElement;
  private readonly contentSlot: HTMLElement;
  private readonly actionBar: HTMLElement;
  private readonly filterBar: HTMLElement;

  constructor(callbacks: ExploreViewCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--explore");

    this.progressSlot = el("div", "slot");
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

    // Top scan toolbar
    const toolbar = el("div", "scan-toolbar");
    const primaryRow = el("div", "scan-toolbar__primary");

    const pickBtn = el("button", "btn btn--secondary", "选择文件夹…");
    pickBtn.type = "button";
    pickBtn.addEventListener("click", () => {
      void this.callbacks.onPickRoots();
    });
    primaryRow.appendChild(pickBtn);

    this.rootsSummaryEl = el("span", "scan-toolbar__roots", "未选择目录");
    primaryRow.appendChild(this.rootsSummaryEl);

    const scanBtn = el("button", "btn btn--primary", "扫描");
    scanBtn.type = "button";
    scanBtn.addEventListener("click", () => {
      void this.callbacks.onStartScan();
    });
    this.scanBtnEl = scanBtn;

    const optionsDisclosure = el("details", "scan-options");
    optionsDisclosure.appendChild(el("summary", "scan-options__summary", "选项"));
    const optRow = el("div", "scan-toolbar__options");

    const allLabel = el("label", "switch");
    const allCb = el("input");
    allCb.type = "checkbox";
    allCb.checked = model.scanOptions.all_volumes;
    allCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ all_volumes: allCb.checked }),
    );
    this.allVolInput = allCb;
    allLabel.appendChild(allCb);
    allLabel.appendChild(el("span", "", "全盘本地卷"));
    optRow.appendChild(allLabel);

    const metaLabel = el("label", "switch");
    const metaCb = el("input");
    metaCb.type = "checkbox";
    metaCb.checked = model.scanOptions.metadata_only;
    metaCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ metadata_only: metaCb.checked }),
    );
    this.metaInput = metaCb;
    metaLabel.appendChild(metaCb);
    metaLabel.appendChild(el("span", "", "仅元数据"));
    optRow.appendChild(metaLabel);

    const dupLabel = el("label", "switch");
    const dupCb = el("input");
    dupCb.type = "checkbox";
    dupCb.checked = model.scanOptions.no_duplicates;
    dupCb.addEventListener("change", () =>
      this.callbacks.onUpdateOptions({ no_duplicates: dupCb.checked }),
    );
    this.noDupInput = dupCb;
    dupLabel.appendChild(dupCb);
    dupLabel.appendChild(el("span", "", "跳过查重"));
    optRow.appendChild(dupLabel);

    const staleLabel = el("label", "inline-field");
    staleLabel.appendChild(el("span", "", "陈旧天数"));
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

    const rulesBtn = el("button", "btn btn--ghost", "自定义规则");
    rulesBtn.type = "button";
    rulesBtn.addEventListener("click", () => {
      void this.callbacks.onPickRules();
    });
    this.rulesBtnEl = rulesBtn;
    optRow.appendChild(rulesBtn);

    optionsDisclosure.appendChild(optRow);
    primaryRow.appendChild(optionsDisclosure);
    primaryRow.appendChild(scanBtn);
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
        this.rootsSummaryEl.textContent = "未选择目录";
      }
    }
    if (this.rulesBtnEl) {
      this.rulesBtnEl.textContent = model.rulesFile?.path_display
        ? `规则：${model.rulesFile.path_display} (${model.rulesFile.rule_count})`
        : "自定义规则 (TOML)";
    }
    if (this.scanBtnEl) {
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
    clearChildren(this.progressSlot);
    if (!model.scanning) {
      return;
    }
    const bar = el("div", "scan-progress");
    const phaseLabel = (phase: string): string => {
      switch (phase) {
        case "discovering":
          return "枚举目录";
        case "metadata":
          return "识别类型";
        case "content":
          return "分段哈希";
        case "duplicates":
          return "完整查重";
        case "complete":
          return "整理结果";
        default:
          return phase;
      }
    };
    const p = model.scanProgress;
    const text = p
      ? `${phaseLabel(p.phase)} · 发现 ${p.discovered} · 已处理 ${p.processed} · 已读 ${formatBytes(p.content_bytes_read)} · 错误 ${p.errors}`
      : "正在扫描…";
    bar.appendChild(el("span", "scan-progress__text", text));
    const cancelBtn = el("button", "btn btn--danger-outline btn--compact", "停止扫描");
    cancelBtn.type = "button";
    cancelBtn.addEventListener("click", () => {
      void this.callbacks.onCancelScan();
    });
    bar.appendChild(cancelBtn);
    this.progressSlot.appendChild(bar);
  }

  private renderSummary(model: AppStateModel): void {
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
    const strip = el(
      "div",
      "summary-strip",
      `共 ${summary.files} 文件 / ${summary.directories} 目录 · 逻辑 ${formatBytes(summary.logical_bytes)} · 去重 ${formatBytes(summary.unique_file_logical_bytes)} · 实占 ${alloc} · 已读内容 ${formatBytes(summary.content_bytes_read)}`,
    );
    this.summarySlot.appendChild(strip);

    if (summary.notices.length > 0) {
      this.summarySlot.appendChild(el("div", "notice-strip", summary.notices.join(" · ")));
    }
  }

  private renderFilterBar(model: AppStateModel): void {
    if (!model.scanSummary) {
      this.searchInputEl = null;
      this.selectAllBtnEl = null;
      clearChildren(this.filterBar);
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
    clearChildren(this.filterBar);

    const tabs: Array<{ id: ScanTab; label: string }> = [
      { id: "browse", label: "浏览" },
      { id: "top", label: `大文件 (${model.scanSummary.top_entry_ids.length})` },
      { id: "duplicates", label: `重复 (${model.scanSummary.duplicates.length})` },
      { id: "stale", label: `陈旧 (${model.scanSummary.stale_entry_ids.length})` },
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
      btn.addEventListener("click", () => {
        void this.callbacks.onFilterChange({
          tab: t.id,
          duplicate_group_id: null,
        });
      });
      tabRow.appendChild(btn);
    }
    barRow.appendChild(tabRow);

    if (model.scanFilter.tab !== "skipped") {
      const controls = el("div", "filter-controls");

      const search = el("input", "input input--search");
      search.type = "search";
      search.placeholder = "搜索…";
      search.value = model.scanFilter.search_text;
      search.addEventListener("change", () => {
        void this.callbacks.onFilterChange({ search_text: search.value });
      });
      this.searchInputEl = search;
      controls.appendChild(search);

      const zoneSel = el("select", "select");
      const zones: Array<{ value: ZoneKind | "all"; label: string }> = [
        { value: "all", label: "全部区域" },
        { value: "C_GrantedPersistent", label: "C 持久" },
        { value: "C_GrantedSession", label: "C 会话" },
        { value: "B_Sensitive", label: "B 敏感" },
        { value: "A_Protected", label: "A 保护" },
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
      controls.appendChild(zoneSel);

      const sortSel = el("select", "select");
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
      controls.appendChild(sortSel);

      const hideHidden = el("label", "switch");
      const hhCb = el("input");
      hhCb.type = "checkbox";
      hhCb.checked = model.scanFilter.hide_hidden;
      hhCb.addEventListener("change", () => {
        void this.callbacks.onFilterChange({ hide_hidden: hhCb.checked });
      });
      hideHidden.appendChild(hhCb);
      hideHidden.appendChild(el("span", "", "隐藏点文件"));
      controls.appendChild(hideHidden);

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

      barRow.appendChild(controls);
    }

    this.filterBar.appendChild(barRow);
  }

  private renderContent(model: AppStateModel): void {
    const gen = model.scanSummary?.scan_generation ?? null;
    if (!model.scanSummary) {
      clearChildren(this.contentSlot);
      const hero = el("div", "empty-hero");
      hero.appendChild(el("div", "empty-hero__icon", "📁"));
      hero.appendChild(el("div", "empty-hero__title", "选择目录后点击“扫描”"));
      this.contentSlot.appendChild(hero);
      return;
    }

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
          el("summary", "treemap-disclosure__summary", "空间分布图（Top 40 目录）"),
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
            `修改时间（mtime）超过 ${model.scanOptions.stale_days} 天`,
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
    for (const grp of summary.duplicates) {
      const btn = el("button", "dup-group-btn");
      btn.type = "button";
      if (model.scanFilter.duplicate_group_id === grp.group_id) {
        btn.classList.add("dup-group-btn--active");
      }
      btn.textContent = `${grp.entry_ids.length} 份 · 单份 ${formatBytes(grp.size_bytes)} · 可省 ${formatBytes(grp.duplicate_logical_bytes)} · ${grp.blake3_prefix}…`;
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
      top.appendChild(el("span", "tag tag--warn", item.reason));
      if (item.incomplete) {
        top.appendChild(el("span", "tag tag--danger", "导致不完整"));
      }
      top.appendChild(el("span", "item-card__title", item.path_display));
      row.appendChild(top);
      row.appendChild(el("div", "item-card__sub", item.detail));
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
      el("span", "inspector__glyph", entry.kind === "directory" ? "📁" : "📄"),
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
    const addKv = (label: string, val: string): void => {
      const row = el("div", "inspector__kv-row");
      row.appendChild(el("dt", "inspector__dt", label));
      row.appendChild(el("dd", "inspector__dd", val));
      meta.appendChild(row);
    };
    addKv("逻辑大小", formatBytesWithExact(entry.size_bytes));
    if (entry.allocated_bytes !== null) {
      addKv("实际占用", formatBytesWithExact(entry.allocated_bytes));
    }
    if (entry.category) {
      addKv(
        "类型",
        `${entry.category}${entry.type_evidence ? ` (${entry.type_evidence})` : ""}`,
      );
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
    this.inspectorEl.appendChild(
      el("div", "inspector__meta", `目录汇总：${formatBytesWithExact(node.logical_bytes)}`),
    );
    const explanation = createPolicyExplanationBox(node.policy);
    if (explanation) {
      this.inspectorEl.appendChild(explanation);
    }
  }

  private renderActionBar(model: AppStateModel): void {
    clearChildren(this.actionBar);
    const gen = model.scanSummary?.scan_generation ?? "0";
    const count = selectedCountEstimate(
      model.selection,
      model.totalFilteredCount,
      gen,
    );
    if (count === 0) {
      this.actionBar.classList.remove("action-bar--visible");
      return;
    }
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

    const renameBtn = el("button", "btn btn--secondary", "重命名…");
    renameBtn.type = "button";
    renameBtn.disabled = count !== 1;
    renameBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("rename", false);
    });
    actions.appendChild(renameBtn);

    const permBtn = el("button", "btn btn--danger-outline", "永久删除…");
    permBtn.type = "button";
    permBtn.addEventListener("click", () => {
      void this.callbacks.onTriggerAction("permanent_delete", false);
    });
    actions.appendChild(permBtn);

    this.actionBar.appendChild(actions);
  }
}
