import type {
  EntryId,
  FileEntryDto,
  ScanGeneration,
  SelectionSpec,
} from "../api/types.ts";
import { isEntrySelected } from "../state/store.ts";
import { clearChildren, el, formatBytes, formatUnixTime } from "./safe-text.ts";
import { createZoneBadge } from "./zone-badge.ts";
import { EntryTree, type EntryBranch } from "./entry-tree.ts";

export interface VirtualListCallbacks {
  onFetchWindow(offset: number, limit: number): Promise<{
    totalCount: number;
    entries: FileEntryDto[];
  }>;
  onToggleSelect(entryId: EntryId): void;
  onInspectEntry(entry: FileEntryDto): void;
  onDrillDirectory(entry: FileEntryDto): void;
  onFetchChildren?(parentId: EntryId | null, offset: number, limit: number): Promise<{
    totalCount: number;
    entries: FileEntryDto[];
  }>;
}

const WINDOW_ROWS = 18;
const PAGE_CACHE_SIZE = 72;

/**
 * Zero-inline-style virtualized list component.
 * Uses a fixed visible window of DOM rows paired with wheel + keyboard + range scrubber
 * so 1,000,000+ entries never hit browser max DOM/canvas height caps or CSP style-src.
 */
export class VirtualEntryList {
  readonly root: HTMLElement;
  private readonly viewport: HTMLElement;
  private readonly rowsEl: HTMLElement;
  private readonly scrubber: HTMLInputElement;
  private readonly statusEl: HTMLElement;
  private readonly toolbar: HTMLElement;
  private readonly collapseButton: HTMLButtonElement;

  private callbacks: VirtualListCallbacks;
  private generation: ScanGeneration = "0";
  private totalCount = 0;
  private offset = 0;
  private focusedIndex = 0;
  private selection: SelectionSpec = { mode: "ids", scan_generation: "0", ids: [] };
  private cache = new Map<number, FileEntryDto>();
  private loadingSeq: number | null = null;
  private requestSeq = 0;
  private wheelAccumulator = 0;
  private destroyed = false;
  private tree: EntryTree | null = null;

  constructor(callbacks: VirtualListCallbacks) {
    this.callbacks = callbacks;
    this.root = el("div", "vlist");

    this.toolbar = el("div", "vlist__toolbar");
    this.toolbar.hidden = true;
    const title = el("div", "vlist__title-group");
    title.appendChild(el("span", "vlist__title", "文件结构"));
    title.appendChild(el("span", "vlist__hint", "点击箭头展开目录 · ← → 键导航"));
    this.collapseButton = el("button", "btn btn--ghost btn--compact vlist__collapse", "全部收起");
    this.collapseButton.type = "button";
    this.collapseButton.addEventListener("click", () => {
      if (!this.tree) return;
      const focused = this.tree.row(this.focusedIndex);
      let ancestor = focused?.branch;
      while (ancestor?.parent?.parent) ancestor = ancestor.parent;
      this.focusedIndex = ancestor?.parent ? ancestor.parentIndex : focused?.siblingIndex ?? 0;
      this.tree.collapseAll();
      this.syncTreeCount();
      this.offset = Math.max(0, Math.min(this.focusedIndex, this.maxOffset()));
      void this.loadWindow(this.offset);
      this.viewport.focus();
    });
    this.toolbar.appendChild(title);
    this.toolbar.appendChild(this.collapseButton);
    this.root.appendChild(this.toolbar);

    const header = el("div", "vlist__header");
    header.appendChild(el("span", "vlist__col-check", ""));
    header.appendChild(el("span", "vlist__col-name", "名称"));
    header.appendChild(el("span", "vlist__col-zone", "区域"));
    header.appendChild(el("span", "vlist__col-size", "大小"));
    header.appendChild(el("span", "vlist__col-time", "修改时间"));
    this.root.appendChild(header);

    const body = el("div", "vlist__body");
    this.viewport = el("div", "vlist__viewport");
    this.viewport.tabIndex = 0;
    this.viewport.setAttribute("role", "listbox");
    this.viewport.setAttribute("aria-label", "扫描文件列表");
    this.viewport.setAttribute("aria-multiselectable", "true");

    this.rowsEl = el("div", "vlist__rows");
    this.viewport.appendChild(this.rowsEl);

    this.scrubber = el("input", "vlist__scrubber");
    this.scrubber.type = "range";
    this.scrubber.min = "0";
    this.scrubber.max = "0";
    this.scrubber.value = "0";
    this.scrubber.setAttribute("aria-label", "列表滚动位置");

    body.appendChild(this.viewport);
    body.appendChild(this.scrubber);
    this.root.appendChild(body);

    this.statusEl = el("div", "vlist__status", "暂无条目");
    this.root.appendChild(this.statusEl);

    this.bindEvents();
  }

  private bindEvents(): void {
    this.viewport.addEventListener("wheel", (ev) => {
      if (this.totalCount <= WINDOW_ROWS) {
        return;
      }
      ev.preventDefault();
      this.wheelAccumulator += ev.deltaY;
      const stepPx = 36;
      const deltaRows = Math.trunc(this.wheelAccumulator / stepPx);
      if (deltaRows !== 0) {
        this.wheelAccumulator -= deltaRows * stepPx;
        void this.scrollTo(this.offset + deltaRows);
      }
    });

    this.scrubber.addEventListener("input", () => {
      const next = Number.parseInt(this.scrubber.value, 10);
      if (Number.isFinite(next)) {
        void this.scrollTo(next);
      }
    });

    this.viewport.addEventListener("keydown", (ev) => {
      if (ev.target !== this.viewport) return;
      if (this.totalCount === 0) {
        return;
      }
      switch (ev.key) {
        case "ArrowDown":
          ev.preventDefault();
          void this.moveFocus(this.focusedIndex + 1);
          break;
        case "ArrowUp":
          ev.preventDefault();
          void this.moveFocus(this.focusedIndex - 1);
          break;
        case "PageDown":
          ev.preventDefault();
          void this.moveFocus(this.focusedIndex + WINDOW_ROWS);
          break;
        case "PageUp":
          ev.preventDefault();
          void this.moveFocus(this.focusedIndex - WINDOW_ROWS);
          break;
        case "Home":
          ev.preventDefault();
          void this.moveFocus(0);
          break;
        case "End":
          ev.preventDefault();
          void this.moveFocus(this.totalCount - 1);
          break;
        case " ": {
          ev.preventDefault();
          const entry = this.entryAt(this.focusedIndex);
          if (entry) {
            this.callbacks.onToggleSelect(entry.id);
          }
          break;
        }
        case "Enter": {
          ev.preventDefault();
          const entry = this.entryAt(this.focusedIndex);
          if (entry) {
            if (this.tree && entry.kind === "directory") {
              void this.toggleDirectory(this.focusedIndex);
            } else if (entry.kind === "directory") {
              this.callbacks.onDrillDirectory(entry);
            } else {
              this.callbacks.onInspectEntry(entry);
            }
          }
          break;
        }
        case "ArrowRight":
          if (this.tree) {
            ev.preventDefault();
            const row = this.tree.row(this.focusedIndex);
            if (row?.entry?.kind === "directory") {
              if (this.tree.child(row)?.expanded) {
                const firstChild = this.tree.row(this.focusedIndex + 1);
                if (firstChild && !firstChild.note && firstChild.branch === this.tree.child(row)) {
                  void this.moveFocus(this.focusedIndex + 1);
                }
              }
              else void this.toggleDirectory(this.focusedIndex);
            }
          }
          break;
        case "ArrowLeft":
          if (this.tree) {
            ev.preventDefault();
            const row = this.tree.row(this.focusedIndex);
            if (row && this.tree.child(row)?.expanded) void this.toggleDirectory(this.focusedIndex);
            else if (row?.branch.parent) {
              const parentIndex = this.tree.indexOf(row.branch.parent, row.branch.parentIndex);
              if (parentIndex !== null) void this.moveFocus(parentIndex);
            }
          }
          break;
      }
    });
  }

  async resetAndLoad(generation: ScanGeneration, selection: SelectionSpec, treeMode = false): Promise<void> {
    this.generation = generation;
    this.selection = selection;
    this.offset = 0;
    this.focusedIndex = 0;
    this.requestSeq += 1;
    this.loadingSeq = null;
    this.cache.clear();
    this.totalCount = 0;
    this.wheelAccumulator = 0;
    this.tree = treeMode && this.callbacks.onFetchChildren ? new EntryTree() : null;
    this.toolbar.hidden = !this.tree;
    if (this.tree) this.root.classList.add("vlist--tree");
    else this.root.classList.remove("vlist--tree");
    this.viewport.setAttribute("role", this.tree ? "tree" : "listbox");
    this.viewport.setAttribute("aria-label", this.tree ? "扫描文件树" : "扫描文件列表");
    this.render();
    await this.loadWindow(0);
  }

  updateSelection(selection: SelectionSpec, generation: ScanGeneration): void {
    this.selection = selection;
    this.generation = generation;
    this.render();
  }

  private maxOffset(): number {
    return Math.max(0, this.totalCount - WINDOW_ROWS);
  }

  private entryAt(index: number): FileEntryDto | undefined {
    return this.tree ? this.tree.row(index)?.entry : this.cache.get(index);
  }

  private syncTreeCount(): void {
    if (!this.tree) return;
    this.totalCount = this.tree.count();
    this.focusedIndex = Math.max(0, Math.min(this.focusedIndex, this.totalCount - 1));
    this.offset = Math.max(0, Math.min(this.offset, this.maxOffset()));
    this.scrubber.max = String(this.maxOffset());
    this.scrubber.value = String(this.offset);
    this.collapseButton.disabled = ![...this.tree.root.children.values()].some((child) => child.expanded);
  }

  private async fetchBranch(tree: EntryTree, branch: EntryBranch, start: number): Promise<void> {
    const page = Math.floor(start / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE;
    const pending = branch.pending.get(page);
    if (pending) return pending;
    branch.error = false;
    const load = async (): Promise<void> => {
      try {
        const res = await this.callbacks.onFetchChildren!(branch.parentId, page, PAGE_CACHE_SIZE);
        if (this.destroyed || this.tree !== tree) return;
        const focusAnchor = tree.row(this.focusedIndex);
        const focusWasVisible = this.focusedIndex >= this.offset && this.focusedIndex < this.offset + WINDOW_ROWS;
        const scrollAnchor = tree.row(this.offset);
        branch.initialized = true;
        branch.total = res.totalCount;
        res.entries.forEach((entry, index) => branch.entries.set(page + index, entry));
        if (focusAnchor && !focusAnchor.note) {
          this.focusedIndex = tree.indexOf(focusAnchor.branch, focusAnchor.siblingIndex) ?? this.focusedIndex;
        }
        if (scrollAnchor && !scrollAnchor.note) {
          this.offset = tree.indexOf(scrollAnchor.branch, scrollAnchor.siblingIndex) ?? this.offset;
        }
        if (focusWasVisible) {
          if (this.focusedIndex < this.offset) this.offset = this.focusedIndex;
          else if (this.focusedIndex >= this.offset + WINDOW_ROWS) this.offset = this.focusedIndex - WINDOW_ROWS + 1;
        }
        // Keep pages bounded even for a directory with millions of children.
        if (branch.entries.size > 600) {
          for (const at of branch.entries.keys()) {
            if (Math.abs(at - start) > 300 && !branch.children.has(at)) branch.entries.delete(at);
          }
        }
      } catch {
        if (this.tree === tree) branch.error = true;
      } finally {
        branch.pending.delete(page);
        if (!this.destroyed && this.tree === tree) {
          this.syncTreeCount();
          this.render();
        }
      }
    };
    const promise = Promise.resolve().then(load);
    branch.pending.set(page, promise);
    this.render();
    return promise;
  }

  private async toggleDirectory(index: number): Promise<void> {
    const tree = this.tree;
    const row = tree?.row(index);
    if (!tree || !row || row.entry?.kind !== "directory") return;
    this.focusedIndex = index;
    let child = tree.child(row);
    if (child?.expanded) child.expanded = false;
    else child = tree.expand(row);
    this.syncTreeCount();
    this.render();
    this.viewport.focus();
    if (child?.expanded && !child.initialized) await this.fetchBranch(tree, child, 0);
    if (this.tree === tree) await this.loadWindow(this.offset);
  }

  private async moveFocus(nextIndex: number): Promise<void> {
    let clamped = Math.max(0, Math.min(this.totalCount - 1, nextIndex));
    if (this.tree?.row(clamped)?.note) {
      const step = clamped === this.totalCount - 1 || nextIndex < this.focusedIndex ? -1 : 1;
      while (this.tree.row(clamped)?.note) {
        const next = clamped + step;
        if (next < 0 || next >= this.totalCount) return;
        clamped = next;
      }
    }
    this.focusedIndex = clamped;
    if (clamped < this.offset) {
      await this.scrollTo(clamped);
    } else if (clamped >= this.offset + WINDOW_ROWS) {
      await this.scrollTo(clamped - WINDOW_ROWS + 1);
    } else {
      const entry = this.entryAt(clamped);
      if (entry) {
        this.callbacks.onInspectEntry(entry);
      }
      this.render();
    }
  }

  async scrollTo(targetOffset: number): Promise<void> {
    const clamped = Math.max(0, Math.min(this.maxOffset(), targetOffset));
    this.offset = clamped;
    this.scrubber.value = String(clamped);
    const missing = this.hasMissingRows(clamped, WINDOW_ROWS);
    if (missing) {
      await this.loadWindow(clamped);
    } else {
      this.render();
    }
  }

  private hasMissingRows(start: number, count: number): boolean {
    const end = Math.min(this.totalCount, start + count);
    for (let i = start; i < end; i += 1) {
      if (!this.entryAt(i) && !this.tree?.row(i)?.note) {
        return true;
      }
    }
    return false;
  }

  private async loadWindow(startOffset: number): Promise<void> {
    if (this.tree) {
      const tree = this.tree;
      if (!tree.root.initialized) await this.fetchBranch(tree, tree.root, 0);
      if (this.destroyed || this.tree !== tree) return;
      const loads = new Map<EntryBranch, Set<number>>();
      const end = Math.min(this.totalCount, this.offset + WINDOW_ROWS);
      for (let index = this.offset; index < end; index += 1) {
        const row = tree.row(index);
        if (!row || row.entry || row.note) continue;
        const pages = loads.get(row.branch) ?? new Set<number>();
        pages.add(Math.floor(row.siblingIndex / PAGE_CACHE_SIZE) * PAGE_CACHE_SIZE);
        loads.set(row.branch, pages);
      }
      await Promise.all([...loads].flatMap(([branch, pages]) =>
        [...pages].map((page) => this.fetchBranch(tree, branch, page))));
      if (!this.destroyed && this.tree === tree) this.render();
      return;
    }
    const fetchOffset = Math.max(0, startOffset - 10);
    const seq = ++this.requestSeq;
    this.loadingSeq = seq;
    const requestedGen = this.generation;
    try {
      const res = await this.callbacks.onFetchWindow(fetchOffset, PAGE_CACHE_SIZE);
      if (this.destroyed || this.generation !== requestedGen || this.requestSeq !== seq) {
        return;
      }
      this.totalCount = res.totalCount;
      for (let i = 0; i < res.entries.length; i += 1) {
        const item = res.entries[i];
        if (item) {
          this.cache.set(fetchOffset + i, item);
        }
      }
      // Trim far cache entries to stay bounded.
      if (this.cache.size > 600) {
        for (const key of this.cache.keys()) {
          if (Math.abs(key - this.offset) > 300) {
            this.cache.delete(key);
          }
        }
      }
      this.offset = Math.max(0, Math.min(this.maxOffset(), this.offset));
      this.scrubber.max = String(this.maxOffset());
      this.scrubber.value = String(this.offset);
      this.render();
    } finally {
      if (this.loadingSeq === seq) {
        this.loadingSeq = null;
      }
    }
  }

  render(): void {
    clearChildren(this.rowsEl);
    this.viewport.removeAttribute("aria-activedescendant");
    if (this.totalCount <= WINDOW_ROWS) {
      this.scrubber.classList.add("vlist__scrubber--hidden");
    } else {
      this.scrubber.classList.remove("vlist__scrubber--hidden");
    }

    if (this.totalCount === 0) {
      const root = this.tree?.root;
      const empty = el("div", "vlist__empty", root?.error ? "文件结构加载失败" :
        root && !root.initialized ? "正在加载文件结构…" : "当前筛选条件下没有条目");
      if (root?.error) empty.appendChild(this.retryButton(root, 0));
      this.rowsEl.appendChild(empty);
      this.statusEl.textContent = root && !root.initialized ? "按需加载子目录" : "0 项";
      return;
    }

    const end = Math.min(this.totalCount, this.offset + WINDOW_ROWS);
    let focusedPath: string | null = null;

    for (let index = this.offset; index < end; index += 1) {
      const treeRow = this.tree?.row(index);
      const entry = this.entryAt(index);
      if (!entry) {
        const note = el("div", "vlist__row vlist__branch-note");
        note.appendChild(el("span"));
        const label = el("div", "vlist__name-line");
        this.appendIndents(label, treeRow?.branch.depth ?? 0);
        const branch = treeRow?.branch;
        label.appendChild(el("span", "", branch?.error ? "加载失败" :
          treeRow?.note && branch?.initialized ? "没有可见条目" : "加载中…"));
        if (branch?.error) label.appendChild(this.retryButton(branch, treeRow?.siblingIndex ?? 0));
        note.appendChild(label);
        note.setAttribute("role", "presentation");
        this.rowsEl.appendChild(note);
        continue;
      }
      const row = el("div", "vlist__row");
      const selected = isEntrySelected(this.selection, entry.id, this.generation);
      if (selected) {
        row.classList.add("vlist__row--selected");
      }
      if (index === this.focusedIndex) {
        row.classList.add("vlist__row--focused");
        focusedPath = entry.path_display;
      }
      row.id = `file-entry-${index}`;
      if (index === this.focusedIndex) this.viewport.setAttribute("aria-activedescendant", row.id);
      row.setAttribute("role", this.tree ? "treeitem" : "option");
      row.setAttribute("aria-selected", selected ? "true" : "false");
      const expanded = treeRow ? this.tree?.child(treeRow)?.expanded ?? false : false;
      if (treeRow) {
        row.setAttribute("aria-level", String(treeRow.branch.depth + 1));
        row.setAttribute("aria-posinset", String(treeRow.siblingIndex + 1));
        row.setAttribute("aria-setsize", String(treeRow.branch.total));
        if (entry.kind === "directory") row.setAttribute("aria-expanded", String(expanded));
      }
      row.title = entry.policy.blocked_reason
        ? `${entry.path_display}\n${entry.policy.blocked_reason}`
        : entry.path_display;

      const checkCell = el("div", "vlist__col-check");
      const checkbox = el("input");
      checkbox.type = "checkbox";
      checkbox.checked = selected;
      checkbox.setAttribute("aria-label", `选择 ${entry.name_display}`);
      checkbox.addEventListener("click", (ev) => {
        ev.stopPropagation();
        this.focusedIndex = index;
        this.callbacks.onToggleSelect(entry.id);
      });
      checkCell.appendChild(checkbox);
      row.appendChild(checkCell);

      const nameCell = el("div", "vlist__col-name");
      const titleRow = el("div", "vlist__name-line");
      if (treeRow) {
        this.appendIndents(titleRow, treeRow.branch.depth);
        if (entry.kind === "directory") {
          const toggle = el("button", "vlist__toggle");
          toggle.type = "button";
          toggle.tabIndex = -1;
          toggle.setAttribute("aria-label", `${expanded ? "收起" : "展开"} ${entry.name_display}`);
          toggle.setAttribute("aria-expanded", String(expanded));
          if (this.tree?.child(treeRow)?.pending.size) toggle.classList.add("vlist__toggle--loading");
          toggle.addEventListener("click", (ev) => {
            ev.stopPropagation();
            void this.toggleDirectory(index);
          });
          toggle.addEventListener("dblclick", (ev) => ev.stopPropagation());
          titleRow.appendChild(toggle);
        } else titleRow.appendChild(el("span", "vlist__toggle-spacer"));
      }
      const icon = el("span", `vlist__kind-icon vlist__kind-icon--${entry.kind}${expanded ? " vlist__kind-icon--open" : ""}`);
      icon.setAttribute("aria-hidden", "true");
      titleRow.appendChild(icon);
      titleRow.appendChild(el("span", "vlist__name", entry.name_display));
      if (entry.hidden) {
        titleRow.appendChild(el("span", "chip-quiet", "隐藏"));
      }
      if (entry.is_stale) {
        titleRow.appendChild(el("span", "chip-quiet chip-quiet--warn", "陈旧"));
      }
      nameCell.appendChild(titleRow);
      row.appendChild(nameCell);

      const zoneCell = el("div", "vlist__col-zone");
      zoneCell.appendChild(createZoneBadge(entry.policy));
      if (entry.policy.atomic_root_display) {
        zoneCell.appendChild(el("span", "chip-quiet", "整体"));
      }
      row.appendChild(zoneCell);

      const sizeCell = el("div", "vlist__col-size");
      sizeCell.appendChild(el("span", "vlist__size-main", formatBytes(entry.size_bytes)));
      row.appendChild(sizeCell);

      const timeCell = el("div", "vlist__col-time", formatUnixTime(entry.modified_unix));
      timeCell.title = formatUnixTime(entry.modified_unix);
      row.appendChild(timeCell);

      row.addEventListener("click", () => {
        this.focusedIndex = index;
        this.callbacks.onInspectEntry(entry);
        this.render();
        this.viewport.focus();
      });
      row.addEventListener("dblclick", () => {
        if (entry.kind === "directory") {
          if (this.tree) void this.toggleDirectory(index);
          else this.callbacks.onDrillDirectory(entry);
        }
      });

      this.rowsEl.appendChild(row);
    }

    clearChildren(this.statusEl);
    this.statusEl.appendChild(
      el("span", "vlist__status-path", focusedPath ?? ""),
    );
    this.statusEl.appendChild(
      el("span", "vlist__status-count", `${this.offset + 1}–${end} / ${this.totalCount} ${this.tree ? "行" : "项"}`),
    );
  }

  private appendIndents(target: HTMLElement, depth: number): void {
    for (let level = 0; level < depth; level += 1) {
      const indent = el("span", "vlist__indent");
      indent.setAttribute("aria-hidden", "true");
      target.appendChild(indent);
    }
  }

  private retryButton(branch: EntryBranch, offset: number): HTMLButtonElement {
    const button = el("button", "btn btn--link vlist__retry", "重试");
    button.type = "button";
    button.addEventListener("click", () => {
      if (this.tree) void this.fetchBranch(this.tree, branch, offset);
    });
    return button;
  }

  destroy(): void {
    this.destroyed = true;
  }
}
