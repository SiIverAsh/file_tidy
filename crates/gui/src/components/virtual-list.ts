import type {
  EntryId,
  FileEntryDto,
  ScanGeneration,
  SelectionSpec,
} from "../api/types.ts";
import { isEntrySelected } from "../state/store.ts";
import { clearChildren, el, formatBytes, formatUnixTime } from "./safe-text.ts";
import { createZoneBadge } from "./zone-badge.ts";

export interface VirtualListCallbacks {
  onFetchWindow(offset: number, limit: number): Promise<{
    totalCount: number;
    entries: FileEntryDto[];
  }>;
  onToggleSelect(entryId: EntryId): void;
  onInspectEntry(entry: FileEntryDto): void;
  onDrillDirectory(entry: FileEntryDto): void;
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

  constructor(callbacks: VirtualListCallbacks) {
    this.callbacks = callbacks;
    this.root = el("div", "vlist");

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
          const entry = this.cache.get(this.focusedIndex);
          if (entry) {
            this.callbacks.onToggleSelect(entry.id);
          }
          break;
        }
        case "Enter": {
          const entry = this.cache.get(this.focusedIndex);
          if (entry) {
            if (entry.kind === "directory") {
              this.callbacks.onDrillDirectory(entry);
            } else {
              this.callbacks.onInspectEntry(entry);
            }
          }
          break;
        }
      }
    });
  }

  async resetAndLoad(generation: ScanGeneration, selection: SelectionSpec): Promise<void> {
    this.generation = generation;
    this.selection = selection;
    this.offset = 0;
    this.focusedIndex = 0;
    this.requestSeq += 1;
    this.loadingSeq = null;
    this.cache.clear();
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

  private async moveFocus(nextIndex: number): Promise<void> {
    const clamped = Math.max(0, Math.min(this.totalCount - 1, nextIndex));
    this.focusedIndex = clamped;
    if (clamped < this.offset) {
      await this.scrollTo(clamped);
    } else if (clamped >= this.offset + WINDOW_ROWS) {
      await this.scrollTo(clamped - WINDOW_ROWS + 1);
    } else {
      const entry = this.cache.get(clamped);
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
      if (!this.cache.has(i)) {
        return true;
      }
    }
    return false;
  }

  private async loadWindow(startOffset: number): Promise<void> {
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
    if (this.totalCount <= WINDOW_ROWS) {
      this.scrubber.classList.add("vlist__scrubber--hidden");
    } else {
      this.scrubber.classList.remove("vlist__scrubber--hidden");
    }

    if (this.totalCount === 0) {
      this.rowsEl.appendChild(el("div", "vlist__empty", "当前筛选条件下没有条目"));
      this.statusEl.textContent = "0 项";
      return;
    }

    const end = Math.min(this.totalCount, this.offset + WINDOW_ROWS);
    let focusedPath: string | null = null;

    for (let index = this.offset; index < end; index += 1) {
      const entry = this.cache.get(index);
      if (!entry) {
        this.rowsEl.appendChild(el("div", "vlist__row vlist__row--loading", "加载中…"));
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
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", selected ? "true" : "false");
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
      titleRow.appendChild(
        el("span", "vlist__kind-icon", entry.kind === "directory" ? "📁" : "📄"),
      );
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
      row.appendChild(timeCell);

      row.addEventListener("click", () => {
        this.focusedIndex = index;
        this.callbacks.onInspectEntry(entry);
        this.render();
      });
      row.addEventListener("dblclick", () => {
        if (entry.kind === "directory") {
          this.callbacks.onDrillDirectory(entry);
        }
      });

      this.rowsEl.appendChild(row);
    }

    clearChildren(this.statusEl);
    this.statusEl.appendChild(
      el("span", "vlist__status-path", focusedPath ?? ""),
    );
    this.statusEl.appendChild(
      el("span", "vlist__status-count", `${this.offset + 1}–${end} / 共 ${this.totalCount} 项`),
    );
  }

  destroy(): void {
    this.destroyed = true;
  }
}
