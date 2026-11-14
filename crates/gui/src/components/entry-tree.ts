import type { EntryId, FileEntryDto, ScanFilter } from "../api/types.ts";

export function isTreeBrowseFilter(filter: ScanFilter): boolean {
  return filter.tab === "browse" && filter.parent_entry_id === null &&
    filter.search_text.trim() === "" && filter.zone_filter === "all" &&
    filter.category_filter === "all";
}

export interface EntryBranch {
  parentId: EntryId | null;
  parent: EntryBranch | null;
  parentIndex: number;
  depth: number;
  initialized: boolean;
  expanded: boolean;
  total: number;
  entries: Map<number, FileEntryDto>;
  children: Map<number, EntryBranch>;
  pending: Map<number, Promise<void>>;
  error: boolean;
}

export interface TreeRow {
  branch: EntryBranch;
  siblingIndex: number;
  entry: FileEntryDto | undefined;
  note: boolean;
}

function branch(parentId: EntryId | null, parent: EntryBranch | null, parentIndex: number): EntryBranch {
  return {
    parentId, parent, parentIndex, depth: parent ? parent.depth + 1 : 0,
    initialized: false, expanded: true, total: 0,
    entries: new Map(), children: new Map(), pending: new Map(), error: false,
  };
}

/** Sparse sibling pages and expanded branches; never allocates a row per scanned file. */
export class EntryTree {
  readonly root = branch(null, null, 0);

  count(node = this.root): number {
    if (!node.expanded) return 0;
    if (node.total === 0) return node.parent ? 1 : 0;
    let total = node.total;
    for (const child of node.children.values()) total += this.count(child);
    return total;
  }

  row(index: number, node = this.root): TreeRow | undefined {
    if (index < 0 || index >= this.count(node)) return undefined;
    if (node.total === 0) return { branch: node, siblingIndex: 0, entry: undefined, note: true };
    let sibling = 0;
    for (const [at, child] of [...node.children].sort(([a], [b]) => a - b)) {
      if (!child.expanded) continue;
      const before = at - sibling + 1;
      if (index < before) return this.entryRow(node, sibling + index);
      index -= before;
      const childCount = this.count(child);
      if (index < childCount) return this.row(index, child);
      index -= childCount;
      sibling = at + 1;
    }
    return this.entryRow(node, sibling + index);
  }

  private entryRow(node: EntryBranch, index: number): TreeRow {
    return { branch: node, siblingIndex: index, entry: node.entries.get(index), note: false };
  }

  child(row: TreeRow): EntryBranch | undefined {
    return row.branch.children.get(row.siblingIndex);
  }

  expand(row: TreeRow): EntryBranch | undefined {
    if (row.entry?.kind !== "directory") return undefined;
    let child = this.child(row);
    if (!child) {
      child = branch(row.entry.id, row.branch, row.siblingIndex);
      row.branch.children.set(row.siblingIndex, child);
    }
    child.expanded = true;
    return child;
  }

  indexOf(node: EntryBranch, siblingIndex: number): number | null {
    if (!node.expanded) return null;
    let index = siblingIndex;
    for (const [at, child] of node.children) {
      if (at < siblingIndex) index += this.count(child);
    }
    if (!node.parent) return index;
    const parentIndex = this.indexOf(node.parent, node.parentIndex);
    return parentIndex === null ? null : parentIndex + 1 + index;
  }

  collapseAll(): void {
    const collapse = (node: EntryBranch): void => {
      for (const child of node.children.values()) {
        child.expanded = false;
        collapse(child);
      }
    };
    collapse(this.root);
  }
}
