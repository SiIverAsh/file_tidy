import assert from "node:assert/strict";
import test from "node:test";
import type { FileEntryDto } from "../src/api/types.ts";
import { EntryTree, isTreeBrowseFilter, type EntryBranch, type TreeRow } from "../src/components/entry-tree.ts";
import { defaultFilter } from "../src/state/store.ts";

function entry(id: string, kind: FileEntryDto["kind"] = "file"): FileEntryDto {
  return {
    id, kind, path_display: `/scan/${id}`, name_display: id,
    size_bytes: "100", allocated_bytes: null, modified_unix: null,
    hidden: false, category: null, type_evidence: null,
    content_inspected: false, is_stale: false,
    policy: {
      zone: "Unauthenticated", protected: false, sensitive: false,
      atomic_root_display: null, sensitivity_reason: null,
      allowed_actions: [], blocked_reason: null,
    },
  };
}

function row(tree: EntryTree, index: number): TreeRow {
  const result = tree.row(index);
  if (!result) throw new Error(`Missing visible row ${index}`);
  return result;
}

function expand(tree: EntryTree, index: number): EntryBranch {
  const result = tree.expand(row(tree, index));
  if (!result) throw new Error(`Row ${index} is not expandable`);
  return result;
}

function names(tree: EntryTree): Array<string | undefined> {
  return Array.from({ length: tree.count() }, (_, index) => row(tree, index).entry?.id);
}

test("Tree browsing is enabled by the default filter and keeps filtered searches flat", () => {
  const filter = defaultFilter();
  assert.equal(isTreeBrowseFilter(filter), true);
  assert.equal(isTreeBrowseFilter({ ...filter, search_text: "  " }), true);
  assert.equal(isTreeBrowseFilter({ ...filter, hide_hidden: false }), true);
  assert.equal(isTreeBrowseFilter({ ...filter, search_text: "report" }), false);
  assert.equal(isTreeBrowseFilter({ ...filter, zone_filter: "B_Sensitive" }), false);
  assert.equal(isTreeBrowseFilter({ ...filter, category_filter: "document" }), false);
  assert.equal(isTreeBrowseFilter({ ...filter, parent_entry_id: "folder" }), false);
  assert.equal(isTreeBrowseFilter({ ...filter, tab: "duplicates" }), false);
});

test("A million siblings stay sparse and allow access to unloaded rows", () => {
  const tree = new EntryTree();
  tree.root.initialized = true;
  tree.root.total = 1_000_000;
  const first = entry("first");
  const last = entry("last");
  tree.root.entries.set(0, first);
  tree.root.entries.set(999_999, last);

  assert.equal(tree.count(), 1_000_000);
  assert.equal(row(tree, 0).entry, first);
  assert.equal(row(tree, 999_999).entry, last);
  const unloaded = row(tree, 750_000);
  assert.equal(unloaded.entry, undefined);
  assert.equal(unloaded.siblingIndex, 750_000);
  assert.equal(unloaded.note, false);
  assert.equal(tree.indexOf(tree.root, 750_000), 750_000);
  assert.equal(tree.row(-1), undefined);
  assert.equal(tree.row(1_000_000), undefined);
  assert.equal(tree.root.entries.size, 2);
  assert.equal(tree.root.children.size, 0);
});

test("Nested expansion and collapse preserve visible ordering and row indices", () => {
  const tree = new EntryTree();
  tree.root.total = 3;
  tree.root.entries.set(0, entry("alpha", "directory"));
  tree.root.entries.set(1, entry("beta"));
  tree.root.entries.set(2, entry("gamma", "directory"));
  // Expand in reverse sibling order to verify display order is independent of map insertion.
  const gamma = expand(tree, 2);
  gamma.total = 1;
  gamma.entries.set(0, entry("gamma-file"));
  const alpha = expand(tree, 0);
  alpha.total = 3;
  alpha.entries.set(0, entry("alpha-file"));
  alpha.entries.set(1, entry("nested", "directory"));
  alpha.entries.set(2, entry("alpha-last"));
  const nested = expand(tree, 2);
  nested.total = 2;
  nested.entries.set(0, entry("nested-first"));
  nested.entries.set(1, entry("nested-last"));

  assert.deepEqual(names(tree), [
    "alpha", "alpha-file", "nested", "nested-first", "nested-last", "alpha-last",
    "beta", "gamma", "gamma-file",
  ]);
  assert.equal(tree.indexOf(tree.root, 1), 6);
  assert.equal(tree.indexOf(tree.root, 2), 7);
  assert.equal(tree.indexOf(alpha, 2), 5);
  assert.equal(tree.indexOf(nested, 1), 4);
  assert.equal(tree.expand(row(tree, 1)), undefined);

  alpha.expanded = false;
  assert.deepEqual(names(tree), ["alpha", "beta", "gamma", "gamma-file"]);
  assert.equal(tree.indexOf(nested, 1), null);
  assert.equal(tree.indexOf(tree.root, 1), 1);
  assert.equal(expand(tree, 0), alpha);
  assert.equal(tree.count(), 9);
  assert.equal(row(tree, 4).entry?.id, "nested-last");
});

test("Collapse all keeps branch caches and restores each folder independently", () => {
  const tree = new EntryTree();
  tree.root.total = 2;
  tree.root.entries.set(0, entry("alpha", "directory"));
  tree.root.entries.set(1, entry("empty", "directory"));
  const alpha = expand(tree, 0);
  alpha.initialized = true;
  alpha.total = 1;
  alpha.entries.set(0, entry("nested", "directory"));
  const nested = expand(tree, 1);
  nested.initialized = true;
  nested.total = 1;
  const cachedFile = entry("cached-file");
  nested.entries.set(0, cachedFile);
  const empty = expand(tree, 3);
  empty.initialized = true;
  assert.equal(tree.count(), 5);
  assert.equal(row(tree, 4).note, true);

  tree.collapseAll();
  assert.deepEqual(names(tree), ["alpha", "empty"]);
  assert.equal(tree.root.expanded, true);
  assert.equal(alpha.expanded, false);
  assert.equal(nested.expanded, false);
  assert.equal(empty.expanded, false);
  assert.equal(nested.entries.get(0), cachedFile);
  assert.equal(tree.root.children.size, 2);
  assert.equal(alpha.children.size, 1);

  assert.equal(expand(tree, 0), alpha);
  assert.deepEqual(names(tree), ["alpha", "nested", "empty"]);
  assert.equal(expand(tree, 1), nested);
  assert.equal(row(tree, 2).entry, cachedFile);
  assert.equal(expand(tree, 3), empty);
  assert.equal(tree.count(), 5);
  assert.equal(row(tree, 4).note, true);
  assert.equal(row(tree, 4).branch, empty);
});
