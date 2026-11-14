import assert from "node:assert/strict";
import test from "node:test";
import {
  formatBytes,
  formatCountdown,
  parseBigIntSafe,
} from "../src/components/safe-text.ts";
import { describeSensitivityReason } from "../src/components/zone-badge.ts";
import type { SelectionSpec } from "../src/api/types.ts";
import {
  AppStore,
  clearSelection,
  defaultFilter,
  isEntrySelected,
  selectAllCurrentFilter,
  selectedCountEstimate,
  toggleEntrySelection,
} from "../src/state/store.ts";

test("BigInt byte formatting avoids JS Number precision loss", () => {
  const huge = "9007199254740993123"; // > Number.MAX_SAFE_INTEGER
  assert.equal(parseBigIntSafe(huge), 9007199254740993123n);
  assert.match(formatBytes(huge), /PiB$/);
  assert.equal(formatBytes("512"), "512 B");
  assert.equal(formatBytes(null), "未知");
});

test("SelectionSpec handles ids and filtered+excludes with scan_generation isolation", () => {
  let sel = toggleEntrySelection(
    { mode: "ids", scan_generation: "1", ids: [] },
    "10",
    "1",
  );
  assert.equal(sel.mode, "ids");
  assert.equal(isEntrySelected(sel, "10", "1"), true);
  // Old generation is ignored
  assert.equal(isEntrySelected(sel, "10", "2"), false);
  assert.equal(selectedCountEstimate(sel, 500, "2"), 0);

  // Filtered mode + excludes
  const filtered = selectAllCurrentFilter("2", defaultFilter());
  assert.equal(filtered.mode, "filtered");
  assert.equal(selectedCountEstimate(filtered, 500, "2"), 500);
  assert.equal(isEntrySelected(filtered, "42", "2"), true);

  sel = toggleEntrySelection(filtered, "42", "2");
  assert.equal(sel.mode, "filtered");
  assert.equal(isEntrySelected(sel, "42", "2"), false);
  assert.equal(selectedCountEstimate(sel, 500, "2"), 499);

  sel = clearSelection("2");
  assert.equal(selectedCountEstimate(sel, 500, "2"), 0);
});

test("Countdown formatting detects expiry", () => {
  assert.deepEqual(formatCountdown("1000", 1000), {
    expired: true,
    label: "已过期，请重新生成",
  });
  assert.deepEqual(formatCountdown("1065", 1000), {
    expired: false,
    label: "01:05",
  });
});

test("Changing filters clears the old filtered selection before notifying plan consumers", () => {
  const store = new AppStore();
  store.state.scanFilter.search_text = "documents";
  store.state.selection = selectAllCurrentFilter("1", store.state.scanFilter);
  const notifiedSelections: SelectionSpec[] = [];
  store.subscribe(() => {
    notifiedSelections.push(store.state.selection);
  });

  store.updateScanFilter({ search_text: "photos" });

  assert.equal(store.state.scanFilter.search_text, "photos");
  assert.deepEqual(notifiedSelections, [
    { mode: "ids", scan_generation: "1", ids: [] },
  ]);
  assert.equal(isEntrySelected(store.state.selection, "old-document-id", "1"), false);
  assert.equal(selectedCountEstimate(store.state.selection, 20, "1"), 0);
});

test("B-zone cascade reasons have clear human descriptions", () => {
  assert.match(
    describeSensitivityReason("contains_sensitive_child") ?? "",
    /级联拒绝原因/,
  );
  assert.match(
    describeSensitivityReason("hardlink_alias_propagated") ?? "",
    /硬链接别名/,
  );
});
