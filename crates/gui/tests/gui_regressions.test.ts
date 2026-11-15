import assert from "node:assert/strict";
import test from "node:test";
import { registerHooks } from "node:module";
import type { ApiClient } from "../src/api/tauri.ts";
import type { BatchHistoryDetailDto, PlanPreviewDto, QuarantineItemDto, ScanSummaryDto, WorkspaceStatusDto } from "../src/api/types.ts";
import { OverlayFocus } from "../src/components/overlay-focus.ts";
import { PermanentDeleteModal } from "../src/components/permanent-modal.ts";
import { ReviewDrawer } from "../src/components/review-drawer.ts";
import { AppStore } from "../src/state/store.ts";
import { ExploreView, type ExploreViewCallbacks } from "../src/views/explore.ts";
import type { SafetyHistoryCallbacks } from "../src/views/safety-history.ts";
import type { AccessRulesCallbacks } from "../src/views/access-rules.ts";
import type { ReviewDrawerCallbacks } from "../src/components/review-drawer.ts";

let setFocus: (node: FakeNode) => void = () => {};
class FakeNode {
  readonly tagName: string;
  children: FakeNode[] = [];
  parentNode: FakeNode | null = null;
  className = "";
  dataset: Record<string, string> = {};
  attributes = new Map<string, string>();
  listeners = new Map<string, Array<(event: unknown) => void>>();
  textContent = "";
  type = "";
  value = "";
  disabled = false;
  checked = false;
  hidden = false;
  inert = false;
  open = false;
  isConnected = true;
  tabIndex = -1;
  readonly classList = { add: (..._names: string[]) => {}, remove: (..._names: string[]) => {}, contains: (_name: string) => false };
  constructor(tag: string) { this.tagName = tag.toUpperCase(); }
  appendChild(node: FakeNode): FakeNode { node.parentNode = this; this.children.push(node); return node; }
  replaceChildren(): void { for (const node of this.children) node.parentNode = null; this.children = []; }
  setAttribute(key: string, value: string): void { this.attributes.set(key, value); }
  getAttribute(key: string): string | null { return this.attributes.get(key) ?? null; }
  removeAttribute(key: string): void { this.attributes.delete(key); }
  addEventListener(key: string, callback: (event: unknown) => void): void {
    const listeners = this.listeners.get(key) ?? []; listeners.push(callback); this.listeners.set(key, listeners);
  }
  removeEventListener(key: string, callback: (event: unknown) => void): void {
    this.listeners.set(key, (this.listeners.get(key) ?? []).filter((item) => item !== callback));
  }
  dispatch(key: string, event: unknown = {}): void { for (const callback of [...this.listeners.get(key) ?? []]) callback(event); }
  focus(): void { setFocus(this); }
  getContext(): null { return null; }
  find(predicate: (node: FakeNode) => boolean): FakeNode | undefined {
    if (predicate(this)) return this;
    for (const child of this.children) { const found = child.find(predicate); if (found) return found; }
    return undefined;
  }
}

function installDOM(): FakeNode {
  let active: FakeNode | null = null;
  setFocus = (node) => { active = node; };
  const doc = new FakeNode("document");
  Object.assign(doc, { createElement: (tag: string) => new FakeNode(tag), getElementById: () => null });
  Object.defineProperty(doc, "activeElement", { get: () => active });
  (globalThis as unknown as { document: unknown }).document = doc;
  (globalThis as unknown as { window: unknown }).window = globalThis;
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: () => null, setItem() {} } });
  return doc;
}

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve: (value: T) => void = () => {};
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function preview(id = "p1", expires = String(Math.floor(Date.now() / 1000) + 600)): PlanPreviewDto {
  return {
    plan_id: id, plan_digest: `digest-${id}`, created_at_unix: "1", expires_at_unix: expires,
    authorization_epoch: "1", files_and_links: "1", directories: "0", empty_directories: "0",
    confirmation_count: "1", total_bytes: "10", requires_count_confirmation: false,
    sensitive_acknowledgements: [], has_permanent_delete: false, executable_error: null, blocked_b_write_reasons: [],
    operations: [{ id: "op1", kind: "copy", source_display: "/a", source_policy: {
      zone: "C_GrantedSession", protected: false, sensitive: false, atomic_root_display: null,
      sensitivity_reason: null, allowed_actions: [], blocked_reason: null,
    }, destination: null, destination_policy: null, manifest: [], source_grant_id: "g1", destination_grant_id: "g2", irreversible: false }],
  };
}

const workspace: WorkspaceStatusDto = {
  storage_initialized: true, storage_root_display: "/new", authorization_epoch: "1", grants: [],
  pending_recovery_count: 0, due_quarantine_count: 0, platform: "macos",
};
function quarantine(id: string): QuarantineItemDto {
  return { id, batch_id: "b1", original_path_display: "/a", storage_path_display: "/q/a", retained_at_unix: "1", expires_at_unix: "2", due: true, state: "stored" };
}
function batch(id: string): BatchHistoryDetailDto {
  return { batch: { id, digest: id, state: "completed", item_count: "1", total_bytes: "10", created_at_unix: "1", completed_at_unix: "2" }, operations: [], events: [], events_truncated: false };
}

interface Harness {
  store: AppStore;
  openDrawerWithLoader(loader: () => Promise<PlanPreviewDto>): Promise<void>;
  openPermanentModalWithLoader(loader: () => Promise<PlanPreviewDto>): Promise<void>;
  closeDrawer(): void;
  closePermanentModal(): void;
  refreshSafetyData(): Promise<void>;
  replaceWorkspace(next: WorkspaceStatusDto): void;
  buildRestorePlan(pick: boolean): Promise<void>;
  safetyView: { callbacks: SafetyHistoryCallbacks };
  accessView: { callbacks: AccessRulesCallbacks };
  reviewDrawer: { callbacks: ReviewDrawerCallbacks };
}

async function appHarness(api: Partial<ApiClient>): Promise<Harness> {
  installDOM();
  // Test the actual application controller while leaving CSS to browser verification.
  const hooks = registerHooks({ load(url, context, nextLoad) {
    return url.endsWith(".css") ? { format: "module", source: "", shortCircuit: true } : nextLoad(url, context);
  } });
  try {
    const { FileTidyApp } = await import("../src/main.ts");
    return new FileTidyApp(new FakeNode("div") as unknown as HTMLElement, api as ApiClient) as unknown as Harness;
  } finally { hooks.deregister(); }
}

test("Closing and replacing operation previews ignores slow responses from an older plan", async () => {
  const filtered = deferred<PlanPreviewDto>();
  const app = await appHarness({ filterPlanOperations: () => filtered.promise });
  const old = deferred<PlanPreviewDto>();
  const first = app.openDrawerWithLoader(() => old.promise);
  app.closeDrawer();
  await app.openDrawerWithLoader(async () => preview("new"));
  old.resolve(preview("old")); await first;
  assert.equal(app.store.state.planDrawer.preview?.plan_id, "new");
  const filtering = app.reviewDrawer.callbacks.onFilterOperations("new", ["op1"]);
  app.closeDrawer();
  await app.openDrawerWithLoader(async () => preview("after-filter"));
  filtered.resolve(preview("stale-filter")); await filtering;
  assert.equal(app.store.state.planDrawer.preview?.plan_id, "after-filter");
  const permanentOld = deferred<PlanPreviewDto>();
  const deleting = app.openPermanentModalWithLoader(() => permanentOld.promise);
  app.closePermanentModal();
  await app.openPermanentModalWithLoader(async () => preview("new-delete"));
  permanentOld.resolve(preview("old-delete")); await deleting;
  assert.equal(app.store.state.permanentModal.preview?.plan_id, "new-delete");
});

test("Safety filtering and history details keep the newest response and visible stored selections", async () => {
  const all = deferred<QuarantineItemDto[]>();
  const due = deferred<QuarantineItemDto[]>();
  const a = deferred<BatchHistoryDetailDto>();
  const b = deferred<BatchHistoryDetailDto>();
  const app = await appHarness({ listQuarantine: (dueOnly) => dueOnly ? due.promise : all.promise,
    listHistory: async () => [], getRecoveryReport: async () => ({ items: [] }),
    getBatchDetail: (id) => id === "a" ? a.promise : b.promise });
  app.store.state.workspace = workspace;
  const first = app.refreshSafetyData();
  app.store.state.safety.selectedQuarantineIds.add("old");
  const second = app.safetyView.callbacks.onToggleDueOnly(true);
  assert.equal(app.store.state.safety.selectedQuarantineIds.size, 0);
  app.store.state.safety.selectedQuarantineIds.add("due");
  app.store.state.safety.selectedQuarantineIds.add("missing");
  due.resolve([quarantine("due")]); await second;
  all.resolve([quarantine("old")]); await first;
  assert.deepEqual(app.store.state.safety.quarantineItems.map((item) => item.id), ["due"]);
  assert.deepEqual([...app.store.state.safety.selectedQuarantineIds], ["due"]);
  const firstDetail = app.safetyView.callbacks.onSelectBatch("a");
  const secondDetail = app.safetyView.callbacks.onSelectBatch("b");
  b.resolve(batch("b")); await secondDetail; a.resolve(batch("a")); await firstDetail;
  assert.equal(app.store.state.safety.selectedBatchDetail?.batch.id, "b");
});

test("Workspace replacement invalidates old scans, plans and safety requests; restore picker errors surface", async () => {
  const old = deferred<QuarantineItemDto[]>();
  const app = await appHarness({ listQuarantine: () => old.promise, listHistory: async () => [],
    getRecoveryReport: async () => ({ items: [] }), openExistingStorage: async () => workspace,
    pickDestinationDirectory: async () => { throw new Error("picker failed"); } });
  app.store.state.workspace = workspace;
  app.store.state.scanSummary = { scan_generation: "1" } as ScanSummaryDto;
  app.store.state.selection = { mode: "ids", scan_generation: "1", ids: ["entry"] };
  app.store.state.safety.selectedBatchDetail = batch("old");
  app.store.state.planDrawer.preview = preview("old");
  app.store.state.rulesFile = { path_display: "/rules.toml", rule_count: 1 };
  await app.accessView.callbacks.onOpenExistingStorage();
  assert.equal(app.store.state.scanSummary?.scan_generation, "1");
  const refresh = app.refreshSafetyData();
  app.replaceWorkspace({ ...workspace, storage_root_display: "/other" });
  old.resolve([quarantine("old")]); await refresh;
  assert.equal(app.store.state.scanSummary, null);
  assert.equal(app.store.state.planDrawer.preview, null);
  assert.equal(app.store.state.rulesFile?.path_display, "/rules.toml");
  assert.deepEqual(app.store.state.selection, { mode: "ids", scan_generation: "0", ids: [] });
  assert.equal(app.store.state.safety.selectedBatchDetail, null);
  assert.equal(app.store.state.safety.quarantineItems.length, 0);
  app.store.state.safety.selectedQuarantineIds.add("current");
  await app.buildRestorePlan(true);
  assert.equal(app.store.state.globalError, "picker failed");
});

test("Overlay keyboard focus wraps, respects execution locks and returns to its opener", () => {
  installDOM();
  const opener = new FakeNode("button"); opener.focus();
  const root = new FakeNode("div");
  const first = root.appendChild(new FakeNode("button"));
  const last = root.appendChild(new FakeNode("input"));
  let locked = true; let dismissed = 0;
  const focus = new OverlayFocus(root as unknown as HTMLElement, () => { dismissed += 1; }, () => !locked);
  focus.activate();
  assert.equal(document.activeElement, first as unknown as Element);
  let prevented = false;
  first.focus(); root.dispatch("keydown", { key: "Tab", shiftKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, true); assert.equal(document.activeElement, last as unknown as Element);
  const escape = { key: "Escape", preventDefault() {}, stopPropagation() {} };
  root.dispatch("keydown", escape); assert.equal(dismissed, 0);
  locked = false; root.dispatch("keydown", escape); assert.equal(dismissed, 1);
  focus.deactivate(); assert.equal(document.activeElement, opener as unknown as Element);
});

test("Closing floating panels releases document capture listeners before another page or dialog", () => {
  const doc = installDOM();
  const callbacks = new Proxy({}, { get: () => async () => {} }) as ExploreViewCallbacks;
  const view = new ExploreView(callbacks);
  view.render(new AppStore().state);
  const root = view.root as unknown as FakeNode;
  const details = root.find((node) => node.className === "scan-options");
  if (!details) throw new Error("scan options not found");
  details.open = true; details.dispatch("toggle");
  assert.equal(doc.listeners.get("keydown")?.length, 1);
  view.closeFloatingPanels(false);
  assert.equal(doc.listeners.get("keydown")?.length, 0);
  assert.equal(doc.listeners.get("pointerdown")?.length, 0);
  assert.equal(details.open, false);
  details.open = true; details.dispatch("toggle");
  details.children[1]?.children[0]?.children[0]?.focus();
  view.closeFloatingPanels();
  assert.equal(document.activeElement, details.children[0] as unknown as Element);
  view.virtualList.destroy();
});

test("Expiry disables both confirmation buttons without a render and keeps challenge regeneration available", () => {
  installDOM();
  const originalNow = Date.now;
  let now = 1_000_000;
  const timers: Array<() => void> = [];
  Date.now = () => now;
  (globalThis as unknown as { window: unknown }).window = { setInterval: (callback: () => void) => { timers.push(callback); return timers.length; }, clearInterval: () => {} };
  const store = new AppStore();
  const drawer = new ReviewDrawer({ onClose() {}, onFilterOperations: async () => {}, onToggleAckKey() {}, onItemCountInput() {}, onExecute: async () => {}, onCancelExecution: async () => {}, onJumpToRecovery() {} });
  const modal = new PermanentDeleteModal({ onClose() {}, onRequestChallenge: async () => {}, onPhraseInput() {}, onCountInput() {}, onExecutePermanent: async () => {} });
  try {
    const plan = preview("expiry", "1002");
    store.state.planDrawer.open = true; store.state.planDrawer.preview = plan;
    store.state.permanentModal.open = true; store.state.permanentModal.preview = plan;
    store.state.permanentModal.challenge = { plan_id: plan.plan_id, plan_digest: plan.plan_digest, challenge_code: "CODE", expected_prefix: "PERMANENT", confirmation_count: "1", expires_at_unix: "1001" };
    store.state.permanentModal.phraseInput = "PERMANENT 1 CODE";
    drawer.render(store.state); modal.render(store.state);
    const execute = (drawer.root as unknown as FakeNode).find((node) => node.textContent === "确认并执行计划");
    const permanent = (modal.root as unknown as FakeNode).find((node) => node.textContent === "永久删除 不可撤销");
    assert.equal(execute?.disabled, false); assert.equal(permanent?.disabled, false);
    now = 1_003_000; for (const tick of timers) tick();
    assert.equal(execute?.disabled, true); assert.equal(permanent?.disabled, true);
    assert.equal(Boolean((modal.root as unknown as FakeNode).find((node) => node.textContent === "重新生成确认码")), true);
  } finally {
    store.state.planDrawer.open = false; store.state.permanentModal.open = false;
    drawer.render(store.state); modal.render(store.state);
    Date.now = originalNow;
  }
});
