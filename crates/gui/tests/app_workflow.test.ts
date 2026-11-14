import assert from "node:assert/strict";
import test from "node:test";
import type { FileEntryDto, PlanPreviewDto, TreemapResponse } from "../src/api/types.ts";
import { PermanentDeleteModal } from "../src/components/permanent-modal.ts";
import { ReviewDrawer } from "../src/components/review-drawer.ts";
import { TreemapPanel } from "../src/components/treemap.ts";
import { VirtualEntryList } from "../src/components/virtual-list.ts";
import { AppStore } from "../src/state/store.ts";

class FakeClassList {
  private set = new Set<string>();
  add(...names: string[]): void {
    for (const n of names) {
      if (n) {
        this.set.add(n);
      }
    }
  }
  remove(...names: string[]): void {
    for (const n of names) {
      this.set.delete(n);
    }
  }
  contains(name: string): boolean {
    return this.set.has(name);
  }
}

class FakeElement {
  readonly tagName: string;
  className = "";
  readonly classList = new FakeClassList();
  children: FakeElement[] = [];
  parentNode: FakeElement | null = null;
  attributes = new Map<string, string>();
  dataset: Record<string, string> = {};
  listeners = new Map<string, Array<(ev: unknown) => void>>();
  textContent: string | null = "";
  type = "";
  value = "";
  placeholder = "";
  inputMode = "";
  disabled = false;
  checked = false;
  id = "";
  title = "";
  tabIndex = -1;
  width = 0;
  height = 0;

  constructor(tag: string) {
    this.tagName = tag.toUpperCase();
    if (this.tagName === "BUTTON" || this.tagName === "INPUT") {
      this.tabIndex = 0;
    }
  }

  get firstChild(): FakeElement | null {
    return this.children[0] ?? null;
  }

  appendChild(child: FakeElement): FakeElement {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  removeChild(child: FakeElement): FakeElement {
    const idx = this.children.indexOf(child);
    if (idx >= 0) {
      this.children.splice(idx, 1);
      child.parentNode = null;
    }
    return child;
  }

  replaceChildren(...nodes: FakeElement[]): void {
    for (const c of this.children) {
      c.parentNode = null;
    }
    this.children = [];
    for (const n of nodes) {
      this.appendChild(n);
    }
  }

  setAttribute(name: string, val: string): void {
    this.attributes.set(name, val);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name: string): void {
    this.attributes.delete(name);
  }

  focus(): void {}

  addEventListener(type: string, cb: (ev: unknown) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(cb);
    this.listeners.set(type, list);
  }

  dispatch(type: string, event: unknown = {}): void {
    for (const cb of this.listeners.get(type) ?? []) {
      cb(event);
    }
  }

  getContext(): null {
    return null;
  }

  findAll(pred: (el: FakeElement) => boolean): FakeElement[] {
    const out: FakeElement[] = [];
    if (pred(this)) {
      out.push(this);
    }
    for (const c of this.children) {
      out.push(...c.findAll(pred));
    }
    return out;
  }
}

function installFakeDom(): { setActive(el: FakeElement | null): void } {
  let activeEl: FakeElement | null = null;
  const fakeDoc = {
    createElement(tag: string): FakeElement {
      return new FakeElement(tag);
    },
    get activeElement(): FakeElement | null {
      return activeEl;
    },
  };
  (globalThis as unknown as { document: unknown }).document = fakeDoc;
  (globalThis as unknown as { window: unknown }).window = globalThis;
  return {
    setActive(el: FakeElement | null): void {
      activeEl = el;
    },
  };
}

function samplePreview(overrides: Partial<PlanPreviewDto> = {}): PlanPreviewDto {
  const futureUnix = String(Math.floor(Date.now() / 1000) + 600);
  return {
    plan_id: "plan-1",
    plan_digest: "abcdef1234567890",
    created_at_unix: "1700000000",
    expires_at_unix: futureUnix,
    authorization_epoch: "1",
    operations: [
      {
        id: "op-1",
        kind: "copy",
        source_display: "/tmp/id_rsa",
        source_policy: {
          zone: "B_Sensitive",
          protected: false,
          sensitive: true,
          atomic_root_display: null,
          sensitivity_reason: "sensitive_filename",
          allowed_actions: ["copy_out"],
          blocked_reason: "sensitive",
        },
        destination: null,
        destination_policy: null,
        manifest: [],
        source_grant_id: "g-1",
        destination_grant_id: "g-2",
        irreversible: false,
      },
    ],
    files_and_links: "120",
    directories: "0",
    empty_directories: "0",
    confirmation_count: "120",
    total_bytes: "2048",
    requires_count_confirmation: true,
    sensitive_acknowledgements: [],
    has_permanent_delete: false,
    executable_error: null,
    blocked_b_write_reasons: [],
    ...overrides,
  };
}

test("ReviewDrawer preserves itemCountInput focus across keystrokes and blocks B-zone writes", () => {
  const dom = installFakeDom();
  const store = new AppStore();
  store.state.planDrawer.open = true;
  store.state.planDrawer.preview = samplePreview({
    blocked_b_write_reasons: ["B 区禁止写操作"],
  });
  store.state.planDrawer.selectedOpIds = new Set(["op-1"]);

  const drawer = new ReviewDrawer({
    onClose: () => {},
    onFilterOperations: async () => {},
    onToggleAckKey: () => {},
    onItemCountInput: (v) => {
      store.state.planDrawer.itemCountInput = v;
      drawer.render(store.state);
    },
    onExecute: async () => {},
    onCancelExecution: async () => {},
    onJumpToRecovery: () => {},
  });

  drawer.render(store.state);
  const rootEl = drawer.root as unknown as FakeElement;
  const countdown = rootEl.findAll((el) => el.className === "plan-meta__timer")[0];
  assert.match(countdown?.textContent ?? "", /预览有效剩余 \d{2}:\d{2}/);
  const inputs = rootEl.findAll((el) => el.tagName === "INPUT" && el.type === "text");
  assert.equal(inputs.length, 1);
  const countInput = inputs[0];
  if (!countInput) {
    throw new Error("expected countInput element");
  }

  dom.setActive(countInput);
  countInput.value = "120";
  countInput.dispatch("input");

  // Same FakeElement instance stays mounted (not destroyed by clearChildren).
  const inputsAfter = rootEl.findAll((el) => el.tagName === "INPUT" && el.type === "text");
  assert.equal(inputsAfter[0], countInput);

  // Even after typing exact confirmation count, blocked_b_write_reasons keeps execute button disabled.
  const execBtns = rootEl.findAll(
    (el) => el.tagName === "BUTTON" && el.textContent === "确认并执行计划",
  );
  assert.equal(execBtns[0]?.disabled, true);

  store.state.planDrawer.open = false;
  drawer.render(store.state);
});

test("PermanentDeleteModal preserves phraseInput focus and enforces expiration & matching count", () => {
  const dom = installFakeDom();
  const store = new AppStore();
  const future = String(Math.floor(Date.now() / 1000) + 120);
  store.state.permanentModal.open = true;
  store.state.permanentModal.preview = samplePreview({
    has_permanent_delete: true,
    requires_count_confirmation: false,
    confirmation_count: "1",
  });
  store.state.permanentModal.challenge = {
    plan_id: "plan-1",
    plan_digest: "abcdef1234567890",
    challenge_code: "A1B2C3D4E5F6",
    expected_prefix: "PERMANENT",
    confirmation_count: "1",
    expires_at_unix: future,
  };

  const modal = new PermanentDeleteModal({
    onClose: () => {},
    onRequestChallenge: async () => {},
    onPhraseInput: (v) => {
      store.state.permanentModal.phraseInput = v;
      modal.render(store.state);
    },
    onCountInput: () => {},
    onExecutePermanent: async () => {},
  });

  modal.render(store.state);
  const rootEl = modal.root as unknown as FakeElement;
  const countdown = rootEl.findAll((el) => el.className === "danger-challenge__timer")[0];
  assert.match(countdown?.textContent ?? "", /挑战码剩余有效期 \d{2}:\d{2}/);
  const phraseInput = rootEl.findAll((el) => el.tagName === "INPUT" && el.type === "text")[0];
  if (!phraseInput) {
    throw new Error("expected phraseInput element");
  }

  const submitBtn = (): FakeElement | undefined =>
    rootEl.findAll((el) => el.tagName === "BUTTON" && el.textContent === "永久删除 不可撤销")[0];
  assert.equal(submitBtn()?.disabled, true);

  dom.setActive(phraseInput);
  phraseInput.value = "PERMANENT 1 A1B2C3D4E5F6";
  phraseInput.dispatch("input");

  // Input element preserved + submit button unlocked cleanly.
  assert.equal(
    rootEl.findAll((el) => el.tagName === "INPUT" && el.type === "text")[0],
    phraseInput,
  );
  assert.equal(submitBtn()?.disabled, false);

  store.state.permanentModal.open = false;
  modal.render(store.state);
});

test("VirtualEntryList drops stale in-flight query results after resetAndLoad", async () => {
  installFakeDom();

  const resolvers: Array<() => void> = [];
  let callIndex = 0;
  const makeEntry = (id: string, name: string): FileEntryDto => ({
    id,
    path_display: `/c/${name}`,
    name_display: name,
    kind: "file",
    size_bytes: "100",
    allocated_bytes: "100",
    modified_unix: "1700000000",
    hidden: false,
    category: "document",
    type_evidence: null,
    content_inspected: false,
    is_stale: false,
    policy: {
      zone: "C_GrantedSession",
      protected: false,
      sensitive: false,
      atomic_root_display: null,
      sensitivity_reason: null,
      allowed_actions: [],
      blocked_reason: null,
    },
  });

  const vlist = new VirtualEntryList({
    onFetchWindow: () => {
      const myCall = ++callIndex;
      return new Promise((resolve) => {
        resolvers.push(() =>
          resolve({
            totalCount: 1,
            entries: [makeEntry(String(myCall), `file-${myCall}.txt`)],
          }),
        );
      });
    },
    onToggleSelect: () => {},
    onInspectEntry: () => {},
    onDrillDirectory: () => {},
  });

  const p1 = vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] });
  const p2 = vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] });

  // Resolve newer request first, then stale request #1 afterward
  resolvers[1]?.();
  await p2;
  resolvers[0]?.();
  await p1;

  const rootEl = vlist.root as unknown as FakeElement;
  const names = rootEl
    .findAll((el) => el.className === "vlist__name")
    .map((el) => el.textContent);
  assert.deepEqual(names, ["file-2.txt"]);
  vlist.destroy();
});

function treeEntry(id: string, name: string, kind: FileEntryDto["kind"]): FileEntryDto {
  return {
    id,
    path_display: `/work/${name}`,
    name_display: name,
    kind,
    size_bytes: "1024",
    allocated_bytes: "1024",
    modified_unix: "1700000000",
    hidden: false,
    category: null,
    type_evidence: null,
    content_inspected: false,
    is_stale: false,
    policy: {
      zone: "C_GrantedSession",
      protected: false,
      sensitive: false,
      atomic_root_display: null,
      sensitivity_reason: null,
      allowed_actions: [],
      blocked_reason: null,
    },
  };
}

function treeNames(root: FakeElement): Array<string | null> {
  return root.findAll((el) => el.className === "vlist__name").map((el) => el.textContent);
}

function treeToggle(root: FakeElement, label: string): FakeElement {
  const toggle = root.findAll((el) => el.getAttribute("aria-label") === label)[0];
  if (!toggle) throw new Error(`expected tree toggle ${label}`);
  return toggle;
}

async function settleTree(): Promise<void> {
  // DOM event callbacks launch async work without returning its promise.
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

test("VirtualEntryList lazily expands nested directories and reopens cached branches", async () => {
  installFakeDom();
  const requests: Array<string | null> = [];
  const selected: string[] = [];
  const pending: { resolve?: (value: { totalCount: number; entries: FileEntryDto[] }) => void } = {};
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => { throw new Error("tree must use child queries"); },
    onFetchChildren: async (parentId) => {
      requests.push(parentId);
      if (parentId === null) return { totalCount: 1, entries: [treeEntry("root", "Project", "directory")] };
      if (parentId === "root") return new Promise((resolve) => { pending.resolve = resolve; });
      return { totalCount: 1, entries: [treeEntry("leaf", "notes.txt", "file")] };
    },
    onToggleSelect: (id) => { selected.push(id); },
    onInspectEntry: () => {},
    onDrillDirectory: () => { throw new Error("tree expansion must stay in place"); },
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  assert.deepEqual(requests, [null]);
  assert.deepEqual(treeNames(root), ["Project"]);
  assert.equal(root.findAll((el) => el.getAttribute("role") === "tree").length, 1);
  assert.equal(root.findAll((el) => el.getAttribute("role") === "treeitem")[0]?.getAttribute("aria-level"), "1");

  const checkbox = root.findAll((el) => el.getAttribute("aria-label") === "选择 Project")[0];
  let stopped = false;
  checkbox?.dispatch("click", { stopPropagation: () => { stopped = true; } });
  assert.equal(stopped, true);
  assert.deepEqual(selected, ["root"]);
  assert.deepEqual(requests, [null]);
  assert.equal(treeToggle(root, "展开 Project").getAttribute("aria-expanded"), "false");

  treeToggle(root, "展开 Project").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.deepEqual(requests, [null, "root"]);
  assert.equal(treeToggle(root, "收起 Project").getAttribute("aria-expanded"), "true");
  assert.equal(root.findAll((el) => el.textContent === "加载中…").length, 1);
  pending.resolve?.({ totalCount: 2, entries: [treeEntry("nested", "Documents", "directory"), treeEntry("report", "report.pdf", "file")] });
  await settleTree();
  treeToggle(root, "展开 Documents").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.deepEqual(treeNames(root), ["Project", "Documents", "notes.txt", "report.pdf"]);
  assert.deepEqual(root.findAll((el) => el.getAttribute("role") === "treeitem").map((el) => el.getAttribute("aria-level")), ["1", "2", "3", "2"]);

  treeToggle(root, "收起 Project").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.deepEqual(treeNames(root), ["Project"]);
  treeToggle(root, "展开 Project").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.deepEqual(treeNames(root), ["Project", "Documents", "notes.txt", "report.pdf"]);
  assert.deepEqual(requests, [null, "root", "nested"]);

  root.findAll((el) => el.textContent === "全部收起")[0]?.dispatch("click");
  await settleTree();
  assert.deepEqual(treeNames(root), ["Project"]);
  treeToggle(root, "展开 Project").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.deepEqual(treeNames(root), ["Project", "Documents", "report.pdf"]);
  assert.deepEqual(requests, [null, "root", "nested"]);
  vlist.destroy();
});

test("VirtualEntryList ignores an old directory response after a new scan reset", async () => {
  installFakeDom();
  let scan = 1;
  const pending: { resolve?: (value: { totalCount: number; entries: FileEntryDto[] }) => void } = {};
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => ({ totalCount: 0, entries: [] }),
    onFetchChildren: async (parentId) => {
      if (parentId === null) return { totalCount: 1, entries: [treeEntry(`scan-${scan}`, `Scan ${scan}`, "directory")] };
      return new Promise((resolve) => { pending.resolve = resolve; });
    },
    onToggleSelect: () => {},
    onInspectEntry: () => {},
    onDrillDirectory: () => {},
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  treeToggle(root, "展开 Scan 1").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  scan = 2;
  await vlist.resetAndLoad("2", { mode: "ids", scan_generation: "2", ids: [] }, true);
  pending.resolve?.({ totalCount: 1, entries: [treeEntry("stale", "old result.txt", "file")] });
  await settleTree();
  assert.deepEqual(treeNames(root), ["Scan 2"]);
  assert.equal(treeToggle(root, "展开 Scan 2").getAttribute("aria-expanded"), "false");
  vlist.destroy();
});

test("VirtualEntryList retries a failed directory load and identifies an empty folder", async () => {
  installFakeDom();
  let childRequests = 0;
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => ({ totalCount: 0, entries: [] }),
    onFetchChildren: async (parentId) => {
      if (parentId === null) return { totalCount: 1, entries: [treeEntry("empty", "Empty", "directory")] };
      childRequests += 1;
      if (childRequests === 1) throw new Error("temporary failure");
      return { totalCount: 0, entries: [] };
    },
    onToggleSelect: () => {},
    onInspectEntry: () => {},
    onDrillDirectory: () => {},
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  treeToggle(root, "展开 Empty").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.equal(root.findAll((el) => el.textContent === "加载失败").length, 1);
  root.findAll((el) => el.textContent === "重试")[0]?.dispatch("click");
  await settleTree();
  assert.equal(childRequests, 2);
  assert.equal(root.findAll((el) => el.textContent === "没有可见条目").length, 1);
  assert.equal(root.findAll((el) => el.textContent === "重试").length, 0);
  treeToggle(root, "收起 Empty").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.equal(root.findAll((el) => el.textContent === "没有可见条目").length, 0);
  vlist.destroy();
});

test("VirtualEntryList supports keyboard tree navigation without turning selection into expansion", async () => {
  installFakeDom();
  const selected: string[] = [];
  const inspected: string[] = [];
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => ({ totalCount: 0, entries: [] }),
    onFetchChildren: async (parentId) => parentId === null
      ? { totalCount: 1, entries: [treeEntry("project", "Project", "directory")] }
      : { totalCount: 1, entries: [treeEntry("notes", "notes.txt", "file")] },
    onToggleSelect: (id) => { selected.push(id); },
    onInspectEntry: (entry) => { inspected.push(entry.id); },
    onDrillDirectory: () => {},
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  const viewport = root.findAll((el) => el.getAttribute("role") === "tree")[0];
  if (!viewport) throw new Error("expected focusable tree viewport");
  const key = async (value: string): Promise<void> => {
    viewport.dispatch("keydown", { key: value, target: viewport, preventDefault: () => {} });
    await settleTree();
  };
  await key(" ");
  assert.deepEqual(selected, ["project"]);
  assert.deepEqual(treeNames(root), ["Project"]);
  await key("ArrowRight");
  assert.deepEqual(treeNames(root), ["Project", "notes.txt"]);
  await key("ArrowRight");
  assert.equal(viewport.getAttribute("aria-activedescendant"), "file-entry-1");
  assert.deepEqual(inspected, ["notes"]);
  await key("ArrowLeft");
  assert.equal(viewport.getAttribute("aria-activedescendant"), "file-entry-0");
  await key("ArrowLeft");
  assert.deepEqual(treeNames(root), ["Project"]);
  await key("Enter");
  assert.deepEqual(treeNames(root), ["Project", "notes.txt"]);
  assert.deepEqual(selected, ["project"]);
  vlist.destroy();
});

test("VirtualEntryList keeps focus on the same sibling when an earlier folder finishes loading", async () => {
  installFakeDom();
  const pending: { resolve?: (value: { totalCount: number; entries: FileEntryDto[] }) => void } = {};
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => ({ totalCount: 0, entries: [] }),
    onFetchChildren: async (parentId) => {
      if (parentId === null) return {
        totalCount: 2,
        entries: [treeEntry("a", "A", "directory"), treeEntry("b", "B", "directory")],
      };
      return new Promise((resolve) => { pending.resolve = resolve; });
    },
    onToggleSelect: () => {},
    onInspectEntry: () => {},
    onDrillDirectory: () => {},
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  const viewport = root.findAll((el) => el.getAttribute("role") === "tree")[0];
  if (!viewport) throw new Error("expected tree viewport");
  treeToggle(root, "展开 A").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  viewport.dispatch("keydown", { key: "ArrowDown", target: viewport, preventDefault: () => {} });
  await settleTree();
  const focusedName = (): string | null | undefined => {
    const activeId = viewport.getAttribute("aria-activedescendant");
    const active = root.findAll((el) => el.id === activeId)[0];
    return active?.findAll((el) => el.className === "vlist__name")[0]?.textContent;
  };
  assert.equal(focusedName(), "B");
  pending.resolve?.({
    totalCount: 24,
    entries: Array.from({ length: 24 }, (_, index) => treeEntry(`child-${index}`, `child-${index}.txt`, "file")),
  });
  await settleTree();
  assert.equal(focusedName(), "B");
  assert.equal(root.findAll((el) => el.getAttribute("role") === "treeitem").length, 18);
  vlist.destroy();
});

test("VirtualEntryList keeps ArrowRight on an expanded empty directory", async () => {
  installFakeDom();
  const vlist = new VirtualEntryList({
    onFetchWindow: async () => ({ totalCount: 0, entries: [] }),
    onFetchChildren: async (parentId) => parentId === null
      ? { totalCount: 2, entries: [treeEntry("empty", "Empty", "directory"), treeEntry("next", "Next", "directory")] }
      : { totalCount: 0, entries: [] },
    onToggleSelect: () => {},
    onInspectEntry: () => {},
    onDrillDirectory: () => {},
  });
  await vlist.resetAndLoad("1", { mode: "ids", scan_generation: "1", ids: [] }, true);
  const root = vlist.root as unknown as FakeElement;
  const viewport = root.findAll((el) => el.getAttribute("role") === "tree")[0];
  if (!viewport) throw new Error("expected tree viewport");
  treeToggle(root, "展开 Empty").dispatch("click", { stopPropagation: () => {} });
  await settleTree();
  assert.equal(root.findAll((el) => el.textContent === "没有可见条目").length, 1);
  viewport.dispatch("keydown", { key: "ArrowRight", target: viewport, preventDefault: () => {} });
  await settleTree();
  assert.equal(viewport.getAttribute("aria-activedescendant"), "file-entry-0");
  assert.equal(treeToggle(root, "收起 Empty").getAttribute("aria-expanded"), "true");
  vlist.destroy();
});

test("TreemapPanel renders focusable DOM treeitem nodes alongside canvas", () => {
  installFakeDom();
  const treemap = new TreemapPanel({
    onDrillDown: () => {},
    onHighlightNode: () => {},
  });
  const data: TreemapResponse = {
    scan_generation: "1",
    parent_entry_id: null,
    breadcrumbs: [{ entry_id: null, label_display: "扫描根" }],
    total_bytes: "4096",
    nodes: [
      {
        id: "tm-10",
        entry_id: "10",
        label_display: "logs",
        path_display: "/work/logs",
        logical_bytes: "4096",
        file_count: "4",
        is_other_rollup: false,
        drillable: true,
        policy: {
          zone: "C_GrantedSession",
          protected: false,
          sensitive: false,
          atomic_root_display: null,
          sensitivity_reason: null,
          allowed_actions: [],
          blocked_reason: null,
        },
      },
    ],
  };
  treemap.setData(data);
  const rootEl = treemap.root as unknown as FakeElement;
  const treeItems = rootEl.findAll((el) => el.getAttribute("role") === "treeitem");
  assert.equal(treeItems.length, 1);
  assert.equal(treeItems[0]?.tabIndex, 0);
});
