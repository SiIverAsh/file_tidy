import assert from "node:assert/strict";
import test from "node:test";
import {
  APPEARANCE_STORAGE_KEY,
  AppearanceController,
  DEFAULT_APPEARANCE,
  type AppearanceMedia,
} from "../src/state/appearance.ts";

class MemoryStorage {
  readonly data = new Map<string, string>();
  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.data.set(key, value);
  }
}

class SystemAppearance implements AppearanceMedia {
  matches = false;
  readonly listeners = new Set<(event: { matches: boolean }) => void>();
  addEventListener(_type: "change", listener: (event: { matches: boolean }) => void): void {
    this.listeners.add(listener);
  }
  removeEventListener(_type: "change", listener: (event: { matches: boolean }) => void): void {
    this.listeners.delete(listener);
  }
  change(dark: boolean): void {
    this.matches = dark;
    for (const listener of this.listeners) listener({ matches: dark });
  }
}

test("Invalid saved appearance and unavailable storage do not prevent local choices", () => {
  const storage = new MemoryStorage();
  for (const saved of ["{", "null", "[]", '{"mode":"dark"}', '{"mode":"dark","preset":"unknown"}']) {
    storage.setItem(APPEARANCE_STORAGE_KEY, saved);
    const controller = new AppearanceController({ storage, root: { dataset: {} }, media: null });
    assert.deepEqual(controller.preference, DEFAULT_APPEARANCE);
    controller.destroy();
  }

  const root = { dataset: {} as DOMStringMap };
  const unavailableStorage = {
    getItem(): never { throw new Error("Storage denied"); },
    setItem(): never { throw new Error("Quota exceeded"); },
  };
  const controller = new AppearanceController({ storage: unavailableStorage, root, media: null });
  assert.equal(root.dataset.colorMode, "light");
  assert.equal(controller.setPreference({ mode: "dark", preset: "forest" }), false);
  assert.deepEqual(controller.preference, { mode: "dark", preset: "forest", detailMode: "simple" });
  assert.equal(root.dataset.colorMode, "dark");
  assert.equal(root.dataset.themePreset, "forest");
  assert.equal(root.dataset.detailMode, "simple");
  controller.destroy();
});

test("Appearance choices persist, restore and expose an immutable preference", () => {
  const storage = new MemoryStorage();
  const controller = new AppearanceController({ storage, root: { dataset: {} }, media: null });
  assert.equal(controller.setPreference({ mode: "dark", preset: "sand", detailMode: "detailed" }), true);
  assert.equal(Object.isFrozen(controller.preference), true);

  const root = { dataset: {} as DOMStringMap };
  const restored = new AppearanceController({ storage, root, media: null });
  assert.deepEqual(restored.preference, { mode: "dark", preset: "sand", detailMode: "detailed" });
  assert.equal(root.dataset.colorMode, "dark");
  assert.equal(root.dataset.themePreset, "sand");
  assert.equal(root.dataset.detailMode, "detailed");
  restored.setPreference(DEFAULT_APPEARANCE);
  assert.equal(root.dataset.detailMode, "simple");
  controller.destroy();
  restored.destroy();
});

test("Older and invalid detail preferences keep the saved theme and default to simple", () => {
  for (const detail of [undefined, "unknown", null, 123]) {
    const storage = new MemoryStorage();
    storage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify({ mode: "light", preset: "violet", detailMode: detail }));
    const root = { dataset: {} as DOMStringMap };
    const controller = new AppearanceController({ storage, root, media: null });
    assert.deepEqual(controller.preference, { mode: "light", preset: "violet", detailMode: "simple" });
    assert.equal(root.dataset.themePreset, "violet");
    assert.equal(root.dataset.detailMode, "simple");
    assert.equal(controller.setPreference({ detailMode: "detailed" }), true);
    assert.deepEqual(JSON.parse(storage.getItem(APPEARANCE_STORAGE_KEY) ?? "null"), {
      mode: "light", preset: "violet", detailMode: "detailed",
    });
    controller.destroy();
  }
});

test("System changes follow system mode, respect manual mode and stop after cleanup", () => {
  const media = new SystemAppearance();
  const root = { dataset: {} as DOMStringMap };
  const controller = new AppearanceController({ storage: null, root, media });
  let notifications = 0;
  const unsubscribe = controller.subscribe(() => { notifications += 1; });

  media.change(true);
  assert.equal(root.dataset.colorMode, "dark");
  assert.equal(notifications, 1);
  controller.setPreference({ mode: "light" });
  assert.equal(notifications, 2);
  media.change(false);
  media.change(true);
  assert.equal(root.dataset.colorMode, "light");
  assert.equal(notifications, 2);
  controller.setPreference({ mode: "system" });
  assert.equal(root.dataset.colorMode, "dark");
  assert.equal(notifications, 3);

  unsubscribe();
  media.change(false);
  assert.equal(root.dataset.colorMode, "light");
  assert.equal(notifications, 3);
  controller.destroy();
  assert.equal(media.listeners.size, 0);
  media.change(true);
  assert.equal(root.dataset.colorMode, "light");
});
