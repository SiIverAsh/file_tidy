export type ColorMode = "system" | "light" | "dark";
export type ThemePreset = "indigo" | "forest" | "sand" | "rose" | "violet";
export type DetailMode = "simple" | "detailed";

export interface AppearancePreference {
  mode: ColorMode;
  preset: ThemePreset;
  detailMode: DetailMode;
}

export const COLOR_MODES = [
  { id: "system", label: "跟随系统" },
  { id: "light", label: "浅色" },
  { id: "dark", label: "深色" },
] as const satisfies readonly { id: ColorMode; label: string }[];

export const THEME_PRESETS = [
  { id: "indigo", label: "靛蓝" },
  { id: "forest", label: "松林" },
  { id: "sand", label: "暖砂" },
  { id: "rose", label: "玫瑰" },
  { id: "violet", label: "雾紫" },
] as const satisfies readonly { id: ThemePreset; label: string }[];

export const DETAIL_MODES = [
  { id: "simple", label: "简洁" },
  { id: "detailed", label: "详细" },
] as const satisfies readonly { id: DetailMode; label: string }[];

export const APPEARANCE_STORAGE_KEY = "file-tidy.appearance";
export const DEFAULT_APPEARANCE: Readonly<AppearancePreference> = Object.freeze({
  mode: "system",
  preset: "indigo",
  detailMode: "simple",
});

interface AppearanceMediaChange {
  readonly matches: boolean;
}

export interface AppearanceMedia {
  readonly matches: boolean;
  addEventListener(type: "change", listener: (event: AppearanceMediaChange) => void): void;
  removeEventListener(type: "change", listener: (event: AppearanceMediaChange) => void): void;
}

export interface AppearanceOptions {
  storage?: Pick<Storage, "getItem" | "setItem"> | null;
  root?: Pick<HTMLElement, "dataset"> | null;
  media?: AppearanceMedia | null;
}

function defaultStorage(): AppearanceOptions["storage"] {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

function defaultRoot(): AppearanceOptions["root"] {
  try {
    return typeof document === "undefined" ? null : document.documentElement;
  } catch {
    return null;
  }
}

function defaultMedia(): AppearanceMedia | null {
  try {
    return typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;
  } catch {
    return null;
  }
}

function readPreference(value: unknown): AppearancePreference | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  const mode = COLOR_MODES.find((item) => item.id === candidate.mode);
  const preset = THEME_PRESETS.find((item) => item.id === candidate.preset);
  if (!mode || !preset) return null;
  // Older settings and unrecognized detail modes keep the user's valid theme.
  const detailMode = DETAIL_MODES.find((item) => item.id === candidate.detailMode)?.id ?? "simple";
  return { mode: mode.id, preset: preset.id, detailMode };
}

/** Applies local appearance choices without requiring storage or browser globals. */
export class AppearanceController {
  private readonly storage: AppearanceOptions["storage"];
  private readonly root: AppearanceOptions["root"];
  private readonly media: AppearanceMedia | null;
  private readonly listeners = new Set<(preference: Readonly<AppearancePreference>) => void>();
  private preferenceValue: Readonly<AppearancePreference> = DEFAULT_APPEARANCE;
  private systemDark = false;
  private listeningForMedia = false;

  private readonly handleMediaChange = (event: AppearanceMediaChange): void => {
    const changed = this.systemDark !== event.matches;
    this.systemDark = event.matches;
    if (changed && this.preferenceValue.mode === "system") {
      this.apply();
      this.notify();
    }
  };

  constructor(options: AppearanceOptions = {}) {
    this.storage = options.storage === undefined ? defaultStorage() : options.storage;
    this.root = options.root === undefined ? defaultRoot() : options.root;
    this.media = options.media === undefined ? defaultMedia() : options.media;

    try {
      const saved = this.storage?.getItem(APPEARANCE_STORAGE_KEY);
      const value: unknown = saved ? JSON.parse(saved) : null;
      const preference = readPreference(value);
      if (preference) {
        this.preferenceValue = Object.freeze(preference);
      }
    } catch {
      // A denied storage read or malformed value must not prevent startup.
    }

    try {
      this.systemDark = this.media?.matches ?? false;
      this.media?.addEventListener("change", this.handleMediaChange);
      this.listeningForMedia = this.media !== null;
    } catch {
      // Unsupported media listeners leave the initially resolved mode usable.
    }
    this.apply();
  }

  get preference(): Readonly<AppearancePreference> {
    return this.preferenceValue;
  }

  /** Returns false when persistence is unavailable; valid choices still apply. */
  setPreference(patch: Partial<AppearancePreference>): boolean {
    const next = readPreference({ ...this.preferenceValue, ...patch });
    if (!next) return false;
    const changed = next.mode !== this.preferenceValue.mode || next.preset !== this.preferenceValue.preset ||
      next.detailMode !== this.preferenceValue.detailMode;
    this.preferenceValue = Object.freeze(next);
    this.apply();

    let persisted = false;
    try {
      if (this.storage) {
        this.storage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(this.preferenceValue));
        persisted = true;
      }
    } catch {
      // The UI can explain that this choice applies only to the current session.
    }
    if (changed) this.notify();
    return persisted;
  }

  subscribe(listener: (preference: Readonly<AppearancePreference>) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  destroy(): void {
    if (this.listeningForMedia) {
      try {
        this.media?.removeEventListener("change", this.handleMediaChange);
      } catch {
        // Cleanup must also be safe when the host media API is unavailable.
      }
    }
    this.listeningForMedia = false;
    this.listeners.clear();
  }

  private apply(): void {
    if (!this.root) return;
    const { mode, preset, detailMode } = this.preferenceValue;
    this.root.dataset.colorMode = mode === "system" ? (this.systemDark ? "dark" : "light") : mode;
    this.root.dataset.themePreset = preset;
    this.root.dataset.detailMode = detailMode;
  }

  private notify(): void {
    for (const listener of this.listeners) listener(this.preferenceValue);
  }
}
