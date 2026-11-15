import { el } from "../components/safe-text.ts";
import {
  COLOR_MODES,
  DETAIL_MODES,
  THEME_PRESETS,
  type AppearancePreference,
  type ColorMode,
  type DetailMode,
  type ThemePreset,
} from "../state/appearance.ts";

export interface AppearanceViewCallbacks {
  onChange(patch: Partial<AppearancePreference>): void;
  onReset(): void;
}

let nextViewId = 0;

/** Stable native controls keep keyboard focus during live theme previews. */
export class AppearanceView {
  readonly root: HTMLElement;
  private readonly modeInputs = new Map<ColorMode, HTMLInputElement>();
  private readonly detailInputs = new Map<DetailMode, HTMLInputElement>();
  private readonly presetInputs = new Map<ThemePreset, HTMLInputElement>();
  private readonly presetLabels = new Map<ThemePreset, HTMLElement>();
  private readonly saveNotice: HTMLElement;

  constructor(callbacks: AppearanceViewCallbacks) {
    const viewId = nextViewId++;
    this.root = el("section", "view view--appearance");

    const header = el("header", "page-header");
    header.appendChild(el("h1", "page-header__title", "外观"));
    this.root.appendChild(header);

    const modes = el("fieldset", "appearance-section");
    modes.appendChild(el("legend", "appearance-section__title", "显示模式"));
    const modeOptions = el("div", "appearance-modes");
    for (const mode of COLOR_MODES) {
      const label = el("label", "appearance-mode");
      const radio = el("input", "appearance-radio");
      radio.type = "radio";
      radio.name = `appearance-mode-${viewId}`;
      radio.value = mode.id;
      radio.addEventListener("change", () => {
        if (radio.checked) callbacks.onChange({ mode: mode.id });
      });
      this.modeInputs.set(mode.id, radio);
      label.appendChild(radio);
      label.appendChild(el("span", "", mode.label));
      modeOptions.appendChild(label);
    }
    modes.appendChild(modeOptions);
    this.root.appendChild(modes);

    const detail = el("fieldset", "appearance-section");
    detail.appendChild(el("legend", "appearance-section__title", "界面信息"));
    const detailOptions = el("div", "appearance-modes");
    for (const mode of DETAIL_MODES) {
      const label = el("label", "appearance-mode");
      const radio = el("input", "appearance-radio");
      radio.type = "radio";
      radio.name = `appearance-detail-${viewId}`;
      radio.value = mode.id;
      radio.addEventListener("change", () => {
        if (radio.checked) callbacks.onChange({ detailMode: mode.id });
      });
      this.detailInputs.set(mode.id, radio);
      label.appendChild(radio);
      label.appendChild(el("span", "", mode.label));
      detailOptions.appendChild(label);
    }
    detail.appendChild(detailOptions);
    const detailDescription = el("p", "appearance-section__description", "简洁模式显示常用信息，详细模式显示技术信息。");
    detailDescription.id = `appearance-detail-description-${viewId}`;
    detail.setAttribute("aria-describedby", detailDescription.id);
    detail.appendChild(detailDescription);
    this.root.appendChild(detail);

    const presets = el("fieldset", "appearance-section");
    presets.appendChild(el("legend", "appearance-section__title", "主题配色"));
    const presetOptions = el("div", "theme-options");
    for (const preset of THEME_PRESETS) {
      const label = el("label", `theme-option theme-option--${preset.id}`);
      const radio = el("input", "appearance-radio");
      radio.type = "radio";
      radio.name = `appearance-preset-${viewId}`;
      radio.value = preset.id;
      radio.addEventListener("change", () => {
        if (radio.checked) callbacks.onChange({ preset: preset.id });
      });
      this.presetInputs.set(preset.id, radio);
      this.presetLabels.set(preset.id, label);
      label.appendChild(radio);
      label.appendChild(el("span", "theme-option__name", preset.label));

      const swatches = el("span", "theme-option__swatches");
      swatches.setAttribute("aria-hidden", "true");
      for (const tone of ["accent", "soft", "neutral"]) {
        swatches.appendChild(el("span", `theme-option__swatch theme-option__swatch--${tone}`));
      }
      label.appendChild(swatches);
      presetOptions.appendChild(label);
    }
    presets.appendChild(presetOptions);
    this.root.appendChild(presets);

    const footer = el("div", "appearance-actions");
    const reset = el("button", "btn btn--secondary", "恢复默认");
    reset.type = "button";
    reset.addEventListener("click", () => callbacks.onReset());
    footer.appendChild(reset);
    this.saveNotice = el("p", "appearance-save-notice", "本次选择已生效，当前环境无法保存。");
    this.saveNotice.setAttribute("role", "status");
    this.saveNotice.hidden = true;
    footer.appendChild(this.saveNotice);
    this.root.appendChild(footer);
  }

  render(preference: AppearancePreference, persisted = true): void {
    for (const [mode, input] of this.modeInputs) {
      input.checked = mode === preference.mode;
    }
    for (const [mode, input] of this.detailInputs) {
      input.checked = mode === preference.detailMode;
    }
    for (const [preset, input] of this.presetInputs) {
      const selected = preset === preference.preset;
      input.checked = selected;
      const label = this.presetLabels.get(preset);
      if (selected) {
        label?.classList.add("theme-option--selected");
      } else {
        label?.classList.remove("theme-option--selected");
      }
    }
    this.saveNotice.hidden = persisted;
  }
}
