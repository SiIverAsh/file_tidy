/** Keeps exiting content mounted while CSS handles its visibility transition. */
export class MotionPresence {
  private readonly root: HTMLElement;
  private readonly openClass: string;
  private readonly durationMs: number;
  private open = false;
  private exitTimer: ReturnType<typeof globalThis.setTimeout> | null = null;

  constructor(root: HTMLElement, openClass: string, durationMs = 220) {
    this.root = root;
    this.openClass = openClass;
    this.durationMs = durationMs;
    this.setInteractive(false);
  }

  show(): void {
    if (this.exitTimer !== null) {
      globalThis.clearTimeout(this.exitTimer);
      this.exitTimer = null;
    }
    if (this.open) return;
    this.open = true;
    this.setInteractive(true);
    this.root.classList.add(this.openClass);
  }

  hide(onExited: () => void): void {
    if (!this.open) return;
    this.open = false;
    this.setInteractive(false);
    this.root.classList.remove(this.openClass);

    // Test DOMs and non-browser renderers do not have animated transitions.
    const reducedMotion = typeof window === "undefined" ||
      typeof window.matchMedia !== "function" ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reducedMotion || this.durationMs <= 0) {
      onExited();
      return;
    }

    this.exitTimer = globalThis.setTimeout(() => {
      this.exitTimer = null;
      if (!this.open) onExited();
    }, this.durationMs);
  }

  private setInteractive(interactive: boolean): void {
    this.root.inert = !interactive;
    this.root.setAttribute("aria-hidden", String(!interactive));
  }
}
