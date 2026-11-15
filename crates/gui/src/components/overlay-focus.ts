export function containsNode(root: HTMLElement, target: Node | null): boolean {
  while (target) {
    if (target === root) return true;
    target = target.parentNode;
  }
  return false;
}

function focusableChildren(root: HTMLElement): HTMLElement[] {
  const result: HTMLElement[] = [];
  const visit = (parent: HTMLElement): void => {
    for (const child of Array.from(parent.children) as HTMLElement[]) {
      if (child.hidden || child.inert || child.getAttribute("aria-hidden") === "true") continue;
      const disabled = "disabled" in child && Boolean(child.disabled);
      const tag = child.tagName.toLowerCase();
      const nativeControl = ["button", "input", "select", "textarea", "summary"].includes(tag);
      if (!disabled && (nativeControl || child.tabIndex >= 0) &&
        child.getAttribute("tabindex") !== "-1" && child.getAttribute("type") !== "hidden") {
        result.push(child);
      }
      if (tag === "details" && !(child as HTMLDetailsElement).open) {
        const summary = Array.from(child.children).find((node) => node.tagName.toLowerCase() === "summary");
        if (summary) result.push(summary as HTMLElement);
      } else visit(child);
    }
  };
  visit(root);
  return result;
}

/** One active overlay owns keyboard focus; the app makes its background inert. */
export class OverlayFocus {
  private active = false;
  private returnTarget: HTMLElement | null = null;
  private readonly root: HTMLElement;
  private readonly onDismiss: () => void;
  private readonly canDismiss: () => boolean;

  constructor(
    root: HTMLElement,
    onDismiss: () => void,
    canDismiss: () => boolean = () => true,
  ) {
    this.root = root;
    this.onDismiss = onDismiss;
    this.canDismiss = canDismiss;
    root.tabIndex = -1;
    root.addEventListener("keydown", (event) => {
      if (!this.active) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (this.canDismiss()) this.onDismiss();
      } else if (event.key === "Tab") {
        const children = focusableChildren(root);
        const first = children[0];
        const last = children[children.length - 1];
        if (!first || !last) {
          event.preventDefault();
          root.focus();
        } else if (event.shiftKey && (document.activeElement === first || !containsNode(root, document.activeElement))) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !containsNode(root, document.activeElement))) {
          event.preventDefault();
          first.focus();
        }
      }
    });
  }

  activate(): void {
    if (!this.active) {
      const previous = document.activeElement;
      this.returnTarget = previous && "focus" in previous ? previous as HTMLElement : null;
      this.active = true;
    }
    if (!containsNode(this.root, document.activeElement)) {
      (focusableChildren(this.root)[0] ?? this.root).focus();
    }
  }

  deactivate(restoreFocus = true): void {
    if (!this.active) return;
    this.active = false;
    const target = this.returnTarget;
    this.returnTarget = null;
    if (restoreFocus && target && target.isConnected !== false) target.focus();
  }
}
