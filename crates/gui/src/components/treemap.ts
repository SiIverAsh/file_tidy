import type { EntryId, TreemapNodeDto, TreemapResponse } from "../api/types.ts";
import { clearChildren, el, formatBytes, parseBigIntSafe } from "./safe-text.ts";
import { createZoneBadge } from "./zone-badge.ts";

interface DrawnRect {
  x: number;
  y: number;
  w: number;
  h: number;
  node: TreemapNodeDto;
}

export interface TreemapCallbacks {
  onDrillDown(parentEntryId: EntryId | null): void;
  onHighlightNode(node: TreemapNodeDto | null): void;
}

const CANVAS_WIDTH = 560;
const CANVAS_HEIGHT = 300;

/**
 * Squarified treemap rendered onto <canvas> (zero inline styles) paired with a
 * synchronized, keyboard-focusable DOM list capped at Top 40 nodes + Other rollup.
 */
export class TreemapPanel {
  readonly root: HTMLElement;
  private readonly breadcrumbsEl: HTMLElement;
  private readonly canvas: HTMLCanvasElement;
  private readonly listEl: HTMLElement;
  private readonly callbacks: TreemapCallbacks;

  private data: TreemapResponse | null = null;
  private rects: DrawnRect[] = [];
  private activeNodeId: string | null = null;

  constructor(callbacks: TreemapCallbacks) {
    this.callbacks = callbacks;
    this.root = el("div", "treemap-panel");

    this.breadcrumbsEl = el("nav", "treemap-breadcrumbs");
    this.breadcrumbsEl.setAttribute("aria-label", "目录面包屑");
    this.root.appendChild(this.breadcrumbsEl);

    const grid = el("div", "treemap-grid");
    const canvasWrap = el("div", "treemap-canvas-wrap");
    this.canvas = el("canvas", "treemap-canvas");
    this.canvas.width = CANVAS_WIDTH;
    this.canvas.height = CANVAS_HEIGHT;
    this.canvas.setAttribute("aria-label", "空间占用矩形树图");
    canvasWrap.appendChild(this.canvas);
    grid.appendChild(canvasWrap);

    this.listEl = el("div", "treemap-list");
    this.listEl.setAttribute("role", "tree");
    this.listEl.setAttribute("aria-label", "目录占用排行（可键盘聚焦）");
    grid.appendChild(this.listEl);

    this.root.appendChild(grid);
    this.bindCanvasEvents();
  }

  setData(response: TreemapResponse | null): void {
    this.data = response;
    this.activeNodeId = null;
    this.renderBreadcrumbs();
    this.layoutRects();
    this.drawCanvas();
    this.renderList();
  }

  private bindCanvasEvents(): void {
    this.canvas.addEventListener("mousemove", (ev) => {
      const hit = this.hitTest(ev);
      const nextId = hit ? hit.node.id : null;
      if (nextId !== this.activeNodeId) {
        this.activeNodeId = nextId;
        this.drawCanvas();
        this.syncListFocusClass();
        this.callbacks.onHighlightNode(hit ? hit.node : null);
      }
    });

    this.canvas.addEventListener("mouseleave", () => {
      if (this.activeNodeId !== null) {
        this.activeNodeId = null;
        this.drawCanvas();
        this.syncListFocusClass();
        this.callbacks.onHighlightNode(null);
      }
    });

    this.canvas.addEventListener("click", (ev) => {
      const hit = this.hitTest(ev);
      if (hit && hit.node.drillable && hit.node.entry_id !== null) {
        this.callbacks.onDrillDown(hit.node.entry_id);
      }
    });
  }

  private hitTest(ev: MouseEvent): DrawnRect | null {
    const rect = this.canvas.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) {
      return null;
    }
    const scaleX = CANVAS_WIDTH / rect.width;
    const scaleY = CANVAS_HEIGHT / rect.height;
    const x = (ev.clientX - rect.left) * scaleX;
    const y = (ev.clientY - rect.top) * scaleY;
    for (const r of this.rects) {
      if (x >= r.x && x <= r.x + r.w && y >= r.y && y <= r.y + r.h) {
        return r;
      }
    }
    return null;
  }

  private renderBreadcrumbs(): void {
    clearChildren(this.breadcrumbsEl);
    if (!this.data) {
      this.breadcrumbsEl.appendChild(el("span", "crumb-empty", "尚未扫描"));
      return;
    }
    this.data.breadcrumbs.forEach((crumb, idx) => {
      if (idx > 0) {
        this.breadcrumbsEl.appendChild(el("span", "crumb-sep", "/"));
      }
      const btn = el("button", "crumb-btn", crumb.label_display);
      btn.type = "button";
      btn.addEventListener("click", () => {
        this.callbacks.onDrillDown(crumb.entry_id);
      });
      this.breadcrumbsEl.appendChild(btn);
    });
  }

  private layoutRects(): void {
    this.rects = [];
    if (!this.data || this.data.nodes.length === 0) {
      return;
    }

    const total = this.data.nodes.reduce(
      (acc, n) => acc + Number(parseBigIntSafe(n.logical_bytes)),
      0,
    );
    if (total <= 0) {
      return;
    }

    // Simple slice-and-dice / strip treemap that alternates orientation by aspect ratio.
    let x = 2;
    let y = 2;
    let w = CANVAS_WIDTH - 4;
    let h = CANVAS_HEIGHT - 4;
    let remaining = total;

    for (const node of this.data.nodes) {
      const value = Number(parseBigIntSafe(node.logical_bytes));
      if (value <= 0 || remaining <= 0 || w <= 2 || h <= 2) {
        continue;
      }
      const ratio = Math.min(1, value / remaining);
      if (w >= h) {
        const rw = Math.max(4, w * ratio);
        this.rects.push({ x, y, w: rw - 2, h: h - 2, node });
        x += rw;
        w -= rw;
      } else {
        const rh = Math.max(4, h * ratio);
        this.rects.push({ x, y, w: w - 2, h: rh - 2, node });
        y += rh;
        h -= rh;
      }
      remaining -= value;
    }
  }

  private fillColorForNode(node: TreemapNodeDto, active: boolean): string {
    if (node.is_other_rollup) {
      return active ? "#64748b" : "#475569";
    }
    const zone = node.policy?.zone;
    switch (zone) {
      case "A_Protected":
        return active ? "#7f1d1d" : "#991b1b";
      case "B_Sensitive":
        return active ? "#b45309" : "#92400e";
      case "C_GrantedPersistent":
      case "C_GrantedSession":
        return active ? "#2563eb" : "#1d4ed8";
      default:
        return active ? "#334155" : "#1e293b";
    }
  }

  private drawCanvas(): void {
    const ctx = this.canvas.getContext("2d");
    if (!ctx) {
      return;
    }
    ctx.clearRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

    if (this.rects.length === 0) {
      ctx.fillStyle = "#94a3b8";
      ctx.font = "14px sans-serif";
      ctx.fillText("暂无可绘制的占用节点", 20, 40);
      return;
    }

    for (const r of this.rects) {
      const active = r.node.id === this.activeNodeId;
      ctx.fillStyle = this.fillColorForNode(r.node, active);
      ctx.fillRect(r.x, r.y, r.w, r.h);

      ctx.strokeStyle = active ? "#f8fafc" : "#0f172a";
      ctx.lineWidth = active ? 2 : 1;
      ctx.strokeRect(r.x, r.y, r.w, r.h);

      if (r.w > 54 && r.h > 28) {
        ctx.fillStyle = "#f8fafc";
        ctx.font = "12px sans-serif";
        const label =
          r.node.label_display.length > 16
            ? r.node.label_display.slice(0, 15) + "…"
            : r.node.label_display;
        ctx.fillText(label, r.x + 6, r.y + 16);
        if (r.h > 42) {
          ctx.fillStyle = "#cbd5e1";
          ctx.font = "11px sans-serif";
          ctx.fillText(formatBytes(r.node.logical_bytes), r.x + 6, r.y + 32);
        }
      }
    }
  }

  private renderList(): void {
    clearChildren(this.listEl);
    if (!this.data || this.data.nodes.length === 0) {
      this.listEl.appendChild(el("div", "treemap-list__empty", "当前层级没有子项"));
      return;
    }

    for (const node of this.data.nodes) {
      const btn = el("button", "treemap-item");
      btn.type = "button";
      btn.dataset.nodeId = node.id;
      btn.setAttribute("role", "treeitem");
      if (node.id === this.activeNodeId) {
        btn.classList.add("treemap-item--active");
      }

      const left = el("span", "treemap-item__label");
      left.appendChild(
        el(
          "span",
          "treemap-item__name",
          node.is_other_rollup
            ? `⋯ ${node.label_display}`
            : node.drillable
              ? `📁 ${node.label_display}`
              : `📄 ${node.label_display}`,
        ),
      );
      if (node.policy) {
        left.appendChild(createZoneBadge(node.policy));
      }
      btn.appendChild(left);

      btn.appendChild(
        el("span", "treemap-item__size", formatBytes(node.logical_bytes)),
      );

      const activate = () => {
        this.activeNodeId = node.id;
        this.drawCanvas();
        this.syncListFocusClass();
        this.callbacks.onHighlightNode(node);
      };

      btn.addEventListener("mouseenter", activate);
      btn.addEventListener("focus", activate);
      btn.addEventListener("click", () => {
        if (node.drillable && node.entry_id !== null) {
          this.callbacks.onDrillDown(node.entry_id);
        }
      });

      this.listEl.appendChild(btn);
    }
  }

  private syncListFocusClass(): void {
    const items = this.listEl.querySelectorAll<HTMLButtonElement>(".treemap-item");
    for (const item of items) {
      if (item.dataset.nodeId === this.activeNodeId) {
        item.classList.add("treemap-item--active");
      } else {
        item.classList.remove("treemap-item--active");
      }
    }
  }
}
