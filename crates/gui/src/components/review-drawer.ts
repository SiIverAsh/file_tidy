import type { PlanPreviewDto, PlannedOperationDto } from "../api/types.ts";
import type { AppStateModel } from "../state/store.ts";
import {
  clearChildren,
  el,
  formatBytesWithExact,
  formatCountdown,
} from "./safe-text.ts";
import { createZoneBadge, describeSensitivityReason } from "./zone-badge.ts";

export interface ReviewDrawerCallbacks {
  onClose(): void;
  onFilterOperations(planId: string, selectedOpIds: string[]): Promise<void>;
  onToggleAckKey(key: string): void;
  onItemCountInput(value: string): void;
  onExecute(preview: PlanPreviewDto): Promise<void>;
  onCancelExecution(): Promise<void>;
  onJumpToRecovery(): void;
}

export class ReviewDrawer {
  readonly root: HTMLElement;
  private readonly callbacks: ReviewDrawerCallbacks;
  private expandedManifests = new Set<string>();
  private timerId: number | null = null;
  private countdownEl: HTMLElement | null = null;
  private latestPreview: PlanPreviewDto | null = null;
  private countInputEl: HTMLInputElement | null = null;
  private execBtnEl: HTMLButtonElement | null = null;
  private renderedPreviewKey: string | null = null;

  constructor(callbacks: ReviewDrawerCallbacks) {
    this.callbacks = callbacks;
    this.root = el("aside", "drawer");
    this.root.setAttribute("role", "dialog");
    this.root.setAttribute("aria-label", "操作计划审阅与执行");
  }

  render(model: AppStateModel): void {
    const drawer = model.planDrawer;
    if (!drawer.open) {
      this.root.classList.remove("drawer--open");
      this.stopTimer();
      this.countInputEl = null;
      this.execBtnEl = null;
      this.renderedPreviewKey = null;
      clearChildren(this.root);
      return;
    }

    const previewKey =
      !drawer.loading && !drawer.executionReport && !drawer.executing && drawer.preview
        ? `${drawer.preview.plan_id}:${drawer.preview.plan_digest}:${drawer.error ?? ""}`
        : null;
    if (
      previewKey !== null &&
      previewKey === this.renderedPreviewKey &&
      this.countInputEl !== null &&
      document.activeElement === this.countInputEl &&
      drawer.preview
    ) {
      if (this.execBtnEl) {
        this.execBtnEl.disabled = !this.canSubmit(drawer.preview, drawer);
      }
      return;
    }
    this.renderedPreviewKey = previewKey;
    this.countInputEl = null;
    this.execBtnEl = null;

    this.root.classList.add("drawer--open");
    clearChildren(this.root);

    const header = el("div", "drawer__header");
    header.appendChild(el("h2", "drawer__title", "审阅操作计划"));
    const closeBtn = el("button", "btn btn--ghost", "关闭");
    closeBtn.type = "button";
    closeBtn.disabled = drawer.executing;
    closeBtn.addEventListener("click", () => this.callbacks.onClose());
    header.appendChild(closeBtn);
    this.root.appendChild(header);

    const body = el("div", "drawer__body");
    this.root.appendChild(body);

    if (drawer.error) {
      body.appendChild(el("div", "alert alert--error", drawer.error));
    }

    if (drawer.loading) {
      body.appendChild(el("div", "loading-state", "正在生成操作预览…"));
      return;
    }

    if (drawer.executionReport) {
      this.renderExecutionReport(body, drawer);
      return;
    }

    const preview = drawer.preview;
    this.latestPreview = preview;
    if (!preview) {
      body.appendChild(el("div", "empty-state", "暂无待审阅计划"));
      this.stopTimer();
      return;
    }

    // Plan meta + 15-min countdown
    const metaBar = el("div", "plan-meta");
    const countdown = el("span", "plan-meta__timer");
    metaBar.appendChild(countdown);
    metaBar.appendChild(
      el(
        "span",
        "plan-meta__digest",
        `摘要 ${preview.plan_digest.slice(0, 12)}… · 授权代次 #${preview.authorization_epoch}`,
      ),
    );
    body.appendChild(metaBar);
    this.startTimer(countdown);

    // Summary stats
    const stats = el("div", "plan-stats");
    stats.appendChild(
      el(
        "div",
        "plan-stats__item",
        `待处理文件/链接：${preview.files_and_links} · 目录：${preview.directories}（空目录 ${preview.empty_directories}）`,
      ),
    );
    stats.appendChild(
      el("div", "plan-stats__item", `总大小：${formatBytesWithExact(preview.total_bytes)}`),
    );
    body.appendChild(stats);

    // Explicit B-zone write rejection callout (never confirmable!)
    if (preview.blocked_b_write_reasons.length > 0) {
      const bAlert = el("div", "alert alert--error");
      bAlert.appendChild(
        el(
          "strong",
          "",
          "以下 B 区条目不支持写入或删除（仅允许复制到 C 区）：",
        ),
      );
      for (const reason of preview.blocked_b_write_reasons) {
        bAlert.appendChild(el("p", "alert__line", reason));
      }
      body.appendChild(bAlert);
    }

    if (preview.executable_error) {
      body.appendChild(
        el("div", "alert alert--error", preview.executable_error),
      );
    }

    // Operations Before / After cards
    const opsWrap = el("div", "plan-ops");
    for (const op of preview.operations) {
      opsWrap.appendChild(this.renderOperationCard(op, preview, drawer.selectedOpIds));
    }
    body.appendChild(opsWrap);

    // B-zone Copy-Out Content Read Acknowledgements (strictly copy-out only, no "Select All")
    if (preview.sensitive_acknowledgements.length > 0) {
      const bSection = el("div", "confirm-section confirm-section--warn");
      bSection.appendChild(
        el(
          "h3",
          "confirm-section__title",
          "敏感文件复制确认",
        ),
      );
      for (const ack of preview.sensitive_acknowledgements) {
        const label = el("label", "ack-row");
        const cb = el("input");
        cb.type = "checkbox";
        cb.checked = drawer.acknowledgedContentKeys.has(ack.key);
        cb.addEventListener("change", () => this.callbacks.onToggleAckKey(ack.key));
        label.appendChild(cb);
        label.appendChild(el("span", "ack-row__text", ack.description));
        bSection.appendChild(label);
      }
      body.appendChild(bSection);
    }

    // Large plan count confirmation
    if (preview.requires_count_confirmation) {
      const countBox = el("div", "confirm-section");
      countBox.appendChild(
        el(
          "label",
          "confirm-section__label",
          `输入条目总数 (${preview.confirmation_count}) 以确认：`,
        ),
      );
      const input = el("input", "input");
      input.type = "text";
      input.inputMode = "numeric";
      input.placeholder = preview.confirmation_count;
      input.value = drawer.itemCountInput;
      input.addEventListener("input", () => this.callbacks.onItemCountInput(input.value));
      this.countInputEl = input;
      countBox.appendChild(input);
      body.appendChild(countBox);
    }

    // Footer actions
    const footer = el("div", "drawer__footer");
    const canExecute = this.canSubmit(preview, drawer);
    if (drawer.executing) {
      const cancelBtn = el("button", "btn btn--danger", "停止执行");
      cancelBtn.type = "button";
      cancelBtn.addEventListener("click", () => {
        void this.callbacks.onCancelExecution();
      });
      footer.appendChild(cancelBtn);
      if (drawer.execProgress) {
        footer.appendChild(
          el(
            "span",
            "exec-progress-text",
            `正在执行 ${drawer.execProgress.completed_operations}/${drawer.execProgress.total_operations}`,
          ),
        );
      }
    } else {
      const execBtn = el("button", "btn btn--primary", "确认并执行计划");
      execBtn.type = "button";
      execBtn.disabled = !canExecute;
      execBtn.addEventListener("click", () => {
        void this.callbacks.onExecute(preview);
      });
      this.execBtnEl = execBtn;
      footer.appendChild(execBtn);
    }
    this.root.appendChild(footer);
  }

  private canSubmit(
    preview: PlanPreviewDto,
    drawer: AppStateModel["planDrawer"],
  ): boolean {
    if (preview.blocked_b_write_reasons.length > 0 || preview.executable_error !== null) {
      return false;
    }
    if (preview.operations.length === 0) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (Number(preview.expires_at_unix) <= nowSec) {
      return false;
    }
    if (
      preview.requires_count_confirmation &&
      drawer.itemCountInput.trim() !== preview.confirmation_count
    ) {
      return false;
    }
    for (const ack of preview.sensitive_acknowledgements) {
      if (!drawer.acknowledgedContentKeys.has(ack.key)) {
        return false;
      }
    }
    return true;
  }

  private renderOperationCard(
    op: PlannedOperationDto,
    preview: PlanPreviewDto,
    selectedOpIds: Set<string>,
  ): HTMLElement {
    const card = el("div", "op-card");

    const top = el("div", "op-card__top");
    const checkLabel = el("label", "op-card__check");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = selectedOpIds.has(op.id);
    cb.disabled = preview.operations.length <= 1;
    cb.addEventListener("change", () => {
      const next = new Set(selectedOpIds);
      if (cb.checked) {
        next.add(op.id);
      } else {
        next.delete(op.id);
      }
      void this.callbacks.onFilterOperations(preview.plan_id, [...next]);
    });
    checkLabel.appendChild(cb);
    checkLabel.appendChild(el("span", "tag tag--kind", op.kind.toUpperCase()));
    top.appendChild(checkLabel);
    top.appendChild(createZoneBadge(op.source_policy));
    card.appendChild(top);

    const diff = el("div", "op-diff");
    diff.appendChild(el("div", "op-diff__row", `原路径：${op.source_display}`));
    if (op.destination) {
      diff.appendChild(
        el("div", "op-diff__row op-diff__row--after", `目标路径：${op.destination.path_display}`),
      );
      if (op.destination.renamed_for_conflict) {
        diff.appendChild(
          el("span", "tag tag--warn", "目标同名冲突 · 已预览无覆盖改名"),
        );
      }
      if (op.destination.spelling_temporary_display) {
        diff.appendChild(
          el(
            "div",
            "op-diff__sub",
            `大小写中间临时名：${op.destination.spelling_temporary_display}`,
          ),
        );
      }
      if (op.destination.copy_temporary_display) {
        diff.appendChild(
          el(
            "div",
            "op-diff__sub",
            `校验暂存位置：${op.destination.copy_temporary_display}`,
          ),
        );
      }
      if (op.destination.create_directories_display.length > 0) {
        diff.appendChild(
          el(
            "div",
            "op-diff__sub",
            `将创建目录：${op.destination.create_directories_display.join(" , ")}`,
          ),
        );
      }
      if (op.destination.copy_metadata === "private_data_stream_and_mtime") {
        diff.appendChild(
          el(
            "div",
            "op-diff__sub",
            "复制策略：仅保留主数据流与修改时间（私有权限，不复制 ACL/xattr）",
          ),
        );
      }
    }
    card.appendChild(diff);

    // Directory / full manifest expandable section
    if (op.manifest.length > 0) {
      const expanded = this.expandedManifests.has(op.id);
      const toggleBtn = el(
        "button",
        "btn btn--link",
        expanded
          ? `收起完整清单（共 ${op.manifest.length} 项）`
          : `展开完整清单（共 ${op.manifest.length} 项）`,
      );
      toggleBtn.type = "button";
      toggleBtn.addEventListener("click", () => {
        if (expanded) {
          this.expandedManifests.delete(op.id);
        } else {
          this.expandedManifests.add(op.id);
        }
        // Re-render card manifest in place by toggling a sibling container
        const existing = card.querySelector(".manifest-list");
        if (existing) {
          existing.remove();
          toggleBtn.textContent = `展开完整清单（共 ${op.manifest.length} 项）`;
        } else {
          card.appendChild(this.renderManifestList(op));
          toggleBtn.textContent = `收起完整清单（共 ${op.manifest.length} 项）`;
        }
      });
      card.appendChild(toggleBtn);
      if (expanded) {
        card.appendChild(this.renderManifestList(op));
      }
    }

    return card;
  }

  private renderManifestList(op: PlannedOperationDto): HTMLElement {
    const list = el("div", "manifest-list");
    for (const item of op.manifest) {
      const row = el("div", "manifest-list__item");
      const line = el(
        "div",
        "manifest-list__path",
        `[${item.kind}] ${item.path_display} (${formatBytesWithExact(item.size_bytes)})`,
      );
      row.appendChild(line);
      if (item.hidden) {
        row.appendChild(el("span", "tag tag--muted", "隐藏"));
      }
      if (item.sensitive) {
        const reason = describeSensitivityReason(item.sensitivity_reason) ?? "敏感受保护项";
        row.appendChild(el("span", "tag tag--warn", `B 敏感：${reason}`));
      }
      if (item.link_target_display) {
        row.appendChild(
          el("div", "manifest-list__sub", `链接目标：${item.link_target_display}`),
        );
      }
      list.appendChild(row);
    }
    return list;
  }

  private renderExecutionReport(
    body: HTMLElement,
    drawer: AppStateModel["planDrawer"],
  ): void {
    const report = drawer.executionReport;
    if (!report) {
      return;
    }
    this.stopTimer();

    const banner = el(
      "div",
      report.completed ? "alert alert--ok" : "alert alert--warn",
      report.completed
        ? `执行完成（批次 ${report.batch_id.slice(0, 12)}…）`
        : `执行部分完成或中断（批次 ${report.batch_id.slice(0, 12)}…）`,
    );
    body.appendChild(banner);

    if (report.journal_error) {
      body.appendChild(el("div", "alert alert--error", `日志告警：${report.journal_error}`));
    }

    let needsRecovery = false;
    const list = el("div", "exec-results");
    for (const op of report.operations) {
      if (op.status === "needs_recovery") {
        needsRecovery = true;
      }
      const item = el("div", "exec-result");
      item.appendChild(el("span", `tag tag--status-${op.status}`, op.status));
      item.appendChild(el("div", "exec-result__path", `源：${op.source_display}`));
      if (op.destination_display) {
        item.appendChild(el("div", "exec-result__path", `目标：${op.destination_display}`));
      }
      if (op.reason) {
        item.appendChild(el("div", "exec-result__reason", op.reason));
      }
      list.appendChild(item);
    }
    body.appendChild(list);

    if (needsRecovery) {
      const btn = el("button", "btn btn--primary", "前往“隔离与历史”查看恢复诊断");
      btn.type = "button";
      btn.addEventListener("click", () => this.callbacks.onJumpToRecovery());
      body.appendChild(btn);
    }
  }

  private startTimer(countdownEl: HTMLElement): void {
    this.stopTimer();
    this.countdownEl = countdownEl;
    const tick = () => {
      if (!this.countdownEl || !this.latestPreview) {
        return;
      }
      const res = formatCountdown(
        this.latestPreview.expires_at_unix,
        Math.floor(Date.now() / 1000),
      );
      this.countdownEl.textContent = res.expired
        ? `⏰ ${res.label}`
        : `⏳ 预览有效剩余 ${res.label}`;
      if (res.expired) {
        this.countdownEl.classList.add("plan-meta__timer--expired");
      }
    };
    tick();
    this.timerId = window.setInterval(tick, 1000);
  }

  private stopTimer(): void {
    if (this.timerId !== null) {
      window.clearInterval(this.timerId);
      this.timerId = null;
    }
    this.countdownEl = null;
  }
}
