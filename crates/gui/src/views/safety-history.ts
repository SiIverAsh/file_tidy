import type { AppStateModel, SafetySubTab } from "../state/store.ts";
import {
  clearChildren,
  el,
  formatBytes,
  formatUnixTime,
} from "../components/safe-text.ts";
import { labeledValue, operationLabel, recoveryLabel, statusLabel } from "../components/display-labels.ts";

export interface SafetyHistoryCallbacks {
  onSwitchTab(tab: SafetySubTab): Promise<void>;
  onToggleDueOnly(dueOnly: boolean): Promise<void>;
  onToggleQuarantineItem(itemId: string): void;
  onRestoreSelected(pickNewTarget: boolean): Promise<void>;
  onPurgeSelected(): Promise<void>;
  onSelectBatch(batchId: string): Promise<void>;
  onUndoBatch(batchId: string, operationIds: string[]): Promise<void>;
  onRefreshRecovery(): Promise<void>;
}

export class SafetyHistoryView {
  readonly root: HTMLElement;
  private readonly callbacks: SafetyHistoryCallbacks;
  private readonly focusTargets = new Map<string, HTMLElement>();

  constructor(callbacks: SafetyHistoryCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--safety");
  }

  render(model: AppStateModel): void {
    const active = document.activeElement as HTMLElement | null;
    const focusKey = active && typeof this.root.contains === "function" && this.root.contains(active)
      ? active.dataset?.focusKey
      : undefined;
    const scrollHost = this.root.parentElement;
    const scrollTop = scrollHost?.scrollTop;
    this.focusTargets.clear();
    this.renderPage(model);
    const target = focusKey ? this.focusTargets.get(focusKey) : undefined;
    if (target && !(target as HTMLInputElement).disabled) {
      target.focus({ preventScroll: true });
      if (scrollHost && scrollTop !== undefined) scrollHost.scrollTop = scrollTop;
    }
  }

  private focusable<T extends HTMLElement>(node: T, key: string): T {
    node.dataset.focusKey = key;
    this.focusTargets.set(key, node);
    return node;
  }

  private renderPage(model: AppStateModel): void {
    clearChildren(this.root);

    const header = el("header", "page-header");
    header.appendChild(el("h1", "page-header__title", "隔离与历史"));
    header.appendChild(el("p", "page-header__description", "找回隔离文件，查看操作记录，处理需要核对的项目。"));
    this.root.appendChild(header);

    const recoveryCount = model.safety.recoveryReport?.items.length ?? 0;
    if (recoveryCount > 0) {
      const banner = el("div", "alert alert--warn");
      banner.appendChild(
        el(
          "span",
          "",
          `发现 ${recoveryCount} 项待核对记录`,
        ),
      );
      const jumpBtn = this.focusable(el("button", "btn btn--secondary btn--compact", "查看详情"), "view-recovery");
      jumpBtn.type = "button";
      jumpBtn.addEventListener("click", () => {
        void this.callbacks.onSwitchTab("recovery");
      });
      banner.appendChild(jumpBtn);
      this.root.appendChild(banner);
    }

    const tabBar = el("div", "safety-tabs");
    const tabs = el("div", "subtabs");
    tabs.setAttribute("aria-label", "隔离与历史分类");
    const defs: Array<{ id: SafetySubTab; label: string }> = [
      { id: "quarantine", label: `隔离区 (${model.safety.quarantineItems.length})` },
      { id: "history", label: `操作记录 (${model.safety.historyBatches.length})` },
      { id: "recovery", label: `恢复诊断 (${recoveryCount})` },
    ];
    for (const d of defs) {
      const btn = this.focusable(el("button", "subtab", d.label), `tab:${d.id}`);
      btn.type = "button";
      btn.setAttribute("aria-pressed", String(model.safety.tab === d.id));
      if (model.safety.tab === d.id) {
        btn.classList.add("subtab--active");
      }
      btn.addEventListener("click", () => {
        void this.callbacks.onSwitchTab(d.id);
      });
      tabs.appendChild(btn);
    }
    tabBar.appendChild(tabs);
    this.root.appendChild(tabBar);

    if (!model.workspace?.storage_initialized) {
      const empty = el("div", "status-empty status-empty--large");
      empty.appendChild(el("div", "status-empty__title", "连接工作区，保留每一步记录"));
      empty.appendChild(el("p", "status-empty__description", "在“授权与规则”中打开或新建工作区，即可使用隔离区和操作历史。"));
      this.root.appendChild(empty);
      return;
    }

    if (model.safety.tab === "quarantine") {
      this.renderQuarantine(model);
    } else if (model.safety.tab === "history") {
      this.renderHistory(model);
    } else {
      this.renderRecovery(model);
    }
  }

  private renderQuarantine(model: AppStateModel): void {
    const bar = el("div", "panel-toolbar safety-toolbar");
    const dueLabel = el("label", "switch");
    const cb = this.focusable(el("input"), "due-only");
    cb.type = "checkbox";
    cb.checked = model.safety.dueOnly;
    cb.addEventListener("change", () => {
      void this.callbacks.onToggleDueOnly(cb.checked);
    });
    dueLabel.appendChild(cb);
    dueLabel.appendChild(el("span", "", "仅看已到期"));
    bar.appendChild(dueLabel);

    const selectedCount = model.safety.selectedQuarantineIds.size;
    const actions = el("div", "panel-toolbar safety-toolbar__actions");
    actions.appendChild(el("span", "selection-label", `已选 ${selectedCount} 项`));
    const restoreOrig = this.focusable(el(
      "button",
      "btn btn--primary",
      `恢复原位 (${selectedCount})`,
    ), "restore-original");
    restoreOrig.type = "button";
    restoreOrig.disabled = selectedCount === 0;
    restoreOrig.addEventListener("click", () => {
      void this.callbacks.onRestoreSelected(false);
    });
    actions.appendChild(restoreOrig);

    const restorePick = this.focusable(el("button", "btn btn--secondary", "恢复到其他目录…"), "restore-other");
    restorePick.type = "button";
    restorePick.disabled = selectedCount === 0;
    restorePick.addEventListener("click", () => {
      void this.callbacks.onRestoreSelected(true);
    });
    actions.appendChild(restorePick);

    const purgeBtn = this.focusable(el("button", "btn btn--danger-outline", "永久删除…"), "purge");
    purgeBtn.type = "button";
    purgeBtn.disabled = selectedCount === 0;
    purgeBtn.addEventListener("click", () => {
      void this.callbacks.onPurgeSelected();
    });
    actions.appendChild(purgeBtn);
    if (selectedCount > 0) {
      bar.appendChild(actions);
    } else {
      bar.appendChild(el("span", "section-heading__description", "选择文件后可恢复或删除"));
    }

    this.root.appendChild(bar);

    const list = el("div", "card-list");
    if (model.safety.quarantineItems.length === 0) {
      const empty = el("div", "status-empty status-empty--large");
      empty.appendChild(el("div", "status-empty__title", model.safety.dueOnly ? "没有已到期的文件" : "隔离区很干净"));
      empty.appendChild(el("p", "status-empty__description", model.safety.dueOnly ? "取消“仅看已到期”可查看全部隔离文件。" : "隔离的文件会出现在这里，保留期内可以恢复。"));
      list.appendChild(empty);
    }
    for (const item of model.safety.quarantineItems) {
      const card = el("div", "item-card");
      const top = el("div", "item-card__top");
      const check = el("label", "item-card__check");
      const box = this.focusable(el("input"), `quarantine:${item.id}`);
      box.type = "checkbox";
      box.checked = model.safety.selectedQuarantineIds.has(item.id);
      box.disabled = item.state !== "stored";
      box.addEventListener("change", () => this.callbacks.onToggleQuarantineItem(item.id));
      check.appendChild(box);
      check.appendChild(el("span", "item-card__title", item.original_path_display));
      top.appendChild(check);
      if (item.due) {
        top.appendChild(el("span", "tag tag--warn", "已到期提醒"));
      }
      top.appendChild(labeledValue(statusLabel(item.state), item.state, "tag"));
      card.appendChild(top);
      card.appendChild(
        el("div", "item-card__sub", `隔离位置：${item.storage_path_display}`),
      );
      const timing = el("div", "item-card__sub",
        `隔离时间：${formatUnixTime(item.retained_at_unix)} · 保留期至：${formatUnixTime(item.expires_at_unix)}`);
      timing.appendChild(el("span", "technical-detail", ` · 批次 ${item.batch_id.slice(0, 12)}…`));
      card.appendChild(timing);
      list.appendChild(card);
    }
    this.root.appendChild(list);
  }

  private renderHistory(model: AppStateModel): void {
    if (model.safety.historyBatches.length === 0) {
      const empty = el("div", "status-empty status-empty--large");
      empty.appendChild(el("div", "status-empty__title", "还没有操作记录"));
      empty.appendChild(el("p", "status-empty__description", "完成文件整理后，可在这里查看明细并撤销支持恢复的操作。"));
      this.root.appendChild(empty);
      return;
    }
    const split = el("div", "history-split");
    const left = el("div", "card-list");
    for (const batch of model.safety.historyBatches) {
      const card = this.focusable(el("button", "batch-card"), `batch:${batch.id}`);
      card.type = "button";
      if (model.safety.selectedBatchDetail?.batch.id === batch.id) {
        card.classList.add("batch-card--active");
      }
      card.appendChild(
        el(
          "div",
          "batch-card__top",
          `${formatUnixTime(batch.created_at_unix)} · ${batch.item_count} 项 · ${formatBytes(batch.total_bytes)}`,
        ),
      );
      card.appendChild(labeledValue(statusLabel(batch.state), batch.state, `tag tag--batch-${batch.state}`));
      card.addEventListener("click", () => {
        void this.callbacks.onSelectBatch(batch.id);
      });
      left.appendChild(card);
    }
    split.appendChild(left);

    const detailPane = el("div", "detail-pane");
    const detail = model.safety.selectedBatchDetail;
    if (!detail) {
      const empty = el("div", "status-empty");
      empty.appendChild(el("div", "status-empty__title", "选择一条操作记录"));
      empty.appendChild(el("p", "status-empty__description", "查看文件明细、执行结果和可用的撤销操作。"));
      detailPane.appendChild(empty);
    } else {
      const top = el("div", "detail-pane__top");
      const title = el("h3");
      title.appendChild(el("span", "simple-detail", "操作详情"));
      title.appendChild(el("span", "technical-detail", `批次 ${detail.batch.id.slice(0, 14)}…`));
      top.appendChild(title);
      top.appendChild(labeledValue(statusLabel(detail.batch.state), detail.batch.state, "tag"));
      const undoAll = this.focusable(el("button", "btn btn--primary", "撤销此批次"), `undo-batch:${detail.batch.id}`);
      undoAll.type = "button";
      const completed = detail.operations.filter((op) => op.state === "done");
      const hasIrreversible = completed.some((op) => op.kind === "permanent_delete");
      undoAll.disabled = completed.length === 0 || hasIrreversible;
      if (hasIrreversible) {
        undoAll.title = "包含已完成的永久删除，请单独选择可撤销操作";
      } else if (completed.length === 0) {
        undoAll.title = "此批次没有已完成的可撤销操作";
      }
      undoAll.addEventListener("click", () => {
        void this.callbacks.onUndoBatch(detail.batch.id, []);
      });
      top.appendChild(undoAll);
      detailPane.appendChild(top);

      for (const op of detail.operations) {
        const opRow = el("div", "item-card");
        const opHead = el("div", "item-card__top");
        opHead.appendChild(labeledValue(operationLabel(op.kind), op.kind, "tag"));
        opHead.appendChild(labeledValue(statusLabel(op.state), op.state, "tag"));
        if (op.kind !== "permanent_delete") {
          const singleUndo = this.focusable(el("button", "btn btn--ghost btn--compact", "撤销"), `undo-op:${op.id}`);
          singleUndo.type = "button";
          singleUndo.disabled = op.state !== "done";
          if (singleUndo.disabled) singleUndo.title = "仅已完成的操作支持撤销";
          singleUndo.addEventListener("click", () => {
            void this.callbacks.onUndoBatch(detail.batch.id, [op.id]);
          });
          opHead.appendChild(singleUndo);
        } else {
          opHead.appendChild(el("span", "tag tag--danger", "不可撤销"));
        }
        opRow.appendChild(opHead);
        opRow.appendChild(el("div", "item-card__sub", `源：${op.source_display}`));
        if (op.destination_display) {
          opRow.appendChild(
            el("div", "item-card__sub", `目标：${op.destination_display}`),
          );
        }
        if (op.reason) {
          opRow.appendChild(el("div", "item-card__sub", `说明：${op.reason}`));
        }
        detailPane.appendChild(opRow);
      }

      const audit = el("section", "technical-detail");
      audit.appendChild(el("h4", "detail-pane__sub", "逐步审计事件"));
      for (const ev of detail.events) {
        audit.appendChild(
          el(
            "div",
            "event-line",
            `[${formatUnixTime(ev.created_at_unix)}] ${ev.step} (${ev.phase})`,
          ),
        );
      }
      if (detail.events_truncated) {
        audit.appendChild(el("div", "event-line", "… 其余事件已截断"));
      }
      detailPane.appendChild(audit);
    }
    split.appendChild(detailPane);
    this.root.appendChild(split);
  }

  private renderRecovery(model: AppStateModel): void {
    const top = el("div", "panel-toolbar safety-toolbar");
    top.appendChild(el("p", "section-heading__description", "检查上次执行中断后需要核对的记录。"));
    const refresh = this.focusable(el("button", "btn btn--secondary", "刷新核验"), "refresh-recovery");
    refresh.type = "button";
    refresh.addEventListener("click", () => {
      void this.callbacks.onRefreshRecovery();
    });
    top.appendChild(refresh);
    this.root.appendChild(top);

    const items = model.safety.recoveryReport?.items ?? [];
    if (items.length === 0) {
      const empty = el("div", "status-empty status-empty--large");
      empty.appendChild(el("div", "status-empty__title", "一切就绪"));
      empty.appendChild(el("p", "status-empty__description", "当前没有需要核对或恢复的操作。"));
      this.root.appendChild(empty);
      return;
    }

    const list = el("div", "card-list");
    for (const item of items) {
      const card = el("div", "item-card");
      card.appendChild(labeledValue(recoveryLabel(item.disposition), item.disposition, "tag tag--warn"));
      card.appendChild(el("span", "tag technical-detail", `日志状态 ${item.journal_state}`));
      if (item.policy_changed) {
        card.appendChild(el("span", "tag tag--danger", "策略已变化"));
      }
      card.appendChild(el("div", "item-card__sub", `源：${item.source_display}`));
      if (item.destination_display) {
        card.appendChild(
          el("div", "item-card__sub", `目标：${item.destination_display}`),
        );
      }
      if (item.temporary_display) {
        card.appendChild(
          el("div", "item-card__sub technical-detail", `暂存/中间路径：${item.temporary_display}`),
        );
      }
      card.appendChild(el("div", "item-card__title", item.reason));
      list.appendChild(card);
    }
    this.root.appendChild(list);
  }
}
