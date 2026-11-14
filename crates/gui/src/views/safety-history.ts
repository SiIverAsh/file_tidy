import type { AppStateModel, SafetySubTab } from "../state/store.ts";
import {
  clearChildren,
  el,
  formatBytes,
  formatUnixTime,
} from "../components/safe-text.ts";

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

  constructor(callbacks: SafetyHistoryCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--safety");
  }

  render(model: AppStateModel): void {
    clearChildren(this.root);

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
      const jumpBtn = el("button", "btn btn--secondary btn--compact", "查看详情");
      jumpBtn.type = "button";
      jumpBtn.addEventListener("click", () => {
        void this.callbacks.onSwitchTab("recovery");
      });
      banner.appendChild(jumpBtn);
      this.root.appendChild(banner);
    }

    const tabs = el("div", "subtabs");
    const defs: Array<{ id: SafetySubTab; label: string }> = [
      { id: "quarantine", label: `隔离区 (${model.safety.quarantineItems.length})` },
      { id: "history", label: `操作记录 (${model.safety.historyBatches.length})` },
      { id: "recovery", label: `恢复诊断 (${recoveryCount})` },
    ];
    for (const d of defs) {
      const btn = el("button", "subtab", d.label);
      btn.type = "button";
      if (model.safety.tab === d.id) {
        btn.classList.add("subtab--active");
      }
      btn.addEventListener("click", () => {
        void this.callbacks.onSwitchTab(d.id);
      });
      tabs.appendChild(btn);
    }
    this.root.appendChild(tabs);

    if (!model.workspace?.storage_initialized) {
      this.root.appendChild(
        el(
          "div",
          "empty-hero",
          "请先在“授权与规则”中初始化工作区，以启用历史记录和隔离区。",
        ),
      );
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
    const bar = el("div", "panel-toolbar");
    const dueLabel = el("label", "switch");
    const cb = el("input");
    cb.type = "checkbox";
    cb.checked = model.safety.dueOnly;
    cb.addEventListener("change", () => {
      void this.callbacks.onToggleDueOnly(cb.checked);
    });
    dueLabel.appendChild(cb);
    dueLabel.appendChild(el("span", "", "仅看已到期"));
    bar.appendChild(dueLabel);

    const selectedCount = model.safety.selectedQuarantineIds.size;
    const restoreOrig = el(
      "button",
      "btn btn--primary",
      `恢复原位 (${selectedCount})`,
    );
    restoreOrig.type = "button";
    restoreOrig.disabled = selectedCount === 0;
    restoreOrig.addEventListener("click", () => {
      void this.callbacks.onRestoreSelected(false);
    });
    bar.appendChild(restoreOrig);

    const restorePick = el("button", "btn btn--secondary", "恢复到其他目录…");
    restorePick.type = "button";
    restorePick.disabled = selectedCount === 0;
    restorePick.addEventListener("click", () => {
      void this.callbacks.onRestoreSelected(true);
    });
    bar.appendChild(restorePick);

    const purgeBtn = el("button", "btn btn--danger-outline", "永久删除…");
    purgeBtn.type = "button";
    purgeBtn.disabled = selectedCount === 0;
    purgeBtn.addEventListener("click", () => {
      void this.callbacks.onPurgeSelected();
    });
    bar.appendChild(purgeBtn);

    this.root.appendChild(bar);

    const list = el("div", "card-list");
    if (model.safety.quarantineItems.length === 0) {
      list.appendChild(el("div", "empty-state", "当前隔离区为空"));
    }
    for (const item of model.safety.quarantineItems) {
      const card = el("div", "item-card");
      const top = el("div", "item-card__top");
      const check = el("label", "item-card__check");
      const box = el("input");
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
      top.appendChild(el("span", "tag", item.state));
      card.appendChild(top);
      card.appendChild(
        el("div", "item-card__sub", `隔离位置：${item.storage_path_display}`),
      );
      card.appendChild(
        el(
          "div",
          "item-card__sub",
          `隔离时间：${formatUnixTime(item.retained_at_unix)} · 保留期至：${formatUnixTime(item.expires_at_unix)} · 批次 ${item.batch_id.slice(0, 12)}…`,
        ),
      );
      list.appendChild(card);
    }
    this.root.appendChild(list);
  }

  private renderHistory(model: AppStateModel): void {
    const split = el("div", "history-split");
    const left = el("div", "card-list");
    if (model.safety.historyBatches.length === 0) {
      left.appendChild(el("div", "empty-state", "暂无执行记录"));
    }
    for (const batch of model.safety.historyBatches) {
      const card = el("button", "batch-card");
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
      card.appendChild(el("span", `tag tag--batch-${batch.state}`, batch.state));
      card.addEventListener("click", () => {
        void this.callbacks.onSelectBatch(batch.id);
      });
      left.appendChild(card);
    }
    split.appendChild(left);

    const detailPane = el("div", "detail-pane");
    const detail = model.safety.selectedBatchDetail;
    if (!detail) {
      detailPane.appendChild(el("div", "empty-state", "点击左侧批次查看明细与逆序撤销"));
    } else {
      const top = el("div", "detail-pane__top");
      top.appendChild(
        el("h3", "", `批次 ${detail.batch.id.slice(0, 14)}…（${detail.batch.state}）`),
      );
      const undoAll = el("button", "btn btn--primary", "撤销此批次");
      undoAll.type = "button";
      undoAll.addEventListener("click", () => {
        void this.callbacks.onUndoBatch(detail.batch.id, []);
      });
      top.appendChild(undoAll);
      detailPane.appendChild(top);

      for (const op of detail.operations) {
        const opRow = el("div", "item-card");
        const opHead = el("div", "item-card__top");
        opHead.appendChild(el("span", "tag", `${op.kind} · ${op.state}`));
        if (op.kind !== "permanent_delete") {
          const singleUndo = el("button", "btn btn--ghost btn--compact", "撤销");
          singleUndo.type = "button";
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

      detailPane.appendChild(el("h4", "detail-pane__sub", "逐步审计事件"));
      for (const ev of detail.events) {
        detailPane.appendChild(
          el(
            "div",
            "event-line",
            `[${formatUnixTime(ev.created_at_unix)}] ${ev.step} (${ev.phase})`,
          ),
        );
      }
      if (detail.events_truncated) {
        detailPane.appendChild(el("div", "event-line", "… 其余事件已截断"));
      }
    }
    split.appendChild(detailPane);
    this.root.appendChild(split);
  }

  private renderRecovery(model: AppStateModel): void {
    const top = el("div", "panel-toolbar");
    const refresh = el("button", "btn btn--secondary", "刷新核验");
    refresh.type = "button";
    refresh.addEventListener("click", () => {
      void this.callbacks.onRefreshRecovery();
    });
    top.appendChild(refresh);
    this.root.appendChild(top);

    const items = model.safety.recoveryReport?.items ?? [];
    if (items.length === 0) {
      this.root.appendChild(el("div", "empty-state", "暂无待恢复记录"));
      return;
    }

    const list = el("div", "card-list");
    for (const item of items) {
      const card = el("div", "item-card");
      card.appendChild(
        el("span", "tag tag--warn", `${item.disposition} · 日志状态 ${item.journal_state}`),
      );
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
          el("div", "item-card__sub", `暂存/中间路径：${item.temporary_display}`),
        );
      }
      card.appendChild(el("div", "item-card__title", item.reason));
      list.appendChild(card);
    }
    this.root.appendChild(list);
  }
}
