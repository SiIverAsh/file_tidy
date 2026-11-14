import type { AppStateModel } from "../state/store.ts";
import { clearChildren, el, formatUnixTime } from "../components/safe-text.ts";
import { createPolicyExplanationBox, createZoneBadge } from "../components/zone-badge.ts";

export interface AccessRulesCallbacks {
  onOpenExistingStorage(): Promise<void>;
  onPickStorageInit(): Promise<void>;
  onConfirmStorageInit(grantId: string, digest: string): Promise<void>;
  onCancelPendingStorageInit(): void;
  onPickAndPreviewGrant(): Promise<void>;
  onConfirmGrant(grantId: string, persistent: boolean): Promise<void>;
  onCancelPendingGrant(): void;
  onRevokeGrant(grantId: string): Promise<void>;
  onRequestSuggested(allowPrivateConfig: boolean): Promise<void>;
}

export class AccessRulesView {
  readonly root: HTMLElement;
  private readonly callbacks: AccessRulesCallbacks;

  constructor(callbacks: AccessRulesCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--access");
  }

  render(model: AppStateModel): void {
    clearChildren(this.root);

    // 1. State Storage (.file-tidy) card
    const storageCard = el("div", "panel-card");
    storageCard.appendChild(el("h2", "panel-card__title", "工作区与隔离存储（.file-tidy）"));
    const ws = model.workspace;
    if (ws?.storage_initialized) {
      storageCard.appendChild(
        el(
          "div",
          "panel-card__desc",
          `已绑定：${ws.storage_root_display ?? "未知"} · 授权 #${ws.authorization_epoch}`,
        ),
      );
    } else {
      storageCard.appendChild(
        el(
          "div",
          "panel-card__desc",
          "未绑定工作区目录。初始化后可保存授权、操作历史和同卷隔离区。",
        ),
      );
    }

    const storageActions = el("div", "panel-toolbar");
    const openBtn = el("button", "btn btn--secondary", "打开工作区…");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => {
      void this.callbacks.onOpenExistingStorage();
    });
    storageActions.appendChild(openBtn);

    const initBtn = el("button", "btn btn--primary", "初始化工作区…");
    initBtn.type = "button";
    initBtn.addEventListener("click", () => {
      void this.callbacks.onPickStorageInit();
    });
    storageActions.appendChild(initBtn);
    storageCard.appendChild(storageActions);

    if (model.access.pendingStorageInit) {
      const p = model.access.pendingStorageInit;
      const box = el("div", "confirm-section confirm-section--warn");
      box.appendChild(
        el(
          "div",
          "confirm-section__title",
          `即将初始化私有状态目录：${p.directory_display}`,
        ),
      );
      box.appendChild(
        el(
          "div",
          "item-card__sub",
          `将创建对象：${p.objects.join(" , ")} · 摘要 ${p.digest.slice(0, 12)}… · 过期 ${formatUnixTime(p.expires_at_unix)}`,
        ),
      );
      const btns = el("div", "panel-toolbar");
      const ok = el("button", "btn btn--primary", "确认初始化");
      ok.type = "button";
      ok.addEventListener("click", () => {
        void this.callbacks.onConfirmStorageInit(p.grant_id, p.digest);
      });
      const cancel = el("button", "btn btn--ghost", "取消");
      cancel.type = "button";
      cancel.addEventListener("click", () => this.callbacks.onCancelPendingStorageInit());
      btns.appendChild(ok);
      btns.appendChild(cancel);
      box.appendChild(btns);
      storageCard.appendChild(box);
    }
    this.root.appendChild(storageCard);

    // 2. Grants list
    const grantsCard = el("div", "panel-card");
    grantsCard.appendChild(el("h2", "panel-card__title", "已授权目录（C 区）"));
    grantsCard.appendChild(
      el(
        "p",
        "panel-card__desc",
        "已授权目录可执行移动、隔离和删除操作。",
      ),
    );

    const addGrantBtn = el("button", "btn btn--primary", "添加授权目录…");
    addGrantBtn.type = "button";
    addGrantBtn.addEventListener("click", () => {
      void this.callbacks.onPickAndPreviewGrant();
    });
    grantsCard.appendChild(addGrantBtn);

    if (model.access.pendingGrant) {
      const g = model.access.pendingGrant;
      const box = el("div", "confirm-section");
      box.appendChild(
        el("div", "confirm-section__title", `待确认授权目录：${g.root_display}`),
      );
      const btns = el("div", "panel-toolbar");
      const sessBtn = el("button", "btn btn--secondary", "本次会话");
      sessBtn.type = "button";
      sessBtn.addEventListener("click", () => {
        void this.callbacks.onConfirmGrant(g.id, false);
      });
      const persBtn = el("button", "btn btn--primary", "持久授权");
      persBtn.type = "button";
      persBtn.disabled = !ws?.storage_initialized;
      if (!ws?.storage_initialized) {
        persBtn.title = "需先初始化 .file-tidy 状态存储才能保存持久授权";
      }
      persBtn.addEventListener("click", () => {
        void this.callbacks.onConfirmGrant(g.id, true);
      });
      const cancelBtn = el("button", "btn btn--ghost", "取消");
      cancelBtn.type = "button";
      cancelBtn.addEventListener("click", () => this.callbacks.onCancelPendingGrant());
      btns.appendChild(sessBtn);
      btns.appendChild(persBtn);
      btns.appendChild(cancelBtn);
      box.appendChild(btns);
      grantsCard.appendChild(box);
    }

    const grantList = el("div", "card-list");
    const grants = ws?.grants ?? [];
    if (grants.length === 0) {
      grantList.appendChild(el("div", "empty-state", "暂无授权目录"));
    }
    for (const g of grants) {
      const row = el("div", "item-card");
      const top = el("div", "item-card__top");
      top.appendChild(el("span", "item-card__title", g.root_display));
      top.appendChild(
        el("span", "tag", g.persistent ? "持久授权" : "仅本次会话"),
      );
      if (g.revoked) {
        top.appendChild(el("span", "tag tag--muted", "已撤销"));
      } else {
        const revokeBtn = el("button", "btn btn--danger-outline", "撤销授权");
        revokeBtn.type = "button";
        revokeBtn.addEventListener("click", () => {
          void this.callbacks.onRevokeGrant(g.id);
        });
        top.appendChild(revokeBtn);
      }
      row.appendChild(top);
      grantList.appendChild(row);
    }
    grantsCard.appendChild(grantList);
    this.root.appendChild(grantsCard);

    // 3. System Suggested Directories (with explicit B-zone consent on Linux!)
    const suggCard = el("div", "panel-card");
    suggCard.appendChild(el("h2", "panel-card__title", "常见目录"));

    const sugg = model.access.suggested;
    if (!sugg || sugg.requires_private_config_consent) {
      const warning = el("div", "policy-callout policy-callout--b");
      warning.appendChild(
        el(
          "div",
          "policy-callout__title",
          "读取系统目录配置",
        ),
      );
      warning.appendChild(
        el(
          "p",
          "policy-callout__line",
          sugg?.consent_reason ??
            "识别系统下载/桌面目录需要读取 ~/.config/user-dirs.dirs。",
        ),
      );
      const consentBtn = el(
        "button",
        "btn btn--secondary",
        "允许读取",
      );
      consentBtn.type = "button";
      consentBtn.addEventListener("click", () => {
        void this.callbacks.onRequestSuggested(true);
      });
      warning.appendChild(consentBtn);
      suggCard.appendChild(warning);
    } else if (sugg.items.length === 0) {
      suggCard.appendChild(el("div", "empty-state", "未检测到系统推荐目录"));
    } else {
      const list = el("div", "card-list");
      for (const item of sugg.items) {
        const row = el("div", "item-card");
        const top = el("div", "item-card__top");
        top.appendChild(el("span", "tag", item.purpose));
        top.appendChild(el("span", "item-card__title", item.path_display));
        top.appendChild(createZoneBadge(item.policy));
        row.appendChild(top);
        const explain = createPolicyExplanationBox(item.policy);
        if (explain) {
          row.appendChild(explain);
        }
        list.appendChild(row);
      }
      suggCard.appendChild(list);
    }
    this.root.appendChild(suggCard);
  }
}
