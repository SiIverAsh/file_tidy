import type { AppStateModel } from "../state/store.ts";
import { clearChildren, el, formatUnixTime } from "../components/safe-text.ts";
import { createPolicyExplanationBox, createZoneBadge } from "../components/zone-badge.ts";
import { directoryPurposeLabel, labeledValue } from "../components/display-labels.ts";

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
  private suggestedExpanded = false;
  private readonly focusTargets = new Map<string, HTMLElement>();

  constructor(callbacks: AccessRulesCallbacks) {
    this.callbacks = callbacks;
    this.root = el("section", "view view--access");
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
    let target = focusKey ? this.focusTargets.get(focusKey) : undefined;
    if (!target && focusKey?.startsWith("grant:")) {
      target = this.focusTargets.get("grant:add");
    } else if (!target && focusKey?.startsWith("storage:")) {
      target = this.focusTargets.get("storage:open");
    }
    if (target && !(target as HTMLButtonElement).disabled) {
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
    header.appendChild(el("h1", "page-header__title", "授权与规则"));
    header.appendChild(el("p", "page-header__description", "管理工作区和目录权限，让每次整理都有清晰边界。"));
    this.root.appendChild(header);

    const grid = el("div", "settings-grid");

    // 1. State Storage (.file-tidy) card
    const storageCard = el("div", "panel-card");
    const storageHeading = el("div", "section-heading");
    storageHeading.appendChild(el("h2", "section-heading__title", "工作区存储"));
    storageHeading.appendChild(el("p", "section-heading__description", "保存目录授权、操作历史与同卷隔离文件。"));
    storageCard.appendChild(storageHeading);
    const ws = model.workspace;
    if (ws?.storage_initialized) {
      storageCard.appendChild(el("span", "tag tag--ok", "已连接"));
      storageCard.appendChild(
        el(
          "div",
          "panel-card__desc storage-path",
          ws.storage_root_display ?? "未知",
        ),
      );
    } else {
      storageCard.appendChild(el("span", "tag", "尚未连接"));
      storageCard.appendChild(
        el(
          "div",
          "panel-card__desc",
          "选择已有工作区，或创建新的工作区存储。",
        ),
      );
    }

    const storageActions = el("div", "panel-toolbar");
    const openBtn = this.focusable(el("button", "btn btn--secondary", "打开已有工作区…"), "storage:open");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => {
      void this.callbacks.onOpenExistingStorage();
    });
    storageActions.appendChild(openBtn);

    const initBtn = this.focusable(el("button", ws?.storage_initialized ? "btn btn--secondary" : "btn btn--primary", "新建工作区…"), "storage:new");
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
      box.appendChild(el("div", "item-card__sub", "将在所选目录中创建用于保存授权、操作记录和隔离文件的私有存储。"));
      box.appendChild(el("div", "item-card__sub technical-detail", `将创建对象：${p.objects.join(" , ")}`));
      const previewMeta = el("div", "item-card__sub");
      previewMeta.appendChild(el("span", "", `确认有效期至 ${formatUnixTime(p.expires_at_unix)}`));
      previewMeta.appendChild(el("span", "technical-detail", ` · 摘要 ${p.digest.slice(0, 12)}…`));
      box.appendChild(previewMeta);
      const btns = el("div", "panel-toolbar");
      const ok = this.focusable(el("button", "btn btn--primary", "确认初始化"), `storage:confirm:${p.grant_id}`);
      ok.type = "button";
      ok.addEventListener("click", () => {
        void this.callbacks.onConfirmStorageInit(p.grant_id, p.digest);
      });
      const cancel = this.focusable(el("button", "btn btn--ghost", "取消"), "storage:cancel");
      cancel.type = "button";
      cancel.addEventListener("click", () => this.callbacks.onCancelPendingStorageInit());
      btns.appendChild(ok);
      btns.appendChild(cancel);
      box.appendChild(btns);
      storageCard.appendChild(box);
    }
    grid.appendChild(storageCard);

    // 2. Grants list
    const grantsCard = el("div", "panel-card");
    const grantsHeading = el("div", "section-heading");
    const grants = ws?.grants ?? [];
    const activeGrants = grants.filter((grant) => !grant.revoked);
    grantsHeading.appendChild(el("h2", "section-heading__title", "目录授权"));
    grantsHeading.appendChild(el("p", "section-heading__description", "授权目录允许移动、隔离和删除；操作仍需预览确认。"));
    grantsCard.appendChild(grantsHeading);

    const addGrantBtn = this.focusable(el("button", "btn btn--primary", "添加授权目录…"), "grant:add");
    addGrantBtn.type = "button";
    addGrantBtn.addEventListener("click", () => {
      void this.callbacks.onPickAndPreviewGrant();
    });
    const grantActions = el("div", "panel-toolbar");
    grantActions.appendChild(addGrantBtn);
    grantActions.appendChild(el("span", "panel-card__desc", `${activeGrants.length} 个有效授权`));
    grantsCard.appendChild(grantActions);

    if (model.access.pendingGrant) {
      const g = model.access.pendingGrant;
      const box = el("div", "confirm-section");
      box.appendChild(
        el("div", "confirm-section__title", `待确认授权目录：${g.root_display}`),
      );
      const btns = el("div", "panel-toolbar");
      const sessBtn = this.focusable(el("button", "btn btn--secondary", "本次会话"), `grant:session:${g.id}`);
      sessBtn.type = "button";
      sessBtn.addEventListener("click", () => {
        void this.callbacks.onConfirmGrant(g.id, false);
      });
      const persBtn = this.focusable(el("button", "btn btn--primary", "持久授权"), `grant:persistent:${g.id}`);
      persBtn.type = "button";
      persBtn.disabled = !ws?.storage_initialized;
      if (!ws?.storage_initialized) {
        persBtn.title = "需先新建工作区存储，才能保存持久授权";
      }
      persBtn.addEventListener("click", () => {
        void this.callbacks.onConfirmGrant(g.id, true);
      });
      const cancelBtn = this.focusable(el("button", "btn btn--ghost", "取消"), "grant:cancel");
      cancelBtn.type = "button";
      cancelBtn.addEventListener("click", () => this.callbacks.onCancelPendingGrant());
      btns.appendChild(sessBtn);
      btns.appendChild(persBtn);
      btns.appendChild(cancelBtn);
      box.appendChild(btns);
      grantsCard.appendChild(box);
    }

    const grantList = el("div", "card-list");
    if (grants.length === 0) {
      const empty = el("div", "status-empty");
      empty.appendChild(el("div", "status-empty__title", "还没有授权目录"));
      empty.appendChild(el("p", "status-empty__description", "浏览和扫描无需授权，整理文件前再添加即可。"));
      grantList.appendChild(empty);
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
        const revokeBtn = this.focusable(el("button", "btn btn--danger-outline", "撤销授权"), `grant:revoke:${g.id}`);
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
    grid.appendChild(grantsCard);
    this.root.appendChild(grid);

    // 3. System Suggested Directories (with explicit B-zone consent on Linux!)
    const suggCard = el("details", "panel-card settings-disclosure");
    suggCard.open = this.suggestedExpanded;
    suggCard.addEventListener("toggle", () => {
      this.suggestedExpanded = suggCard.open;
    });
    const summary = this.focusable(el("summary", "settings-disclosure__summary"), "suggested:toggle");
    summary.appendChild(el("span", "section-heading__title", "常见目录与区域规则"));
    summary.appendChild(el("span", "section-heading__description", "查看系统推荐位置及其权限范围"));
    suggCard.appendChild(summary);
    const suggBody = el("div", "settings-disclosure__body");

    const sugg = model.access.suggested;
    if (!sugg) {
      const empty = el("div", "status-empty");
      empty.appendChild(el("p", "status-empty__description", "暂无常见目录信息"));
      const reload = this.focusable(el("button", "btn btn--secondary btn--compact", "重新加载"), "suggested:reload");
      reload.type = "button";
      reload.addEventListener("click", () => {
        void this.callbacks.onRequestSuggested(model.access.allowPrivateConfig);
      });
      empty.appendChild(reload);
      suggBody.appendChild(empty);
    } else if (sugg.requires_private_config_consent) {
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
      const consentBtn = this.focusable(el(
        "button",
        "btn btn--secondary",
        "允许读取",
      ), "suggested:consent");
      consentBtn.type = "button";
      consentBtn.addEventListener("click", () => {
        void this.callbacks.onRequestSuggested(true);
      });
      warning.appendChild(consentBtn);
      suggBody.appendChild(warning);
    } else if (sugg.items.length === 0) {
      suggBody.appendChild(el("div", "empty-state", "未检测到系统推荐目录"));
    } else {
      const list = el("div", "card-list");
      for (const item of sugg.items) {
        const row = el("div", "item-card");
        const top = el("div", "item-card__top");
        top.appendChild(labeledValue(directoryPurposeLabel(item.purpose), item.purpose, "tag"));
        top.appendChild(el("span", "item-card__title", item.path_display));
        top.appendChild(createZoneBadge(item.policy));
        row.appendChild(top);
        const explain = createPolicyExplanationBox(item.policy);
        if (explain) {
          row.appendChild(explain);
        }
        list.appendChild(row);
      }
      suggBody.appendChild(list);
    }
    suggCard.appendChild(suggBody);
    this.root.appendChild(suggCard);
  }
}
