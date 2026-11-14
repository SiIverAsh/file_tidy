import type { EntryPolicyView, SensitivityReason, ZoneKind } from "../api/types.ts";
import { el } from "./safe-text.ts";

export function describeZoneLabel(zone: ZoneKind): {
  icon: string;
  text: string;
  cssClass: string;
} {
  switch (zone) {
    case "A_Protected":
      return { icon: "●", text: "A 保护", cssClass: "zone-badge zone-a" };
    case "B_Sensitive":
      return { icon: "●", text: "B 敏感", cssClass: "zone-badge zone-b" };
    case "C_GrantedPersistent":
      return { icon: "●", text: "C 持久", cssClass: "zone-badge zone-c" };
    case "C_GrantedSession":
      return { icon: "●", text: "C 会话", cssClass: "zone-badge zone-c" };
    case "Unauthenticated":
      return { icon: "○", text: "未授权", cssClass: "zone-badge zone-u" };
  }
}

export function describeSensitivityReason(reason: SensitivityReason | null): string | null {
  switch (reason) {
    case "sensitive_root_ancestor":
      return "位于敏感根目录内（如 ~/.ssh、~/.gnupg、~/.config 等）";
    case "sensitive_filename":
      return "匹配密钥或凭据文件名规则（如 .env*、*.pem、*.key）";
    case "hardlink_alias_propagated":
      return "硬链接别名传播：与敏感文件共享实体，按 B 区保护";
    case "contains_sensitive_child":
      return "级联拒绝原因：包含敏感子项，禁止目录写入操作";
    case "conservative_unknown":
      return "目录上下文未知，按敏感项处理";
    case null:
      return null;
  }
}

export function createZoneBadge(policy: EntryPolicyView): HTMLElement {
  const info = describeZoneLabel(policy.zone);
  const badge = el("span", info.cssClass, `${info.icon} ${info.text}`);
  if (policy.blocked_reason) {
    badge.title = policy.blocked_reason;
  }
  return badge;
}

export function createPolicyExplanationBox(policy: EntryPolicyView): HTMLElement | null {
  const cascadeText = describeSensitivityReason(policy.sensitivity_reason);
  const hasAtomic = policy.atomic_root_display !== null;
  const hasBlocked = policy.blocked_reason !== null;
  if (!cascadeText && !hasAtomic && !hasBlocked) {
    return null;
  }

  const box = el(
    "div",
    policy.zone === "B_Sensitive"
      ? "policy-callout policy-callout--b"
      : policy.zone === "A_Protected"
        ? "policy-callout policy-callout--a"
        : "policy-callout",
  );

  const title = el(
    "div",
    "policy-callout__title",
    policy.zone === "B_Sensitive" ? "B 区限制" : "操作限制",
  );
  box.appendChild(title);

  if (policy.blocked_reason) {
    box.appendChild(el("p", "policy-callout__line", policy.blocked_reason));
  }
  if (cascadeText) {
    box.appendChild(el("p", "policy-callout__line", cascadeText));
  }
  if (policy.atomic_root_display) {
    box.appendChild(
      el(
        "p",
        "policy-callout__line",
        `整体目录：${policy.atomic_root_display}（不可拆分操作）`,
      ),
    );
  }
  if (policy.zone === "B_Sensitive" && policy.allowed_actions.includes("copy_out")) {
    box.appendChild(
      el(
        "p",
        "policy-callout__hint",
        "可确认后复制到已授权目录",
      ),
    );
  }
  return box;
}
