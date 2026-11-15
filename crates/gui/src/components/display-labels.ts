import { el } from "./safe-text.ts";

const OPERATION_LABELS: Readonly<Record<string, string>> = {
  copy: "复制", move: "移动", rename: "重命名", quarantine: "移入隔离区",
  restore: "恢复文件", undo_copy: "撤销复制", permanent_delete: "永久删除",
};
const STATUS_LABELS: Readonly<Record<string, string>> = {
  running: "执行中", completed: "已完成", partial: "部分完成", cancelled: "已停止",
  done: "已完成", failed: "失败", not_started: "尚未开始", needs_recovery: "需要核对",
  needsrecovery: "需要核对", planned: "等待执行", prepared: "已准备", staged: "已暂存",
  verified: "已校验", published: "已写入目标", source_remove_intent: "准备移除原文件",
  sourceremoveintent: "准备移除原文件", skipped: "已跳过", stored: "已隔离",
  restored: "已恢复", purged: "已永久删除",
};
const FILE_LABELS: Readonly<Record<string, string>> = {
  regular: "文件", file: "文件", directory: "文件夹", symlink: "符号链接",
  reparse: "重解析项", special: "特殊文件",
};
const RECOVERY_LABELS: Readonly<Record<string, string>> = {
  notcommitted: "尚未提交更改", permanentprogressobserved: "检测到删除进度",
  migrationprogressobserved: "检测到移动进度", temporaryobserved: "发现重命名暂存文件",
  renameobserved: "发现已重命名文件", stagedcopyobserved: "发现复制暂存文件",
  verifiedcopyobserved: "发现待重新校验的副本", copypublishedobserved: "发现已写入的副本",
  needsattention: "需要人工核对", unavailable: "暂时无法检查",
};
const DIRECTORY_LABELS: Readonly<Record<string, string>> = {
  downloads: "下载", desktop: "桌面", documents: "文档",
};

export const operationLabel = (value: string): string => OPERATION_LABELS[value.toLowerCase()] ?? "未知操作";
export const statusLabel = (value: string): string => STATUS_LABELS[value.toLowerCase()] ?? "未知状态";
export const fileKindLabel = (value: string): string => FILE_LABELS[value.toLowerCase()] ?? "未知类型";
export const recoveryLabel = (value: string): string => RECOVERY_LABELS[value.toLowerCase()] ?? "未知状态";
export const directoryPurposeLabel = (value: string): string => DIRECTORY_LABELS[value.toLowerCase()] ?? "其他目录";

/** Keep the original protocol value available only in detailed mode. */
export function labeledValue(label: string, raw: string, className = ""): HTMLElement {
  const node = el("span", className);
  node.appendChild(el("span", "", label));
  node.appendChild(el("span", "technical-detail", ` (${raw})`));
  return node;
}
