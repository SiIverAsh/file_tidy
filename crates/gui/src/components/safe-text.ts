/**
 * Safe DOM & formatting helpers.
 * Never uses innerHTML, outerHTML, insertAdjacentHTML, or runtime inline styles.
 */

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

export function clearChildren(node: HTMLElement): void {
  node.replaceChildren();
}

export function setText(node: HTMLElement, text: string): void {
  if (node.textContent !== text) {
    node.textContent = text;
  }
}

export function parseBigIntSafe(decimal: string | null | undefined): bigint {
  if (!decimal || !/^-?\d+$/.test(decimal)) {
    return 0n;
  }
  try {
    return BigInt(decimal);
  } catch {
    return 0n;
  }
}

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

export function formatBytes(decimal: string | null | undefined): string {
  if (decimal === null || decimal === undefined) {
    return "未知";
  }
  const bytes = parseBigIntSafe(decimal);
  if (bytes < 1024n) {
    return `${bytes.toString()} B`;
  }
  let unitIdx = 0;
  let scaled = bytes * 100n;
  while (scaled >= 102400n && unitIdx < UNITS.length - 1) {
    scaled = scaled / 1024n;
    unitIdx += 1;
  }
  const whole = scaled / 100n;
  const frac = (scaled % 100n).toString().padStart(2, "0");
  return `${whole.toString()}.${frac} ${UNITS[unitIdx] ?? "B"}`;
}

export function formatBytesWithExact(decimal: string | null | undefined): string {
  if (decimal === null || decimal === undefined) {
    return "未知";
  }
  return `${formatBytes(decimal)} (${decimal} B)`;
}

export function formatUnixTime(unixSeconds: string | null | undefined): string {
  if (!unixSeconds || !/^-?\d+$/.test(unixSeconds)) {
    return "未知";
  }
  const seconds = Number(unixSeconds);
  if (!Number.isFinite(seconds)) {
    return unixSeconds;
  }
  const date = new Date(seconds * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

export function formatCountdown(expiresAtUnix: string, nowSeconds: number): {
  expired: boolean;
  label: string;
} {
  const expires = Number(expiresAtUnix);
  if (!Number.isFinite(expires)) {
    return { expired: true, label: "已失效" };
  }
  const remaining = Math.floor(expires - nowSeconds);
  if (remaining <= 0) {
    return { expired: true, label: "已过期，请重新生成" };
  }
  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  return {
    expired: false,
    label: `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`,
  };
}
