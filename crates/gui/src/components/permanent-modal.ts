import type { PlanPreviewDto } from "../api/types.ts";
import type { AppStateModel } from "../state/store.ts";
import {
  clearChildren,
  el,
  formatBytesWithExact,
  formatCountdown,
} from "./safe-text.ts";

export interface PermanentModalCallbacks {
  onClose(): void;
  onRequestChallenge(planId: string, planDigest: string): Promise<void>;
  onPhraseInput(value: string): void;
  onCountInput(value: string): void;
  onExecutePermanent(preview: PlanPreviewDto): Promise<void>;
}

/**
 * Isolated high-risk permanent deletion confirmation modal.
 * Strictly separated from normal plan execution, binds challenge to (plan_id, plan_digest),
 * enforces explicit "永久删除 不可撤销" wording and non-color indicators.
 */
export class PermanentDeleteModal {
  readonly root: HTMLElement;
  private readonly callbacks: PermanentModalCallbacks;
  private timerId: number | null = null;
  private challengeTimerEl: HTMLElement | null = null;
  private latestExpiresAt: string | null = null;
  private phraseInputEl: HTMLInputElement | null = null;
  private countInputEl: HTMLInputElement | null = null;
  private submitBtnEl: HTMLButtonElement | null = null;
  private renderedModalKey: string | null = null;

  constructor(callbacks: PermanentModalCallbacks) {
    this.callbacks = callbacks;
    this.root = el("div", "modal-backdrop");
    this.root.setAttribute("role", "alertdialog");
    this.root.setAttribute("aria-modal", "true");
    this.root.setAttribute("aria-label", "永久删除不可撤销确认");
  }

  render(model: AppStateModel): void {
    const modal = model.permanentModal;
    if (!modal.open) {
      this.root.classList.remove("modal-backdrop--open");
      this.stopTimer();
      this.phraseInputEl = null;
      this.countInputEl = null;
      this.submitBtnEl = null;
      this.renderedModalKey = null;
      clearChildren(this.root);
      return;
    }

    const modalKey =
      !modal.loading && !modal.executionReport && !modal.executing && modal.preview && modal.challenge
        ? `${modal.preview.plan_id}:${modal.preview.plan_digest}:${modal.challenge.challenge_code}:${modal.error ?? ""}`
        : null;
    if (
      modalKey !== null &&
      modalKey === this.renderedModalKey &&
      ((this.phraseInputEl !== null && document.activeElement === this.phraseInputEl) ||
        (this.countInputEl !== null && document.activeElement === this.countInputEl))
    ) {
      if (this.submitBtnEl) {
        this.submitBtnEl.disabled = !this.canSubmit(model);
      }
      return;
    }
    this.renderedModalKey = modalKey;
    this.phraseInputEl = null;
    this.countInputEl = null;
    this.submitBtnEl = null;

    this.root.classList.add("modal-backdrop--open");
    clearChildren(this.root);

    const card = el("div", "danger-modal");
    this.root.appendChild(card);

    const header = el("div", "danger-modal__header");
    header.appendChild(el("span", "danger-badge", "永久删除"));
    const closeBtn = el("button", "btn btn--ghost", "取消");
    closeBtn.type = "button";
    closeBtn.disabled = modal.executing;
    closeBtn.addEventListener("click", () => this.callbacks.onClose());
    header.appendChild(closeBtn);
    card.appendChild(header);

    const body = el("div", "danger-modal__body");
    card.appendChild(body);

    if (modal.error) {
      body.appendChild(el("div", "alert alert--error", modal.error));
    }
    if (modal.loading) {
      body.appendChild(el("div", "loading-state", "正在生成删除清单…"));
      return;
    }

    if (modal.executionReport) {
      const done = modal.executionReport;
      body.appendChild(
        el(
          "div",
          done.completed ? "alert alert--warn" : "alert alert--error",
          `删除完成（批次 ${done.batch_id.slice(0, 12)}…）`,
        ),
      );
      for (const op of done.operations) {
        body.appendChild(
          el(
            "div",
            "exec-result",
            `[${op.status}] ${op.source_display}${op.reason ? " — " + op.reason : ""}`,
          ),
        );
      }
      return;
    }

    const preview = modal.preview;
    if (!preview) {
      return;
    }

    if (preview.blocked_b_write_reasons.length > 0) {
      const err = el("div", "alert alert--error");
      err.appendChild(
        el(
          "strong",
          "",
          "包含 B 区敏感项目，不支持永久删除：",
        ),
      );
      for (const r of preview.blocked_b_write_reasons) {
        err.appendChild(el("p", "alert__line", r));
      }
      body.appendChild(err);
      return;
    }

    if (preview.executable_error) {
      body.appendChild(
        el("div", "alert alert--error", preview.executable_error),
      );
      return;
    }

    body.appendChild(
      el(
        "p",
        "danger-modal__lead",
        `将永久删除 ${preview.files_and_links} 个文件、${preview.directories} 个目录（共 ${formatBytesWithExact(preview.total_bytes)}），删除后不可恢复。`,
      ),
    );

    // Complete leaf manifest (mandatory review)
    const manifestBox = el("div", "danger-manifest");
    manifestBox.appendChild(
      el("div", "danger-manifest__title", "待删除清单："),
    );
    const ul = el("ul", "danger-manifest__list");
    for (const op of preview.operations) {
      for (const entry of op.manifest) {
        ul.appendChild(
          el(
            "li",
            "danger-manifest__item",
            `[${entry.kind}] ${entry.path_display} — ${formatBytesWithExact(entry.size_bytes)}${entry.hidden ? " [隐藏]" : ""}`,
          ),
        );
      }
    }
    manifestBox.appendChild(ul);
    body.appendChild(manifestBox);

    // Challenge section bound to (plan_id, plan_digest) with short expiration
    const challengeBox = el("div", "danger-challenge");
    if (!modal.challenge) {
      const reqBtn = el("button", "btn btn--danger-outline", "生成确认码");
      reqBtn.type = "button";
      reqBtn.addEventListener("click", () => {
        void this.callbacks.onRequestChallenge(preview.plan_id, preview.plan_digest);
      });
      challengeBox.appendChild(reqBtn);
      this.stopTimer();
    } else {
      const ch = modal.challenge;
      this.latestExpiresAt = ch.expires_at_unix;
      const timerLine = el("div", "danger-challenge__timer");
      challengeBox.appendChild(timerLine);
      this.startTimer(timerLine);

      const expected = `${ch.expected_prefix} ${ch.confirmation_count} ${ch.challenge_code}`;
      challengeBox.appendChild(
        el(
          "div",
          "danger-challenge__code",
          "请输入以下确认短语：",
        ),
      );
      challengeBox.appendChild(el("code", "danger-challenge__phrase", expected));

      const phraseInput = el("input", "input input--danger");
      phraseInput.type = "text";
      phraseInput.placeholder = expected;
      phraseInput.value = modal.phraseInput;
      phraseInput.addEventListener("input", () =>
        this.callbacks.onPhraseInput(phraseInput.value),
      );
      this.phraseInputEl = phraseInput;
      challengeBox.appendChild(phraseInput);

      if (preview.requires_count_confirmation) {
        challengeBox.appendChild(
          el(
            "label",
            "confirm-section__label",
            `输入条目数量 (${preview.confirmation_count})：`,
          ),
        );
        const countInput = el("input", "input input--danger");
        countInput.type = "text";
        countInput.inputMode = "numeric";
        countInput.value = modal.countInput;
        countInput.addEventListener("input", () =>
          this.callbacks.onCountInput(countInput.value),
        );
        this.countInputEl = countInput;
        challengeBox.appendChild(countInput);
      }
    }
    body.appendChild(challengeBox);

    const footer = el("div", "danger-modal__footer");
    const submitBtn = el("button", "btn btn--danger", "永久删除 不可撤销");
    submitBtn.type = "button";
    submitBtn.disabled = !this.canSubmit(model);
    submitBtn.addEventListener("click", () => {
      void this.callbacks.onExecutePermanent(preview);
    });
    this.submitBtnEl = submitBtn;
    footer.appendChild(submitBtn);
    card.appendChild(footer);
  }

  private canSubmit(model: AppStateModel): boolean {
    const modal = model.permanentModal;
    const preview = modal.preview;
    const ch = modal.challenge;
    if (!preview || !ch || modal.executing) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (Number(ch.expires_at_unix) <= nowSec) {
      return false;
    }
    const expected = `${ch.expected_prefix} ${ch.confirmation_count} ${ch.challenge_code}`;
    if (modal.phraseInput.trim() !== expected) {
      return false;
    }
    if (
      preview.requires_count_confirmation &&
      modal.countInput.trim() !== preview.confirmation_count
    ) {
      return false;
    }
    return true;
  }

  private startTimer(challengeTimerEl: HTMLElement): void {
    this.stopTimer();
    this.challengeTimerEl = challengeTimerEl;
    const tick = () => {
      if (!this.challengeTimerEl || !this.latestExpiresAt) {
        return;
      }
      const res = formatCountdown(this.latestExpiresAt, Math.floor(Date.now() / 1000));
      this.challengeTimerEl.textContent = res.expired
        ? `⏰ 挑战码已过期，请重新生成`
        : `⏳ 挑战码剩余有效期 ${res.label}`;
    };
    tick();
    this.timerId = window.setInterval(tick, 1000);
  }

  private stopTimer(): void {
    if (this.timerId !== null) {
      window.clearInterval(this.timerId);
      this.timerId = null;
    }
    this.challengeTimerEl = null;
  }
}
