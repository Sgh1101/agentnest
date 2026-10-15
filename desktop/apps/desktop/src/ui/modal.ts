import { h, type Child } from "../dom";

export interface ModalHandle {
  el: HTMLElement;
  close(): void;
}

/**
 * Minimal modal. `dismissable=false` ignores Escape and backdrop clicks: the SAS prompt may only be
 * closed by an explicit [승인] / [거절] (or by the controller when it expires).
 */
export function openModal(root: HTMLElement, opts: { title: string; labelId: string; body: Child[]; dismissable: boolean; onClose?: () => void }): ModalHandle {
  const heading = h("h2", { id: opts.labelId }, opts.title);
  const dialog = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": opts.labelId }, heading, ...opts.body);
  const backdrop = h("div", { class: "modal-backdrop" }, dialog);
  let closed = false;

  const close = (): void => {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey, true);
    backdrop.remove();
    opts.onClose?.();
  };
  function onKey(e: KeyboardEvent): void {
    if (e.key === "Escape") {
      e.stopPropagation();
      if (opts.dismissable) close();
    }
  }
  document.addEventListener("keydown", onKey, true);
  if (opts.dismissable) {
    backdrop.addEventListener("click", (e) => {
      if (e.target === backdrop) close();
    });
  }
  root.appendChild(backdrop);
  return { el: backdrop, close };
}
