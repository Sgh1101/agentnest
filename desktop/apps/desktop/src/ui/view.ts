import type { AppController } from "../controller";
import { clear, append, type Child } from "../dom";
import type { AppState } from "../store";

export interface ViewCtx {
  controller: AppController;
  clock: () => number;
  /** Container for modal dialogs (revoke, SAS). */
  modalRoot: HTMLElement;
}

export interface ViewInstance {
  el: HTMLElement;
  update(state: AppState): void;
  /** Optional per-second hook (countdowns, expiry). */
  tick?(nowMs: number): void;
  destroy?(): void;
}

export type ViewFactory = (ctx: ViewCtx) => ViewInstance;

/**
 * A view that re-renders only when the slices it depends on change (shallow `Object.is`), so
 * unrelated daemon events do not rebuild it (important for sliders and text inputs).
 * `render` receives `rerender` for purely local UI state.
 */
export function simpleView(
  deps: (s: AppState) => readonly unknown[],
  render: (s: AppState, ctx: ViewCtx, rerender: () => void) => Child[],
  className = "view",
): ViewFactory {
  return (ctx) => {
    const el = document.createElement("div");
    el.className = className;
    let last: readonly unknown[] | null = null;
    let current: AppState | null = null;

    const draw = (): void => {
      if (current === null) return;
      const active = document.activeElement;
      const fid = active instanceof HTMLElement && el.contains(active) ? active.getAttribute("data-fid") : null;
      clear(el);
      append(el, render(current, ctx, draw));
      if (fid !== null) {
        for (const cand of Array.from(el.querySelectorAll<HTMLElement>("[data-fid]"))) {
          if (cand.getAttribute("data-fid") === fid) {
            cand.focus();
            break;
          }
        }
      }
    };

    return {
      el,
      update(s) {
        current = s;
        const next = deps(s);
        if (last !== null && next.length === last.length && next.every((v, i) => Object.is(v, last?.[i]))) return;
        last = next;
        draw();
      },
    };
  };
}
