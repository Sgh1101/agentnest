import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { vi } from "vitest";
import { MockBackend } from "../src/api/mock";
import type { Backend } from "../src/api/backend";
import { AppController } from "../src/controller";
import { createStore, initialState, type Store, type ViewId } from "../src/store";
import { mountApp, type AppHandle } from "../src/ui/app";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HERE, "../../../..");
export const APP_ROOT = resolve(HERE, "..");

export function readJson(...parts: string[]): unknown {
  return JSON.parse(readFileSync(join(REPO_ROOT, ...parts), "utf8")) as unknown;
}

export function listJson(...parts: string[]): string[] {
  return readdirSync(join(REPO_ROOT, ...parts))
    .filter((f) => f.endsWith(".json") && !f.startsWith("_"))
    .sort();
}

export const T0 = Date.parse("2026-10-15T12:35:00.000Z");

/** Let pending promises and 0 ms timers run (works with vi fake timers). */
export async function settle(rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(0);
}

export interface Harness {
  root: HTMLElement;
  backend: Backend;
  mock: MockBackend | null;
  store: Store;
  controller: AppController;
  app: AppHandle;
  go(view: ViewId): Promise<void>;
  destroy(): void;
}

export async function mountHarness(opts: { backend?: Backend; view?: ViewId; settings?: ConstructorParameters<typeof MockBackend>[0] } = {}): Promise<Harness> {
  const backend = opts.backend ?? new MockBackend({ now: () => Date.now(), ...(opts.settings ?? {}) });
  const root = document.createElement("div");
  document.body.appendChild(root);
  const store = createStore(initialState(backend.kind));
  const controller = new AppController(backend, store, () => Date.now());
  const app = mountApp(root, controller, () => Date.now());
  await controller.init();
  if (opts.view) controller.navigate(opts.view);
  await settle();
  app.flush();
  return {
    root,
    backend,
    mock: backend instanceof MockBackend ? backend : null,
    store,
    controller,
    app,
    async go(view) {
      controller.navigate(view);
      await settle();
      app.flush();
    },
    destroy() {
      controller.dispose();
      app.destroy();
      root.remove();
    },
  };
}

export function q<T extends Element = HTMLElement>(root: ParentNode, sel: string): T {
  const el = root.querySelector<T>(sel);
  if (el === null) throw new Error(`missing element: ${sel}`);
  return el;
}

export function qa<T extends Element = HTMLElement>(root: ParentNode, sel: string): T[] {
  return Array.from(root.querySelectorAll<T>(sel));
}

export function press(el: Element): void {
  el.dispatchEvent(new Event("pointerdown", { bubbles: true }));
}
export function release(el: Element): void {
  el.dispatchEvent(new Event("pointerup", { bubbles: true }));
}
export function click(el: Element): void {
  el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
}
export function typeInto(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}
