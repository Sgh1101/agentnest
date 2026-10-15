import type { Backend } from "./backend";
import { MockBackend } from "./mock";
import { TauriBackend, isTauriRuntime } from "./tauri";

export * from "./types";
export { COMMANDS } from "./backend";
export type { Backend } from "./backend";
export { BackendError, messageKo, toBackendError } from "./errors";
export { MockBackend } from "./mock";
export { TauriBackend, isTauriRuntime, toIpcArgs } from "./tauri";

/** Tauri backend inside the app webview, otherwise the in-memory mock (browser `vite dev`). */
export function createBackend(): Backend {
  return isTauriRuntime() ? new TauriBackend() : new MockBackend({ seed: true });
}
