import { createBackend } from "./api";
import { MockBackend } from "./api/mock";
import { AppController } from "./controller";
import { mountDevPanel } from "./devPanel";
import { createStore, initialState } from "./store";
import { mountApp } from "./ui/app";
import "./styles.css";

async function boot(): Promise<void> {
  const root = document.getElementById("app");
  if (root === null) throw new Error("#app missing");
  const backend = createBackend();
  const store = createStore(initialState(backend.kind));
  const controller = new AppController(backend, store);
  mountApp(root, controller);
  await controller.init();
  if (backend instanceof MockBackend) mountDevPanel(document.body, backend, controller);
}

void boot();
