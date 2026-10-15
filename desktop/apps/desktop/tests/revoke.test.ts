import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sampleDevice } from "../src/api/samples";
import { T0, click, mountHarness, q, settle, typeInto, type Harness } from "./helpers";

describe("device revoke by typing the name (security.md 10)", () => {
  let h: Harness;
  beforeEach(async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    h = await mountHarness({ settings: { seed: true } });
    h.mock?.setDevices([sampleDevice({ name: "Pixel 9", device_id: "dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" })]);
    await h.controller.refreshDevices();
    await h.go("devices");
  });
  afterEach(() => {
    h.destroy();
    vi.useRealTimers();
  });

  const calls = (): Array<Record<string, unknown>> => (h.mock?.calls ?? []).filter((c) => c.command === "device_revoke").map((c) => c.args);

  it("the confirm button stays disabled until the exact name is typed", async () => {
    click(q(h.root, "[data-fid^=revoke-dev_]"));
    const input = q<HTMLInputElement>(h.root, "[data-revoke-input]");
    const confirm = q<HTMLButtonElement>(h.root, "[data-action=revoke-confirm]");
    expect(confirm.disabled).toBe(true);
    for (const wrong of ["", "pixel 9", "Pixel", "Pixel 9 ", "Pixel 99"]) {
      typeInto(input, wrong);
      expect(confirm.disabled, JSON.stringify(wrong)).toBe(true);
    }
    click(confirm);
    await settle();
    expect(calls()).toHaveLength(0);
    typeInto(input, "Pixel 9");
    expect(confirm.disabled).toBe(false);
  });

  it("typing the name revokes via device_revoke(device_id, name_typed) and closes the dialog", async () => {
    click(q(h.root, "[data-fid^=revoke-dev_]"));
    typeInto(q<HTMLInputElement>(h.root, "[data-revoke-input]"), "Pixel 9");
    click(q(h.root, "[data-action=revoke-confirm]"));
    await settle();
    expect(calls()).toEqual([{ device_id: "dev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name_typed: "Pixel 9" }]);
    expect(h.root.querySelector(".modal")).toBeNull();
    expect(h.store.get().devices[0]?.revoked_at).not.toBeNull();
    await h.go("devices");
    expect(h.root.querySelector("[data-fid^=revoke-dev_]")).toBeNull();
    expect(h.root.textContent).toContain("폐기한 기기 (1)");
  });

  it("cancel closes without revoking, Escape too", async () => {
    click(q(h.root, "[data-fid^=revoke-dev_]"));
    click(q(h.root, "[data-action=revoke-cancel]"));
    expect(h.root.querySelector(".modal")).toBeNull();
    click(q(h.root, "[data-fid^=revoke-dev_]"));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(h.root.querySelector(".modal")).toBeNull();
    expect(calls()).toHaveLength(0);
  });

  it("the controller refuses a mismatching name even if the dialog is bypassed", async () => {
    const [d] = h.store.get().devices;
    if (!d) throw new Error("device");
    expect(await h.controller.revokeDevice(d, "pixel 9")).toBe(false);
    expect(calls()).toHaveLength(0);
  });
});
