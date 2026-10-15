import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PairingDevice } from "../src/api/types";
import { T0, click, mountHarness, q, qa, settle, type Harness } from "./helpers";

describe("pairing, QR visibility and SAS modal (security.md 4)", () => {
  let h: Harness;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
  });
  afterEach(() => {
    h.destroy();
    vi.useRealTimers();
  });

  const calls = (cmd: string): Array<Record<string, unknown>> => (h.mock?.calls ?? []).filter((c) => c.command === cmd).map((c) => c.args);
  const qr = (): HTMLImageElement | null => h.root.querySelector<HTMLImageElement>("img[data-qr]");
  const modal = (): HTMLElement | null => h.root.querySelector<HTMLElement>(".modal-root .modal");

  async function startPairing(opts: Parameters<typeof mountHarness>[0] = { settings: { seed: true } }): Promise<void> {
    h = await mountHarness(opts);
    await h.go("pairing");
    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
  }

  it("the QR is not shown until pairing mode starts, then shows with a countdown", async () => {
    h = await mountHarness({ settings: { seed: true } });
    await h.go("pairing");
    expect(qr()).toBeNull();
    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
    const img = qr();
    expect(img).not.toBeNull();
    expect(img?.getAttribute("src")).toMatch(/^data:image\/svg\+xml;base64,/);
    expect(q(h.root, "[data-pairing-active] [data-countdown-until]").textContent).toBe("2:00");
    await vi.advanceTimersByTimeAsync(10_000);
    expect(q(h.root, "[data-pairing-active] [data-countdown-until]").textContent).toBe("1:50");
  });

  it("the QR disappears on cancel, on expiry, on link disable and when a phone connects", async () => {
    await startPairing();
    click(q(h.root, "[data-fid=pairing-cancel]"));
    await settle();
    expect(qr()).toBeNull();
    expect(h.store.get().pairing).toBeNull();
    expect(calls("pairing_cancel")).toHaveLength(1);

    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
    expect(qr()).not.toBeNull();
    await vi.advanceTimersByTimeAsync(121_000);
    expect(qr()).toBeNull();
    expect(h.store.get().pairing).toBeNull();

    click(q(h.root, "[data-fid=pairing-start]"));
    await settle();
    expect(qr()).not.toBeNull();
    await h.controller.setLinkEnabled(false);
    await settle();
    expect(qr()).toBeNull();
    expect(h.store.get().pairing).toBeNull();
  });

  it("the QR (and its markup in the store) is dropped as soon as the phone sends its proof", async () => {
    await startPairing();
    h.mock?.simulatePairPending({ name: "Galaxy S25", platform: "android", model: "SM-S931" });
    await settle();
    expect(qr()).toBeNull();
    expect(h.store.get().pairing).toBeNull();
    expect(modal()).not.toBeNull();
  });

  it("pairing cannot start before the R1 risk is accepted (button disabled; backend would refuse anyway)", async () => {
    h = await mountHarness({ settings: { settings: { "risk.accepted": [] } } });
    await h.go("pairing");
    expect(q<HTMLButtonElement>(h.root, "[data-fid=pairing-start]").disabled).toBe(true);
    expect(h.root.textContent).toContain("수용된 위험");
    await h.controller.startPairing();
    expect(h.store.get().pairing).toBeNull();
    expect(qa(h.root, "[data-toast=error]").length).toBeGreaterThan(0);
  });

  describe("SAS modal", () => {
    async function pending(sas = "482915", device: PairingDevice = { name: "Galaxy S25", platform: "android", model: "SM-S931" }): Promise<void> {
      await startPairing();
      h.mock?.simulatePairPending(device, sas);
      await settle();
    }

    it("shows the SAS big, the device name/model, and keeps [승인] disabled for exactly 2 s", async () => {
      await pending();
      const m = q(h.root, ".modal");
      expect(q(m, "[data-sas]").textContent).toBe("482 915");
      expect(m.textContent).toContain("와 같습니까?");
      expect(q(m, "[data-sas-device]").textContent).toContain("Galaxy S25");
      expect(q(m, "[data-sas-device]").textContent).toContain("SM-S931");
      const approve = q<HTMLButtonElement>(m, "[data-action=sas-approve]");
      const reject = q<HTMLButtonElement>(m, "[data-action=sas-reject]");
      expect(approve.disabled).toBe(true);
      expect(approve.textContent).toContain("2초 뒤 활성");
      expect(reject.disabled).toBe(false);
      await vi.advanceTimersByTimeAsync(1750);
      expect(approve.disabled).toBe(true);
      await vi.advanceTimersByTimeAsync(250);
      expect(approve.disabled).toBe(false);
      expect(approve.textContent).toBe("승인");
    });

    it("approve before 2 s is refused even if the button is clicked programmatically", async () => {
      await pending();
      const approve = q<HTMLButtonElement>(h.root, "[data-action=sas-approve]");
      approve.disabled = false;
      click(approve);
      await settle();
      expect(calls("pairing_confirm")).toHaveLength(0);
      expect(await h.controller.confirmPairing(true)).toBe(false);
    });

    it("approve after 2 s calls pairing_confirm(pairing_id, true), adds the device and closes the modal", async () => {
      await pending();
      const id = h.store.get().sas?.pairing_id;
      await vi.advanceTimersByTimeAsync(2000);
      click(q(h.root, "[data-action=sas-approve]"));
      await settle();
      expect(calls("pairing_confirm")).toEqual([{ pairing_id: id, approve: true }]);
      expect(modal()).toBeNull();
      expect(h.store.get().devices.some((d) => d.name === "Galaxy S25")).toBe(true);
      expect(h.store.get().sas).toBeNull();
    });

    it("reject is available immediately and calls pairing_confirm(pairing_id, false)", async () => {
      await pending();
      click(q(h.root, "[data-action=sas-reject]"));
      await settle();
      expect(calls("pairing_confirm")).toMatchObject([{ approve: false }]);
      expect(modal()).toBeNull();
      expect(h.store.get().devices.some((d) => d.name === "Galaxy S25")).toBe(false);
    });

    it("Escape and backdrop clicks do not dismiss or approve", async () => {
      await pending();
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      click(q(h.root, ".modal-backdrop"));
      await settle();
      expect(modal()).not.toBeNull();
      expect(calls("pairing_confirm")).toHaveLength(0);
    });

    it("a malformed SAS can only be rejected (fail closed)", async () => {
      await pending("12ab56");
      await vi.advanceTimersByTimeAsync(3000);
      expect(q<HTMLButtonElement>(h.root, "[data-action=sas-approve]").disabled).toBe(true);
      expect(h.root.querySelector("[data-sas]")).toBeNull();
      expect(await h.controller.confirmPairing(true)).toBe(false);
      expect(calls("pairing_confirm")).toHaveLength(0);
    });

    it("an unanswered prompt is rejected automatically at the confirm timeout", async () => {
      await startPairing();
      h.mock?.simulatePairPending({ name: "Pixel", platform: "android", model: null }, "123456", 60_000);
      await settle();
      await vi.advanceTimersByTimeAsync(61_000);
      await settle();
      expect(calls("pairing_confirm")).toMatchObject([{ approve: false }]);
      expect(modal()).toBeNull();
    });

    it("device name from the phone is rendered as text, never markup", async () => {
      await pending("482915", { name: "<img src=x onerror=alert(1)>", platform: "android", model: null });
      expect(h.root.querySelector(".modal img")).toBeNull();
      expect(q(h.root, "[data-sas-device]").textContent).toContain("<img src=x onerror=alert(1)>");
    });

    it("completion toast and device list update after approval", async () => {
      await pending();
      await vi.advanceTimersByTimeAsync(2000);
      click(q(h.root, "[data-action=sas-approve]"));
      await settle();
      expect(qa(h.root, "[data-toast=success]").some((t) => t.textContent?.includes("기기를 추가"))).toBe(true);
    });
  });
});
