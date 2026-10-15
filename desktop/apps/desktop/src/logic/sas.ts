/** SAS confirmation rules (security.md 4.2 / 4.3). */

/** The approve button stays disabled for this long after the modal is shown. */
export const SAS_APPROVE_DELAY_MS = 2000;

/** "482915" -> "482 915". Returns null for anything that is not exactly six digits. */
export function formatSas(sas: string): string | null {
  return /^\d{6}$/.test(sas) ? `${sas.slice(0, 3)} ${sas.slice(3)}` : null;
}

export class SasGate {
  constructor(
    readonly shownAtMs: number,
    readonly timeoutMs: number,
    readonly delayMs: number = SAS_APPROVE_DELAY_MS,
  ) {}

  approveEnabled(nowMs: number): boolean {
    return nowMs - this.shownAtMs >= this.delayMs && !this.expired(nowMs);
  }

  /** Whole seconds until the approve button activates (0 when active). */
  secondsUntilEnabled(nowMs: number): number {
    return Math.max(0, Math.ceil((this.shownAtMs + this.delayMs - nowMs) / 1000));
  }

  expired(nowMs: number): boolean {
    return nowMs - this.shownAtMs >= this.timeoutMs;
  }
}
