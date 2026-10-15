/** Press-and-hold controller. Completes exactly once per press; any release/leave cancels. */
export class HoldGate {
  private handle: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly durationMs: number,
    private readonly onComplete: () => void,
    private readonly onActiveChange?: (active: boolean) => void,
  ) {}

  get active(): boolean {
    return this.handle !== null;
  }

  start(): void {
    if (this.handle !== null) return;
    this.handle = setTimeout(() => {
      this.handle = null;
      this.onActiveChange?.(false);
      this.onComplete();
    }, this.durationMs);
    this.onActiveChange?.(true);
  }

  cancel(): void {
    if (this.handle === null) return;
    clearTimeout(this.handle);
    this.handle = null;
    this.onActiveChange?.(false);
  }
}
