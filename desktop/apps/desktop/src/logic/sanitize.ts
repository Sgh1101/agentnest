/**
 * Display hygiene for daemon/agent-provided strings.
 *
 * The UI never uses innerHTML (see dom.ts), so HTML injection is impossible. These helpers
 * address the remaining text-level tricks: bidirectional overrides and invisible characters
 * that make a command look different from what it is. They are made *visible* instead of
 * being silently removed, so the user sees that something odd is in the text.
 */

// C0 controls except \t \n \r, DEL and C1 controls, bidi marks/embeddings/isolates, zero-width and BOM.
const SUSPICIOUS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

export function visualize(input: string): string {
  return input.replace(SUSPICIOUS, (ch) => `⟦U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}⟧`);
}

export function hasSuspicious(input: string): boolean {
  SUSPICIOUS.lastIndex = 0;
  return SUSPICIOUS.test(input);
}

/** Truncate by code points (never splits a surrogate pair) and append an ellipsis. */
export function truncate(input: string, max: number): string {
  const chars = Array.from(input);
  if (chars.length <= max) return input;
  return `${chars.slice(0, Math.max(0, max - 1)).join("")}…`;
}

/** visualize + truncate: the default for rendering any untrusted one-line string. */
export function safeText(input: string | null | undefined, max = 200): string {
  if (input === null || input === undefined) return "";
  return truncate(visualize(input), max);
}
