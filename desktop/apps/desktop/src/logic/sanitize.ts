/**
 * Display hygiene for daemon/agent-provided strings.
 *
 * The UI never uses innerHTML (see dom.ts), so HTML injection is impossible. These helpers
 * address the remaining text-level tricks: bidirectional overrides and invisible characters
 * that make a command look different from what it is. They are made *visible* instead of
 * being silently removed, so the user sees that something odd is in the text.
 */

// Characters that change what a human reads without being visible themselves (second line of defence: the daemon's
// `mask_for_display` has already escaped most of them):
//   C0 controls except \t \n \r, DEL and C1 controls
//   U+00AD soft hyphen, U+034F combining grapheme joiner, U+061C Arabic letter mark
//   U+115F/U+1160 Hangul choseong/jungseong fillers, U+17B4/U+17B5 Khmer inherent vowels, U+180E Mongolian vowel separator
//   U+200B-U+200F zero-width + LRM/RLM, U+2028/U+2029 line/paragraph separators, U+202A-U+202E bidi embeddings/overrides
//   U+2060-U+2064 word joiner + invisible operators, U+2066-U+2069 bidi isolates, U+206A-U+206F deprecated format characters
//   U+2800 braille blank, U+3164 Hangul filler, U+FEFF BOM, U+FFA0 halfwidth Hangul filler, U+FFF9-U+FFFB interlinear annotation
//   U+E0000-U+E007F tag characters (invisible text smuggling)
const SUSPICIOUS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\u2066-\u206F\u2800\u3164\uFEFF\uFFA0\uFFF9-\uFFFB\u{E0000}-\u{E007F}]/gu;

export function visualize(input: string): string {
  return input.replace(SUSPICIOUS, (ch) => `⟦U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}⟧`);
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
